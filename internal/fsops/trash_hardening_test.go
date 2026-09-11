package fsops

// The M2-A review-round-1 hardening tests for the trash: F1 (ownership on every
// consuming path), F2 (the trash root itself), F6 (a symlinked original parent),
// F8 (an attacker-controlled sidecar), F9 (the fixed payload name) and F10 (the
// worker's own never-write component rule).
//
// The ownership cases skip off Linux, where a FileInfo carries no uid and every
// one of those checks degrades to a type test (INV-2 — never simulate the
// kernel). The CI Linux jobs run them for real.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestTrashRoundTripsAnItemCalledMetaJSON is F9. The payload used to keep its
// original basename inside the entry directory, so an item literally called
// "meta.json" collided with the sidecar that had just been written beside it and
// the NOREPLACE rename refused it: a file nobody could delete to trash.
func TestTrashRoundTripsAnItemCalledMetaJSON(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	const body = "a meta.json of the user's own"
	write(t, base, trashMetaName, body)
	var log jobLog

	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/" + trashMetaName}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Files != 1 || res.Skipped != 0 {
		t.Fatalf("result = %+v (%v), want the item trashed", res, log.warns)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	if string(items[0].Name) != trashMetaName {
		t.Errorf("item name = %q, want %q", items[0].Name, trashMetaName)
	}

	var restore jobLog
	res, err = TrashRestore(context.Background(), r, plat, uid, []string{items[0].ID}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 1 || res.Skipped != 0 {
		t.Fatalf("result = %+v (%v), want the item restored", res, restore.warns)
	}
	got, err := os.ReadFile(filepath.Join(base, trashMetaName))
	if err != nil || string(got) != body {
		t.Fatalf("the restored file = %q, %v", got, err)
	}
}

// TestTrashListSkipsAnOrphanSidecar is the other half of F9: an entry directory
// holding only a meta.json is what a crash between the sidecar write and the
// rename leaves behind, and it must never be mistaken for a payload. With the
// payload under a fixed name the test is exact — "item" is either there or it is
// not, and a file under the item's own basename is not a payload any more.
func TestTrashListSkipsAnOrphanSidecar(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	const id = "1700000000-deadbeef"
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(trashMeta{OrigPath: api + "/lost.txt", Name: "lost.txt", Type: "file", DeletedAt: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashMetaName), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "lost.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want the orphan sidecar skipped", items)
	}

	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if exists(t, base, "lost.txt") {
		t.Fatal("an orphan sidecar was restored as though it named a payload")
	}
}

// TestTrashRefusesAnAttackerOwnedRoot is F2. .@qfm_trash is 1777 and the OWNER
// of a sticky directory is exempt from its restrictions — they may rename and
// unlink everything inside it — so a sticky directory that does not belong to
// root has the mode bits of a safe trash and none of the safety. It is treated
// as no trash at all, and "delete to trash" must therefore leave the item
// exactly where it is rather than quietly becoming a delete.
func TestTrashRefusesAnAttackerOwnedRoot(t *testing.T) {
	requireOwnership(t)
	r, plat, base, api := trashFixture(t)
	// The directory really belongs to this process; telling the worker the
	// front-end runs as somebody else is the same comparison the other way up,
	// and it is the only one a test without a second account can make.
	expectTrashOwner(t, selfUID()+1)
	write(t, base, "doc.txt", "keep me")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, selfUID(), []string{api + "/doc.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the item skipped", res)
	}
	if len(log.warns) != 1 || log.warns[0].Code != "no_trash" {
		t.Fatalf("warns = %v, want exactly one no_trash", log.warns)
	}
	if got, err := os.ReadFile(filepath.Join(base, "doc.txt")); err != nil || string(got) != "keep me" {
		t.Fatalf("the item was not left alone: %q %v", got, err)
	}
	if items, err := TrashList(context.Background(), r, plat, selfUID()); err != nil || len(items) != 0 {
		t.Fatalf("TrashList = %+v, %v — an untrusted root must list nothing", items, err)
	}
}

// TestTrashRefusesANonStickyRoot is the rest of F2: without the sticky bit any
// user may rename any other user's deleted files out of the shared directory.
func TestTrashRefusesANonStickyRoot(t *testing.T) {
	requireOwnership(t)
	base := tempDir(t)
	r, api := hostRoot(t, base)
	plat := synthPlatform(t, synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"})
	expectTrashOwner(t, selfUID())
	dir := filepath.Join(base, TrashDirName)
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	write(t, base, "doc.txt", "keep me")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, selfUID(), []string{api + "/doc.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Skipped != 1 || len(log.warns) != 1 || log.warns[0].Code != "no_trash" {
		t.Fatalf("result = %+v warns = %v, want no_trash", res, log.warns)
	}
	if !exists(t, base, "doc.txt") {
		t.Fatal("the item was moved into a trash directory with no sticky bit")
	}
}

// TestTrashIgnoresAForgedEntry is F1, and it is the finding that mattered most.
// Anyone may create <trash>/0/<id>/ inside the shared sticky directory, with a
// payload and a meta.json naming a root-only destination. A root worker that
// listed it would show an administrator somebody else's entry as their own, and
// a restore of it would write an attacker's file to an attacker's chosen path.
//
// The forgery here is the same comparison from the other side — an entry
// directory that exists under a uid it does not belong to — which is what lets
// it run without a second account.
func TestTrashIgnoresAForgedEntry(t *testing.T) {
	requireOwnership(t)
	r, plat, base, api := trashFixture(t)
	victim := selfUID() + 1 // the uid whose trash this pretends to be
	const id = "1700000000-0badf00d"
	entry := trashEntryDir(base, victim, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(trashMeta{
		OrigPath: api + "/planted.txt", Name: "planted.txt", Type: "file", DeletedAt: 1700000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashMetaName), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := TrashList(context.Background(), r, plat, victim)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want the forged entry ignored", items)
	}

	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, victim, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if exists(t, base, "planted.txt") {
		t.Fatal("a forged trash entry was restored to the path its sidecar named")
	}

	// Emptied: nothing, because emptying it would be this worker deleting
	// whatever an attacker chose to have removed at that moment.
	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, victim, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if !exists(t, base, TrashDirName+"/"+itoa(victim)+"/"+id+"/"+trashItemName) {
		t.Fatal("a forged trash entry was deleted by an empty")
	}
	if indexOf(empty.codes(), "protected") < 0 {
		t.Errorf("warn codes = %v, want the untrusted entry reported as protected", empty.codes())
	}
}

// TestTrashRestoreRefusesASymlinkedParent is F6: the original parent must still
// be reachable with no symlink component. resolve() follows links, so a parent
// that has become one since the item was trashed would put the file back
// wherever the link now points — which is not where it came from.
func TestTrashRestoreRefusesASymlinkedParent(t *testing.T) {
	requireSymlinks(t)
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "home")
	write(t, base, "home/doc.txt", "hello")
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/home/doc.txt"}, log.emit()); err != nil {
		t.Fatal(err)
	}
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}

	// "home" is now a link to somewhere else entirely.
	if err := os.Remove(filepath.Join(base, "home")); err != nil {
		t.Fatal(err)
	}
	mkdir(t, base, "elsewhere")
	if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(base, "home")); err != nil {
		t.Fatal(err)
	}

	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{items[0].ID}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v (%v), want the restore refused", res, restore.warns)
	}
	if len(restore.warns) != 1 || restore.warns[0].Code != "conflict" {
		t.Fatalf("warns = %v, want conflict", restore.warns)
	}
	if exists(t, base, "elsewhere/doc.txt") {
		t.Fatal("the restore wrote through a symlinked parent")
	}
	if items, err := TrashList(context.Background(), r, plat, uid); err != nil || len(items) != 1 {
		t.Fatalf("the refused restore lost the trashed copy: %+v %v", items, err)
	}
}

// TestTrashRefusesNeverWriteComponents is F10 on the trash side: .zfs is
// read-only in the kernel and @Recycle is never written to (decision 10), so
// neither is moved into the trash — the guard refuses them for a job's root
// paths and the worker refuses them again for itself.
func TestTrashRefusesNeverWriteComponents(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	mkdir(t, base, "@Recycle")
	write(t, base, "@Recycle/bin.txt", "the recycle bin")
	mkdir(t, base, ".zfs/snapshot")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, selfUID(),
		[]string{api + "/@Recycle", api + "/.zfs", api + "/@Recycle/bin.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Skipped != 3 || res.Files != 0 || res.Dirs != 0 {
		t.Fatalf("result = %+v, want all three refused", res)
	}
	for _, code := range log.codes() {
		if code != "protected" {
			t.Fatalf("warn codes = %v, want every one of them protected", log.codes())
		}
	}
	if !exists(t, base, "@Recycle/bin.txt") || !exists(t, base, ".zfs/snapshot") {
		t.Fatal("a never-write path was moved into the trash")
	}
}

// TestDeleteTreeRefusesNeverWriteComponents is F10 on the delete side, both for
// a selected path and for a component the recursion reaches on its own — which
// is the case the guard cannot see, because it is only ever shown a job's roots.
func TestDeleteTreeRefusesNeverWriteComponents(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/.zfs/snapshot")
	mkdir(t, base, "a/@Recycle")
	write(t, base, "a/@Recycle/bin.txt", "the recycle bin")
	write(t, base, "a/ordinary.txt", "fine")
	r := newRoot(t, base)

	var selected jobLog
	res, err := DeleteTree(context.Background(), r, nil, []string{"/a/.zfs", "/a/@Recycle"},
		DeleteOptions{Recursive: true}, selected.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Skipped != 2 || res.Files != 0 || res.Dirs != 0 {
		t.Fatalf("result = %+v, want both selected paths refused", res)
	}
	for _, code := range selected.codes() {
		if code != "protected" {
			t.Fatalf("warn codes = %v, want protected", selected.codes())
		}
	}

	// And from above: the ordinary file goes, the two protected directories
	// stay, and their parent is reported as not empty rather than half-removed.
	var above jobLog
	res, err = DeleteTree(context.Background(), r, nil, []string{"/a"}, DeleteOptions{Recursive: true}, above.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("result = %+v, want the ordinary file removed", res)
	}
	if !exists(t, base, "a/.zfs/snapshot") || !exists(t, base, "a/@Recycle/bin.txt") {
		t.Fatal("a never-write component was deleted by a recursion the guard never saw")
	}
	codes := above.codes()
	if indexOf(codes, "protected") < 0 || indexOf(codes, "not_empty") < 0 {
		t.Fatalf("warn codes = %v, want protected and not_empty", codes)
	}
}

// TestSizeSkipsSnapshotsAndCountsTheRecycleBin is the read-only half of F10: a
// snapshot tree is skipped because it can be enormous, and @Recycle is counted
// because decision 10 only forbids WRITING to it.
func TestSizeSkipsSnapshotsAndCountsTheRecycleBin(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/.zfs/snapshot")
	mkdir(t, base, "a/@Recycle")
	write(t, base, "a/.zfs/snapshot/old.txt", "a snapshot of the whole share")
	write(t, base, "a/@Recycle/bin.txt", "sixsix")
	write(t, base, "a/one.txt", "one")
	r := newRoot(t, base)
	var log jobLog

	res, err := Size(context.Background(), r, nil, []string{"/a"}, false, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	// /a, /a/@Recycle and their two files: the snapshot tree is not counted.
	if res.Files != 2 || res.Dirs != 2 || res.Bytes != 9 {
		t.Fatalf("result = %+v, want 2 files, 2 dirs, 9 bytes (@Recycle counted, .zfs skipped)", res)
	}
	if w, ok := log.warnFor("/a/.zfs"); !ok || w.Code != "protected" {
		t.Fatalf("warns = %v, want protected for /a/.zfs", log.warns)
	}
}
