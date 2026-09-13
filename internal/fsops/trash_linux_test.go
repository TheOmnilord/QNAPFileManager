package fsops

// The trash checks that only a real Linux kernel can be asked about (INV-2).

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// plantTrashEntry builds one trash entry by hand — the entry directory, a
// sidecar naming a destination inside the fixture, and a payload — the way an
// attacker who can create entries in the 1777 trash would. The modes are the
// point of the tests below, so they are passed in rather than assumed.
func plantTrashEntry(t *testing.T, base, api string, uid int, id string, dirMode, metaMode os.FileMode) string {
	t.Helper()
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(entry, trashMetaName)
	body := `{"origPath":"` + api + `/planted.txt","name":"planted.txt","type":"file"}`
	if err := os.WriteFile(meta, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(meta, metaMode); err != nil {
		t.Fatal(err)
	}
	// The entry directory's mode goes on last: a 0777 one still has to be
	// writable by this test, and it is, but the order keeps the two independent.
	if err := os.Chmod(entry, dirMode); err != nil {
		t.Fatal(err)
	}
	return entry
}

// TestTrashEntryDirectoryMustNotBeWritableByOthers is B1. Round 1 established
// that nothing is consumed that the consumer does not OWN; round 2's point is
// that ownership is not authenticity. An entry directory that belongs to this
// uid but is group- or other-writable is a directory somebody else can write
// into — and writing into it is the whole attack: the payload is replaced under
// a sidecar that is still perfectly valid, and the owner's worker (root's, for an
// administrator) then restores the attacker's content to the path the sidecar
// names.
//
// The worker creates every entry directory 0700, so a real one is never refused.
func TestTrashEntryDirectoryMustNotBeWritableByOthers(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	const id = "1700000000-aaaa0001"
	entry := plantTrashEntry(t, base, api, uid, id, 0o777, 0o600)

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want a world-writable entry directory skipped", items)
	}

	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if exists(t, base, "planted.txt") {
		t.Fatal("a directory anybody could write into chose what a worker restored")
	}

	// An empty must not destroy it either: it is not an entry this worker may
	// consume, so it is reported and left exactly where it is.
	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if indexOf(empty.codes(), "protected") < 0 {
		t.Errorf("warn codes = %v, want the untrusted entry reported", empty.codes())
	}
	if _, err := os.Lstat(filepath.Join(entry, trashItemName)); err != nil {
		t.Errorf("the entry was emptied anyway: %v", err)
	}
}

// TestTrashSidecarMustNotBeWritableByOthers is B2, the same lesson applied to
// meta.json. origPath is the destination a restore renames to, so a sidecar
// another identity may rewrite is that identity choosing where this worker
// writes — and for an administrator's session that worker is root.
//
// TestTrashEmptyKeepsAnEntryWithAnUntrustedSidecar is the empty half (B6): the
// same entry the listing and the restore refuse here is one an empty must not
// destroy either.
func TestTrashSidecarMustNotBeWritableByOthers(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	const id = "1700000000-aaaa0002"
	plantTrashEntry(t, base, api, uid, id, 0o700, 0o666)

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want a world-writable sidecar skipped", items)
	}

	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if len(restore.warns) != 1 || restore.warns[0].Code != "protected" {
		t.Fatalf("warns = %v, want protected", restore.warns)
	}
	if exists(t, base, "planted.txt") {
		t.Fatal("a sidecar anybody could rewrite chose where a worker wrote")
	}
}

// TestTrashSidecarMustBeARegularFile is F8. meta.json lives inside a directory
// in a 1777 tree, so it is attacker-controlled, and a fifo planted at that name
// would park a worker goroutine inside open(2) with no writer — where no
// deadline in this process can reach it. Sixty-four such entries would take
// every slot the worker has.
//
// The sidecar is therefore opened O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
// through the entry directory's own descriptor and then fstat'ed: a fifo is not
// a regular file, so it is skipped, and the open returned instead of blocking.
func TestTrashSidecarMustBeARegularFile(t *testing.T) {
	r, plat, base, _ := trashFixture(t)
	uid := selfUID()
	const id = "1700000000-f1f0f1f0"
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(entry, trashMetaName), 0o600); err != nil {
		t.Skipf("this filesystem will not take a fifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The listing must come back, and promptly: a blocked open would hang here
	// until the test binary's own timeout rather than failing.
	done := make(chan []string, 1)
	go func() {
		items, err := TrashList(context.Background(), r, plat, uid)
		if err != nil {
			done <- []string{"error: " + err.Error()}
			return
		}
		names := make([]string, 0, len(items))
		for _, it := range items {
			names = append(names, string(it.Name))
		}
		done <- names
	}()
	select {
	case names := <-done:
		if len(names) != 0 {
			t.Fatalf("TrashList = %v, want the fifo sidecar skipped", names)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("TrashList blocked on a fifo standing in for meta.json")
	}

	// And a restore of it is refused rather than blocked.
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if len(restore.warns) != 1 || restore.warns[0].Code != "protected" {
		t.Fatalf("warns = %v, want protected", restore.warns)
	}
}

// TestTrashSidecarMustBeOwnedByTheReader is the ownership half of F8, and it
// needs a second uid: only root can hand a file to somebody else. The CI root
// job runs it.
func TestTrashSidecarMustBeOwnedByTheReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file away needs root; the CI root job runs this one")
	}
	r, plat, base, api := trashFixture(t)
	uid := selfUID() // 0 here: an administrator's session, whose trash is <trash>/0/
	const id = "1700000000-0f0f0f0f"
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(entry, trashMetaName)
	if err := os.WriteFile(meta, []byte(`{"origPath":"`+api+`/planted.txt","name":"planted.txt","type":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The sidecar is nobody's business but the reader's, and this one is not
	// theirs: uid 65534 is nobody on every distribution the NAS resembles.
	if err := os.Chown(meta, 65534, 65534); err != nil {
		t.Skipf("cannot give the sidecar away here: %v", err)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want the foreign sidecar skipped", items)
	}
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if exists(t, base, "planted.txt") {
		t.Fatal("a sidecar owned by somebody else chose where a root worker wrote")
	}
}

// TestTrashEmptyKeepsAnEntryWithAnUntrustedSidecar is B6.
//
// Round 2 taught emptying to check the entry DIRECTORY's owner and mode; the
// sidecar inside it went unchecked, so a uid-owned entry carrying a meta.json
// anybody may rewrite was emptied even though TrashList skips it and
// TrashRestore refuses it. That is the one operation in the file destroying a
// record the rest of it calls untrusted — permanently, and for an entry the user
// was never shown.
//
// The orphan entry in the same trash is the control, and it is the behaviour the
// round-1 follow-up deliberately kept: an entry with NO sidecar cannot be listed
// or restored by anyone, so clearing it is exactly what an empty is for.
func TestTrashEmptyKeepsAnEntryWithAnUntrustedSidecar(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	const (
		untrusted = "1700000000-bbbb0001"
		orphan    = "1700000000-bbbb0002"
	)
	entry := plantTrashEntry(t, base, api, uid, untrusted, 0o700, 0o666)

	// The orphan: an entry directory and a payload, with the sidecar the crash
	// between the two writes never got to leave behind.
	orphanDir := trashEntryDir(base, uid, orphan)
	if err := os.MkdirAll(orphanDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanDir, trashItemName), []byte("nameless"), 0o600); err != nil {
		t.Fatal(err)
	}

	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}

	entryAPI := api + "/" + TrashDirName + "/" + itoa(uid) + "/" + untrusted
	w, ok := empty.warnFor(entryAPI)
	if !ok || w.Code != "protected" {
		t.Errorf("warns = %v, want %q reported as protected", empty.warns, entryAPI)
	}
	for _, name := range []string{trashMetaName, trashItemName} {
		if _, err := os.Lstat(filepath.Join(entry, name)); err != nil {
			t.Errorf("%s of the untrusted entry was destroyed: %v", name, err)
		}
	}
	if _, err := os.Lstat(orphanDir); !os.IsNotExist(err) {
		t.Errorf("the orphan entry survived the empty (%v); an entry nobody can restore is what an empty clears", err)
	}
}

// TestTrashEmptyKeepsAnEntryWhoseSidecarIsSomebodyElses is the ownership half of
// B6, and it needs a second uid: only root can hand a file to somebody else. The
// CI root job runs it.
func TestTrashEmptyKeepsAnEntryWhoseSidecarIsSomebodyElses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file away needs root; the CI root job runs this one")
	}
	r, plat, base, api := trashFixture(t)
	uid := selfUID() // 0 here: an administrator's session, whose trash is <trash>/0/
	const id = "1700000000-bbbb0003"
	entry := plantTrashEntry(t, base, api, uid, id, 0o700, 0o600)
	if err := os.Chown(filepath.Join(entry, trashMetaName), 65534, 65534); err != nil {
		t.Skipf("cannot give the sidecar away here: %v", err)
	}

	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if indexOf(empty.codes(), "protected") < 0 {
		t.Errorf("warn codes = %v, want the foreign sidecar reported", empty.codes())
	}
	for _, name := range []string{trashMetaName, trashItemName} {
		if _, err := os.Lstat(filepath.Join(entry, name)); err != nil {
			t.Errorf("%s of an entry whose sidecar is somebody else's was destroyed: %v", name, err)
		}
	}
}

// TestTrashEmptyKeepsAnEntryTheKernelWillNotEmpty is finding 14 with the kernel
// making the refusal rather than the app: a payload holding a sub-item this
// process may not unlink, because the directory it is in is read-only to it.
//
// The entry must come out of the empty exactly as it went in — sidecar, payload
// and all — because an entry whose sidecar had gone first would still be holding
// the user's data with nothing left to name it: not listed, not restorable.
//
// Root is refused nothing (CAP_DAC_OVERRIDE), so this asks the unprivileged
// Linux job; the @Recycle version of the same property runs everywhere.
func TestTrashEmptyKeepsAnEntryTheKernelWillNotEmpty(t *testing.T) {
	requireUnprivileged(t)
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "tree/locked")
	write(t, base, "tree/locked/file.txt", "x")
	var log jobLog
	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/tree"}, log.emit())
	if err != nil || len(res.TrashIDs) != 1 {
		t.Fatalf("Trash = %+v, %v (%v)", res, err, log.warns)
	}
	id := res.TrashIDs[0]
	// r-x: the file inside can be seen but not unlinked, so the directory
	// holding it cannot go either.
	locked := filepath.Join(trashEntryDir(base, uid, id), trashItemName, "locked")
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	// Put it back before t.TempDir tries to remove the tree.
	chmodBack(t, locked, 0o700)

	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList after empty: %v", err)
	}
	if len(items) != 1 || items[0].ID != id {
		t.Fatalf("TrashList = %+v, want entry %s still listed after an empty it survived", items, id)
	}
	entry := trashEntryDir(base, uid, id)
	for _, name := range []string{trashMetaName, trashItemName} {
		if _, err := os.Lstat(filepath.Join(entry, name)); err != nil {
			t.Errorf("%s of the kept entry: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(locked, "file.txt")); err != nil {
		t.Errorf("the file the kernel would not let go is gone: %v", err)
	}
	if indexOf(empty.codes(), "not_empty") < 0 {
		t.Errorf("warn codes = %v, want the entry reported as kept", empty.codes())
	}
}

// TestTrashHoldsTheItemItMeasured: the reference the three-way identity check is
// made against is a HELD O_PATH descriptor, not a stat taken and let go.
//
// The difference is the whole point. A stat is a snapshot of a NAME: the inode
// behind it can be unlinked while the scan runs and its (dev, ino) handed
// straight back to a file somebody else creates, at which point two entirely
// different objects compare equal and the check passes a sidecar describing
// another tree. A descriptor is a reference to the inode, so while the trash
// holds it the number cannot be reused — which is what this asserts, by taking
// the name away underneath it.
func TestTrashHoldsTheItemItMeasured(t *testing.T) {
	base := tempDir(t)
	write(t, base, "doc.txt", "hello")
	r := newRoot(t, base)
	tg, err := resolve(r, "/doc.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := openItemRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatalf("openItemRef: %v", err)
	}
	defer ref.close()
	if ref.f == nil {
		t.Fatal("the reference must hold a descriptor, not just a stat")
	}
	if err := os.Remove(filepath.Join(base, "doc.txt")); err != nil {
		t.Fatal(err)
	}
	// The name is gone; the object is not, and it is still the same one.
	again, err := ref.f.Stat()
	if err != nil {
		t.Fatalf("the held descriptor stopped describing its object: %v", err)
	}
	if same, known := sameObject(ref.fi, again); !known || !same {
		t.Errorf("the held descriptor changed object when the name did (comparable: %v)", known)
	}
}
