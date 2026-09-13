package fsops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/wproto"
)

// selfUID is the uid the worker would use: the one the kernel gave this
// process, and 0 on Windows, where os.Getuid reports -1 and there is no
// impersonation to speak of.
func selfUID() int {
	if uid := os.Getuid(); uid >= 0 {
		return uid
	}
	return 0
}

// trashFixture builds a temporary directory that the mount table declares to be
// an ext4 storage mount, with the .@qfm_trash directory already in place — the
// two things the real system provides and this package refuses to invent: the
// mount (the kernel's) and the sticky trash directory (the root front-end's,
// internal/trashroot).
func trashFixture(t *testing.T) (fsx.Root, *platform.Platform, string, string) {
	t.Helper()
	base := tempDir(t)
	r, api := hostRoot(t, base)
	plat := synthPlatform(t, synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"})
	makeTrashDir(t, base)
	return r, plat, base, api
}

// makeTrashDir creates the trash directory the way the root front-end does:
// world-writable and sticky, so a user may add entries and only remove their
// own. Windows has no sticky bit and no second user; the directory is enough
// there.
//
// The ownership the worker now demands of it (F2 — uid 0, because the root
// front-end is what makes it) cannot be produced by a test running as an
// ordinary user, so trashRootUID is pointed at whoever this process is. On the
// CI root job that is already zero and the assignment changes nothing; the check
// itself runs either way, and TestTrashRefusesAnAttackerOwnedRoot is what proves
// a mismatch is refused.
func makeTrashDir(t *testing.T, base string) {
	t.Helper()
	expectTrashOwner(t, selfUID())
	dir := filepath.Join(base, TrashDirName)
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
	}
}

// expectTrashOwner points the trash root's required owner at uid for one test.
func expectTrashOwner(t *testing.T, uid int) {
	t.Helper()
	prev := trashRootUID
	trashRootUID = uid
	t.Cleanup(func() { trashRootUID = prev })
}

// requireOwnership skips a test whose subject is a uid comparison. Windows has
// no uid behind a FileInfo, so statDetail reports none and every ownership check
// in this package degrades to a type test there (INV-2 — never simulate the
// kernel). The Linux CI jobs run these for real.
func requireOwnership(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a Windows FileInfo carries no uid, so there is no ownership to compare")
	}
}

// trashEntryDir names the directory one trash entry lives in.
func trashEntryDir(base string, uid int, id string) string {
	return filepath.Join(base, TrashDirName, itoa(uid), id)
}

// TestTrashDirNameMatchesTheFrontEnd: the worker renames into the directory the
// front-end created, so the two names have to be one fact. They are separate
// constants because the packages are on opposite sides of the RPC — this test
// is what keeps them from drifting apart.
func TestTrashDirNameMatchesTheFrontEnd(t *testing.T) {
	if TrashDirName != trashroot.DirName {
		t.Fatalf("fsops.TrashDirName = %q, trashroot.DirName = %q", TrashDirName, trashroot.DirName)
	}
}

// TestTrashRoundTrip is the whole of decision 10 in one test: a delete to trash
// is a same-device rename into <mount>/.@qfm_trash/<uid>/<id>/, described by a
// sidecar written first, listed for its owner, put back where it came from, and
// finally emptied.
func TestTrashRoundTrip(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	write(t, base, "doc.txt", "hello")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/doc.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Files != 1 || res.Bytes != 5 || res.Skipped != 0 {
		t.Fatalf("result = %+v (%v), want one file of five bytes trashed", res, log.warns)
	}
	if exists(t, base, "doc.txt") {
		t.Fatal("the item is still at its original path")
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("TrashList = %+v, want one item", items)
	}
	item := items[0]
	if string(item.OrigPath) != api+"/doc.txt" || string(item.Name) != "doc.txt" {
		t.Errorf("item = %+v, want the original path and name", item)
	}
	if item.Type != "file" || item.Size != 5 || item.DeletedAt == 0 {
		t.Errorf("item = %+v, want type file, size 5 and a deletion time", item)
	}
	if string(item.Trash) != api+"/"+TrashDirName {
		t.Errorf("item.Trash = %q, want the trash root that holds it", item.Trash)
	}

	// The sidecar is on disk, beside the item, inside this uid's subdirectory.
	entry := filepath.Join(base, TrashDirName, itoa(uid), item.ID)
	raw, err := os.ReadFile(filepath.Join(entry, trashMetaName))
	if err != nil {
		t.Fatalf("reading the sidecar: %v", err)
	}
	var meta trashMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("the sidecar is not JSON: %v", err)
	}
	if meta.OrigPath != api+"/doc.txt" || meta.Name != "doc.txt" || meta.Type != "file" || meta.Size != 5 {
		t.Errorf("meta = %+v", meta)
	}
	if meta.DeletedAt == 0 || meta.MTime == 0 || meta.Mode == "" {
		t.Errorf("meta = %+v, want the stat carried over", meta)
	}
	if runtime.GOOS != "windows" {
		if meta.UID != uid {
			t.Errorf("meta.UID = %d, want %d", meta.UID, uid)
		}
		for _, dir := range []string{filepath.Join(base, TrashDirName, itoa(uid)), entry} {
			fi, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o700 {
				t.Errorf("%s is mode %v, want 0700: a user's trash is their own", dir, fi.Mode().Perm())
			}
		}
	}
	// F9: on disk the payload has a fixed internal name, and the original
	// basename lives in the sidecar. That is what lets an item called
	// "meta.json" be trashed at all.
	if got, err := os.ReadFile(filepath.Join(entry, trashItemName)); err != nil || string(got) != "hello" {
		t.Fatalf("the item in the trash = %q, %v", got, err)
	}
	if exists(t, entry, "doc.txt") {
		t.Error("the payload must not keep its original name inside the entry directory")
	}

	// Restore puts it back and takes the entry with it.
	var restore jobLog
	res, err = TrashRestore(context.Background(), r, plat, uid, []string{item.ID}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 1 || res.Skipped != 0 {
		t.Fatalf("result = %+v (%v), want the item restored", res, restore.warns)
	}
	if got, err := os.ReadFile(filepath.Join(base, "doc.txt")); err != nil || string(got) != "hello" {
		t.Fatalf("the restored file = %q, %v", got, err)
	}
	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Errorf("the trash entry survived the restore: %v", err)
	}
	if items, err := TrashList(context.Background(), r, plat, uid); err != nil || len(items) != 0 {
		t.Fatalf("TrashList after the restore = %+v, %v", items, err)
	}
}

// TestTrashMovesAWholeTreeInOneRename: trashing a directory is one rename, not
// a walk, which is what makes it instant and what makes EXDEV a loud failure
// rather than a silent copy.
func TestTrashMovesAWholeTreeInOneRename(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/two.txt", "twotwo")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/a"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Dirs != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want one directory moved", res)
	}
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 || items[0].Type != "dir" {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	entry := trashEntryDir(base, uid, items[0].ID)
	if got, err := os.ReadFile(filepath.Join(entry, trashItemName, "sub", "two.txt")); err != nil || string(got) != "twotwo" {
		t.Fatalf("the tree did not move whole: %q %v", got, err)
	}
	if string(items[0].Name) != "a" {
		t.Errorf("item name = %q, want the original basename from the sidecar", items[0].Name)
	}
}

// TestTrashRestoreRefusesToOverwrite: the original path is occupied again, so
// the trashed copy stays in the trash rather than replacing what is there now.
// The rename is NOREPLACE, so it is the kernel that refuses, not a check that
// could be raced.
func TestTrashRestoreRefusesToOverwrite(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	write(t, base, "doc.txt", "old")
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/doc.txt"}, log.emit()); err != nil {
		t.Fatal(err)
	}
	write(t, base, "doc.txt", "new")

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{items[0].ID}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if len(restore.warns) != 1 || restore.warns[0].Code != "exists" {
		t.Fatalf("warns = %v, want exists", restore.warns)
	}
	if got, _ := os.ReadFile(filepath.Join(base, "doc.txt")); string(got) != "new" {
		t.Fatalf("the file at the original path = %q, want the newer one untouched", got)
	}
	if items, err := TrashList(context.Background(), r, plat, uid); err != nil || len(items) != 1 {
		t.Fatalf("the refused restore lost the trashed copy: %+v %v", items, err)
	}
}

// TestTrashRestoreWithoutItsOriginalFolder: v1 does not recreate the parent, so
// the honest answer is not_found and the item stays in the trash.
func TestTrashRestoreWithoutItsOriginalFolder(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "gone")
	write(t, base, "gone/doc.txt", "hello")
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/gone/doc.txt"}, log.emit()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(base, "gone")); err != nil {
		t.Fatal(err)
	}

	items, _ := TrashList(context.Background(), r, plat, uid)
	if len(items) != 1 {
		t.Fatalf("TrashList = %+v", items)
	}
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{items[0].ID}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Skipped != 1 || len(restore.warns) != 1 || restore.warns[0].Code != "not_found" {
		t.Fatalf("result = %+v warns = %v, want not_found", res, restore.warns)
	}
	if items, _ := TrashList(context.Background(), r, plat, uid); len(items) != 1 {
		t.Fatal("the item must stay in the trash when it cannot be put back")
	}
}

// TestTrashWithoutAUsableTrashSkipsAndNeverDeletes is the safety property of
// the whole file: "delete to trash" that cannot reach a trash leaves the item
// exactly where it is. It must never quietly become a permanent delete.
func TestTrashWithoutAUsableTrashSkipsAndNeverDeletes(t *testing.T) {
	cases := []struct {
		name string
		// setup returns the platform to use and whether the trash directory is
		// created.
		plat      func(t *testing.T, api string) *platform.Platform
		makeTrash bool
	}{
		{
			name:      "no mount table at all",
			plat:      func(*testing.T, string) *platform.Platform { return nil },
			makeTrash: true,
		},
		{
			name: "not a storage filesystem",
			plat: func(t *testing.T, api string) *platform.Platform {
				return synthPlatform(t, synthMount{mountPoint: api, fsType: "tmpfs", dev: "0:21", source: "tmpfs"})
			},
			makeTrash: true,
		},
		{
			name: "a network mount",
			plat: func(t *testing.T, api string) *platform.Platform {
				return synthPlatform(t, synthMount{mountPoint: api, fsType: "nfs4", dev: "0:42", source: "nas:/export"})
			},
			makeTrash: true,
		},
		{
			name: "the trash directory has not been created",
			plat: func(t *testing.T, api string) *platform.Platform {
				return synthPlatform(t, synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"})
			},
			makeTrash: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := tempDir(t)
			r, api := hostRoot(t, base)
			if c.makeTrash {
				makeTrashDir(t, base)
			}
			write(t, base, "doc.txt", "keep me")
			var log jobLog

			res, err := Trash(context.Background(), r, c.plat(t, api), selfUID(), []string{api + "/doc.txt"}, log.emit())
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
		})
	}
}

// TestTrashRefusesASymlinkedTrashDirectory: following it would move a user's
// files wherever whoever planted it pointed.
func TestTrashRefusesASymlinkedTrashDirectory(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	r, api := hostRoot(t, base)
	plat := synthPlatform(t, synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"})
	mkdir(t, base, "elsewhere")
	if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(base, TrashDirName)); err != nil {
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
		t.Fatal("the item was moved through a symlinked trash directory")
	}
}

// TestTrashRefusesToTrashTheTrash: the panel empties it, a recursive rename
// into itself does not.
func TestTrashRefusesToTrashTheTrash(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	var log jobLog

	res, err := Trash(context.Background(), r, plat, selfUID(), []string{api + "/" + TrashDirName}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Skipped != 1 || len(log.warns) != 1 || log.warns[0].Code != "no_trash" {
		t.Fatalf("result = %+v warns = %v, want no_trash", res, log.warns)
	}
	if !exists(t, base, TrashDirName) {
		t.Fatal("the trash directory was moved into itself")
	}
}

// TestTrashEmptyRemovesEverythingThatWasTrashed, permanently.
func TestTrashEmptyRemovesEverything(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	write(t, base, "one.txt", "one")
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/two.txt", "twotwo")
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/one.txt", api + "/a"}, log.emit()); err != nil {
		t.Fatal(err)
	}
	if items, _ := TrashList(context.Background(), r, plat, uid); len(items) != 2 {
		t.Fatalf("TrashList = %+v, want two items", items)
	}

	var empty jobLog
	res, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit())
	if err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if res.Skipped != 0 || res.Files == 0 {
		t.Fatalf("result = %+v (%v), want a clean permanent delete", res, empty.warns)
	}
	if items, err := TrashList(context.Background(), r, plat, uid); err != nil || len(items) != 0 {
		t.Fatalf("TrashList after empty = %+v, %v", items, err)
	}
	if exists(t, base, TrashDirName+"/"+itoa(uid)) {
		t.Error("the user's trash subdirectory should have gone with its contents")
	}
	if !exists(t, base, TrashDirName) {
		t.Error("the shared trash directory itself must not be removed")
	}
}

// TestTrashEmptyKeepsAnEntryWhosePayloadCannotGo is finding 14: emptying must
// never destroy the sidecar of an entry whose payload is still there.
//
// The payload here holds a component the worker never writes to (@Recycle, F10),
// which is a refusal every uid gets — root included — so this asserts the
// ordering rather than a permission the CI root job would not observe. The old
// implementation was one recursive DeleteTree of <uid>/, which walked meta.json
// as an ordinary file and could unlink it before reaching the payload: the entry
// then still held the user's data but had nothing to name it with, so it fell
// out of the listing and could never be restored.
func TestTrashEmptyKeepsAnEntryWhosePayloadCannotGo(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "keep/@Recycle")
	write(t, base, "keep/note.txt", "note")
	write(t, base, "go.txt", "gone")
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/keep", api + "/go.txt"}, log.emit()); err != nil {
		t.Fatal(err)
	}
	if items, _ := TrashList(context.Background(), r, plat, uid); len(items) != 2 {
		t.Fatalf("TrashList = %+v, want two items", items)
	}

	var empty jobLog
	res, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit())
	if err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	// The entry that could go, went; the other is still listed, which is the
	// whole property: an entry that survives an empty must survive it INTACT.
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList after empty: %v", err)
	}
	if len(items) != 1 || string(items[0].Name) != "keep" {
		t.Fatalf("TrashList after empty = %+v (%+v, %v), want the refused entry still listed", items, res, empty.warns)
	}
	kept := TrashDirName + "/" + itoa(uid) + "/" + items[0].ID
	if !exists(t, base, kept+"/"+trashMetaName) {
		t.Fatal("the sidecar of a kept entry was removed before its payload")
	}
	if !exists(t, base, kept+"/"+trashItemName) {
		t.Fatal("the payload of a kept entry is gone but its sidecar is not")
	}
	if indexOf(empty.codes(), "not_empty") < 0 || indexOf(empty.codes(), "protected") < 0 {
		t.Errorf("warn codes = %v, want the refusal and the entry that was kept", empty.codes())
	}

	// And the point of keeping it: it can still be put back. What comes back is
	// what the empty could not remove — the user asked for everything in the
	// trash to go, so note.txt going and @Recycle staying is the honest outcome;
	// what the fix is about is that the entry is still THERE to be restored.
	var restore jobLog
	rres, err := TrashRestore(context.Background(), r, plat, uid, []string{items[0].ID}, restore.emit())
	if err != nil || rres.Dirs != 1 || rres.Skipped != 0 {
		t.Fatalf("TrashRestore = %+v, %v (%v)", rres, err, restore.warns)
	}
	if !exists(t, base, "keep/@Recycle") {
		t.Fatal("the kept entry did not come back")
	}
}

// TestTrashEmptyCancellationLeavesTheRestIntact: a cancellation stops the empty
// between entries, and every entry it never reached is still a listable,
// restorable entry — not a payload whose sidecar was already gone.
func TestTrashEmptyCancellationLeavesTheRestIntact(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	for _, name := range []string{"one.txt", "two.txt", "three.txt"} {
		write(t, base, name, name)
	}
	var log jobLog
	if _, err := Trash(context.Background(), r, plat, uid,
		[]string{api + "/one.txt", api + "/two.txt", api + "/three.txt"}, log.emit()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var empty jobLog
	emit := empty.emit()
	inner := emit.Prog
	// Cancelled from inside the job, the moment the first item has gone: the
	// alternative is a sleep, and a sleep would be racing the delete.
	emit.Prog = func(p wproto.Prog) {
		inner(p)
		cancel()
	}

	res, err := TrashEmpty(ctx, r, plat, uid, emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TrashEmpty = %+v, %v, want context.Canceled", res, err)
	}
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList after a cancelled empty: %v", err)
	}
	if len(items) == 0 || len(items) == 3 {
		t.Fatalf("TrashList = %+v, want some entries emptied and the rest intact", items)
	}
	for _, it := range items {
		entry := TrashDirName + "/" + itoa(uid) + "/" + it.ID
		if !exists(t, base, entry+"/"+trashMetaName) || !exists(t, base, entry+"/"+trashItemName) {
			t.Fatalf("entry %s survived a cancellation only in part", it.ID)
		}
	}
	// Nothing was rolled back and nothing is half-removed, so a second empty
	// finishes the job.
	var again jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, again.emit()); err != nil {
		t.Fatalf("second TrashEmpty: %v", err)
	}
	if items, _ := TrashList(context.Background(), r, plat, uid); len(items) != 0 {
		t.Fatalf("TrashList after the second empty = %+v", items)
	}
}

// TestTrashIDsNameTheEntriesThatWereCreated: the ids the job reports are what
// the front-end's Undo restores, so they must be the entries on disk, in the
// order the paths were given, and only for the items actually trashed.
func TestTrashIDsNameTheEntriesThatWereCreated(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	write(t, base, "first.txt", "first")
	write(t, base, "second.txt", "second")
	var log jobLog
	// The middle path does not exist, so it is skipped and contributes no id.
	res, err := Trash(context.Background(), r, plat, uid,
		[]string{api + "/first.txt", api + "/missing.txt", api + "/second.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Files != 2 || res.Skipped != 1 {
		t.Fatalf("result = %+v (%v)", res, log.warns)
	}
	if len(res.TrashIDs) != 2 {
		t.Fatalf("TrashIDs = %v, want one id per item actually trashed", res.TrashIDs)
	}
	for i, want := range []string{"first.txt", "second.txt"} {
		id := res.TrashIDs[i]
		raw, err := os.ReadFile(filepath.Join(trashEntryDir(base, uid, id), trashMetaName))
		if err != nil {
			t.Fatalf("id %q names no entry on disk: %v", id, err)
		}
		var m trashMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m.Name != want {
			t.Errorf("TrashIDs[%d] = %q, whose sidecar names %q, want %q", i, id, m.Name, want)
		}
		if !exists(t, base, TrashDirName+"/"+itoa(uid)+"/"+id+"/"+trashItemName) {
			t.Errorf("entry %q has no payload", id)
		}
	}
	// And they are exactly what a restore takes.
	var restore jobLog
	rres, err := TrashRestore(context.Background(), r, plat, uid, res.TrashIDs, restore.emit())
	if err != nil || rres.Files != 2 || rres.Skipped != 0 {
		t.Fatalf("TrashRestore = %+v, %v (%v)", rres, err, restore.warns)
	}
	if !exists(t, base, "first.txt") || !exists(t, base, "second.txt") {
		t.Fatal("the reported ids did not restore the items that were trashed")
	}
}

// TestTrashListSkipsAHalfWrittenEntry: the sidecar is written before the item
// is moved, so a crash in between leaves a meta.json with nothing beside it.
// Listing it would offer a restore that could only fail.
func TestTrashListSkipsAHalfWrittenEntry(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	entry := filepath.Join(base, TrashDirName, itoa(uid), "1700000000-deadbeef")
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := trashMeta{OrigPath: api + "/lost.txt", Name: "lost.txt", Type: "file", DeletedAt: 1700000000}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashMetaName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// And an entry with no sidecar at all, which is equally not a listing.
	if err := os.MkdirAll(filepath.Join(base, TrashDirName, itoa(uid), "1700000001-cafebabe"), 0o700); err != nil {
		t.Fatal(err)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want the half-written entries skipped", items)
	}

	// TrashEmpty is what clears them.
	var log jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, log.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if exists(t, base, TrashDirName+"/"+itoa(uid)) {
		t.Error("the orphaned entries survived an empty")
	}
}

// TestTrashListIsNewestFirstAndOnlyThisUser.
func TestTrashListIsNewestFirstAndOnlyThisUser(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	var log jobLog
	for _, name := range []string{"first.txt", "second.txt"} {
		write(t, base, name, name)
		if _, err := Trash(context.Background(), r, plat, uid, []string{api + "/" + name}, log.emit()); err != nil {
			t.Fatal(err)
		}
	}
	// Somebody else's subdirectory, with a perfectly good entry in it.
	other := filepath.Join(base, TrashDirName, itoa(uid+1), "1700000000-0badf00d")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(trashMeta{OrigPath: api + "/theirs.txt", Name: "theirs.txt", Type: "file", DeletedAt: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, trashMetaName), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "theirs.txt"), []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("TrashList = %+v, want only this user's two items", items)
	}
	for _, it := range items {
		if string(it.Name) == "theirs.txt" {
			t.Fatal("another user's trash was listed")
		}
	}
	if items[0].DeletedAt < items[1].DeletedAt {
		t.Errorf("items are not newest first: %+v", items)
	}
}

// readSidecar reads and parses the sidecar of one trash entry.
func readSidecar(t *testing.T, base string, uid int, id string) trashMeta {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(trashEntryDir(base, uid, id), trashMetaName))
	if err != nil {
		t.Fatalf("reading the sidecar of %q: %v", id, err)
	}
	var m trashMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("the sidecar of %q is not JSON: %v", id, err)
	}
	return m
}

// TestTrashRecordsTheSizeOfTheWholeItem is the bug this file's size field had on
// real hardware: a trashed FOLDER was recorded as fi.Size() of the directory
// itself — 4096 on ext4 — so the panel could only show "—" and the empty-trash
// confirmation offered "4 096 byte(s)" as the size of a tree holding gigabytes.
//
// The size in the sidecar is now the size of everything the rename moved, and
// it has to be taken at trash time: the sidecar is written before the rename,
// and afterwards there is nothing at the original path to measure.
func TestTrashRecordsTheSizeOfTheWholeItem(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, base string)
		// item is the basename to trash, at the root of the fixture.
		item  string
		bytes int64
		files int64
	}{
		{
			name:  "a plain file is its own stat",
			build: func(t *testing.T, base string) { write(t, base, "doc.txt", "hello") },
			item:  "doc.txt",
			bytes: 5,
			files: 1,
		},
		{
			name: "a directory is the whole tree",
			build: func(t *testing.T, base string) {
				mkdir(t, base, "tree/sub/deep")
				write(t, base, "tree/one.txt", "one")
				write(t, base, "tree/sub/two.txt", "twotwo")
			},
			item:  "tree",
			bytes: 9,
			// Three directories (tree, sub, deep) and two files: the named
			// directory counts itself, as in Size.
			files: 5,
		},
		{
			name:  "an empty directory counts itself and nothing else",
			build: func(t *testing.T, base string) { mkdir(t, base, "empty") },
			item:  "empty",
			bytes: 0,
			files: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, plat, base, api := trashFixture(t)
			uid := selfUID()
			c.build(t, base)
			var log jobLog

			res, err := Trash(context.Background(), r, plat, uid, []string{api + "/" + c.item}, log.emit())
			if err != nil {
				t.Fatalf("Trash: %v", err)
			}
			if res.Skipped != 0 || len(res.TrashIDs) != 1 {
				t.Fatalf("result = %+v (%v), want the item trashed", res, log.warns)
			}
			// The sidecar is the durable record, so it is asserted on disk and not
			// only through the listing that reads it.
			meta := readSidecar(t, base, uid, res.TrashIDs[0])
			if meta.Size != c.bytes || meta.Files != c.files {
				t.Errorf("sidecar size/files = %d/%d, want %d/%d", meta.Size, meta.Files, c.bytes, c.files)
			}
			items, err := TrashList(context.Background(), r, plat, uid)
			if err != nil || len(items) != 1 {
				t.Fatalf("TrashList = %+v, %v", items, err)
			}
			if items[0].Size != c.bytes || items[0].Files != c.files {
				t.Errorf("item = %+v, want %d bytes in %d entries", items[0], c.bytes, c.files)
			}
		})
	}
}

// TestTrashListReportsAnOlderSidecarAsUnknown: sidecars written before the tree
// was measured are on the owner's NAS right now, and their "size" for a
// directory is the inode's own. They carry no "files" field at all, and a
// directory this build measured always counts at least itself — so files == 0 on
// a directory is exactly "an older build wrote this", and the honest answer for
// it is that the size is not known rather than a number describing nothing.
//
// A file's old sidecar needs no such treatment: st_size was always its real
// size, and it is still reported as one item.
func TestTrashListReportsAnOlderSidecarAsUnknown(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	// Written by hand, as the older build wrote it: every field but "files".
	old := map[string]struct {
		json    string
		dir     bool
		size    int64
		entries int64
	}{
		"1700000000-0000000a": {
			json: `{"origPath":"` + api + `/folder","name":"folder","type":"dir","size":4096,"deletedAt":1700000000}`,
			dir:  true, size: -1, entries: -1,
		},
		"1700000001-0000000b": {
			json: `{"origPath":"` + api + `/note.txt","name":"note.txt","type":"file","size":12,"deletedAt":1700000001}`,
			dir:  false, size: 12, entries: 1,
		},
	}
	for id, c := range old {
		entry := trashEntryDir(base, uid, id)
		if err := os.MkdirAll(entry, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(entry, trashMetaName), []byte(c.json), 0o600); err != nil {
			t.Fatal(err)
		}
		// The payload has to be there or the entry is a half-written one the
		// listing skips for an entirely different reason.
		if c.dir {
			if err := os.Mkdir(filepath.Join(entry, trashItemName), 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("hello world!"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != len(old) {
		t.Fatalf("TrashList = %+v, want both older entries listed", items)
	}
	for _, it := range items {
		want, ok := old[it.ID]
		if !ok {
			t.Fatalf("unexpected entry %+v", it)
		}
		if it.Size != want.size || it.Files != want.entries {
			t.Errorf("item %+v: size/files = %d/%d, want %d/%d", it, it.Size, it.Files, want.size, want.entries)
		}
	}
}

// TestTrashRecordsAnUncountableTreeAsUnknown: past the scan's bound the answer
// is UNKNOWN and not a floor. A partial total presented as a size would be a
// smaller and far more plausible lie than the directory inode's 4096 was.
//
// The bound itself is half a million entries, which is not a unit test; the
// variable it lives in is one so that the capped branch can be reached with
// three files (the same reason trashRootUID is a variable).
func TestTrashRecordsAnUncountableTreeAsUnknown(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "big")
	for _, name := range []string{"one.txt", "two.txt", "three.txt"} {
		write(t, base, "big/"+name, name)
	}
	write(t, base, "doc.txt", "hello")

	prev := trashScanMaxEntries
	trashScanMaxEntries = 1
	t.Cleanup(func() { trashScanMaxEntries = prev })

	var log jobLog
	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/big", api + "/doc.txt"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Skipped != 0 || len(res.TrashIDs) != 2 {
		t.Fatalf("result = %+v (%v), want both items trashed", res, log.warns)
	}
	// The tree is still moved — a size that could not be counted is never a
	// reason to leave an item where it is — and the sidecar says so.
	if meta := readSidecar(t, base, uid, res.TrashIDs[0]); meta.Size != -1 || meta.Files != -1 {
		t.Errorf("capped sidecar size/files = %d/%d, want -1/-1", meta.Size, meta.Files)
	}
	// A plain file never scans anything, so the bound cannot reach it.
	if meta := readSidecar(t, base, uid, res.TrashIDs[1]); meta.Size != 5 || meta.Files != 1 {
		t.Errorf("file sidecar size/files = %d/%d, want 5/1", meta.Size, meta.Files)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 2 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	for _, it := range items {
		want := int64(5)
		wantFiles := int64(1)
		if it.Type == "dir" {
			want, wantFiles = -1, -1
		}
		if it.Size != want || it.Files != wantFiles {
			t.Errorf("item %+v: size/files = %d/%d, want %d/%d", it, it.Size, it.Files, want, wantFiles)
		}
	}
}

// TestTrashRecordsAnIncompleteScanAsUnknown: a measurement that could not read
// the whole tree is UNKNOWN, not a floor. The bound is only one of the ways a
// scan comes back short — a subdirectory this user cannot read, a component the
// walk refuses to enter, a tree deeper than maxWalkDepth — and each of those
// used to be persisted in the sidecar as though it were the whole answer, which
// is a smaller and far more plausible lie than the inode size it replaced.
func TestTrashRecordsAnIncompleteScanAsUnknown(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, base string)
	}{
		{
			// ".zfs" is never entered by any walk here (F10), so whatever is
			// under it is not counted — and a folder that holds one therefore has
			// no known size.
			name: "a component no walk enters",
			build: func(t *testing.T, base string) {
				mkdir(t, base, "tree/.zfs/snapshot")
				write(t, base, "tree/one.txt", "one")
			},
		},
		{
			name: "a subdirectory this user cannot read",
			build: func(t *testing.T, base string) {
				requireOwnPermissions(t)
				mkdir(t, base, "tree/locked")
				write(t, base, "tree/one.txt", "one")
				if err := os.Chmod(filepath.Join(base, "tree", "locked"), 0o000); err != nil {
					t.Fatal(err)
				}
				// Put it back before t.TempDir tries to remove it.
				t.Cleanup(func() { _ = os.Chmod(filepath.Join(base, "tree", "locked"), 0o700) })
			},
		},
		{
			name: "a tree deeper than the walk goes",
			build: func(t *testing.T, base string) {
				if runtime.GOOS == "windows" {
					t.Skip("a pathname this deep is past MAX_PATH here, and the temporary directory could not be cleaned up")
				}
				rel := "tree"
				for i := 0; i < maxWalkDepth+2; i++ {
					rel += "/d"
				}
				mkdir(t, base, rel)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, plat, base, api := trashFixture(t)
			uid := selfUID()
			c.build(t, base)
			var log jobLog

			res, err := Trash(context.Background(), r, plat, uid, []string{api + "/tree"}, log.emit())
			if err != nil {
				t.Fatalf("Trash: %v", err)
			}
			// The item still goes to the trash: a size that could not be counted
			// is never a reason to leave something where it is.
			if res.Dirs != 1 || res.Skipped != 0 || len(res.TrashIDs) != 1 {
				t.Fatalf("result = %+v (%v), want the folder trashed", res, log.warns)
			}
			if meta := readSidecar(t, base, uid, res.TrashIDs[0]); meta.Size != -1 || meta.Files != -1 {
				t.Errorf("sidecar size/files = %d/%d, want -1/-1 for a tree that was not fully read", meta.Size, meta.Files)
			}
			items, err := TrashList(context.Background(), r, plat, uid)
			if err != nil || len(items) != 1 {
				t.Fatalf("TrashList = %+v, %v", items, err)
			}
			if items[0].Size != -1 || items[0].Files != -1 {
				t.Errorf("item = %+v, want an unknown size", items[0])
			}
		})
	}
}

// TestTrashRewritesASidecarThatMeasuredADifferentTree is the second half of F2,
// one step past the rename: the scan and the rename each look the item up by
// NAME, so another writer on the volume can move the selected folder aside in
// between and what lands in the trash is a different tree — described by a
// sidecar stating somebody else's totals as fact.
//
// The race itself cannot be staged reliably from a test, so the payload lstat is
// the seam: it hands back a different object, which is exactly what the check is
// looking for. What must follow is a sidecar whose size is unknown and an entry
// that is otherwise untouched — still listed, still restorable.
func TestTrashRewritesASidecarThatMeasuredADifferentTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows FileInfo carries no device and inode, so there is no identity to compare (INV-2)")
	}
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	mkdir(t, base, "tree/sub")
	write(t, base, "tree/one.txt", "one")
	write(t, base, "decoy.txt", "decoy")
	decoy, err := os.Lstat(filepath.Join(base, "decoy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	prev := trashPayloadOf
	trashPayloadOf = func(*dirRef) (os.FileInfo, error) { return decoy, nil }
	t.Cleanup(func() { trashPayloadOf = prev })

	var log jobLog
	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/tree"}, log.emit())
	if err != nil {
		t.Fatalf("Trash: %v", err)
	}
	if res.Dirs != 1 || res.Skipped != 0 || len(res.TrashIDs) != 1 {
		t.Fatalf("result = %+v (%v), want the folder trashed all the same", res, log.warns)
	}
	if indexOf(log.codes(), "conflict") < 0 {
		t.Errorf("warn codes = %v, want the corrected size reported", log.codes())
	}
	id := res.TrashIDs[0]
	if meta := readSidecar(t, base, uid, id); meta.Size != -1 || meta.Files != -1 {
		t.Errorf("sidecar size/files = %d/%d, want the numbers rewritten as unknown", meta.Size, meta.Files)
	}
	// The rewrite replaces the sidecar and leaves nothing else behind: a stray
	// temporary would make the entry impossible to empty (its rmdir would find
	// the directory not empty for good).
	entry := trashEntryDir(base, uid, id)
	names, err := os.ReadDir(entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("entry holds %d names, want exactly the sidecar and the payload", len(names))
	}

	// And the entry is otherwise exactly what it was: listed, and restorable.
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 || items[0].Size != -1 || items[0].Files != -1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	var restore jobLog
	rres, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil || rres.Dirs != 1 || rres.Skipped != 0 {
		t.Fatalf("TrashRestore = %+v, %v (%v)", rres, err, restore.warns)
	}
	if got, err := os.ReadFile(filepath.Join(base, "tree", "one.txt")); err != nil || string(got) != "one" {
		t.Fatalf("the restored tree = %q, %v", got, err)
	}
}

// TestTrashEmptyForgetsTheSizeOfWhatItPartlyRemoved: an empty is the one
// operation that can leave PART of an item behind — a protected component inside
// it, a file the kernel will not let go, a cancellation between two unlinks —
// and an entry that survives like that is no longer the tree its sidecar
// measured. The number is therefore given up before the first removal, not
// corrected after the last one, because "after" is a moment a crash can land in
// front of.
func TestTrashEmptyForgetsTheSizeOfWhatItPartlyRemoved(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	// @Recycle is never written to (F10), so the empty can remove note.txt and
	// nothing else — a refusal every uid gets, root included.
	mkdir(t, base, "keep/@Recycle")
	write(t, base, "keep/@Recycle/held.txt", "held")
	write(t, base, "keep/note.txt", "note")
	var log jobLog
	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/keep"}, log.emit())
	if err != nil || len(res.TrashIDs) != 1 {
		t.Fatalf("Trash = %+v, %v (%v)", res, err, log.warns)
	}
	id := res.TrashIDs[0]
	// Four entries — keep, @Recycle, held.txt, note.txt — and eight bytes, all
	// known: that is the number the empty is about to make untrue.
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	if items[0].Size != 8 || items[0].Files != 4 {
		t.Fatalf("item = %+v, want 8 bytes in 4 entries before the empty", items[0])
	}

	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	// The entry survived, part of it is gone, and what it says about itself no
	// longer claims to be the whole tree.
	items, err = TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("TrashList after the empty = %+v, %v (%v)", items, err, empty.warns)
	}
	if items[0].Size != -1 || items[0].Files != -1 {
		t.Errorf("item = %+v, want a size the empty gave up rather than 8 bytes in 4 entries", items[0])
	}
	if meta := readSidecar(t, base, uid, id); meta.Size != -1 || meta.Files != -1 {
		t.Errorf("sidecar size/files = %d/%d, want -1/-1 on disk too", meta.Size, meta.Files)
	}
	// And the entry is otherwise intact: the rewrite left no litter, the payload
	// that could not go is still there, and it can still be restored.
	entry := trashEntryDir(base, uid, id)
	names, err := os.ReadDir(entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("entry holds %d names, want exactly the sidecar and the payload", len(names))
	}
	if exists(t, entry, trashItemName+"/note.txt") {
		t.Error("the part that could go did not go")
	}
	var restore jobLog
	rres, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil || rres.Dirs != 1 || rres.Skipped != 0 {
		t.Fatalf("TrashRestore = %+v, %v (%v)", rres, err, restore.warns)
	}
	if !exists(t, base, "keep/@Recycle/held.txt") {
		t.Error("what the empty kept did not come back")
	}
}

// TestTrashMeasurementStopsAtAMountItDidNotEnter: a mount point inside the
// selected tree is visited and never descended into (decision 9), so its
// contents are not in the total — and a mount OVER a populated directory hides
// files that are on this volume and do move with the rename. Neither is a
// complete measurement, so what the sidecar records is "not known" rather than a
// number that quietly leaves a subtree out.
func TestTrashMeasurementStopsAtAMountItDidNotEnter(t *testing.T) {
	base := tempDir(t)
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/tree/sub", fsType: "ext4", dev: "8:2", source: "/dev/sdb1"},
	)
	makeTrashDir(t, base)
	uid := selfUID()
	mkdir(t, base, "tree/sub")
	write(t, base, "tree/one.txt", "one")
	write(t, base, "tree/sub/beneath.txt", "beneath")
	var log jobLog

	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/tree"}, log.emit())
	if err != nil || res.Dirs != 1 || len(res.TrashIDs) != 1 {
		t.Fatalf("Trash = %+v, %v (%v)", res, err, log.warns)
	}
	if meta := readSidecar(t, base, uid, res.TrashIDs[0]); meta.Size != -1 || meta.Files != -1 {
		t.Errorf("sidecar size/files = %d/%d, want -1/-1 for a tree with a mount inside it", meta.Size, meta.Files)
	}
	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil || len(items) != 1 {
		t.Fatalf("TrashList = %+v, %v", items, err)
	}
	if items[0].Size != -1 || items[0].Files != -1 {
		t.Errorf("item = %+v, want an unknown size", items[0])
	}
}

// TestTrashEmptyClearsALeftOverSidecarTemporary: a crash between a rewrite's
// create and its rename leaves a meta.json.<pid>-<hex>.new behind, and a
// directory with a stray file in it is one no rmdir will take — so without this
// the entry could never be cleared at all. The empty recognises its own litter
// and removes it, which is why that residual is a residual and not a trap.
func TestTrashEmptyClearsALeftOverSidecarTemporary(t *testing.T) {
	r, plat, base, api := trashFixture(t)
	uid := selfUID()
	write(t, base, "doc.txt", "hello")
	var log jobLog
	res, err := Trash(context.Background(), r, plat, uid, []string{api + "/doc.txt"}, log.emit())
	if err != nil || len(res.TrashIDs) != 1 {
		t.Fatalf("Trash = %+v, %v", res, err)
	}
	entry := trashEntryDir(base, uid, res.TrashIDs[0])
	litter := filepath.Join(entry, trashMetaTmpPrefix+"999-deadbeef"+trashMetaTmpSuffix)
	if err := os.WriteFile(litter, []byte(`{"partly`), 0o600); err != nil {
		t.Fatal(err)
	}

	var empty jobLog
	if _, err := TrashEmpty(context.Background(), r, plat, uid, empty.emit()); err != nil {
		t.Fatalf("TrashEmpty: %v", err)
	}
	if len(empty.warns) != 0 {
		t.Errorf("warns = %v, want an empty that simply worked", empty.warns)
	}
	if exists(t, base, TrashDirName+"/"+itoa(uid)) {
		t.Fatal("a leftover sidecar temporary kept the entry from ever being removed")
	}
}

// TestSidecarTemporaryNames: the name is unique per rewrite — two jobs emptying
// one trash must never share it — and it is recognisable, because an empty has
// to be able to tell its own litter from the sidecar and the payload.
func TestSidecarTemporaryNames(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		name, err := trashMetaTmpName()
		if err != nil {
			t.Fatal(err)
		}
		if seen[name] {
			t.Fatalf("%q came back twice: two rewrites could collide", name)
		}
		seen[name] = true
		if !isTrashMetaTmp(name) {
			t.Fatalf("%q is not recognised as a sidecar temporary", name)
		}
		if err := fsx.ValidName(name); err != nil {
			t.Fatalf("%q is not a name that can be created: %v", name, err)
		}
	}
	// And nothing else may be mistaken for one, because being mistaken for one is
	// being unlinked. The whole shape is demanded — "meta.json.", a decimal pid,
	// "-", eight lowercase hex characters, ".new" — so a name this package could
	// never have written is a name it will not remove.
	for _, name := range []string{
		trashMetaName, trashItemName,
		"meta.json.new",                      // no build that wrote this fixed name was ever released
		"meta.json.backup.new",               // a plausible name for somebody else's file
		"meta.json.12-deadbeef.new.x",        // something appended
		"meta.json.-deadbeef.new",            // no pid
		"meta.json.12-DEADBEEF.new",          // uppercase: not what hex.EncodeToString writes
		"meta.json.12-deadbee.new",           // seven hex characters
		"meta.json.12-deadbeef0.new",         // nine
		"meta.json.12-deadbeeg.new",          // not hex at all
		"meta.json.1x-deadbeef.new",          // not a decimal pid
		"meta.json.12345678901-deadbeef.new", // a pid no pid_t produces
		".new", "meta.jsonx.1-2.new", "notes.new",
	} {
		if isTrashMetaTmp(name) {
			t.Errorf("%q must not be taken for a sidecar temporary", name)
		}
	}
}

// TestNoTrashPayload: an invalidation that cannot describe the payload has to
// tell "there is nothing here that could be half-removed" from "the lstat
// failed". The first is nothing to do; the second, treated as the first, lets an
// empty take a tree apart underneath a sidecar still claiming the whole of it.
func TestNoTrashPayload(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "no payload at all", err: fs.ErrNotExist, want: true},
		{name: "wrapped not-exist", err: &fs.PathError{Op: "lstat", Path: "item", Err: syscall.ENOENT}, want: true},
		{name: "the name leads to no directory", err: syscall.ENOTDIR, want: true},
		{name: "too many links to follow", err: fmt.Errorf("lstat: %w", syscall.ELOOP), want: true},
		{name: "the lstat itself failed", err: syscall.EIO, want: false},
		{name: "out of descriptors", err: fmt.Errorf("openat: %w", syscall.EMFILE), want: false},
		{name: "refused", err: fs.ErrPermission, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := noTrashPayload(c.err); got != c.want {
				t.Fatalf("noTrashPayload(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestRewriteTrashMetaRefusesAnOversizedSidecar: a sidecar is accepted up to
// maxTrashMeta, and re-marshalling one can grow it past that — JSON escapes what
// a Linux filename may contain. Publishing an oversized replacement would make
// readTrashMeta refuse the entry from then on: not listed, not restorable, and
// its payload still on the disk. The original stays instead, merely out of date.
func TestRewriteTrashMetaRefusesAnOversizedSidecar(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "entry")
	r := newRoot(t, base)
	tg, err := resolve(r, "/entry", true)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := openDirRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.close()

	original := trashMeta{OrigPath: "/a", Name: "a", Type: "dir", Size: 8, Files: 4, DeletedAt: 1700000000}
	if err := writeTrashMeta(entry, original); err != nil {
		t.Fatal(err)
	}
	// The room left for the name in the REPLACEMENT's shape: -1 is two characters
	// where 8 and 4 were one each, which is exactly the kind of growth this
	// guard exists for.
	probe := original
	probe.Name, probe.Size, probe.Files = "", -1, -1
	raw, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	room := maxTrashMeta - len(raw)

	// Exactly at the limit is published: the check is on what a reader will
	// refuse, and a reader accepts maxTrashMeta itself.
	fits := probe
	fits.Name = strings.Repeat("x", room)
	if err := rewriteTrashMeta(entry, fits); err != nil {
		t.Fatalf("a replacement of exactly %d bytes must still be published: %v", maxTrashMeta, err)
	}
	// One byte more is not, and what stays is the sidecar that was there.
	over := fits
	over.Name += "x"
	if err := rewriteTrashMeta(entry, over); err == nil {
		t.Fatal("a replacement past the limit was published")
	}
	got, err := os.ReadFile(filepath.Join(base, "entry", trashMetaName))
	if err != nil {
		t.Fatal(err)
	}
	var kept trashMeta
	if err := json.Unmarshal(got, &kept); err != nil {
		t.Fatalf("the sidecar that was kept does not parse: %v", err)
	}
	if kept.Name != fits.Name || len(got) > maxTrashMeta {
		t.Errorf("kept a sidecar of %d bytes named %.20q…, want the last one that fitted", len(got), kept.Name)
	}
	// And the refusal left nothing behind to trip an empty's rmdir.
	names, err := os.ReadDir(filepath.Join(base, "entry"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("the entry holds %d names, want only the sidecar", len(names))
	}
}

// TestSidecarNotOnDisplay: an invalidation that cannot read the sidecar has to
// tell "there is nothing a reader was showing" from "the read failed". The first
// is nothing to correct; the second leaves a number on display that the empty is
// about to make wrong, and saying nothing about it is how a stale total survives.
func TestSidecarNotOnDisplay(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "no sidecar at all", err: fs.ErrNotExist, want: true},
		{name: "wrapped not-exist", err: fmt.Errorf("open: %w", fs.ErrNotExist), want: true},
		{name: "not this uid's", err: fmt.Errorf("meta.json: %w", ErrUntrustedTrash), want: true},
		{name: "not the JSON this wrote", err: fmt.Errorf("meta.json: %w", &json.SyntaxError{}), want: true},
		{name: "a field of the wrong type", err: fmt.Errorf("meta.json: %w", &json.UnmarshalTypeError{}), want: true},
		{name: "the read itself failed", err: syscall.EIO, want: false},
		{name: "out of descriptors", err: fmt.Errorf("openat: %w", syscall.EMFILE), want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sidecarNotOnDisplay(c.err); got != c.want {
				t.Fatalf("sidecarNotOnDisplay(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestTrashSizeDescribesOnlyWhatItMeasured is the three-way compare on its own:
// the held reference the item was selected through, the descriptor the scan
// enumerated, and the payload that landed in the entry must all be one object.
// Either of the other two differing means a name was re-pointed between two
// lookups and the numbers belong to a tree that is not in the trash.
//
// It runs where the question can be asked. Off Linux a FileInfo carries no
// device and no inode, sameObject answers "cannot tell", and the rule there is
// that a question which cannot be asked is never answered no (INV-2).
func TestTrashSizeDescribesOnlyWhatItMeasured(t *testing.T) {
	base := tempDir(t)
	write(t, base, "measured.txt", "measured")
	write(t, base, "other.txt", "other")
	measured, err := os.Lstat(filepath.Join(base, "measured.txt"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Lstat(filepath.Join(base, "other.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, known := sameObject(measured, other)
	size := trashSize{bytes: 8, files: 1, scanned: measured}

	// Two of these arms depend on the host and one does not, which is the whole
	// contract in a table. Telling two REAL objects apart needs a device and an
	// inode number, so off Linux the answer is "cannot tell" and the rule is that
	// an unanswerable question is never answered no (want: !known). A MISSING
	// half is not that question: nothing at all is never the object that was
	// measured, on every platform, so those arms are false everywhere.
	cases := []struct {
		name             string
		selected, landed os.FileInfo
		want             bool
	}{
		{name: "all one object", selected: measured, landed: measured, want: true},
		{name: "the scan counted something else", selected: other, landed: measured, want: !known},
		{name: "something else landed in the trash", selected: measured, landed: other, want: !known},
		{name: "nothing landed at all", selected: measured, landed: nil, want: false},
		{name: "nothing was selected", selected: nil, landed: measured, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := size.describes(c.selected, c.landed); got != c.want {
				t.Fatalf("describes = %v, want %v (identity is comparable here: %v)", got, c.want, known)
			}
		})
	}
	// A measurement with no root of its own describes nothing either.
	if (trashSize{bytes: 8, files: 1}).describes(measured, measured) {
		t.Error("a measurement that never recorded what it counted cannot describe anything")
	}
	// An unknown measurement has no numbers to protect, so the check never runs.
	if !(trashSize{bytes: -1, files: -1}).unknown() {
		t.Error("a measurement of -1 is the unknown one")
	}
	if (trashSize{bytes: 0, files: 1}).unknown() {
		t.Error("an empty file is measured, not unknown")
	}
}

// itoa names a uid the way the trash layout does.
func itoa(uid int) string { return strconv.Itoa(uid) }
