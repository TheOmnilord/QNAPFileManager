package fsops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/trashroot"
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

// itoa names a uid the way the trash layout does.
func itoa(uid int) string { return strconv.Itoa(uid) }
