package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// TestMkdirThroughASearchOnlyParent: creating a directory needs write and
// search permission on the parent, and search — not read — on the directories
// above it. The O_PATH walk asks the kernel for exactly that, so a directory
// under a search-only ancestor (mode 0111, a private index with writable
// contents) can still be created. os.Root would have opened the ancestor
// O_RDONLY and turned it into EACCES; this is the mutation-side counterpart of
// the read-side search-only tests. It runs unprivileged, because root's
// CAP_DAC_OVERRIDE would ignore the very bits under test (INV-2).
func TestMkdirThroughASearchOnlyParent(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "outer/inner")
	outer := filepath.Join(base, "outer")
	chmodBack(t, outer, 0o755)
	if err := os.Chmod(outer, 0o111); err != nil { // searchable, not readable
		t.Fatal(err)
	}
	if _, err := os.ReadDir(outer); err == nil {
		t.Skip("this filesystem does not enforce the directory read bit")
	}
	r := newRoot(t, base)

	e, err := Mkdir(context.Background(), r, "/outer/inner", "made", 0, false, nil)
	if err != nil {
		t.Fatalf("Mkdir under a search-only ancestor: %v", err)
	}
	if e.Path != "/outer/inner/made" || e.Type != "dir" {
		t.Fatalf("entry = %+v, want /outer/inner/made", e)
	}
	if fi, serr := os.Stat(filepath.Join(base, "outer", "inner", "made")); serr != nil || !fi.IsDir() {
		t.Fatalf("the directory was not created: %v", serr)
	}
}

// TestMkdirWithOwnerChownsTheLeaf is the admin-as-real-user fix (owner hardware
// report): when an Owner is passed, the just-created directory is chowned to
// the requested uid and chmod'd to the exact mode, defeating the umask — the
// behaviour File Station gives, so a real-uid user can write into a folder an
// admin's root worker made. Handing an inode to another uid needs root, so this
// runs only in the test-linux-root CI job (INV-2: the kernel, not a simulation,
// does the chown). Without an Owner the create is unchanged: root-owned, umask
// mode.
func TestMkdirWithOwnerChownsTheLeaf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chowning a new directory to another uid needs root; the test-linux-root job runs this one")
	}
	const fixtureUID = 65534 // nobody on every distribution the NAS resembles
	base := tempDir(t)
	mkdir(t, base, "area")
	r := newRoot(t, base)

	// With an Owner: the leaf is chowned to the fixture uid, its group left as the
	// parent supplied it (GID -1), and its mode set to exactly 0770.
	if _, err := Mkdir(context.Background(), r, "/area", "owned", 0, false, &Owner{UID: fixtureUID, GID: -1, Mode: 0o770}); err != nil {
		t.Fatalf("Mkdir with an owner: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "area", "owned"), &st); err != nil {
		t.Fatalf("lstat the owned directory: %v", err)
	}
	if int(st.Uid) != fixtureUID {
		t.Errorf("owner uid = %d, want %d", st.Uid, fixtureUID)
	}
	if st.Mode&0o777 != 0o770 {
		t.Errorf("mode = %#o, want 0770 (umask defeated)", st.Mode&0o777)
	}
	if int(st.Gid) != 0 {
		t.Errorf("gid = %d, want 0 kept from the parent (GID -1 leaves it)", st.Gid)
	}

	// Without an Owner: unchanged. The root worker created it, so it is root-owned.
	if _, err := Mkdir(context.Background(), r, "/area", "plain", 0, false, nil); err != nil {
		t.Fatalf("Mkdir without an owner: %v", err)
	}
	var pst syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "area", "plain"), &pst); err != nil {
		t.Fatalf("lstat the plain directory: %v", err)
	}
	if int(pst.Uid) != 0 {
		t.Errorf("plain owner uid = %d, want 0 (unchanged, root-owned)", pst.Uid)
	}
}

// TestRenameAcrossDevicesIsCrossDevice mounts a tmpfs so that a rename crosses a
// filesystem boundary, which the kernel refuses with EXDEV — on QuTS hero the
// everyday case, since every share is its own dataset and a move between shares
// crosses one. It needs root to mount, so it runs only in the test-linux-root
// CI job and skips elsewhere.
func TestRenameAcrossDevicesIsCrossDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting a tmpfs to force EXDEV needs root; this runs in the test-linux-root job")
	}
	base := tempDir(t)
	mnt := filepath.Join(base, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, ""); err != nil {
		t.Skipf("could not mount a tmpfs for the cross-device fixture: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, 0) })
	if err := os.WriteFile(filepath.Join(mnt, "f.txt"), []byte("on the tmpfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	err := Rename(context.Background(), r, "/mnt/f.txt", "/f.txt", false)
	if !errors.Is(err, fsx.ErrCrossDevice) {
		t.Fatalf("Rename across a mount = %v, want fsx.ErrCrossDevice", err)
	}
	if code := fsx.Code(err); code != "cross_device" {
		t.Errorf("code = %q, want cross_device", code)
	}
	// The source is left where it was: a cross-device rename moves nothing.
	if _, serr := os.Lstat(filepath.Join(mnt, "f.txt")); errors.Is(serr, fs.ErrNotExist) {
		t.Error("the source was lost by a refused cross-device rename")
	}
}
