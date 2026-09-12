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
// report): when an Owner is passed, the just-created directory is chowned to the
// requested uid — the behaviour File Station gives, so a real-uid user can write
// into a folder an admin's root worker made (owner rwx in the umask mode). It is
// NOT chmod'd (findings B/D): leaving the umask mode keeps the parent's setgid
// bit and any ACLs intact. Handing an inode to another uid needs root, so this
// runs only in the test-linux-root CI job (INV-2: the kernel, not a simulation,
// does the chown). Without an Owner the create is unchanged: root-owned.
func TestMkdirWithOwnerChownsTheLeaf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chowning a new directory to another uid needs root; the test-linux-root job runs this one")
	}
	const fixtureUID = 65534 // nobody on every distribution the NAS resembles
	base := tempDir(t)
	mkdir(t, base, "area")
	r := newRoot(t, base)

	// With an Owner: the leaf is chowned to the fixture uid and its group left as
	// the parent supplied it (GID -1). Mode is reserved and applied nowhere in M1,
	// so the mode is whatever the umask produced — deliberately not forced.
	if _, err := Mkdir(context.Background(), r, "/area", "owned", 0, false, &Owner{UID: fixtureUID, GID: -1}); err != nil {
		t.Fatalf("Mkdir with an owner: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "area", "owned"), &st); err != nil {
		t.Fatalf("lstat the owned directory: %v", err)
	}
	if int(st.Uid) != fixtureUID {
		t.Errorf("owner uid = %d, want %d", st.Uid, fixtureUID)
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

// TestChownLeafProvenanceRefusesSubstitution is the directory-substitution fix
// (finding A). chownLeaf establishes provenance on the descriptor before it
// chowns: the leaf must be a directory, owned by root, and EMPTY. O_NOFOLLOW
// refuses a symlink swapped over the leaf name but NOT a real directory renamed
// there, so without this an attacker who can rename entries in the parent could
// slide a pre-existing, data-bearing directory under the name and have root
// chown it away. Here the substitution is modelled directly: chownLeaf is asked
// to adopt a name that already resolves to a NON-EMPTY (or foreign-owned)
// directory, and it must refuse with errLeafSubstituted and leave the owner
// untouched. Needs root to create a foreign-owned directory and to observe that
// the chown does not happen, so it runs in the test-linux-root CI job.
func TestChownLeafProvenanceRefusesSubstitution(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("proving a chown is refused, and making a foreign-owned dir, needs root; the test-linux-root job runs this one")
	}
	const fixtureUID = 65534 // nobody
	base := tempDir(t)
	parent, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()

	// A non-empty, root-owned directory: emptiness is the security-relevant
	// property, so adopting this would hand away a directory that already holds
	// data. chownLeaf must refuse.
	mkdir(t, base, "nonempty")
	if err := os.WriteFile(filepath.Join(base, "nonempty", "secret"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := chownLeaf(parent, "nonempty", &Owner{UID: fixtureUID, GID: -1}); !errors.Is(err, errLeafSubstituted) {
		t.Fatalf("chownLeaf on a non-empty dir = %v, want errLeafSubstituted", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "nonempty"), &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != 0 {
		t.Errorf("a refused adoption still chowned: uid = %d, want 0 (untouched)", st.Uid)
	}

	// A foreign-owned but empty directory: not one the root worker just made, so
	// its uid != 0 and provenance refuses it before any chown.
	mkdir(t, base, "foreign")
	if err := syscall.Chown(filepath.Join(base, "foreign"), fixtureUID, -1); err != nil {
		t.Fatal(err)
	}
	if err := chownLeaf(parent, "foreign", &Owner{UID: 0, GID: -1}); !errors.Is(err, errLeafSubstituted) {
		t.Fatalf("chownLeaf on a foreign-owned dir = %v, want errLeafSubstituted", err)
	}

	// The control: an empty, root-owned directory — the real freshly-created leaf
	// — is adopted.
	mkdir(t, base, "fresh")
	if err := chownLeaf(parent, "fresh", &Owner{UID: fixtureUID, GID: -1}); err != nil {
		t.Fatalf("chownLeaf on an empty root-owned dir = %v, want adoption", err)
	}
	if err := syscall.Lstat(filepath.Join(base, "fresh"), &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != fixtureUID {
		t.Errorf("the fresh leaf was not adopted: uid = %d, want %d", st.Uid, fixtureUID)
	}
}

// TestMkdirUnderSetgidParentKeepsSetgid is finding D: because the create path no
// longer chmods (finding B), a directory created under a setgid parent keeps the
// setgid bit mkdirat inherited, even after the owner chown. Needs root for the
// chown, so it runs in the test-linux-root CI job.
func TestMkdirUnderSetgidParentKeepsSetgid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chowning the created leaf to another uid needs root; the test-linux-root job runs this one")
	}
	const fixtureUID = 65534 // nobody
	base := tempDir(t)
	mkdir(t, base, "sg")
	sg := filepath.Join(base, "sg")
	// setgid on the parent so children inherit it (and the group).
	if err := syscall.Chmod(sg, syscall.S_ISGID|0o770); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	if _, err := Mkdir(context.Background(), r, "/sg", "child", 0, false, &Owner{UID: fixtureUID, GID: -1}); err != nil {
		t.Fatalf("Mkdir under a setgid parent: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "sg", "child"), &st); err != nil {
		t.Fatalf("lstat the child: %v", err)
	}
	if st.Mode&syscall.S_ISGID == 0 {
		t.Errorf("mode = %#o: the inherited setgid bit was lost (a chmod crept back in)", st.Mode&0o7777)
	}
	if int(st.Uid) != fixtureUID {
		t.Errorf("child uid = %d, want %d (chown still applied)", st.Uid, fixtureUID)
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
