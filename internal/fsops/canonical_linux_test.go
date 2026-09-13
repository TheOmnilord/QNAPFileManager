package fsops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// M2-C review round 14 adversarial: the worker is given the spelling the
// front-end's own guarded resolution produced, so a symlink on that path is not
// something to follow — it is evidence that the tree changed after it was
// authorized. Every one of these is Linux's, because what makes the refusal
// possible is openat with O_NOFOLLOW and an inode identity.

// requireBirthTimes skips a test whose subject is statx STATX_BTIME on a
// filesystem that does not record one. ext4, XFS, btrfs and ZFS all do; tmpfs
// does not, and a temporary directory is very often on one.
func requireBirthTimes(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	if cerr := rc.Control(func(fd uintptr) { _, ok = birthTimeOf(int(fd)) }); cerr != nil {
		t.Fatal(cerr)
	}
	if !ok {
		t.Skipf("the filesystem under %s records no birth time (statx STATX_BTIME), so an inode number is the whole identity there", dir)
	}
}

// swapAncestorForSymlink renames dir away and leaves a symlink to target at its
// name — the substitution every one of these tests is about.
func swapAncestorForSymlink(t *testing.T, dir, moved, target string) {
	t.Helper()
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
}

// TestFSIdentityRefusesASymlinkAncestor: the RPC the front-end takes an
// identity with must not follow a replacement, or the identity it hands back
// describes the replacement perfectly and every later check agrees with it.
func TestFSIdentityRefusesASymlinkAncestor(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "safe/inner")
	write(t, base, "safe/inner/file.txt", "authorized")
	mkdir(t, base, "secrets/inner")
	write(t, base, "secrets/inner/file.txt", "not authorized")
	r := newRoot(t, base)

	swapAncestorForSymlink(t, filepath.Join(base, "safe"), filepath.Join(base, "safe-moved"),
		filepath.Join(base, "secrets"))

	_, err := FSIdentity(context.Background(), r, nil, "/safe/inner/file.txt")
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if !strings.Contains(err.Error(), "safe") {
		t.Errorf("the refusal must name the component: %v", err)
	}
}

// TestFSIdentityDescribesASymlinkLeaf keeps the refusal to ancestors: the leaf
// is the thing being described, and a symlink there is a legitimate answer — it
// is the object a move would rename.
func TestFSIdentityDescribesASymlinkLeaf(t *testing.T) {
	base := tempDir(t)
	write(t, base, "target.txt", "x")
	if err := os.Symlink("target.txt", filepath.Join(base, "link.txt")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	r := newRoot(t, base)

	id, err := FSIdentity(context.Background(), r, nil, "/link.txt")
	if err != nil {
		t.Fatalf("a symlink leaf must be described, not refused: %v", err)
	}
	if id.Dir {
		t.Errorf("identity = %+v, want the link itself", id)
	}
	if id.Ino == 0 {
		t.Error("the link's own inode must be reported")
	}
}

// TestOpenWriteRefusesASymlinkAncestor is the same rule on the upload path,
// where the gap between the authorization and the open is the body's headers —
// entirely the client's to time.
func TestOpenWriteRefusesASymlinkAncestor(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "safe/dst")
	mkdir(t, base, "secrets/dst")
	r := newRoot(t, base)

	swapAncestorForSymlink(t, filepath.Join(base, "safe"), filepath.Join(base, "safe-moved"),
		filepath.Join(base, "secrets"))

	f, _, err := OpenWrite(context.Background(), r, nil, openWriteReq("/safe/dst", "a.txt"))
	if err == nil {
		f.Close()
		t.Fatal("an upload through a replaced ancestor must be refused")
	}
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if got := dirNames(t, base, "secrets/dst"); len(got) != 0 {
		t.Fatalf("the replacement was written into: %v", got)
	}
}

// TestOpenWriteRefusesASymlinkDestination: the destination itself is a
// directory the guard cleared, so a link of that name is refused too.
func TestOpenWriteRefusesASymlinkDestination(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "dst")
	mkdir(t, base, "elsewhere")
	r := newRoot(t, base)

	swapAncestorForSymlink(t, filepath.Join(base, "dst"), filepath.Join(base, "dst-moved"),
		filepath.Join(base, "elsewhere"))

	f, _, err := OpenWrite(context.Background(), r, nil, openWriteReq("/dst", "a.txt"))
	if err == nil {
		f.Close()
		t.Fatal("an upload into a symlinked destination must be refused")
	}
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if got := dirNames(t, base, "elsewhere"); len(got) != 0 {
		t.Fatalf("the link's target was written into: %v", got)
	}
}

// TestOpenWriteRefusesARecycledInode is the third finding end to end: the
// directory is removed and recreated at the same name until the allocator hands
// back the number the identity recorded. Birth time is what tells the two
// apart, so the test skips where the filesystem keeps none — and skips again
// where the allocator simply never reuses the number, because then there is
// nothing to stage.
func TestOpenWriteRefusesARecycledInode(t *testing.T) {
	base := tempDir(t)
	requireBirthTimes(t, base)
	mkdir(t, base, "dst")
	r := newRoot(t, base)
	ctx := context.Background()

	id, err := FSIdentity(ctx, r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	if !id.HasBtime {
		t.Skip("this directory has no birth time, so an inode number is the whole identity here")
	}

	// Remove and recreate until the inode number repeats — the loop an attacker
	// runs, and one that finishes quickly on a filesystem that reuses numbers
	// eagerly.
	recycled := false
	for i := 0; i < 4096 && !recycled; i++ {
		if rerr := os.Remove(filepath.Join(base, "dst")); rerr != nil {
			t.Fatal(rerr)
		}
		if merr := os.Mkdir(filepath.Join(base, "dst"), 0o755); merr != nil {
			t.Fatal(merr)
		}
		now, ferr := FSIdentity(ctx, r, nil, "/dst")
		if ferr != nil {
			t.Fatal(ferr)
		}
		recycled = now.Dev == id.Dev && now.Ino == id.Ino
	}
	if !recycled {
		t.Skip("this filesystem did not hand the inode number back, so the recycling case cannot be staged here")
	}

	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &id
	f, _, oerr := OpenWrite(ctx, r, nil, req)
	if oerr == nil {
		f.Close()
		t.Fatal("an upload into a directory recreated at the same inode number must be refused")
	}
	if fsx.Code(oerr) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", oerr, fsx.Code(oerr))
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("the recreated directory was written into: %v", got)
	}
}

// TestArchiveCheckRefusesASymlinkAncestor: the plan is recorded before the
// first byte, so this is where the whole request is refused rather than one
// member skipped.
func TestArchiveCheckRefusesASymlinkAncestor(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "safe")
	write(t, base, "safe/config.json", "authorized")
	mkdir(t, base, "secrets")
	write(t, base, "secrets/config.json", "not authorized")
	r := newRoot(t, base)

	swapAncestorForSymlink(t, filepath.Join(base, "safe"), filepath.Join(base, "safe-moved"),
		filepath.Join(base, "secrets"))

	plan, err := ArchiveCheck(context.Background(), r, nil, archiveReq(ArchiveZip, "/safe/config.json"))
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if plan != nil {
		t.Error("a refused check must hand back no plan")
	}
}

// TestArchiveCheckRecordsABirthTime: the identity the producer compares against
// carries the half an inode number cannot forge.
func TestArchiveCheckRecordsABirthTime(t *testing.T) {
	base := tempDir(t)
	requireBirthTimes(t, base)
	mkdir(t, base, "tree")
	write(t, base, "tree/one.txt", "one")
	r := newRoot(t, base)

	plan, err := ArchiveCheck(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	root := plan.roots[0]
	if !root.id.have || !root.id.hasBtime {
		t.Fatalf("the recorded identity carries no birth time: %+v", root.id)
	}
	if !root.parentID.hasBtime {
		t.Fatalf("the recorded parent identity carries no birth time: %+v", root.parentID)
	}
}

// TestSearchRefusesASymlinkAncestor: the same rule for a search root, which is
// a directory the guard cleared rather than a link of that name.
func TestSearchRefusesASymlinkAncestor(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "safe/inner")
	write(t, base, "safe/inner/report.txt", "authorized")
	mkdir(t, base, "secrets/inner")
	write(t, base, "secrets/inner/report.txt", "not authorized")
	r := newRoot(t, base)

	swapAncestorForSymlink(t, filepath.Join(base, "safe"), filepath.Join(base, "safe-moved"),
		filepath.Join(base, "secrets"))

	res, err := Search(context.Background(), r, nil, searchReq("report", "/safe/inner"), Emit{})
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if len(res.Hits) != 0 {
		t.Fatalf("the replacement was searched: %v", hitNames(res))
	}
}
