package fsops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// TestSymlinkOutOfTheJailIsNotProbed is the regression test for the containment
// gap round 8 found: classifying a mount point used to hand Platform the OS
// pathname, whose fallback stats it and follows its symlinks. With a jail on the
// root filesystem and /escape → /proc inside it, that stat landed on /proc — a
// lookup outside the jail — and reported /proc's mount status under the name of
// a link the user was only allowed to be told about.
//
// The link must be described as a link on the jail's own filesystem, and nothing
// about the directory it points at may show through.
func TestSymlinkOutOfTheJailIsNotProbed(t *testing.T) {
	plat := platform.Detect()
	if !plat.IsMountPoint("/proc") {
		t.Skip("/proc is not a mount point on this box, so there is nothing outside the jail to reach for")
	}
	base := tempDir(t)
	if err := os.Symlink("/proc", filepath.Join(base, "escape")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	e, err := Stat(context.Background(), r, plat, "/escape")
	if err != nil {
		t.Fatalf("Stat(/escape): %v", err)
	}
	if !e.IsSymlink {
		t.Fatalf("/escape must be reported as a symlink: %+v", e)
	}
	if e.MountPoint {
		t.Fatal("/escape was classified from the mount status of /proc, which is outside the jail")
	}

	// The listing of the directory holding it says nothing about /proc either.
	l, err := List(context.Background(), r, plat, "/", fsx.ListOptions{})
	if err != nil {
		t.Fatalf("List(/): %v", err)
	}
	le, ok := find(l, "escape")
	if !ok {
		t.Fatalf("entries = %v", names(l))
	}
	if le.MountPoint {
		t.Errorf("the listed entry was classified from outside the jail: %+v", le)
	}
	if notes := strings.Join(l.Notes, "; "); strings.Contains(notes, "mount point") {
		t.Errorf("the jail base is not a mount point in the table: notes = %v", l.Notes)
	}
}

// TestMountPointOffTheTableIsFoundByDevice covers the other half: the fallback
// that catches a mount made since the table was last read still works, now that
// it compares devices the walk already holds instead of stat'ing a pathname. The
// table here is a static one that mentions only "/", so /proc can only be
// recognised by its device differing from its parent's.
func TestMountPointOffTheTableIsFoundByDevice(t *testing.T) {
	plat, err := platform.FromMountinfo(strings.NewReader("21 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if plat.IsMountPointByTable("/proc") {
		t.Skip("the static table unexpectedly knows /proc")
	}
	var r fsx.Root // the identity mapping production runs with
	e, err := Stat(context.Background(), r, plat, "/proc")
	if err != nil {
		t.Skipf("/proc is not stat-able here: %v", err)
	}
	if !e.MountPoint {
		t.Error("/proc is a mount point and its device differs from /'s, so it must be classified as one")
	}
}

// TestMutatingWalkStopsWhereTheKernelWillNotNameAMount is B4: the fail-closed
// half of F4.
//
// When statx(STATX_MNT_ID) fails AND /proc/self/fdinfo carries no "mnt_id:", the
// only comparison left is st_dev — and a bind mount is one device with two
// mounts, which is the shape QTS builds its whole share layout out of. So the
// device comparison says "same filesystem, carry on" for exactly the boundary a
// recursive delete must not cross. A measurement can live with that; a delete
// cannot, so a mutating walk refuses to descend rather than guess.
//
// The hook is what makes the corner observable: on any kernel since 3.15 one of
// the two sources answers, so this path is a true corner rather than a routine
// one.
func TestMutatingWalkStopsWhereTheKernelWillNotNameAMount(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	mkdir(t, base, "a/far")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/inside.txt", "inside")
	write(t, base, "a/far/inside.txt", "inside")
	r := newRoot(t, base)

	// No mount IDs at all. "sub" shares the parent's device — a bind mount looks
	// precisely like this — and "far" does not.
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		if strings.HasSuffix(d.rel, "far") {
			return mountIdentity{dev: 99, hasDev: true}
		}
		return mountIdentity{dev: 1, hasDev: true}
	}
	t.Cleanup(func() { identityFor = prev })

	// A read-only walk keeps the st_dev fallback (Size): it descends into "sub",
	// because a device comparison has nothing to object to.
	var ro recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, ro.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(ro.pre, "/a/sub/inside.txt") < 0 {
		t.Errorf("a read-only walk must still descend where only st_dev can answer: pre = %v", ro.pre)
	}

	// Both mutating shapes refuse: the delete itself, and the bounded pre-scan
	// that gives it its denominator (ProtectWrite).
	for _, opts := range []WalkOptions{{Mutating: true}, {Protect: ProtectWrite}} {
		var rw recorder
		if err := Walk(context.Background(), r, nil, "/a", opts, rw.visitor()); err != nil {
			t.Fatalf("Walk(%+v): %v", opts, err)
		}
		for _, p := range []string{"/a/sub/inside.txt", "/a/far/inside.txt"} {
			if indexOf(rw.pre, p) >= 0 {
				t.Errorf("Walk(%+v) descended into %q with no mount identity to go on: pre = %v", opts, p, rw.pre)
			}
		}
		for _, p := range []string{"/a/sub", "/a/far"} {
			if indexOf(rw.warns, p) < 0 {
				t.Errorf("Walk(%+v) warns = %v, want %q reported rather than silently skipped", opts, rw.warns, p)
			}
		}
		if indexOf(rw.pre, "/a/one.txt") < 0 {
			t.Errorf("Walk(%+v): the rest of the tree must still be walked: pre = %v", opts, rw.pre)
		}
	}
}

// TestWalkRefusesARealMountPointWithoutCrossMounts is F4 against a real mount
// rather than a test hook: a tmpfs mounted underneath the tree must not be
// entered, and the decision must come from the DESCRIPTOR the walk opened, not
// from the mount table — which here is told nothing about it.
//
// Mounting needs root, so this is the CI root job's test (test-linux-root in
// PLAN.md decision 14). It skips everywhere else rather than simulating the
// kernel (INV-2).
func TestWalkRefusesARealMountPointWithoutCrossMounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting a tmpfs needs root; the CI root job runs this one")
	}
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	mnt := filepath.Join(base, "a", "sub")
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("tmpfs is not available here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, 0) })
	if err := os.WriteFile(filepath.Join(mnt, "inside.txt"), []byte("on the tmpfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// No mount table at all: the fd identity is the only thing that can answer,
	// and it must.
	var off recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, off.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(off.mount, "/a/sub") < 0 {
		t.Errorf("the tmpfs was not recognised as a mount point: mount = %v pre = %v", off.mount, off.pre)
	}
	if indexOf(off.pre, "/a/sub/inside.txt") >= 0 {
		t.Error("the walk entered a real mount point without CrossMounts")
	}
	if indexOf(off.pre, "/a/one.txt") < 0 {
		t.Error("the rest of the tree must still be walked")
	}

	// CrossMounts cannot help either: a tmpfs is not Storage, so decision 9
	// refuses it however the table is asked.
	var on recorder
	if err := Walk(context.Background(), r, platform.Detect(), "/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, "/a/sub/inside.txt") >= 0 {
		t.Error("CrossMounts descended into a RAM disk")
	}
}
