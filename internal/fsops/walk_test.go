package fsops

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// hostRoot returns the unjailed Root — the production mapping, where an API
// path names the host path of the same spelling — together with the API path
// that names dir on this host.
//
// The mount-table tests need it. Platform speaks OS paths in the kernel's
// absolute slash form, and under a jail on Windows an OS path is "C:\...",
// which no mountinfo line can name; unjailed, "/Users/x" maps to "\Users\x" on
// the current drive, which the mount table can. On Linux it is the identity
// either way. Nothing outside the test's own temporary directory is touched.
func hostRoot(t *testing.T, dir string) (fsx.Root, string) {
	t.Helper()
	vol := filepath.VolumeName(dir)
	if vol != "" {
		cwd, err := os.Getwd()
		if err != nil || !strings.EqualFold(filepath.VolumeName(cwd), vol) {
			t.Skipf("the temporary directory is on %s and the process is not; the unjailed mapping names one drive", vol)
		}
	}
	rest := filepath.ToSlash(strings.TrimPrefix(dir, vol))
	return fsx.Root{}, path.Clean("/" + strings.TrimPrefix(rest, "/"))
}

// synthMount is one line of a hand-written mount table.
type synthMount struct {
	mountPoint string
	fsType     string
	dev        string // "major:minor"
	source     string
}

// synthPlatform builds a Platform from mountinfo text, which is how the hero
// and the mount-crossing rules are exercised on a dev box with neither
// (PLAN.md decision 15). The table is static: FromMountinfo never refreshes it
// from the running system.
func synthPlatform(t *testing.T, mounts ...synthMount) *platform.Platform {
	t.Helper()
	var b strings.Builder
	for i, m := range mounts {
		dev := m.dev
		if dev == "" {
			dev = "8:1"
		}
		src := m.source
		if src == "" {
			src = "/dev/sda1"
		}
		fmt.Fprintf(&b, "%d 1 %s / %s rw,relatime - %s %s rw\n",
			36+i, dev, strings.ReplaceAll(m.mountPoint, " ", `\040`), m.fsType, src)
	}
	p, err := platform.FromMountinfo(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("building the synthetic mount table: %v", err)
	}
	return p
}

// requireOwnPermissions skips a test whose subject is the kernel refusing this
// process something. Windows is not that kernel, and root is not refused
// anything, so on both the test would assert a behaviour that is not there
// (INV-2 — never simulate the kernel). The Linux CI jobs run it for real.
func requireOwnPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not refuse this process on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root is refused nothing, so an unreadable directory is readable here")
	}
}

// recorder collects a walk in the order it happened. events is the single
// ordered log — "pre:/a", "post:/a" — because the interesting properties are
// about one hook happening before another, which two separate slices cannot
// express.
type recorder struct {
	events []string
	pre    []string
	post   []string
	mount  []string
	warns  []string
}

func (rec *recorder) visitor() Visitor {
	return Visitor{
		Pre: func(it WalkItem) error {
			rec.events = append(rec.events, "pre:"+it.Path)
			rec.pre = append(rec.pre, it.Path)
			if it.Mount {
				rec.mount = append(rec.mount, it.Path)
			}
			return nil
		},
		Post: func(it WalkItem) error {
			rec.events = append(rec.events, "post:"+it.Path)
			rec.post = append(rec.post, it.Path)
			return nil
		},
		Warn: func(apiPath string, err error) {
			rec.events = append(rec.events, "warn:"+apiPath)
			rec.warns = append(rec.warns, apiPath)
		},
	}
}

func indexOf(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}

// TestWalkIsDepthFirstAndPostOrder pins the order a delete depends on: every
// child is visited before its parent's post hook, and the root's post hook is
// the last thing that happens.
func TestWalkIsDepthFirstAndPostOrder(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub/deep")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/two.txt", "two")
	write(t, base, "a/sub/deep/three.txt", "three")
	r := newRoot(t, base)

	var rec recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	for _, want := range []string{"/a", "/a/one.txt", "/a/sub", "/a/sub/two.txt", "/a/sub/deep", "/a/sub/deep/three.txt"} {
		if indexOf(rec.pre, want) < 0 {
			t.Errorf("%q was never visited; pre = %v", want, rec.pre)
		}
	}
	if len(rec.post) != 3 {
		t.Fatalf("post = %v, want exactly the three directories", rec.post)
	}
	if rec.post[len(rec.post)-1] != "/a" {
		t.Errorf("post order = %v, want the walk root last", rec.post)
	}
	if indexOf(rec.post, "/a/sub/deep") > indexOf(rec.post, "/a/sub") {
		t.Errorf("post order = %v, want a child directory before its parent", rec.post)
	}
	if indexOf(rec.events, "pre:/a/sub/deep/three.txt") > indexOf(rec.events, "post:/a/sub/deep") {
		t.Errorf("a directory's post hook ran before one of its files was visited: %v", rec.events)
	}
	if indexOf(rec.events, "pre:/a/sub") > indexOf(rec.events, "post:/a") {
		t.Errorf("a child was visited after its parent had been finished: %v", rec.events)
	}
	if len(rec.warns) != 0 {
		t.Errorf("warnings on a healthy tree: %v", rec.warns)
	}
}

// TestWalkNeverDescendsASymlink is the containment rule the recursive delete
// rests on: a symlink is one item, and whatever it points at is not part of
// this tree.
func TestWalkNeverDescendsASymlink(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "a")
	mkdir(t, base, "outside")
	write(t, base, "outside/secret.txt", "not part of the tree")
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(base, "a", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	var rec recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(rec.pre, "/a/link") < 0 {
		t.Fatalf("the symlink itself must be visited as an item; pre = %v", rec.pre)
	}
	for _, p := range rec.pre {
		if strings.HasPrefix(p, "/a/link/") {
			t.Fatalf("the walk descended through a symlink: %q", p)
		}
	}
	if indexOf(rec.post, "/a/link") >= 0 {
		t.Errorf("a symlink is never a directory to be finished: post = %v", rec.post)
	}
}

// TestWalkStopsWhenTheContextIsCancelled: a cancelled job must stop promptly,
// not after the remaining million entries.
func TestWalkStopsWhenTheContextIsCancelled(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a")
	for i := 0; i < 40; i++ {
		write(t, base, fmt.Sprintf("a/f%02d.txt", i), "x")
	}
	r := newRoot(t, base)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	err := Walk(ctx, r, nil, "/a", WalkOptions{}, Visitor{
		Pre: func(it WalkItem) error {
			seen++
			if seen == 3 {
				cancel()
			}
			return nil
		},
	})
	if err == nil || ctx.Err() == nil {
		t.Fatalf("Walk = %v, want the context error", err)
	}
	if fsx.Code(err) != "cancelled" {
		t.Errorf("code = %q, want cancelled", fsx.Code(err))
	}
	if seen > 6 {
		t.Errorf("the walk visited %d items after being cancelled at 3", seen)
	}
}

// TestWalkWarnsAndCarriesOn: one unreadable directory must not cost the job the
// rest of the tree.
func TestWalkWarnsAndCarriesOn(t *testing.T) {
	requireOwnPermissions(t)
	base := tempDir(t)
	mkdir(t, base, "a/locked")
	write(t, base, "a/locked/hidden.txt", "unreachable")
	write(t, base, "a/readable.txt", "fine")
	if err := os.Chmod(filepath.Join(base, "a", "locked"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(base, "a", "locked"), 0o755) })
	r := newRoot(t, base)

	var rec recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk = %v, want a warning rather than a failure", err)
	}
	if indexOf(rec.warns, "/a/locked") < 0 {
		t.Errorf("warns = %v, want the unreadable directory named", rec.warns)
	}
	if indexOf(rec.pre, "/a/readable.txt") < 0 {
		t.Errorf("the walk stopped at the unreadable directory: pre = %v", rec.pre)
	}
	if indexOf(rec.post, "/a/locked") >= 0 {
		t.Errorf("a directory that could not be read must not be reported as finished")
	}
}

// TestWalkDoesNotCrossAMountPointByDefault, and crosses one of the same
// storage domain when it is asked to (PLAN.md decision 9).
func TestWalkMountCrossingRule(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)

	same := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:1"},
	)
	var off recorder
	if err := Walk(context.Background(), r, same, api+"/a", WalkOptions{}, off.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(off.mount, api+"/a/sub") < 0 {
		t.Errorf("the mount point was not reported as one: pre = %v", off.pre)
	}
	if indexOf(off.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Errorf("the walk crossed a mount point without being asked to")
	}

	var on recorder
	if err := Walk(context.Background(), r, same, api+"/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, api+"/a/sub/inside.txt") < 0 {
		t.Errorf("CrossMounts did not descend into a mount of the same storage domain: pre = %v", on.pre)
	}

	// A different device is a different domain, so even CrossMounts must not
	// take the walk there — and neither must a tmpfs, whatever it is asked.
	other := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:2", source: "/dev/sdb1"},
	)
	var across recorder
	if err := Walk(context.Background(), r, other, api+"/a", WalkOptions{CrossMounts: true}, across.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(across.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Errorf("the walk crossed into another storage domain")
	}

	ram := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "tmpfs", dev: "0:21", source: "tmpfs"},
	)
	var onto recorder
	if err := Walk(context.Background(), r, ram, api+"/a", WalkOptions{CrossMounts: true}, onto.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(onto.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Errorf("the walk crossed into a RAM disk")
	}
}
