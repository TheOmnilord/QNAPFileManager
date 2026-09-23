package fsops

import (
	"context"
	"fmt"
	"math"
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

// synthMountIDBase is where the invented mount IDs of a synthetic table start.
//
// It is deliberately far above anything a running kernel hands out. The walk
// identifies a child mount from its DESCRIPTOR where it can (F4) — statx's
// STATX_MNT_ID is mountinfo's first field — so a synthetic ID that collided with
// a real one would make the walk resolve a real /tmp descriptor to an invented
// row and answer a crossing question with somebody else's capabilities. Out of
// range, the fd lookup misses and the by-name fallback decides, which is what a
// static table is for (PLAN.md decision 15).
const synthMountIDBase = 900000

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
			synthMountIDBase+i, dev, strings.ReplaceAll(m.mountPoint, " ", `\040`), m.fsType, src)
	}
	p, err := platform.FromMountinfo(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("building the synthetic mount table: %v", err)
	}
	return p
}

// fakeIdentities replaces the walk's fd mount identity for the duration of a
// test: a directory whose jail-relative name ENDS with one of the given
// suffixes gets that mount ID, and everything else gets a single shared one.
// The match is by suffix because an unjailed Root spells a temporary directory
// as its whole absolute path.
//
// It exists because the property under test — "the descriptor says this is
// another mount, so do not enter it" — needs a real mount to observe, and
// mounting anything needs root. The hook lets the decision be exercised on every
// platform; the CI root job mounts the real thing (see
// TestWalkRefusesARealMountPointWithoutCrossMounts, mount_linux_test.go).
func fakeIdentities(t *testing.T, ids map[string]uint64) {
	t.Helper()
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		for suffix, mnt := range ids {
			if d.rel == suffix || strings.HasSuffix(d.rel, "/"+suffix) {
				return mountIdentity{mnt: mnt, hasMnt: true}
			}
		}
		return mountIdentity{mnt: 1, hasMnt: true}
	}
	t.Cleanup(func() { identityFor = prev })
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

// TestWalkNeverTouchesANetworkMountItMayNotEnter is the hang the mount table can
// prevent: a hard NFS mount whose server has gone parks the caller inside lstat
// or openat indefinitely, where no deadline in this process can reach it — so a
// child the walk was never going to enter must not be stat'ed at all when the
// table already names it as a network mount.
//
// identityFor is the proof. It is only reachable through a descriptor for the
// child, so being asked about that child at all means the child was opened.
func TestWalkNeverTouchesANetworkMountItMayNotEnter(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/export")
	write(t, base, "a/one.txt", "one")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/export", fsType: "nfs4", dev: "0:42", source: "nas:/export"},
	)

	var asked []string
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		asked = append(asked, d.rel)
		return prev(d)
	}
	t.Cleanup(func() { identityFor = prev })

	// Both ways round: with CrossMounts off nothing may be entered, and with it
	// on a network mount is still refused (MayCross), so neither may touch it.
	for _, cross := range []bool{false, true} {
		asked = nil
		var rec recorder
		if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{CrossMounts: cross}, rec.visitor()); err != nil {
			t.Fatalf("crossMounts=%v Walk: %v", cross, err)
		}
		for _, rel := range asked {
			if rel == "export" || strings.HasSuffix(rel, "/export") {
				t.Errorf("crossMounts=%v: the network mount was opened (%q)", cross, rel)
			}
		}
		if indexOf(rec.pre, api+"/a/export") >= 0 {
			t.Errorf("crossMounts=%v: the network mount was described rather than left alone", cross)
		}
		if indexOf(rec.warns, api+"/a/export") < 0 {
			t.Errorf("crossMounts=%v: a mount left untouched must still be reported: warns = %v", cross, rec.warns)
		}
		// And the rest of the directory is walked exactly as before.
		if indexOf(rec.pre, api+"/a/one.txt") < 0 {
			t.Errorf("crossMounts=%v: the walk stopped at the mount: pre = %v", cross, rec.pre)
		}
	}
}

// TestWalkStillVisitsALocalMountItMayNotEnter: the table-only refusal above is
// for the class of mount that can block a syscall forever, and nothing else.
// Decision 9 says a local mount point the walk does not cross is still visited
// as the item it is — a size counts the directory itself — and that answer needs
// the lstat the network case skips.
func TestWalkStillVisitsALocalMountItMayNotEnter(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:2", source: "/dev/sdb1"},
	)
	var rec recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(rec.mount, api+"/a/sub") < 0 {
		t.Fatalf("a local mount point must still be visited as one: pre = %v warns = %v", rec.pre, rec.warns)
	}
	if indexOf(rec.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Error("visited is not entered")
	}
}

// TestWalkTreatsABackslashAsAnOrdinaryCharacter: the pre-lstat mount check must
// compare the kernel's bytes and nothing else. A backslash is an ordinary
// character in a Linux filename, so a regular file called `..\export` is a file
// — but a lookup that normalises backslashes into separators and then cleans the
// result turns its path into "/export", and with an NFS mount of that name in
// the table the walk would skip somebody's file as somebody else's mount:
// invisible to a size, and left behind by a recursive delete.
func TestWalkTreatsABackslashAsAnOrdinaryCharacter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a backslash cannot be part of a Windows filename, so there is nothing to confuse here")
	}
	base := tempDir(t)
	mkdir(t, base, "tree")
	const name = `..\export`
	if err := os.WriteFile(filepath.Join(base, "tree", name), []byte("mine"), 0o644); err != nil {
		t.Skipf("this filesystem refuses a backslash in a name: %v", err)
	}
	r, api := hostRoot(t, base)
	// The trap: the mount is at the path the name NORMALISES to.
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/export", fsType: "nfs4", dev: "0:42", source: "nas:/export"},
	)
	var rec recorder
	if err := Walk(context.Background(), r, plat, api+"/tree", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(rec.pre, api+"/tree/"+name) < 0 {
		t.Fatalf("a file whose name holds a backslash was taken for a mount: pre = %v warns = %v", rec.pre, rec.warns)
	}
}

// TestWalkRefusesAMountWhoseNameHasABackslash is the same rule the other way
// round: mountinfo spells a mount point in the kernel's own bytes (octal escapes
// decoded), so a real mount whose name contains a backslash has to match its own
// row — a normalising lookup would miss it and let the walk reach the very lstat
// that can block forever.
func TestWalkRefusesAMountWhoseNameHasABackslash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a backslash cannot be part of a Windows directory name")
	}
	base := tempDir(t)
	const name = `back\slash`
	if err := os.Mkdir(filepath.Join(base, "tree"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "tree", name), 0o755); err != nil {
		t.Skipf("this filesystem refuses a backslash in a name: %v", err)
	}
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/tree/" + name, fsType: "nfs4", dev: "0:42", source: "nas:/export"},
	)
	var asked []string
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		asked = append(asked, d.rel)
		return prev(d)
	}
	t.Cleanup(func() { identityFor = prev })

	var rec recorder
	if err := Walk(context.Background(), r, plat, api+"/tree", WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(rec.warns, api+"/tree/"+name) < 0 {
		t.Fatalf("the network mount was not refused: warns = %v pre = %v", rec.warns, rec.pre)
	}
	for _, rel := range asked {
		if strings.HasSuffix(rel, name) {
			t.Errorf("the network mount was opened (%q)", rel)
		}
	}
}

// TestWalkReportsTheIdentityOfTheDirectoryItOpened: WalkItem.Info is an lstat of
// a PATHNAME, taken before the directory is opened, so it cannot say which
// object was then enumerated — swap the name in between and the two are
// different directories. The Opened hook answers from the descriptor itself,
// which is what a caller comparing identities afterwards has to be given.
func TestWalkReportsTheIdentityOfTheDirectoryItOpened(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	r := newRoot(t, base)

	opened := map[string]os.FileInfo{}
	err := Walk(context.Background(), r, nil, "/a", WalkOptions{}, Visitor{
		Opened: func(it WalkItem, info os.FileInfo) error { opened[it.Path] = info; return nil },
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, want := range []string{"/a", "/a/sub"} {
		info, ok := opened[want]
		if !ok || info == nil || !info.IsDir() {
			t.Fatalf("opened[%q] = %v (present: %v), want the directory's own stat", want, info, ok)
		}
	}
	if _, ok := opened["/a/one.txt"]; ok {
		t.Error("the walk never opens a file, so it can never report one as opened")
	}
	// And it really is that directory: on Linux the two describe one object.
	real, err := os.Lstat(filepath.Join(base, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if same, known := sameObject(opened["/a"], real); known && !same {
		t.Error("the identity reported is not the directory that was walked")
	}
}

// TestSizeSaysWhenItsScanWasCapped: Size asks for no bound, so the only thing
// that can stop it early is the byte total outgrowing an int64 — and that stops
// the WHOLE pass, remaining selected paths included. A floor reported as a total
// is what a Properties panel would then render as fact, so the reason goes out
// as a warning.
func TestSizeSaysWhenItsScanWasCapped(t *testing.T) {
	base := deleteFixture(t) // /a/one.txt (3), /a/sub/two.txt (6), /a/sub/deep/
	r := newRoot(t, base)
	prev := sizeScanLimits
	sizeScanLimits = scanLimits{maxEntries: 2}
	t.Cleanup(func() { sizeScanLimits = prev })

	var log jobLog
	res, err := Size(context.Background(), r, nil, []string{"/a"}, SizeOptions{}, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if res.Files+res.Dirs > 2 {
		t.Fatalf("result = %+v, want the pass stopped at its bound", res)
	}
	if indexOf(log.codes(), scanCappedCode) < 0 {
		t.Fatalf("warn codes = %v, want the capped scan reported", log.codes())
	}
}

// TestScanBytesNeverWrap is the overflow: a sparse file may declare any length
// the filesystem allows and nothing bounds how many times a tree can name one,
// so the accumulator has to refuse rather than wrap. A wrapped total is smaller
// than the truth and completely plausible, which is the one failure a size must
// not have.
func TestScanBytesNeverWrap(t *testing.T) {
	cases := []struct {
		name  string
		start int64
		add   int64
		ok    bool
		want  int64
	}{
		{name: "an ordinary sum", start: 10, add: 5, ok: true, want: 15},
		{name: "exactly full", start: math.MaxInt64 - 5, add: 5, ok: true, want: math.MaxInt64},
		{name: "one byte past full", start: math.MaxInt64 - 5, add: 6, ok: false, want: math.MaxInt64 - 5},
		// Four hard links to one 4 EiB sparse file, which is all it takes.
		{name: "sparse exabytes", start: 3 << 61, add: 3 << 61, ok: false, want: 3 << 61},
		{name: "a size no kernel reports", start: 10, add: -1, ok: false, want: 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanResult{bytes: c.start}
			if got := res.addBytes(c.add); got != c.ok {
				t.Errorf("addBytes(%d) on %d = %v, want %v", c.add, c.start, got, c.ok)
			}
			if res.bytes != c.want {
				t.Errorf("bytes = %d, want %d: a refused addition must change nothing", res.bytes, c.want)
			}
		})
	}
}

// TestWalkRefusesAMountIdentityChangeWithoutCrossMounts is F4: the crossing
// decision is bound to the OPENED directory, not to the lstat that classified
// its name, and it compares a MOUNT IDENTITY rather than only st_dev.
//
// The mount table here says nothing at all — /a/sub is an ordinary directory as
// far as it is concerned — so the only thing that can stop the walk is the
// descriptor itself reporting a different mount. A bind mount is exactly that
// shape: one device, two mounts, and a pure device comparison walks straight
// across it.
func TestWalkRefusesAMountIdentityChangeWithoutCrossMounts(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)
	// The table knows only the volume root: /a/sub is not a mount point by name.
	plat := synthPlatform(t, synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"})
	fakeIdentities(t, map[string]uint64{"a/sub": 4242})

	var off recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{}, off.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(off.mount, api+"/a/sub") < 0 {
		t.Errorf("the descriptor's mount identity was not used: mount = %v pre = %v", off.mount, off.pre)
	}
	if indexOf(off.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Error("the walk entered a directory on another mount without CrossMounts")
	}
	if indexOf(off.pre, api+"/a/one.txt") < 0 {
		t.Error("the rest of the tree must still be walked")
	}

	// With CrossMounts on it is still refused: the table cannot name the mount
	// the descriptor belongs to, and an unidentifiable mount fails closed.
	var on recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Error("CrossMounts crossed into a mount the table could not identify")
	}
}

// TestWalkCrossesAnIdentifiedMountOfTheSameDomain: the other half of F4's
// fail-closed rule. The descriptor says "another mount" and the refreshed table
// can name it, so decision 9 gets a real question to answer — and answers yes
// for a mount of the same storage domain.
func TestWalkCrossesAnIdentifiedMountOfTheSameDomain(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:1"},
	)
	fakeIdentities(t, map[string]uint64{"a/sub": 4242})

	var on recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, api+"/a/sub/inside.txt") < 0 {
		t.Errorf("CrossMounts did not descend into an identified mount of the same domain: pre = %v", on.pre)
	}
}

// pretendLiveTable makes the walk treat a synthetic mount table as the running
// kernel's for one test (B5).
//
// The rule under test only applies to a live table — one whose first field is
// the same number statx reports as STATX_MNT_ID — and a test cannot produce one
// of those on a dev box, or on any box without mounting something. So the seam
// that answers the question is the thing replaced, exactly as identityFor is.
func pretendLiveTable(t *testing.T) {
	t.Helper()
	prev := liveTableOf
	liveTableOf = func(*platform.Platform) bool { return true }
	t.Cleanup(func() { liveTableOf = prev })
}

// TestWalkRefusesToCrossAMountTheLiveTableDoesNotList is B5.
//
// The child descriptor carries a mount ID the kernel gave it, and the refreshed
// table has no row with that ID. Falling through to a lookup by PATHNAME there
// does not answer the question less precisely — it answers a different question,
// "what filesystem does this name lead to now", which after a rename or a fresh
// mount over the name can be somebody else's. Here the table even says yes: it
// lists the child's name as an ext4 mount of the same device, so the pathname
// lookup would authorise the crossing. The identity is what refuses it.
//
// TestWalkCrossesAnIdentifiedMountOfTheSameDomain is the control: the same
// setup, minus the live table, still crosses — because a static table's IDs are
// invented and no descriptor could ever match one (PLAN.md decision 15).
func TestWalkRefusesToCrossAMountTheLiveTableDoesNotList(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:1"},
	)
	// The parent names its own row; the child names a mount no row carries.
	fakeIdentities(t, map[string]uint64{"a": synthMountIDBase, "a/sub": 4242})
	pretendLiveTable(t)

	var on recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Errorf("the walk crossed into a mount the kernel named and the table cannot: pre = %v", on.pre)
	}
	if indexOf(on.mount, api+"/a/sub") < 0 {
		t.Errorf("mount = %v, want the boundary reported as one so a size job can still count the directory", on.mount)
	}
}

// TestWalkCapsComeFromTheMatchedMountNotItsPathname is B7.
//
// Once the kernel's mount ID has named the exact row a descriptor belongs to,
// asking the table again BY PATHNAME throws that answer away. Platform.For is a
// longest-prefix lookup keyed by mount point, and a mount point is not unique:
// two mounts stacked at one path (a bind mount over a share, a tmpfs over a
// directory — the shape QTS builds its layout out of) leave only the topmost one
// reachable by name.
//
// The table here is exactly that. The child descriptor names the nfs4 row, which
// decision 9 never crosses into; a second row over-mounts the same path with an
// ext4 filesystem of the parent's own device, which the crossing rule would
// welcome. So a by-name lookup authorises a walk into a network mount, and only
// caps taken from the matched row itself refuse it.
func TestWalkCapsComeFromTheMatchedMountNotItsPathname(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "inside")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		// The row the descriptor names: a network mount, never crossed into.
		synthMount{mountPoint: api + "/a/sub", fsType: "nfs4", dev: "0:42", source: "nas:/export"},
		// Stacked at the same name, and the only one a pathname can reach.
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:1"},
	)
	fakeIdentities(t, map[string]uint64{"a": synthMountIDBase, "a/sub": synthMountIDBase + 1})

	var on recorder
	if err := Walk(context.Background(), r, plat, api+"/a", WalkOptions{CrossMounts: true}, on.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(on.pre, api+"/a/sub/inside.txt") >= 0 {
		t.Errorf("the walk crossed into the nfs4 mount its descriptor named, on the strength of an ext4 row stacked over the same path: pre = %v", on.pre)
	}
	if indexOf(on.mount, api+"/a/sub") < 0 {
		t.Errorf("mount = %v, want the boundary reported as one", on.mount)
	}
}

// TestWalkProtectRefusesNeverWriteComponents is F10: the guard only ever sees a
// job's root paths, so the walk applies the component rule itself, to every
// entry the recursion reaches.
func TestWalkProtectRefusesNeverWriteComponents(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/.zfs/snapshot")
	mkdir(t, base, "a/@Recycle")
	write(t, base, "a/.zfs/snapshot/old.txt", "a snapshot")
	write(t, base, "a/@Recycle/bin.txt", "the recycle bin")
	write(t, base, "a/ordinary.txt", "fine")
	r := newRoot(t, base)

	var mutating recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{Protect: ProtectWrite}, mutating.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, refused := range []string{"/a/.zfs", "/a/@Recycle"} {
		if indexOf(mutating.pre, refused) >= 0 {
			t.Errorf("%q was visited by a mutating walk: pre = %v", refused, mutating.pre)
		}
		if indexOf(mutating.warns, refused) < 0 {
			t.Errorf("%q was skipped without a warning: warns = %v", refused, mutating.warns)
		}
	}
	if indexOf(mutating.pre, "/a/ordinary.txt") < 0 {
		t.Error("the rest of the tree must still be walked")
	}

	// A read-only walk skips .zfs — a snapshot tree can be enormous — and reads
	// @Recycle, which decision 10 only forbids WRITING to.
	var reading recorder
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{Protect: ProtectSnapshots}, reading.visitor()); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if indexOf(reading.pre, "/a/.zfs") >= 0 {
		t.Errorf("a read-only walk counted a snapshot tree: pre = %v", reading.pre)
	}
	if indexOf(reading.pre, "/a/@Recycle/bin.txt") < 0 {
		t.Errorf("a read-only walk must be able to read @Recycle: pre = %v", reading.pre)
	}
}

// TestNeverWriteName pins the shared helper the guard's rule is mirrored by.
func TestNeverWriteName(t *testing.T) {
	for _, name := range []string{".zfs", "@Recycle"} {
		if reason, hit := NeverWriteName(name); !hit || reason == "" {
			t.Errorf("NeverWriteName(%q) = %q,%v — want a refusal with a reason", name, reason, hit)
		}
	}
	for _, name := range []string{"zfs", ".zfsx", "Recycle", "@Recycled", "a", ""} {
		if _, hit := NeverWriteName(name); hit {
			t.Errorf("NeverWriteName(%q) refused an ordinary name", name)
		}
	}
	// The reasons are path-free, exactly as the guard's are, so one can be shown
	// to a client without disclosing a resolved spelling.
	for _, name := range []string{".zfs", "@Recycle"} {
		reason, _ := NeverWriteName(name)
		if strings.Contains(reason, "/") {
			t.Errorf("NeverWriteName(%q) reason %q carries a path", name, reason)
		}
	}
	if _, hit := neverWritePath("/share/Public/.zfs/snapshot/x"); !hit {
		t.Error("neverWritePath missed a .zfs component in the middle of a path")
	}
	if _, hit := neverWritePath("/share/Public/@Recycle"); !hit {
		t.Error("neverWritePath missed a trailing @Recycle")
	}
	if _, hit := neverWritePath("/share/Public/report.txt"); hit {
		t.Error("neverWritePath refused an ordinary path")
	}
}

// TestWalkRechecksTheMountIdentityOnEveryRetryPass is the rest of F4: a mutating
// visitor may ask for a directory to be read again (errRetryDir, the ext4 htree
// case), and that re-open must be put through the identical check. A mount that
// appeared between two passes over a directory being emptied has to stop the
// walk exactly as one that was there from the start does — otherwise the second
// pass is the unchecked one.
func TestWalkRechecksTheMountIdentityOnEveryRetryPass(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "inside")
	r := newRoot(t, base)

	// "sub" is on the parent's mount the first time it is opened and on another
	// one every time after that.
	opens := 0
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		if strings.HasSuffix(d.rel, "sub") {
			opens++
			if opens > 1 {
				return mountIdentity{mnt: 4242, hasMnt: true}
			}
		}
		return mountIdentity{mnt: 1, hasMnt: true}
	}
	t.Cleanup(func() { identityFor = prev })

	var rec recorder
	v := rec.visitor()
	post := v.Post
	asked := false
	v.Post = func(it WalkItem) error {
		if err := post(it); err != nil {
			return err
		}
		if it.Path == "/a/sub" && !asked {
			asked = true
			return errRetryDir
		}
		return nil
	}
	if err := Walk(context.Background(), r, nil, "/a", WalkOptions{Mutating: true}, v); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !asked {
		t.Fatal("the visitor never got to ask for a second pass")
	}
	if indexOf(rec.warns, "/a/sub") < 0 {
		t.Errorf("warns = %v, want the re-opened directory refused as a mount point", rec.warns)
	}
	// One Post only: the second pass was refused before it could run.
	count := 0
	for _, p := range rec.post {
		if p == "/a/sub" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("post hooks for /a/sub = %d, want exactly one", count)
	}
}
