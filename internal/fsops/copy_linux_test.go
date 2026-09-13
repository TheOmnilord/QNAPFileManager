package fsops

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// The half of the copy engine only a Linux kernel can be asked about: a fifo
// that has no contents to copy, the (dev, ino) chain above a destination, and
// the mode a created file really ends up with. INV-2 — none of it is simulated
// on the dev box.

// TestCopySkipsAFifoAndWarns (§1.6): a fifo, a socket and a device node are
// names for something that is not in the filesystem, so there is nothing to
// copy and the honest answer is a warning.
func TestCopySkipsAFifoAndWarns(t *testing.T) {
	r, base := copyFixture(t)
	if err := syscall.Mkfifo(filepath.Join(base, "src", "a", "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Files != 2 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the two regular files copied and the fifo skipped", res)
	}
	w, ok := log.warnFor("/src/a/pipe")
	if !ok || w.Code != warnUnsupported {
		t.Fatalf("warns = %v, want %q for the fifo", log.warns, warnUnsupported)
	}
	if exists(t, base, "dst/a/pipe") {
		t.Fatal("something was created for the fifo")
	}
	// And the copy did not park a worker goroutine inside open(2) waiting for a
	// writer, which is the reason the fifo is classified before it is opened.
	if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
		t.Errorf("dst/a/one.txt = %q", got)
	}
}

// TestMoveKeepsASourceContainingAFifo: the same rule as every other warning —
// a root that did not copy cleanly keeps its source (§1.1).
func TestMoveKeepsASourceContainingAFifo(t *testing.T) {
	r, base := copyFixture(t)
	if err := syscall.Mkfifo(filepath.Join(base, "src", "a", "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	forceEXDEV(t)
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was deleted even though the fifo could not be copied")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

// TestDestAncestryNamesTheChainAboveTheDestination is the identity half of the
// copy-into-itself refusal (§1.7). A lexical test cannot see a bind mount or a
// rename; this walks openat(fd, "..") from the destination's own descriptor.
func TestDestAncestryNamesTheChainAboveTheDestination(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/b/c")
	r := newRoot(t, base)

	tg, err := resolve(r, "/a/b/c", true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := openPathRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()

	got := destAncestry(tg.jail, d)
	if len(got) < 4 {
		t.Fatalf("ancestry has %d entries, want the destination, b, a and the jail base", len(got))
	}
	for _, rel := range []string{"a/b/c", "a/b", "a", "."} {
		fi, err := os.Lstat(filepath.Join(base, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		k, ok := inodeOf(fi)
		if !ok {
			t.Fatal("no inode identity on Linux")
		}
		found := false
		for _, a := range got {
			if a == k {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not in the destination's ancestry %v", rel, got)
		}
	}
	// It stops at the jail base: nothing above the confinement is this job's
	// business, and the walk must not climb out of it.
	up, err := os.Lstat(filepath.Dir(base))
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := inodeOf(up); ok {
		for _, a := range got {
			if a == k {
				t.Fatalf("the ancestry climbed above the jail base to %q", filepath.Dir(base))
			}
		}
	}
}

// TestCopyCreatesWithTheSourcesModeUnderTheUmask (§1.5): the creation mode is
// the source's permission bits, the kernel applies the umask, and no chmod is
// ever issued afterwards to put back what the umask took.
func TestCopyCreatesWithTheSourcesModeUnderTheUmask(t *testing.T) {
	r, base := copyFixture(t)
	if err := os.Chmod(filepath.Join(base, "src", "a", "one.txt"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	m := lstat(t, base, "dst/one.txt").Mode().Perm()
	if want := os.FileMode(0o640 &^ 0o027); m != want {
		t.Fatalf("destination mode = %o, want %o (the source's mode under the umask, with no chmod after it)", m, want)
	}
}

// TestSameDirectoryThroughABindMount is finding 4 against the real thing: two
// names for ONE directory, which is how QTS builds its share layout and the one
// case no comparison of spellings can see. Moving /alias/a into /real merges a
// directory into itself, copies every file over itself and then deletes both
// spellings — unless the two ends are compared as objects.
//
// Mounting needs root, so this is the CI root job's test (PLAN.md decision 14).
func TestSameDirectoryThroughABindMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a bind mount needs root; the CI root job runs this one")
	}
	base := tempDir(t)
	mkdir(t, base, "real/a/sub")
	mkdir(t, base, "alias")
	write(t, base, "real/a/keep.txt", "the only copy of this")
	write(t, base, "real/a/sub/deep.txt", "and of this")

	alias := filepath.Join(base, "alias")
	if err := syscall.Mount(filepath.Join(base, "real"), alias, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mounts are not available here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(alias, 0) })
	r := newRoot(t, base)

	for _, move := range []bool{false, true} {
		var log jobLog
		res, err := Copy(context.Background(), r, nil,
			copyReq("/real", wproto.CopyOptions{Conflict: wproto.ConflictOverwrite}, "/alias/a"), move, log.emit())
		if err != nil {
			t.Fatalf("Copy(move=%v): %v", move, err)
		}
		if res.Skipped != 1 || res.Files != 0 || res.Dirs != 0 {
			t.Fatalf("move=%v: result = %+v, want the root refused with nothing done", move, res)
		}
		if len(log.warns) != 1 || log.warns[0].Code != warnExists {
			t.Fatalf("move=%v: warns = %v, want one %q", move, log.warns, warnExists)
		}
		if got := readFile(t, base, "real/a/keep.txt"); got != "the only copy of this" {
			t.Fatalf("move=%v: real/a/keep.txt = %q", move, got)
		}
		if got := readFile(t, base, "real/a/sub/deep.txt"); got != "and of this" {
			t.Fatalf("move=%v: real/a/sub/deep.txt = %q", move, got)
		}
		if exists(t, base, "real/a/a") || exists(t, base, "real/a (2)") {
			t.Fatalf("move=%v: the merge-into-itself happened anyway", move)
		}
	}
}

// TestDestinationMountIsRefusedForReal is finding 7 against a real mount rather
// than the identity seam: an EXISTING destination directory that is the root of
// another filesystem must not be merged into, because the destination never
// crosses (§1.8) and the free-space check was made against a different
// filesystem than the one the bytes would land on.
func TestDestinationMountIsRefusedForReal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting a tmpfs needs root; the CI root job runs this one")
	}
	r, base := copyFixture(t)
	mkdir(t, base, "dst/a")
	mnt := filepath.Join(base, "dst", "a")
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("tmpfs is not available here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, 0) })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the root refused", res)
	}
	w, ok := log.warnFor("/dst/a")
	if !ok || w.Code != "protected" {
		t.Fatalf("warns = %v, want protected for the destination mount", log.warns)
	}
	if _, serr := os.Lstat(filepath.Join(mnt, "one.txt")); serr == nil {
		t.Fatal("the copy wrote into the mounted filesystem at the destination")
	}
}

// TestPreservedOwnerComesFromTheDescriptor is round 7's adversarial finding: a
// fallback move preserves the SOURCE's owner, and it used to take it from the
// lstat that classified the name — taken before the file was opened. Chown the
// file to another user in that window and give it private contents, and the
// copy reproduced the NEW contents under the OLD owner and then deleted the
// source: a disclosure.
//
// The owner must come from the fstat of the descriptor the bytes were read
// from. Root only: nobody else may chown to another user.
func TestPreservedOwnerComesFromTheDescriptor(t *testing.T) {
	requireRoot(t)
	r, base := copyFixture(t)
	path := filepath.Join(base, "src", "a", "one.txt")
	if err := os.Lchown(path, 1, 1); err != nil {
		t.Fatal(err)
	}
	forceEXDEV(t)

	// Between the walk's lstat and the open, the file becomes somebody else's.
	prev := openForCopy
	openForCopy = func(d *dirRef, name string, flags int, perm os.FileMode) (*os.File, error) {
		if name == "one.txt" {
			if err := os.Lchown(path, 2, 2); err != nil {
				t.Error(err)
			}
		}
		return prev(d, name, flags, perm)
	}
	t.Cleanup(func() { openForCopy = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	uid, gid, _, ok := statDetail(lstat(t, base, "dst/one.txt"))
	if !ok {
		t.Fatal("no ownership to read at the destination")
	}
	if uid != 2 || gid != 2 {
		t.Fatalf("the copy is owned by %d:%d, want 2:2 — the owner came from a stat taken before the open", uid, gid)
	}
}

// TestDirectoryOwnerComesFromTheEnumeratedDescriptor is round 8's second
// finding, the directory form of round 7's: a directory's owner used to be
// reproduced from the lstat that classified its NAME, taken before the walk
// opened it. Chown it to somebody else in that window and its former owner was
// reproduced over the new owner's contents.
//
// Root only: nobody else may chown to another user.
func TestDirectoryOwnerComesFromTheEnumeratedDescriptor(t *testing.T) {
	requireRoot(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/sub/one.txt", "one")
	subPath := filepath.Join(base, "src", "a", "sub")
	if err := os.Lchown(subPath, 1, 1); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	// identityFor is asked about a child directory immediately AFTER the walk
	// has opened it and before the fstat that Opened reports — which is exactly
	// the window between the lstat that classified the name and the descriptor
	// the contents are enumerated from.
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		if d.rel == "src/a/sub" {
			if err := os.Lchown(subPath, 2, 2); err != nil {
				t.Error(err)
			}
		}
		return prev(d)
	}
	t.Cleanup(func() { identityFor = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	uid, gid, _, ok := statDetail(lstat(t, base, "dst/a/sub"))
	if !ok {
		t.Fatal("no ownership to read at the destination")
	}
	if uid != 2 || gid != 2 {
		t.Fatalf("dst/a/sub is owned by %d:%d, want 2:2 — the owner came from a stat taken before the open", uid, gid)
	}
}
