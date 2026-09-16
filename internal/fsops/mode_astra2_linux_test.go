package fsops

// The engine half of Astra M3 round 2, against a real kernel.
//
// Round 1 closed three of these halfway, and the half that was left is the same
// shape every time: a proof that was made about one kind of object and not about
// the object that actually turned up. #2 proved the identity of a directory only
// when a directory was still there; #5 repaired an unreadable directory only
// when the job had opened it itself; #6 proved an identity the platform cannot
// even report.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// TestPostOrderRefusesADirectoryReplacedByAFile is Astra r2 #2.
//
// The post-order change names a directory a SECOND time — the walker closed the
// descriptor it enumerated before calling Post — and round 1 made that second
// lookup prove itself against the descent. It asked only when the object it
// found was a directory, though, so a nested directory renamed away and replaced
// by a regular FILE at its name fell through to the ordinary leaf branch and was
// chmod'ed like any other entry: the exact substitution the traversal record
// exists to catch, walked straight past because the attacker changed the type.
//
// The replacement is a real rename and a real create, driven through applyEntry
// with the depth slot the descent would have filled — which is the whole of the
// decision and the only part of it a test can make deterministic.
func TestPostOrderRefusesADirectoryReplacedByAFile(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	write(t, base, "tree/nested/inside.txt", "x")
	r := newRoot(t, base)

	parent, ref := heldIn(t, r, "/tree", "nested")
	walked := ref.fi
	if !walked.IsDir() {
		t.Fatal("the fixture did not start as a directory")
	}

	var log jobLog
	j := &modeJob{
		r: r, emit: log.emit(),
		files: perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		dirs:  perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		uid:   -1, gid: -1,
		recursive: true,
	}
	// What the walk recorded when it descended into the directory, before any of
	// its entries was read.
	j.setTraversed(1, objectIDOf(refFD(ref), walked))

	// The swap, while the children are being changed: the directory is renamed
	// away — a rename, so the two objects provably never shared an inode — and a
	// file is created at the name it left behind.
	if err := os.Rename(filepath.Join(base, "tree/nested"), filepath.Join(base, "tree/moved")); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(base, "tree/nested")
	if err := os.WriteFile(planted, []byte("not the folder that was walked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o600); err != nil {
		t.Fatal(err)
	}

	j.applyEntry(WalkItem{Path: "/tree/nested", Name: "nested", Info: walked, Depth: 1, parent: parent})

	if got := modeOf(t, planted); got != 0o600 {
		t.Fatalf("the planted file's mode = %s, want 0600 — it was changed anyway", perm.Octal(got))
	}
	if j.res.Files != 0 || j.res.Dirs != 0 {
		t.Fatalf("result = %+v, want nothing changed", j.res)
	}
	if j.res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want the entry reported", j.res.Skipped)
	}
	w, ok := log.warnFor("/tree/nested")
	if !ok || !strings.Contains(w.Message, "not the folder the walk descended into") {
		t.Fatalf("warns = %+v, want the replacement named", log.warns)
	}

	// And the control: the directory put back is accepted, so the refusal above
	// is about the swap and not about the proof being unsatisfiable.
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "tree/moved"), planted); err != nil {
		t.Fatal(err)
	}
	j.applyEntry(WalkItem{Path: "/tree/nested", Name: "nested", Info: walked, Depth: 1, parent: parent})
	if j.res.Dirs != 1 {
		t.Fatalf("result = %+v, want the directory the walk descended into changed", j.res)
	}
	if got := modeOf(t, planted); got != 0o777 {
		t.Fatalf("mode = %s, want 0777", perm.Octal(got))
	}
}

// TestRecursiveChmodChangesANestedDirectoryItCannotList is Astra r2 #5.
//
// Round 1's fallback covered the SELECTED root and nothing else, because that is
// the one directory the job opens for itself. Below it the walker does the
// opening, and a directory it cannot open is reported through Warn and left: Pre
// defers every directory to post-order and no post-order hook runs for a
// directory that was never entered. So a tree with a 0000 directory three levels
// down had precisely the entry the repair was aimed at counted as one more
// refusal among thousands.
func TestRecursiveChmodChangesANestedDirectoryItCannotList(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 directory, so there is no unlistable directory to make")
	}
	base := tempDir(t)
	mkdir(t, base, "share/tree/locked")
	write(t, base, "share/tree/locked/inside.txt", "x")
	locked := filepath.Join(base, "share/tree/locked")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	var log jobLog
	res, err := ChmodTree(context.Background(), newRoot(t, base), nil,
		[]string{"/share/tree"},
		ChmodOptions{Dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0750}, Recursive: true},
		log.emit())
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if got := modeOf(t, locked); got != 0o750 {
		t.Fatalf("locked mode = %s, want 0750 — the repair did not reach the nested directory", perm.Octal(got))
	}
	if got := modeOf(t, filepath.Join(base, "share/tree")); got != 0o750 {
		t.Fatalf("tree mode = %s, want 0750", perm.Octal(got))
	}
	if res.Dirs != 2 {
		t.Fatalf("result = %+v, want both directories changed", res)
	}
	w, ok := log.warnFor("/share/tree/locked")
	if !ok || !strings.Contains(w.Message, "could not be listed") {
		t.Fatalf("warns = %+v, want the listing failure reported against the nested directory", log.warns)
	}
	if res.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0 — the directory was changed, not skipped", res.Skipped)
	}
}

// TestExpectationStillRefusesAZeroInodeOnLinux is the Linux half of Astra r2 #6:
// the dev-loop tolerance is for a platform that has no inode numbers at all, and
// it must not become a way to hand the worker an empty identity and have the
// precondition wave it through. Here a real file has a real inode, so a zero on
// the other side is a mismatch and stays one.
func TestExpectationStillRefusesAZeroInodeOnLinux(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)
	ctx := context.Background()

	graded, err := Props(ctx, r, nil, "/f.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	empty := &wproto.ACLExpect{State: graded.ACL.State}
	_, err = Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0777}, empty)
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("chmod against an empty identity = %v, want changed", err)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got == 0o777 {
		t.Fatal("the file was changed on an identity nobody proved")
	}
}

// TestBindMountedFileIsACrossing is Astra r2 #4 against the real thing: a
// REGULAR FILE that is its own bind mount. It keeps the device of what it was
// bound from, so the old st_dev comparison called it an ordinary entry of this
// directory and a recursive chmod changed a file on another share — and its
// nlink stays 1, so the hardlink rule did not catch it either.
//
// Mounting needs root, so this is the CI root job's test (PLAN.md decision 14).
func TestBindMountedFileIsACrossing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a bind mount needs root; the CI root job runs this one")
	}
	base := tempDir(t)
	mkdir(t, base, "other")
	mkdir(t, base, "share")
	write(t, base, "other/secret.txt", "somebody else's file")
	write(t, base, "share/leaf.txt", "")
	secret := filepath.Join(base, "other/secret.txt")
	leaf := filepath.Join(base, "share/leaf.txt")
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(secret, leaf, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mounts are not available here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(leaf, 0) })

	var log jobLog
	res, err := ChmodTree(context.Background(), newRoot(t, base), nil,
		[]string{"/share"},
		ChmodOptions{
			Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0666},
			Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0755},
			Recursive: true,
		},
		log.emit())
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if got := modeOf(t, secret); got != 0o600 {
		t.Fatalf("the bind-mounted file's mode = %s, want 0600 — the walk crossed into it", perm.Octal(got))
	}
	if res.Files != 0 || res.Dirs != 1 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the share itself changed and the leaf refused", res)
	}
	w, ok := log.warnFor("/share/leaf.txt")
	if !ok || !strings.Contains(w.Message, "mount point") {
		t.Fatalf("warns = %+v, want the crossing named", log.warns)
	}
}
