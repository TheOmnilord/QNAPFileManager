package fsops

// The engine half of Astra M3 round 1, against a real kernel and without root.
//
// Findings 4, 7, 8, 18 and 20 are all one shape: something that was true when it
// was measured and is asked about again later, through a different lookup or
// from a stale snapshot. Each test here opens exactly that gap and checks that
// the engine notices.
//
// Finding 19 — a regular file that is its own bind mount — is deliberately not
// here: making one needs mount(2), which needs root and a mount namespace, so it
// belongs to the root CI job. What CAN be exercised without privilege is the
// comparison itself, and crossesMount is a pure reading of two st_devs.

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
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// TestChmodRefusesAnObjectSwappedAfterTheConfirmation is finding 4: Props and
// the chmod are two round trips and the gap between them belongs to the client,
// so the ladder can be shown a trivial file and the chmod handed a non-trivial
// one. ChmodReq.Expect closes it — the identity the ladder graded is re-proved on
// the held leaf before anything is changed.
func TestChmodRefusesAnObjectSwappedAfterTheConfirmation(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "the graded file")
	write(t, base, "other.txt", "somebody else's file")
	r := newRoot(t, base)
	ctx := context.Background()

	graded, err := Props(ctx, r, nil, "/f.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	expect := &wproto.ACLExpect{State: graded.ACL.State, Identity: graded.Identity}

	// The control first: with nothing swapped, the precondition passes and the
	// chmod happens. Running it first also proves the refusal below is about the
	// swap and not about the precondition being unsatisfiable in general.
	if _, err := Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0640}, expect); err != nil {
		t.Fatalf("a matching precondition was refused: %v", err)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got != 0o640 {
		t.Fatalf("mode = %s, want 0640", perm.Octal(got))
	}

	// The swap. A RENAME of another existing file over the name is used rather
	// than remove-and-recreate, because two files that existed at the same
	// moment cannot share an inode number — so the test measures the identity
	// check and not the filesystem's inode-recycling policy.
	if err := os.Rename(filepath.Join(base, "other.txt"), filepath.Join(base, "f.txt")); err != nil {
		t.Fatal(err)
	}
	_, err = Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0777}, expect)
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("chmod of a swapped object = %v, want changed", err)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got == 0o777 {
		t.Fatal("the swapped object was changed anyway")
	}

	// And with no precondition at all the same call goes through, which is what
	// keeps a job — which grades no entry individually — working.
	if _, err := Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, nil); err != nil {
		t.Fatalf("chmod with no precondition = %v", err)
	}
}

// TestChmodRefusesAStateThatMovedUnderTheConfirmation is the other half of
// finding 4: the same object, but an ACL state that is no longer the one the
// ladder graded. The identity check cannot see that — it is the same inode — so
// the state is compared in its own right.
//
// A platform is deliberately not supplied, so the probe answers "" and the
// assertion is that a MISMATCH refuses; what a real backend reports is the ZFS
// and ext4 jobs' business (INV-2).
func TestChmodRefusesAStateThatMovedUnderTheConfirmation(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)
	ctx := context.Background()

	graded, err := Props(ctx, r, nil, "/f.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	stale := &wproto.ACLExpect{State: fsx.ACLNFS4Trivial, Identity: graded.Identity}
	_, err = Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0777}, stale)
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("chmod against a stale ACL state = %v, want changed", err)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got == 0o777 {
		t.Fatal("the object was changed on a grade nobody gave")
	}
}

// TestRecursiveChmodChangesADirectoryItCannotList is finding 8: a directory the
// user cannot enumerate — an owner-set 0000 is the ordinary way — used to be
// skipped whole, so a recursive repair could not repair exactly the directories
// that needed repairing. Now the traversal failure is its own warning and the
// change is still made on the held reference.
func TestRecursiveChmodChangesADirectoryItCannotList(t *testing.T) {
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
		[]string{"/share/tree/locked"},
		ChmodOptions{Dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0750}, Recursive: true},
		log.emit())
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Dirs != 1 {
		t.Fatalf("result = %+v, want the directory itself changed", res)
	}
	if got := modeOf(t, locked); got != 0o750 {
		t.Fatalf("mode = %s, want 0750 — the repair did not land", perm.Octal(got))
	}
	var listed bool
	for _, w := range log.warns {
		if strings.Contains(w.Message, "could not be listed") {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("nothing said the contents were unreachable: %+v", log.warns)
	}
}

// TestPostOrderRefusesADirectoryThatWasSwapped is finding 7's guard, exercised
// where it can be: the walker closes a directory's descriptor before Post, so
// applyEntry names it a second time, and the reading taken when the walk
// DESCENDED is what that second lookup is measured against.
//
// Swapping a directory mid-walk needs a hook the visitor does not expose, so
// the comparison is driven directly with two real objects — which is the whole
// of the decision, and the only part of it a test can make deterministic.
func TestPostOrderRefusesADirectoryThatWasSwapped(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "walked")
	mkdir(t, base, "impostor")
	r := newRoot(t, base)

	_, walkedRef := heldIn(t, r, "/", "walked")
	_, impostorRef := heldIn(t, r, "/", "impostor")

	j := &modeJob{}
	j.setTraversed(1, objectIDOf(refFD(walkedRef), walkedRef.fi))

	if !j.sameAsTraversed(1, walkedRef) {
		t.Fatal("the directory the walk descended into was rejected as a stranger")
	}
	if j.sameAsTraversed(1, impostorRef) {
		t.Fatal("a different directory passed as the one that was walked")
	}
	// A depth with no reading at all — an fstat that failed, or a directory the
	// walk never opened — is a refusal and not a pass: an unprovable identity is
	// not a proof.
	if j.sameAsTraversed(2, walkedRef) {
		t.Fatal("an unrecorded depth was treated as proved")
	}
	j.clearTraversed(1)
	if j.sameAsTraversed(1, walkedRef) {
		t.Fatal("a cleared slot still matched")
	}
}

// TestRestatRefreshesTheHeldReading is finding 20: a recursive job takes its
// root's reference before the subtree walk and does not use it again until the
// post-order call, which can be minutes later. A mode changed elsewhere in
// between would be reinstated from the stale snapshot and hidden from the diff,
// because the diff reports against the before-image it is given.
func TestRestatRefreshesTheHeldReading(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	if err := os.Chmod(filepath.Join(base, "f.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	_, ref := heldIn(t, r, "/", "f.txt")

	if got := perm.Bits(ref.fi.Mode()); got != 0o755 {
		t.Fatalf("held reading = %s, want 0755", perm.Octal(got))
	}
	// Somebody else, through another name for the same inode.
	if err := os.Chmod(filepath.Join(base, "f.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := perm.Bits(ref.fi.Mode()); got != 0o755 {
		t.Fatal("the held reading changed on its own; this test is measuring nothing")
	}
	ref.restat()
	if got := perm.Bits(ref.fi.Mode()); got != 0o700 {
		t.Fatalf("after restat = %s, want 0700", perm.Octal(got))
	}
}

// TestACLProbeWeighsTheAttributeAgainstWhatIsLeft is finding 18: the byte bound
// used to be checked before the SIZE QUERY and never against the attribute's own
// size, so a page already 60 KiB in could still read a 16 KiB attribute in full
// and only then notice it had gone past.
//
// The attribute is a user.* one rather than a real ACL: what is under test is the
// budget arithmetic, and a hand-written attribute of a known size is the only way
// to state it without a ZFS dataset.
func TestACLProbeWeighsTheAttributeAgainstWhatIsLeft(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	target := filepath.Join(base, "f.txt")

	const attr = "user.qfm_probe_budget"
	blob := make([]byte, 512)
	for i := range blob {
		blob[i] = 'a'
	}
	if err := syscall.Setxattr(target, attr, blob, 0); err != nil {
		t.Skipf("this filesystem will not take a user extended attribute: %v", err)
	}

	t.Run("an attribute larger than what is left is not read", func(t *testing.T) {
		p := &aclProbe{backend: platform.ACLNFS4, xattr: attr,
			bud: &aclBudget{bytes: fsx.ACLProbeMaxBytes - (len(blob) - 1)}}
		if state, ok := p.probe(aclTarget{osPath: target}); ok {
			t.Fatalf("a probe with too little budget answered %q", state)
		}
		if !p.bud.capped {
			t.Fatal("the probe must record that it stopped at a bound")
		}
		if p.bud.bytes != fsx.ACLProbeMaxBytes-(len(blob)-1) {
			t.Fatalf("bytes = %d: the attribute was read after all", p.bud.bytes)
		}
	})

	t.Run("an attribute that fits is read and charged for", func(t *testing.T) {
		start := fsx.ACLProbeMaxBytes - len(blob)
		p := &aclProbe{backend: platform.ACLNFS4, xattr: attr, bud: &aclBudget{bytes: start}}
		state, ok := p.probe(aclTarget{osPath: target})
		if !ok {
			t.Fatal("a probe with exactly enough budget refused")
		}
		// 512 bytes of 'a' is not an ACE list, so the classification is unknown —
		// the pessimistic answer, and the one this file's own tests pin. What
		// matters here is that the bytes were spent.
		if state != fsx.ACLUnknown {
			t.Fatalf("state = %q, want unknown for bytes that parse as nothing", state)
		}
		if p.bud.bytes != start+len(blob) {
			t.Fatalf("bytes = %d, want %d charged", p.bud.bytes, start+len(blob))
		}
	})
}
