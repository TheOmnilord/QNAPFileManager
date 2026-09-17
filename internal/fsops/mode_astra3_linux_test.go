package fsops

// The engine half of Astra M3 round 3, against a real kernel.
//
// Both findings here are the same shape as the round-2 ones they follow: a
// proof that held for the object it was written about and not for the object
// that actually turned up. #7 read an EMPTY observation as an observed absence,
// when on Linux it can now mean "the mount probe had not finished yet". #9
// compared an enumeration's identity that carried no birth time, so an inode
// number handed back by the allocator was accepted as the same directory.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// TestEmptyExpectationStillRefusesAnACLTheReprobeCanSee is Astra r3 #7.
//
// An expectation whose State is empty used to return as soon as the identity was
// proved, on the reasoning that nothing was observed and so there is no claim to
// hold the object to (r2 #1/#6). That reasoning had a hole in it that round 2's
// own asynchronous mount probe opened: an empty observation is now equally the
// signature of Props having described an object whose dataset had not been
// placed yet — so the confirmation ladder graded an ACL it could not see, and a
// chmod on an aclmode=discard dataset would then reduce or destroy an ACL that
// the re-probe reads perfectly well.
//
// The re-probe therefore happens either way, and the answer is what decides. No
// dataset is needed to state that decision and there is no ZFS on the dev box,
// so the probe is the seam.
func TestEmptyExpectationStillRefusesAnACLTheReprobeCanSee(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reprobed string
		changed  bool
	}{
		{
			// The finding: a real ACL that the grade never saw. Nothing is
			// changed and the caller is sent back to grade again.
			"an nfs4 ACL the grade never saw is a refusal",
			fsx.ACLNFS4,
			true,
		},
		{
			"a posix ACL likewise",
			fsx.ACLPosix,
			true,
		},
		{
			// Unknown is the state a failed read produces, and it is the one the
			// ladder promotes on. It must not be the one that gets waved through
			// for want of an expectation to compare it to.
			"an unreadable ACL is refused rather than assumed harmless",
			fsx.ACLUnknown,
			true,
		},
		{
			// Only what the mode already says, which is what every object on a
			// hero dataset carries. Refusing here would stop every chmod on the
			// NAS.
			"a trivial nfs4 ACL is only what the mode says, so the chmod proceeds",
			fsx.ACLNFS4Trivial,
			false,
		},
		{
			"an observed absence of any ACL likewise",
			fsx.ACLNone,
			false,
		},
		{
			// Still nothing observable: the identity is the whole precondition,
			// exactly as round 2 left it.
			"a re-probe that observes nothing leaves the identity as the whole precondition",
			"",
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tempDir(t)
			write(t, base, "f.txt", "x")
			osPath := filepath.Join(base, "f.txt")
			if err := os.Chmod(osPath, 0o644); err != nil {
				t.Fatal(err)
			}
			r := newRoot(t, base)
			ctx := context.Background()

			graded, err := Props(ctx, r, nil, "/f.txt", "")
			if err != nil {
				t.Fatal(err)
			}
			if graded.ACL.State != "" {
				t.Fatalf("Props observed %q; this test is about an expectation that observed nothing", graded.ACL.State)
			}

			restore := proofProbe
			proofProbe = func(*platform.Platform, string, *itemRef) (string, string, string) {
				return "", "", tc.reprobed
			}
			t.Cleanup(func() { proofProbe = restore })

			expect := &wproto.ACLExpect{State: "", Identity: graded.Identity}
			_, err = Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0700}, expect)
			switch {
			case tc.changed && !errors.Is(err, fsx.ErrChanged):
				t.Fatalf("chmod = %v, want changed: the ladder graded an ACL it could not see", err)
			case !tc.changed && err != nil:
				t.Fatalf("chmod = %v, want it to proceed", err)
			}
			want := uint32(0o700)
			if tc.changed {
				want = 0o644
			}
			if got := modeOf(t, osPath); got != want {
				t.Fatalf("mode = %s, want %s", perm.Octal(got), perm.Octal(want))
			}
		})
	}
}

// TestEmptyExpectationRefusalNamesTheUngradedACL pins the sentence, because it is
// the one the front end turns into "describe it again and confirm": it has to say
// the ACL was not visible when the object was described rather than imply the
// object moved.
func TestEmptyExpectationRefusalNamesTheUngradedACL(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)
	ctx := context.Background()

	graded, err := Props(ctx, r, nil, "/f.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	restore := proofProbe
	proofProbe = func(*platform.Platform, string, *itemRef) (string, string, string) {
		return "", "", fsx.ACLNFS4
	}
	t.Cleanup(func() { proofProbe = restore })

	_, err = Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0700},
		&wproto.ACLExpect{State: "", Identity: graded.Identity})
	if err == nil {
		t.Fatal("the chmod proceeded")
	}
	if !strings.Contains(err.Error(), "was not visible when it was described") {
		t.Fatalf("error = %v, want it to say the ACL was never graded", err)
	}
}

// recordsBirthTime answers the one question this filesystem has to answer before
// a recycled inode is worth staging at all: does it keep a creation time?
//
// It is asked of a directory that already exists — the fixture's own root,
// through a descriptor held while the statx is made — so no object is created
// to ask it, and the answer is the filesystem's rather than one object's. A
// false here means STATX_BTIME is genuinely absent (an old kernel without
// statx, or a filesystem that does not keep the fact) and not that the test
// failed to look (Astra r4 #2).
func recordsBirthTime(t *testing.T, dir string) bool {
	t.Helper()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return objectIDOf(f, fi).hasBtime
}

// parentOnly opens a directory the way the walk holds it and NOTHING inside it.
//
// heldIn is the wrong helper for an object that has to be removed: it also opens
// the entry, and an open descriptor — O_PATH included — pins the inode for as
// long as it lives, so the number is never freed and never handed back.
func parentOnly(t *testing.T, r fsx.Root, dirAPI string) *dirRef {
	t.Helper()
	d, _, err := canonicalDir(r, dirAPI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.close() })
	return d
}

// TestUnopenedFallbackRefusesARecycledInode is Astra r3 #9.
//
// The fallback for a directory the walk could not enumerate re-opens the name
// O_PATH and proves it against the reading the enumeration made. That reading is
// a FileInfo and not a descriptor — lstatIn closed its O_PATH before the walker
// ever saw it — so the comparison was device and inode alone, and an inode number
// is freed with its object and may be handed straight back. A directory that
// cannot be listed, removed and recreated at the same name between the two
// lookups, therefore passed `same` and received the change.
//
// The first version of this test proved none of that, and Astra r4 #2 is why:
// it held the CHILD open across the remove and recreate, which pins the inode,
// so the number could not be recycled, the loop always gave up and the test
// always skipped — including when the birth-time capture it exists to protect
// was deleted. So the parent alone is held; the filesystem is asked about birth
// times up front and independently; and the enumeration is asked to PROVE it
// carried one, which is the fact a regression removes.
//
// That proof is made BEFORE anything is swapped, and it is what makes the rest
// of the test safe to skip (Astra r5 #4). Round 4 turned an allocator that would
// not hand the number back into a failure, on the reasoning that a filesystem
// recording birth times can stage the case. It cannot: whether a freed inode is
// reissued within any number of tries is allocation policy — ZFS and every
// delayed-allocation filesystem are entitled to answer with a rising sequence
// forever — and a red ZFS job would be saying nothing about this code. So the
// hard assertions stand where a regression lands (no birth time from the
// enumeration, or a descriptor retained instead), and only the half that needs
// a recycled number is skipped, naming the numbers the allocator did answer.
func TestUnopenedFallbackRefusesARecycledInode(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	nested := filepath.Join(base, "tree/nested")
	r := newRoot(t, base)

	// Nothing below can be told apart on a filesystem that keeps no creation
	// time, and on one the protection does not exist to be tested (INV-2 — the
	// kernel decides). That is the only skip left here, and it is decided before
	// anything is staged.
	if !recordsBirthTime(t, base) {
		t.Skipf("%s reports no STATX_BTIME, so a recycled inode cannot be told apart on it at all", base)
	}

	parent := parentOnly(t, r, "/tree")

	// What the walk's own enumeration recorded, through the walk's own lstat —
	// the very call the walker makes, so that what is asserted below is what the
	// walker will be holding.
	enumerated, held, err := parent.lstatHeld("nested")
	if err != nil {
		t.Fatal(err)
	}
	if held != nil {
		// A birth time is available here, so the walk has an identity that
		// survives the object and needs to retain nothing (Astra r4 #7).
		_ = held.Close()
		t.Fatal("the enumeration retained a descriptor although this filesystem dates its objects")
	}
	first := objectIDOf(nil, enumerated)
	if !first.have {
		t.Fatal("the fixture reports no inode number at all")
	}
	if !first.hasBtime {
		// The regression this test exists for, caught before the swap: the
		// identity the fallback compares is device and inode alone again, and on
		// a filesystem that does record birth times there is no honest reason
		// for the walk's lstat not to carry one.
		t.Fatalf("the walk's lstat of \"nested\" carried no birth time although %s records them: "+
			"the fallback's identity is device and inode alone, which a recycled number satisfies", base)
	}

	// The swap: removed and recreated at the same name until the allocator hands
	// the number back, which is the case the birth time exists for. Everything
	// above this line has already run, so a regression of the birth-time capture
	// has already failed on every filesystem, recycling or not (Astra r5 #4).
	const attempts = 64
	var (
		seen        []uint64
		replacement objectID
	)
	// Registered before the loop rather than after it: each pass leaves the
	// directory at 0000, and a t.Fatal inside the loop must not leave it that way
	// for the fixture's own removal.
	t.Cleanup(func() { _ = os.Chmod(nested, 0o755) })
	for i := 0; i < attempts && !replacement.have; i++ {
		if err := os.Remove(nested); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(nested, 0o000); err != nil {
			t.Fatal(err)
		}
		again, err := parent.lstat("nested")
		if err != nil {
			t.Fatal(err)
		}
		id := objectIDOf(nil, again)
		if !id.have {
			t.Fatal("the replacement reports no inode number at all")
		}
		seen = append(seen, id.key.ino)
		if id.key == first.key {
			replacement = id
		}
	}
	if !replacement.have {
		// The allocator's answer, not the code's: a monotonic one answers with a
		// rising sequence, a converging one repeats a single number that is not
		// the original. Either way this filesystem will not stage the collision,
		// and the sequence is printed so a reader can tell which it was (Astra
		// r5 #4).
		t.Skipf("inode %d was never handed back in %d removes and recreates (the allocator answered %v): "+
			"the assertion that needs a recycled inode could not be staged on this filesystem",
			first.key.ino, attempts, seen[:min(len(seen), 8)])
	}
	if !replacement.hasBtime || replacement.btime == first.btime {
		// The other half of the proof. A birth time the replacement does not
		// carry, or one too coarse to differ across a remove and a recreate,
		// would make the refusal below an accident of something else.
		t.Fatalf("the replacement at inode %d reports birth time %d (recorded: %v) against the original's %d: the two objects are not distinguishable by it",
			replacement.key.ino, replacement.btime, replacement.hasBtime, first.btime)
	}

	var log jobLog
	j := &modeJob{
		r: r, emit: log.emit(),
		files: perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		dirs:  perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		uid:   -1, gid: -1,
		recursive: true,
	}
	j.unopened(
		WalkItem{Path: "/tree/nested", Name: "nested", Info: enumerated, Depth: 1, parent: parent},
		errors.New("open /tree/nested: permission denied"))

	if got := modeOf(t, nested); got != 0o000 {
		t.Fatalf("the replacement's mode = %s, want 0000 — it was changed anyway", perm.Octal(got))
	}
	if j.res.Dirs != 0 {
		t.Fatalf("result = %+v, want nothing changed", j.res)
	}
	if j.res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want the entry reported", j.res.Skipped)
	}
	w, ok := log.warnFor("/tree/nested")
	if !ok || !strings.Contains(w.Message, "not the folder the walk reached") {
		t.Fatalf("warns = %+v, want the replacement named", log.warns)
	}
}

// TestUnopenedFallbackStillChangesTheDirectoryItReached is the control for the
// test above: the same fallback, with nothing swapped, still does the repair
// round 2 (#5) added. A birth time that refused everything would be the more
// expensive bug.
func TestUnopenedFallbackStillChangesTheDirectoryItReached(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	nested := filepath.Join(base, "tree/nested")
	if err := os.Chmod(nested, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(nested, 0o755) })
	r := newRoot(t, base)

	parent, _ := heldIn(t, r, "/tree", "nested")
	enumerated, err := parent.lstat("nested")
	if err != nil {
		t.Fatal(err)
	}

	var log jobLog
	j := &modeJob{
		r: r, emit: log.emit(),
		dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
		uid:  -1, gid: -1,
		recursive: true,
	}
	j.unopened(
		WalkItem{Path: "/tree/nested", Name: "nested", Info: enumerated, Depth: 1, parent: parent},
		errors.New("open /tree/nested: permission denied"))

	if got := modeOf(t, nested); got != 0o750 {
		t.Fatalf("mode = %s, want 0750 — the repair did not happen", perm.Octal(got))
	}
	if j.res.Dirs != 1 {
		t.Fatalf("result = %+v, want the directory changed", j.res)
	}
	w, ok := log.warnFor("/tree/nested")
	if !ok || !strings.Contains(w.Message, "could not be listed") {
		t.Fatalf("warns = %+v, want the listing failure reported", log.warns)
	}
}
