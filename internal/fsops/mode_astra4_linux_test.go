package fsops

// The engine half of Astra M3 round 4, against a real kernel.
//
// Round 3 gave a directory's identity a birth time, which is the one half of an
// identity a recycled inode number cannot forge. #7 is about the other half of
// that sentence: the filesystems and kernels that have no birth time to give.
// There the identity fell back to device and inode and the Unopened fallback
// went quietly back to proving an object by a number — the same hole, on exactly
// the older ext4-and-no-statx systems that cannot be upgraded out of it.
//
// The answer is not a better comparison. It is not comparing: the walk keeps the
// descriptor it enumerated the directory through, and the fallback acts on that
// object rather than looking the name up a second time.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/perm"
)

// noBirthTime is the seam, and it is the kernel's own: statxNoBtime is the flag
// birthTimeOf sets when statx(2) answers ENOSYS, which is every kernel before
// 4.11 and a great many QTS ones. Setting it here takes the same branch that
// kernel takes rather than a branch written for a test (Astra r4 #7).
func noBirthTime(t *testing.T) {
	t.Helper()
	was := statxNoBtime.Swap(true)
	t.Cleanup(func() { statxNoBtime.Store(was) })
}

// TestEnumerationHoldsTheDirectoryItCouldNotProve is Astra r4 #7.
//
// Without a birth time there is nothing in a FileInfo that survives the object
// it describes: the inode number is freed with the directory and may be handed
// straight back, so a fallback that re-opens the name and compares numbers
// agrees about an object that is not the one the walk reached. The enumeration
// therefore keeps its O_PATH descriptor for a directory it could not date, and
// the fallback works from that.
//
// What the descriptor buys is visible in the swap below: the name means a
// different directory by the time the fallback runs — possibly wearing the very
// same inode number, and it makes no difference either way — and the object the
// walk described is gone. Nothing is changed, and the replacement, which this
// job never authorized, is untouched.
func TestEnumerationHoldsTheDirectoryItCouldNotProve(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	nested := filepath.Join(base, "tree/nested")
	t.Cleanup(func() { _ = os.Chmod(nested, 0o755) })
	r := newRoot(t, base)

	// First the case that must NOT hold anything. A filesystem that records
	// birth times needs no descriptor retained, and retaining one per directory
	// on the NAS's own ext4 would be a cost paid for nothing.
	if recordsBirthTime(t, base) {
		dated := parentOnly(t, r, "/tree")
		fi, held, err := dated.lstatHeld("nested")
		if err != nil {
			t.Fatal(err)
		}
		if held != nil {
			_ = held.Close()
			t.Fatal("the enumeration retained a descriptor for a directory it could date; the identity is proof enough there")
		}
		if !objectIDOf(nil, fi).hasBtime {
			t.Fatal("the enumeration neither dated the directory nor held it: the fallback has nothing but an inode number to go on")
		}
	}

	noBirthTime(t)
	parent := parentOnly(t, r, "/tree")

	fi, held, err := parent.lstatHeld("nested")
	if err != nil {
		t.Fatal(err)
	}
	if held == nil {
		t.Fatal("the enumeration let go of a directory it could not date, so the fallback is back to proving an object by its inode number")
	}
	defer held.Close()
	if objectIDOf(nil, fi).hasBtime {
		t.Fatal("the seam did not take: this reading still carries a birth time")
	}

	// The swap, between the enumeration and the fallback — the window the walk
	// leaves open when it fails to enter a directory and then goes back for it.
	if err := os.Remove(nested); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nested, 0o000); err != nil {
		t.Fatal(err)
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
		WalkItem{Path: "/tree/nested", Name: "nested", Info: fi, Depth: 1, parent: parent, held: held},
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
	if !ok || !strings.Contains(w.Message, "was removed before it could be changed") {
		t.Fatalf("warns = %+v, want the removal named", log.warns)
	}
}

// TestTheWalkHandsTheFallbackTheDirectoryItHeld is the wiring, end to end and
// through the real walk: the enumeration retains, the item carries it to
// Unopened, the fallback repairs the directory it was given — and the walk
// releases the descriptor when it is done with the entry, so a deep tree does
// not accumulate one per directory it could not enter.
//
// It needs an unenterable directory, and root can enter anything (INV-2 — the
// kernel decides who is refused), so the root job cannot stage this one. The
// refusal itself is the ordinary Linux job's.
func TestTheWalkHandsTheFallbackTheDirectoryItHeld(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode-0000 directory, so the walk never reaches the Unopened fallback")
	}
	noBirthTime(t)

	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	nested := filepath.Join(base, "tree/nested")
	if err := os.Chmod(nested, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(nested, 0o755) })
	r := newRoot(t, base)

	var log jobLog
	j := &modeJob{
		r: r, emit: log.emit(),
		dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
		uid:  -1, gid: -1,
		recursive: true,
	}

	var (
		reached bool
		carried *os.File
	)
	err := Walk(context.Background(), r, nil, "/tree", WalkOptions{}, Visitor{
		Unopened: func(it WalkItem, uerr error) {
			if it.Path != "/tree/nested" {
				return
			}
			reached, carried = true, it.held
			if it.held == nil {
				t.Error("the walk handed the fallback a directory it had not dated and had not held")
				return
			}
			j.unopened(it, uerr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Fatal("the walk entered the unreadable directory; the fallback was never asked")
	}
	if got := modeOf(t, nested); got != 0o750 {
		t.Fatalf("mode = %s, want 0750 — the repair the held descriptor exists to make did not happen", perm.Octal(got))
	}
	if j.res.Dirs != 1 {
		t.Fatalf("result = %+v, want the directory changed", j.res)
	}
	if w, ok := log.warnFor("/tree/nested"); !ok || !strings.Contains(w.Message, "could not be listed") {
		t.Fatalf("warns = %+v, want the listing failure reported", log.warns)
	}
	if cerr := carried.Close(); cerr == nil {
		t.Fatal("the descriptor the walk retained was still open after the walk finished with the entry")
	} else if !errors.Is(cerr, os.ErrClosed) {
		t.Fatalf("closing it again = %v, want %v", cerr, os.ErrClosed)
	}
}
