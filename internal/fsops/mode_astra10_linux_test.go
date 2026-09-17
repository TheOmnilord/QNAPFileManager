package fsops

// The engine half of Astra M3 round 10, against a real kernel.
//
// Both findings are the same shape as the rounds before them: a proof that was
// made about the object the code had in its hand, and not about the object that
// turned up when it looked the name up again. #1 recorded a traversed directory
// by a NUMBER the allocator may hand back; #2 asked a leaf a question that
// cannot be answered without a mount id and read the missing answer as "no".

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/perm"
)

// TestTraversedDirectoryIsRecordedWithItsBirthTime is Astra r10 #1.
//
// The post-order change names a directory a SECOND time, because the walker
// closes the descriptor it enumerated before it calls Post, and the reading made
// when the walk DESCENDED is what that second lookup is measured against. That
// reading came from an ordinary fstat of the enumerated descriptor, so it carried
// no birth time even where the filesystem records one — and objectID.same
// compares birth times only when both sides have one, which left device and inode
// alone. An inode number is freed with its object and may be handed straight
// back, so an empty directory removed and recreated in the gap between the close
// and Post — until the number repeats, and the client controls how long that gap
// is — was accepted as the directory that had been traversed and received the
// chmod or chown.
//
// The identity is now taken through the descriptor while the walk still holds it
// (openedInfo), so the recorded objectID carries the one fact nothing can forge.
// The assertion that a regression lands on is made BEFORE anything is swapped
// (Astra r5 #4): whether a freed inode number is reissued within any number of
// tries is allocation policy and not this code's business, so only the half that
// needs the collision is skipped, naming the numbers the allocator did answer.
func TestTraversedDirectoryIsRecordedWithItsBirthTime(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/nested")
	nested := filepath.Join(base, "tree/nested")
	r := newRoot(t, base)

	// Nothing below can be told apart on a filesystem that keeps no creation
	// time, and on one the protection does not exist to be tested (INV-2 — the
	// kernel decides). That is the only skip decided before anything is staged.
	if !recordsBirthTime(t, base) {
		t.Skipf("%s reports no STATX_BTIME, so a recycled inode cannot be told apart on it at all", base)
	}

	parent := parentOnly(t, r, "/tree")

	// What the walk enumerates the entry as, and the descriptor it then opens to
	// read the entry's own children through — the two the walker really makes,
	// so that what is asserted here is what the walker will be holding.
	enumerated, err := parent.lstat("nested")
	if err != nil {
		t.Fatal(err)
	}
	held, err := parent.child("nested")
	if err != nil {
		t.Fatal(err)
	}
	info, err := openedInfo(held)
	if err != nil {
		t.Fatal(err)
	}

	var log jobLog
	j := &modeJob{
		r: r, emit: log.emit(),
		dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		uid:  -1, gid: -1,
		recursive: true,
	}
	it := WalkItem{Path: "/tree/nested", Name: "nested", Info: enumerated, Depth: 1, parent: parent}
	if err := j.opened(it, info); err != nil {
		t.Fatalf("opened = %v", err)
	}
	if len(j.traversedOK) <= 1 || !j.traversedOK[1] {
		t.Fatal("the descent recorded no identity at all for the directory it opened")
	}
	first := j.traversed[1]
	if !first.have {
		t.Fatal("the recorded identity reports no inode number")
	}
	if !first.hasBtime {
		// The regression this test exists for, caught before the swap: the
		// identity the post-order change is measured against is device and inode
		// alone again, and on a filesystem that does record birth times there is
		// no honest reason for the descent's own reading not to carry one.
		t.Fatalf("the identity recorded for the traversed directory carries no birth time although %s records them: "+
			"a recycled inode number satisfies it", base)
	}

	// The walker closes the enumerated descriptor before Post, and the
	// enumeration released its own the moment the entry was handled. From here
	// nothing pins the inode, which is what makes the number recyclable at all
	// (Astra r4 #2: a held descriptor would have made the loop below always skip).
	if err := held.close(); err != nil {
		t.Fatal(err)
	}

	// The control, first: with nothing swapped, the post-order change still lands
	// on the directory that was traversed. A birth time that refused everything
	// would be the more expensive bug.
	j.applyEntry(it)
	if j.res.Dirs != 1 {
		t.Fatalf("result = %+v, want the traversed directory changed: %+v", j.res, log.warns)
	}
	if got := modeOf(t, nested); got != 0o777 {
		t.Fatalf("mode = %s, want 0777 — the post-order change did not land", perm.Octal(got))
	}

	// The swap: removed and recreated at the same name until the allocator hands
	// the number back, which is the case the birth time exists for.
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
		// rising sequence, a converging one repeats a number that is not the
		// original. Either way this filesystem will not stage the collision, and
		// the sequence is printed so a reader can tell which it was (Astra r5 #4).
		t.Skipf("inode %d was never handed back in %d removes and recreates (the allocator answered %v): "+
			"the assertion that needs a recycled inode could not be staged on this filesystem",
			first.key.ino, attempts, seen[:min(len(seen), 8)])
	}
	if !replacement.hasBtime || replacement.btime == first.btime {
		// The other half of the proof. A birth time the replacement does not
		// carry, or one too coarse to differ across a remove and a recreate,
		// would make the refusal below an accident of something else.
		t.Fatalf("the replacement at inode %d reports birth time %d (recorded: %v) against the original's %d: "+
			"the two objects are not distinguishable by it",
			replacement.key.ino, replacement.btime, replacement.hasBtime, first.btime)
	}

	j.applyEntry(it)

	if got := modeOf(t, nested); got != 0o000 {
		t.Fatalf("the replacement's mode = %s, want 0000 — it was changed anyway", perm.Octal(got))
	}
	if j.res.Dirs != 1 {
		t.Fatalf("result = %+v, want nothing changed beyond the control", j.res)
	}
	if j.res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want the replacement reported", j.res.Skipped)
	}
	w, ok := log.warnFor("/tree/nested")
	if !ok || !strings.Contains(w.Message, "not the folder the walk descended into") {
		t.Fatalf("warns = %+v, want the replacement named", log.warns)
	}
}

// TestLeafWithNoMountIdentityIsRefused is Astra r10 #2.
//
// The directory walker has failed closed since B4: where the kernel names mounts
// and would not name this one, the only comparison left is st_dev, a same-device
// bind mount passes it, and a mutating walk must not descend on that. The LEAF
// path never applied the rule — it went straight to differsFrom, which reads two
// missing mount ids as "equal devices, not a crossing" — so a regular file
// bind-mounted into the tree from outside it was changed under crossMounts:false,
// with nlink 1 so the hardlink rule did not catch it either.
//
// The corner is not reachable on any kernel a test can run on: statx answers
// since 5.8 and /proc/self/fdinfo has printed "mnt_id:" since 3.15, so one of the
// two always answers. The identity readings are therefore the seam, exactly as
// they are for the walker's own half of this rule
// (TestMutatingWalkStopsWhereTheKernelWillNotNameAMount), and the real
// measurement is the CI root job's.
func TestLeafWithNoMountIdentityIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      mountIdentity
		want    uint32
		skipped int64
		warn    string
	}{
		{
			// The finding: a device on both sides and no mount id anywhere, which
			// is what a same-device bind mount looks like to st_dev.
			name: "a leaf whose mount cannot be named is left alone",
			id:   mountIdentity{dev: 1, hasDev: true},
			want: 0o600, skipped: 1,
			warn: "would not name the mount",
		},
		{
			// The control: a leaf on the parent's own named mount is an ordinary
			// entry and is changed. A rule that refused everything would be the
			// more expensive bug — every recursive chmod on the NAS is this case.
			name: "a leaf on the parent's own mount still changes",
			id:   mountIdentity{mnt: 7, hasMnt: true, dev: 1, hasDev: true},
			want: 0o666, skipped: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tempDir(t)
			mkdir(t, base, "share/vol/tree")
			write(t, base, "share/vol/tree/leaf.txt", "x")
			leaf := filepath.Join(base, "share/vol/tree/leaf.txt")
			if err := os.Chmod(leaf, 0o600); err != nil {
				t.Fatal(err)
			}
			r := newRoot(t, base)

			prevDir, prevLeaf := identityFor, leafIdentityFor
			identityFor = func(*dirRef) mountIdentity { return tc.id }
			leafIdentityFor = func(*itemRef) mountIdentity { return tc.id }
			t.Cleanup(func() { identityFor, leafIdentityFor = prevDir, prevLeaf })

			var log jobLog
			res, err := ChmodTree(context.Background(), r, nil,
				[]string{"/share/vol/tree"},
				ChmodOptions{
					Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0666},
					Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0755},
					Recursive: true,
				},
				log.emit())
			if err != nil {
				t.Fatalf("ChmodTree = %v", err)
			}
			if got := modeOf(t, leaf); got != tc.want {
				t.Fatalf("the leaf's mode = %s, want %s", perm.Octal(got), perm.Octal(tc.want))
			}
			if res.Skipped != tc.skipped {
				t.Fatalf("result = %+v, want %d skipped: %+v", res, tc.skipped, log.warns)
			}
			if res.Dirs != 1 {
				t.Fatalf("result = %+v, want the selected directory changed", res)
			}
			if tc.warn == "" {
				return
			}
			w, ok := log.warnFor("/share/vol/tree/leaf.txt")
			if !ok || !strings.Contains(w.Message, tc.warn) {
				t.Fatalf("warns = %+v, want the unnamed mount reported against the leaf", log.warns)
			}
		})
	}
}
