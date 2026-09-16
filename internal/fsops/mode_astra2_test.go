package fsops

// The engine half of Astra M3 round 2, in the parts that need no kernel of any
// particular kind.
//
// Two findings live here. #4's crossing rule is arithmetic over two mount
// identities, and mounting anything to produce a real pair needs root and a
// mount namespace — so the decision is stated directly here and the real bind
// mount is the root job's (mode_astra2_linux_test.go). #6 is the dev loop's own
// degradation, which can only be observed where there are no inode numbers at
// all, so its test skips on Linux and the Linux half of the same rule is pinned
// over there.

import (
	"context"
	"testing"

	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// TestLeafCrossingPolicy is Astra r2 #4: a non-directory entry is put through
// the same crossing rule a child directory is, by mount id rather than by
// device, and CrossMounts does not skip the question — it changes it.
//
// The two identities below are the shape that matters: one device, two mount
// ids, which is a bind mount and is how QTS builds its whole share layout. A
// st_dev comparison calls that pair "the same filesystem and carry on", which is
// exactly the entry a recursive chmod had been changing on somebody else's
// share.
func TestLeafCrossingPolicy(t *testing.T) {
	here := mountIdentity{mnt: 7, hasMnt: true, dev: 100, hasDev: true}
	bind := mountIdentity{mnt: 9, hasMnt: true, dev: 100, hasDev: true}
	elsewhere := mountIdentity{mnt: 9, hasMnt: true, dev: 200, hasDev: true}
	unnamed := mountIdentity{}

	cases := []struct {
		name          string
		parent, child mountIdentity
		cross         bool
		domain        bool
		want          bool
		asked         bool
	}{
		{
			name:   "an entry on the parent's own mount is not a crossing",
			parent: here, child: here, cross: false,
			want: false, asked: false,
		},
		{
			// The finding itself. Same device, and it is still another mount.
			name:   "a bind-mounted file is a crossing the device comparison could not see",
			parent: here, child: bind, cross: false,
			want: true, asked: false,
		},
		{
			name:   "with crossing on, the storage domain decides",
			parent: here, child: bind, cross: true, domain: true,
			want: false, asked: true,
		},
		{
			// The other half of the finding: crossMounts:true used to skip the
			// check altogether, so "include mounted sub-folders" meant any mount
			// at all — a USB disk, another pool, a network share.
			name:   "with crossing on, another storage domain is still refused",
			parent: here, child: elsewhere, cross: true, domain: false,
			want: true, asked: true,
		},
		{
			// The degradation, stated: no mount ids and no devices on either
			// side is not a boundary, because inventing one out of missing data
			// would skip every entry on a dev box (INV-2).
			name:   "an unanswerable comparison is not a crossing",
			parent: unnamed, child: unnamed, cross: false,
			want: false, asked: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			got := crossesLeafMount(c.parent, c.child, c.cross, func(p, ch mountIdentity) bool {
				asked = true
				if p != c.parent || ch != c.child {
					t.Fatalf("the domain question was asked about %v/%v, not %v/%v", p, ch, c.parent, c.child)
				}
				return c.domain
			})
			if got != c.want {
				t.Fatalf("crossesLeafMount = %v, want %v", got, c.want)
			}
			if asked != c.asked {
				t.Fatalf("the mount table was consulted = %v, want %v", asked, c.asked)
			}
		})
	}
}

// TestEmptyExpectedStateIsNoClaim is the engine half of Astra r2 #1 in its
// second costume.
//
// The route sends the state the worker OBSERVED, so "" means "nothing was
// learned then" and not "this object has no ACL". Comparing it literally against
// a fresh reading was safe only while the two readings could not differ for an
// innocent reason — and the asynchronous mount probe makes them differ: a mount
// that was unplaced when Props described the object can have a real backend by
// the time the chmod arrives, and nothing about the object moved. A non-empty
// expectation is still held to exactly, in both directions.
func TestEmptyExpectedStateIsNoClaim(t *testing.T) {
	cases := []struct {
		name      string
		want, got string
		satisfied bool
	}{
		{"nothing observed, and nothing read now", "", "", true},
		{
			// The regression this closes: the backend became readable between
			// the two round trips.
			"nothing observed, a backend that has since been placed", "", "posix", true,
		},
		{"nothing observed, and a real ACL read now", "", "nfs4", true},
		{"an observation that still holds", "nfs4-trivial", "nfs4-trivial", true},
		{
			// More serious than what was described: the attack the precondition
			// exists for.
			"an observation that became more serious", "nfs4-trivial", "nfs4", false,
		},
		{
			// Less serious is still a tree that moved under a decision the user
			// made about something else.
			"an observation that became less serious", "nfs4", "none", false,
		},
		{"an observation that can no longer be read at all", "posix", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stateSatisfies(c.want, c.got); got != c.satisfied {
				t.Fatalf("stateSatisfies(%q, %q) = %v, want %v", c.want, c.got, got, c.satisfied)
			}
		})
	}
}

// TestExpectationProvesTheStateWhereThereIsNoInode is Astra r2 #6: off Linux a
// FileInfo carries no inode, so both the grade and the held leaf report the
// platform's own zero identity — and SameInode, quite correctly, reads a zero
// inode as identifying nothing. Every dev-loop chmod with a precondition
// therefore failed "changed", against §14, which asks the dev loop to answer
// best effort.
//
// Where the platform has no identities at all, a zero on both sides is nothing
// to compare and the STATE is proved alone. The Linux half of the rule — a zero
// inode from a real filesystem stays a mismatch — is pinned next door.
func TestExpectationProvesTheStateWhereThereIsNoInode(t *testing.T) {
	if inodeIdentity {
		t.Skip("this platform has inode numbers; the Linux half of the rule is in mode_astra2_linux_test.go")
	}
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)
	ctx := context.Background()

	graded, err := Props(ctx, r, nil, "/f.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	if graded.Identity.Ino != 0 {
		t.Fatalf("Identity.Ino = %d: this platform does carry inodes and this test measures nothing", graded.Identity.Ino)
	}
	if graded.ACL.State != "" {
		t.Fatalf("ACL.State = %q: this platform reads attributes and this half of the test measures nothing",
			graded.ACL.State)
	}
	expect := &wproto.ACLExpect{State: graded.ACL.State, Identity: graded.Identity}
	if _, err := Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, expect); err != nil {
		t.Fatalf("a chmod with an unidentifiable precondition was refused: %v", err)
	}

	// A non-empty state is still held to exactly, which is what keeps the
	// tolerance above from becoming a way to assert nothing and be believed: the
	// file has no ACL to read here, so an expectation that names one is a grade
	// nobody gave.
	stale := &wproto.ACLExpect{State: "nfs4", Identity: graded.Identity}
	if _, err := Chmod(ctx, r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0640}, stale); err == nil {
		t.Fatal("a chmod against a state nobody graded went through")
	}
}
