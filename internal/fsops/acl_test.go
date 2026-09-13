package fsops

import "testing"

// TestWhatAStagingDirectoryPassesDownMustComeFromTheDestination is round 17's
// finding, tested where the judgement lives.
//
// The attack it answers needs no privileges and passes every other proof: an
// empty directory owned by this worker, mode 0700, in the expected group,
// carrying a DEFAULT ACL (or an inheritable NFSv4 ACE) of the attacker's, slid
// over the staging directory's name. The staging directory itself looks
// private — a default ACL grants nobody access to the directory it sits on —
// and then every object built inside it inherits the planted entries and keeps
// them through the rename that publishes it.
func TestWhatAStagingDirectoryPassesDownMustComeFromTheDestination(t *testing.T) {
	const (
		fileInherit = 0x01
		dirInherit  = 0x02
		inheritOnly = 0x08
		read        = 0x00000001 | 0x00000020
		write       = 0x00000002
	)
	fromParent := nfs4ACE{flag: dirInherit, mask: read, who: "4000"}
	planted := nfs4ACE{flag: dirInherit, mask: read, who: "mallory@localhost"}
	// One destination's inheritable list, for the ordering cases.
	allowA := nfs4ACE{flag: dirInherit, mask: read, who: "4000"}
	denyB := nfs4ACE{aceType: 1, flag: dirInherit, mask: write, who: "mallory@localhost"}
	allowC := nfs4ACE{flag: dirInherit, mask: read | write, who: "4001"}

	for _, tc := range []struct {
		name   string
		child  aclFacts
		parent aclFacts
		want   bool
	}{
		{name: "no ACLs anywhere", want: true},
		{
			name:   "the same default ACL",
			child:  aclFacts{defaultACL: []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255}},
			parent: aclFacts{defaultACL: []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255}},
			want:   true,
		},
		{
			name:   "a default ACL the destination does not have",
			child:  aclFacts{defaultACL: []byte{2, 0, 0, 0, 2, 0, 5, 0, 42, 0, 0, 0}},
			parent: aclFacts{},
			want:   false,
		},
		{
			name:   "a default ACL that differs from the destination's",
			child:  aclFacts{defaultACL: []byte{2, 0, 0, 0, 2, 0, 7, 0, 42, 0, 0, 0}},
			parent: aclFacts{defaultACL: []byte{2, 0, 0, 0, 2, 0, 5, 0, 42, 0, 0, 0}},
			want:   false,
		},
		{
			name:   "the destination's own default ACL is missing from the child",
			child:  aclFacts{},
			parent: aclFacts{defaultACL: []byte{2, 0, 0, 0, 2, 0, 5, 0, 42, 0, 0, 0}},
			want:   false,
		},
		{
			name:   "an inheritable entry the destination has",
			child:  aclFacts{inheritable: []nfs4ACE{fromParent}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   true,
		},
		{
			name:   "a planted inheritable entry",
			child:  aclFacts{inheritable: []nfs4ACE{fromParent, planted}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   false,
		},
		{
			name:   "an inheritable entry that grants more than the destination's",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit, mask: read | write, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   false,
		},
		{
			// ZFS's aclinherit modes strip bits on the way down; an entry that
			// grants less than the destination already grants is not one
			// anybody smuggled in.
			name:   "an inheritable entry narrowed on the way down",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit, mask: 0x00000001, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   true,
		},
		{
			// INHERIT_ONLY means "not about this directory": on an ALLOW that
			// hands out less than the destination does, which no attacker
			// gains anything by.
			name:   "an ALLOW that arrives inherit-only",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | inheritOnly, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   true,
		},
		{
			// On a DENY it is the other way round: the directory itself would
			// stop being denied, which is access the destination refused.
			name:   "a DENY that arrives inherit-only",
			child:  aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit | inheritOnly, mask: write, who: "mallory@localhost"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: write, who: "mallory@localhost"}}},
			want:   false,
		},
		{
			name:   "a DENY where the destination has an ALLOW",
			child:  aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   false,
		},
		{
			name:   "a group entry where the destination has a user entry",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | 0x40, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   false,
		},
		{
			name:   "the INHERITED marker on the child's copy",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | 0x80, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   true,
		},

		// An ACL is read entry by entry until one answers, so what it grants is
		// not the set of its entries. These four are the same list with one
		// thing moved or weakened, and every one of them grants MORE than the
		// destination does.
		{
			name: "a dropped DENY",
			child: aclFacts{inheritable: []nfs4ACE{
				{aceType: 1, flag: dirInherit, mask: write, who: "mallory@localhost"},
			}},
			parent: aclFacts{inheritable: []nfs4ACE{
				{aceType: 1, flag: dirInherit, mask: write, who: "mallory@localhost"},
				{aceType: 1, flag: dirInherit, mask: read, who: "mallory@localhost"},
			}},
			want: false,
		},
		{
			name: "an ALLOW moved in front of a DENY",
			child: aclFacts{inheritable: []nfs4ACE{
				{flag: dirInherit, mask: read, who: "4000"},
				{aceType: 1, flag: dirInherit, mask: read, who: "mallory@localhost"},
			}},
			parent: aclFacts{inheritable: []nfs4ACE{
				{aceType: 1, flag: dirInherit, mask: read, who: "mallory@localhost"},
				{flag: dirInherit, mask: read, who: "4000"},
			}},
			want: false,
		},
		{
			name:   "a DENY that denies less",
			child:  aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: read, who: "mallory@localhost"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: read | write, who: "mallory@localhost"}}},
			want:   false,
		},
		{
			name:   "a DENY that denies more",
			child:  aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: read | write, who: "mallory@localhost"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{aceType: 1, flag: dirInherit, mask: read, who: "mallory@localhost"}}},
			want:   true,
		},
		{
			name:   "an extra entry the destination does not have",
			child:  aclFacts{inheritable: []nfs4ACE{fromParent, planted}},
			parent: aclFacts{inheritable: []nfs4ACE{fromParent}},
			want:   false,
		},
		{
			name:   "an AUDIT entry that differs at all",
			child:  aclFacts{inheritable: []nfs4ACE{{aceType: 2, flag: dirInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{aceType: 2, flag: dirInherit, mask: read | write, who: "4000"}}},
			want:   false,
		},

		// What the kernel gives a new DIRECTORY is not a copy of the parent's
		// flags (RFC 7530 §6.2.1.4.1): an entry about files below is carried
		// down as INHERIT_ONLY, because it says nothing about this directory.
		{
			name:   "a file-inherit entry becomes inherit-only",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: fileInherit | inheritOnly, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: fileInherit, mask: read, who: "4000"}}},
			want:   true,
		},
		{
			name:   "a file-inherit entry carried down unchanged",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: fileInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: fileInherit, mask: read, who: "4000"}}},
			want:   false,
		},
		{
			name:   "file and directory inherit are carried as they stand",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: fileInherit | dirInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: fileInherit | dirInherit, mask: read, who: "4000"}}},
			want:   true,
		},
		{
			name:   "a planted entry whose flags look right",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: fileInherit | inheritOnly, mask: read, who: "mallory@localhost"}}},
			parent: aclFacts{},
			want:   false,
		},
		{
			// A no-propagate entry reaches the child and stops, so the child
			// has nothing inheritable at all. (Such a destination is refused
			// for staging before this, but the two answers agree.)
			name:   "a no-propagate entry appears in no child",
			child:  aclFacts{},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | 0x04, mask: read, who: "4000"}}},
			want:   true,
		},

		// ZFS's aclinherit modes do not only narrow masks: `noallow` omits the
		// ALLOW entries outright and `discard` inherits nothing at all. A
		// directory created at the destination directly would come out the same
		// way, so neither is something staging changed.
		{
			name:   "nothing inherited at all",
			child:  aclFacts{},
			parent: aclFacts{inheritable: []nfs4ACE{allowA, denyB, allowC}},
			want:   true,
		},
		{
			name:   "the ALLOW entries omitted",
			child:  aclFacts{inheritable: []nfs4ACE{denyB}},
			parent: aclFacts{inheritable: []nfs4ACE{allowA, denyB, allowC}},
			want:   true,
		},
		{
			name:   "the same entries in another order",
			child:  aclFacts{inheritable: []nfs4ACE{allowC, denyB}},
			parent: aclFacts{inheritable: []nfs4ACE{allowA, denyB, allowC}},
			want:   false,
		},
		{
			name:   "the DENY between them dropped",
			child:  aclFacts{inheritable: []nfs4ACE{allowA, allowC}},
			parent: aclFacts{inheritable: []nfs4ACE{allowA, denyB, allowC}},
			want:   false,
		},
		{
			name:   "an entry the destination never had",
			child:  aclFacts{inheritable: []nfs4ACE{denyB, {flag: dirInherit, mask: read, who: "mallory@localhost"}}},
			parent: aclFacts{inheritable: []nfs4ACE{allowA, denyB, allowC}},
			want:   false,
		},

		// A DIRECTORY_INHERIT entry applies to the directory it reaches, so the
		// copy is not inherit-only any more — and a policy that leaves the flag
		// set says the same thing.
		{
			name:   "an inherit-only directory entry arrives applying",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | inheritOnly, mask: read, who: "4000"}}},
			want:   true,
		},
		{
			name:   "an inherit-only directory entry that kept its flag",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | inheritOnly, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: dirInherit | inheritOnly, mask: read, who: "4000"}}},
			want:   true,
		},
		{
			name:   "a file-inherit entry may not arrive applying",
			child:  aclFacts{inheritable: []nfs4ACE{{flag: fileInherit, mask: read, who: "4000"}}},
			parent: aclFacts{inheritable: []nfs4ACE{{flag: fileInherit | inheritOnly, mask: read, who: "4000"}}},
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inheritedFrom(tc.child, tc.parent); got != tc.want {
				t.Fatalf("inheritedFrom = %v, want %v", got, tc.want)
			}
		})
	}
}
