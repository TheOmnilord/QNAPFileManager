package perm

import (
	"encoding/binary"
	"io/fs"
	"reflect"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// TestModeSpecApply is the whole of contract §1.1 as a table: mask and value,
// never an absolute mode. Every special bit appears, in both directions.
func TestModeSpecApply(t *testing.T) {
	cases := []struct {
		name string
		spec ModeSpec
		cur  uint32
		want uint32
	}{
		{"an absolute set is mask 07777", ModeSpec{Mask: 0o7777, Value: 0o0755}, 0o4777, 0o0755},
		{"an empty mask changes nothing", ModeSpec{}, 0o2755, 0o2755},
		{"an empty mask ignores the value", ModeSpec{Value: 0o777}, 0o0600, 0o0600},
		{"one touched bit leaves the rest", ModeSpec{Mask: 0o020, Value: 0o020}, 0o0644, 0o0664},
		{"clearing one bit leaves the rest", ModeSpec{Mask: 0o007, Value: 0}, 0o0755, 0o0750},
		{"setuid set", ModeSpec{Mask: Setuid, Value: Setuid}, 0o0755, 0o4755},
		{"setuid cleared", ModeSpec{Mask: Setuid, Value: 0}, 0o4755, 0o0755},
		{"setgid set", ModeSpec{Mask: Setgid, Value: Setgid}, 0o0755, 0o2755},
		{"setgid cleared", ModeSpec{Mask: Setgid, Value: 0}, 0o2755, 0o0755},
		{"sticky set", ModeSpec{Mask: Sticky, Value: Sticky}, 0o0777, 0o1777},
		{"sticky cleared", ModeSpec{Mask: Sticky, Value: 0}, 0o1777, 0o0777},
		{"all three cleared at once", ModeSpec{Mask: SpecialBits, Value: 0}, 0o7755, 0o0755},
		{"all three set at once", ModeSpec{Mask: SpecialBits, Value: SpecialBits}, 0o0755, 0o7755},
		{"a file type in cur cannot survive", ModeSpec{Mask: 0o7777, Value: 0o0644}, 0o100644, 0o0644},
		{"a file type in the value cannot get in", ModeSpec{Mask: 0o7777, Value: 0o100644}, 0o0600, 0o0644},
		{"an unmasked value bit is ignored", ModeSpec{Mask: 0o700, Value: 0o777}, 0o0000, 0o0700},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.spec.Apply(c.cur); got != c.want {
				t.Fatalf("Apply(%s) = %s, want %s", Octal(c.cur), Octal(got), Octal(c.want))
			}
		})
	}
}

// TestModeSpecSetsSpecial pins §1.3's exact rule: SETTING a special bit is what
// a recursive job refuses, and CLEARING one is what it exists to allow.
func TestModeSpecSetsSpecial(t *testing.T) {
	cases := []struct {
		name string
		spec ModeSpec
		want bool
	}{
		{"nothing", ModeSpec{}, false},
		{"a plain 0755", ModeSpec{Mask: 0o7777, Value: 0o0755}, false},
		{"setuid set", ModeSpec{Mask: 0o7777, Value: 0o4755}, true},
		{"setgid set", ModeSpec{Mask: 0o7777, Value: 0o2755}, true},
		{"sticky set", ModeSpec{Mask: 0o7777, Value: 0o1777}, true},
		{"clearing all three", ModeSpec{Mask: SpecialBits, Value: 0}, false},
		{"a special value bit that is not masked", ModeSpec{Mask: 0o0777, Value: 0o4755}, false},
		{"setgid masked and cleared while setuid is set but unmasked", ModeSpec{Mask: Setgid, Value: Setuid}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.spec.SetsSpecial(); got != c.want {
				t.Fatalf("SetsSpecial() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestTouchesIsTheFilesOnlyRule: "apply to folders only" is a zero mask on the
// files half and nothing else (§1.2).
func TestTouchesIsTheFilesOnlyRule(t *testing.T) {
	if (ModeSpec{}).Touches() {
		t.Fatal("a zero spec must not touch anything")
	}
	if !(ModeSpec{Mask: Sticky}).Touches() {
		t.Fatal("a masked special bit is a change")
	}
	if (ModeSpec{Value: 0o777}).Touches() {
		t.Fatal("a value with no mask is not a change")
	}
}

// TestSymbolicMatchesOctal checks the ls -l rendering against the octal it came
// from, including the upper-case forms a special bit takes when the matching
// execute bit is clear.
func TestSymbolicMatchesOctal(t *testing.T) {
	cases := []struct {
		mode uint32
		dir  bool
		want string
	}{
		{0o0755, true, "drwxr-xr-x"},
		{0o0644, false, "-rw-r--r--"},
		{0o2755, true, "drwxr-sr-x"},
		{0o4755, false, "-rwsr-xr-x"},
		{0o4644, false, "-rwSr--r--"},
		{0o2644, false, "-rw-r-Sr--"},
		{0o1777, true, "drwxrwxrwt"},
		{0o1666, false, "-rw-rw-rwT"},
		{0o7777, true, "drwsrwsrwt"},
		{0o0000, false, "----------"},
	}
	for _, c := range cases {
		t.Run(Octal(c.mode), func(t *testing.T) {
			if got := Symbolic(c.mode, c.dir); got != c.want {
				t.Fatalf("Symbolic(%s, dir=%v) = %q, want %q", Octal(c.mode), c.dir, got, c.want)
			}
		})
	}
}

// TestBitsRoundTripsFileMode proves the portable mode reduction agrees with
// fsx's own octal rendering, which is what the engine compares against.
func TestBitsRoundTripsFileMode(t *testing.T) {
	for _, mode := range []uint32{0o0000, 0o0644, 0o0755, 0o1777, 0o2755, 0o4755, 0o7777} {
		fm := FileMode(mode, false)
		if got := Bits(fm); got != mode {
			t.Fatalf("Bits(FileMode(%s)) = %s", Octal(mode), Octal(got))
		}
		if got := fsx.ModeOctal(fm); got != Octal(mode) {
			t.Fatalf("fsx.ModeOctal disagrees with perm.Octal for %s: %q", Octal(mode), got)
		}
	}
	if !FileMode(0o755, true).IsDir() {
		t.Fatal("the directory bit was lost")
	}
	if FileMode(0o755, false)&fs.ModeDir != 0 {
		t.Fatal("a directory bit appeared out of nowhere")
	}
}

// entry builds the minimum of an fsx.Entry that DiffOf reads.
func entry(mode uint32, uid, gid int) fsx.Entry {
	return fsx.Entry{Mode: Octal(mode), UID: uid, GID: gid}
}

// TestDiffOfSetgidSilentlyDropped is the first of the three silent cases from
// identity plan §3.1: a non-member asks for 2755 and the kernel stores 0755
// without saying a word. The call SUCCEEDED, so the only way anybody learns is
// the diff.
func TestDiffOfSetgidSilentlyDropped(t *testing.T) {
	spec := ModeSpec{Mask: 0o7777, Value: 0o2755}
	got := DiffOf(spec, -1, -1, entry(0o0755, 1000, 1000), entry(0o0755, 1000, 1000))
	want := []Diff{
		{Field: FieldMode, Want: "2755", Got: "0755"},
		{Field: FieldSetgid, Want: "on", Got: "off"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffOf = %+v, want %+v", got, want)
	}
}

// TestDiffOfSetuidClearedByChown is the second: ownership changed, and the
// kernel cleared setuid as it always does.
//
// The requested spec is EMPTY — a chown asks for no mode at all — so there is no
// whole-mode field in the answer. Emitting one said "mode is 0755, not the 4755
// that was asked for" about a 4755 nobody asked for (round-2 review, P3); the
// setuid field is the true sentence, and it is the only one.
func TestDiffOfSetuidClearedByChown(t *testing.T) {
	got := DiffOf(ModeSpec{}, 1003, -1, entry(0o4755, 0, 0), entry(0o0755, 1003, 0))
	want := []Diff{{Field: FieldSetuid, Want: "on", Got: "off"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffOf = %+v, want %+v", got, want)
	}
}

// TestDiffOfReportsNoModeFieldForAChown is the rule behind the case above,
// stated on its own so it cannot be lost: a spec that asks for nothing can
// disagree with nothing, whatever the mode ends up being.
func TestDiffOfReportsNoModeFieldForAChown(t *testing.T) {
	cases := []struct {
		name          string
		before, after uint32
		wantFields    []string
	}{
		{"setuid cleared", 0o4755, 0o0755, []string{FieldSetuid}},
		{"setgid cleared too, on a group-executable file", 0o6755, 0o0755, []string{FieldSetuid, FieldSetgid}},
		{"nothing changed at all", 0o0644, 0o0644, nil},
		{"a mode that moved for some other reason is still not a mode REQUEST", 0o0644, 0o0600, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DiffOf(ModeSpec{}, 1003, -1, entry(c.before, 0, 0), entry(c.after, 1003, 0))
			fields := make([]string, 0, len(got))
			for _, d := range got {
				if d.Field == FieldMode {
					t.Fatalf("a chown reported a mode field: %+v", got)
				}
				fields = append(fields, d.Field)
			}
			if len(fields) == 0 {
				fields = nil
			}
			if !reflect.DeepEqual(fields, c.wantFields) {
				t.Fatalf("fields = %v, want %v", fields, c.wantFields)
			}
		})
	}
	// And a real chmod still reports it, so the fix narrows nothing else.
	spec := ModeSpec{Mask: 0o7777, Value: 0o2755}
	if d := DiffOf(spec, -1, -1, entry(0o0755, 0, 0), entry(0o0755, 0, 0)); len(d) != 2 || d[0].Field != FieldMode {
		t.Fatalf("a chmod lost its mode field: %+v", d)
	}
}

// TestDiffOfIgnoresAnUnaskedID: gid -1 means "leave it alone", so whatever the
// group ends up as is never a difference.
func TestDiffOfIgnoresAnUnaskedID(t *testing.T) {
	if d := DiffOf(ModeSpec{}, 1003, -1, entry(0o0644, 0, 0), entry(0o0644, 1003, 500)); len(d) != 0 {
		t.Fatalf("DiffOf reported %+v for a gid nobody asked about", d)
	}
}

// TestDiffOfReportsARefusedID: the chown reported success and the uid is not the
// one asked for.
func TestDiffOfReportsARefusedID(t *testing.T) {
	got := DiffOf(ModeSpec{}, 1003, 42, entry(0o0644, 0, 0), entry(0o0644, 0, 0))
	want := []Diff{
		{Field: FieldUID, Want: "1003", Got: "0"},
		{Field: FieldGID, Want: "42", Got: "0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffOf = %+v, want %+v", got, want)
	}
}

// TestDiffOfIsEmptyWhenTheKernelObeyed — the ordinary case, and the one that
// decides whether the UI shows a success toast or a warning one.
func TestDiffOfIsEmptyWhenTheKernelObeyed(t *testing.T) {
	spec := ModeSpec{Mask: 0o7777, Value: 0o0750}
	if d := DiffOf(spec, -1, -1, entry(0o0644, 1000, 1000), entry(0o0750, 1000, 1000)); len(d) != 0 {
		t.Fatalf("DiffOf = %+v, want none", d)
	}
}

// TestDiffOfGroupmask stands in for the third silent case: a ZFS
// aclmode=groupmask chmod landing on different bits than were asked for. It is
// the same arithmetic as the other two, which is the point of having one
// function.
func TestDiffOfGroupmask(t *testing.T) {
	spec := ModeSpec{Mask: 0o7777, Value: 0o0770}
	got := DiffOf(spec, -1, -1, entry(0o0750, 1000, 1000), entry(0o0750, 1000, 1000))
	if len(got) != 1 || got[0].Field != FieldMode || got[0].Want != "0770" || got[0].Got != "0750" {
		t.Fatalf("DiffOf = %+v", got)
	}
}

// TestCapsFor is contract §5.1 for every session shape that matters.
func TestCapsFor(t *testing.T) {
	owned := fsx.Entry{UID: 1003, GID: 100, User: "backup"}
	orphan := fsx.Entry{UID: 65534}

	t.Run("an administrator may do anything", func(t *testing.T) {
		c := CapsFor(0, []int{0}, true, owned)
		if !c.Chmod || !c.ChownUID || c.ChgrpTo != nil || c.Reason != "" {
			t.Fatalf("root caps = %+v", c)
		}
	})
	t.Run("the owner may chmod and chgrp to their own groups", func(t *testing.T) {
		c := CapsFor(1003, []int{100, 101}, false, owned)
		if !c.Chmod || c.ChownUID {
			t.Fatalf("owner caps = %+v", c)
		}
		if !reflect.DeepEqual(c.ChgrpTo, []int{100, 101}) {
			t.Fatalf("owner ChgrpTo = %v", c.ChgrpTo)
		}
		if c.Reason != "" {
			t.Fatalf("the owner needs no explanation, got %q", c.Reason)
		}
	})
	t.Run("a group member who is not the owner may not", func(t *testing.T) {
		c := CapsFor(1005, []int{100}, false, owned)
		if c.Chmod || c.ChownUID || c.ChgrpTo != nil {
			t.Fatalf("non-owner caps = %+v", c)
		}
		if c.Reason == "" {
			t.Fatal("a non-owner needs the sentence explaining the likely refusal")
		}
	})
	t.Run("the reason names the owner and the number", func(t *testing.T) {
		c := CapsFor(1005, nil, false, owned)
		const want = "Owned by backup (uid 1003). Only the owner or an administrator can change permissions."
		if c.Reason != want {
			t.Fatalf("Reason = %q, want %q", c.Reason, want)
		}
	})
	t.Run("an unresolved owner is still named by number", func(t *testing.T) {
		c := CapsFor(1005, nil, false, orphan)
		const want = "Owned by uid 65534. Only the owner or an administrator can change permissions."
		if c.Reason != want {
			t.Fatalf("Reason = %q, want %q", c.Reason, want)
		}
	})
	t.Run("the group set is copied, not aliased", func(t *testing.T) {
		groups := []int{100, 101}
		c := CapsFor(1003, groups, false, owned)
		groups[0] = 999
		if c.ChgrpTo[0] != 100 {
			t.Fatal("CapsFor aliased the caller's slice")
		}
	})
}

// rawACE is one hand-built ACE with every field spelled out: the type, the
// flags, the access mask and the principal. nfs4ACLRaw encodes a list of them.
type rawACE struct {
	typ  uint32
	flag uint32
	mask uint32
	who  string
}

// nfs4ACLRaw builds a system.nfs4_acl attribute: a big-endian count followed by
// ACEs of type, flag, access mask, who-length and the who string padded to four
// bytes. Building them by hand is what lets the trivial judgement be tested on
// a box with no ZFS (contract §15).
func nfs4ACLRaw(aces ...rawACE) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(aces)))
	for _, a := range aces {
		var h [16]byte
		binary.BigEndian.PutUint32(h[0:4], a.typ)
		binary.BigEndian.PutUint32(h[4:8], a.flag)
		binary.BigEndian.PutUint32(h[8:12], a.mask)
		binary.BigEndian.PutUint32(h[12:16], uint32(len(a.who)))
		b = append(b, h[:]...)
		b = append(b, a.who...)
		if pad := len(a.who) % 4; pad != 0 {
			b = append(b, make([]byte, 4-pad)...)
		}
	}
	return b
}

// aceTypeAllow, aceTypeDeny, aceTypeAudit and aceTypeAlarm are the four ACE
// types RFC 8881 defines, in the order it numbers them.
const (
	aceTypeAllow uint32 = 0
	aceTypeDeny  uint32 = 1
	aceTypeAudit uint32 = 2
	aceTypeAlarm uint32 = 3
)

// The two masks the helpers build trivial ACEs out of: everything an rwx triple
// can express and nothing it cannot (§6.1 as amended in round 2).
//
// maskFull is the OWNER@ form — read, write, execute and the two administrative
// bits every ordinary ZFS object grants its owner. maskNoAdmin is the GROUP@ and
// EVERYONE@ form, which drops them.
//
// Neither carries DELETE (0x10000) or DELETE_CHILD (0x40), and that is the
// round-2 correction: the old constants were "every bit in 0x001f01ff", which
// swept both in, so a helper meant to build a trivial ACL was building one the
// mode cannot express at all (Astra r2 #3).
const (
	maskRead      uint32 = 0x00000001 | 0x00000008 | 0x00000080 | 0x00020000 | 0x00100000
	maskWrite     uint32 = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000100
	maskExecute   uint32 = 0x00000020
	maskNoAdmin   uint32 = maskRead | maskWrite | maskExecute
	maskFull      uint32 = maskNoAdmin | 0x00040000 | 0x00080000
	maskReadExec  uint32 = maskRead | maskExecute
	maskDelete    uint32 = 0x00010000
	maskDeleteChl uint32 = 0x00000040
	maskAppend    uint32 = 0x00000004
)

// nfs4ACL is nfs4ACLRaw for the flag-and-who cases: ALLOW entries with a mask
// that grants everything a mode can express and nothing it cannot. The byte
// layout is identical, so the length-sensitive rows below (truncation, padding)
// measure exactly what they did before.
func nfs4ACL(aces ...ace) []byte {
	raw := make([]rawACE, 0, len(aces))
	for _, a := range aces {
		raw = append(raw, rawACE{typ: aceTypeAllow, flag: a.flag, mask: maskNoAdmin, who: a.who})
	}
	return nfs4ACLRaw(raw...)
}

type ace = struct {
	flag uint32
	who  string
}

// unpadLast strips the padding nfs4ACL put after the final who, which is what an
// encoder that pads every who except the last one produces.
func unpadLast(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// TestNFS4State is contract §6.1's heuristic: what the mode already describes is
// trivial, anything else is an ACL worth warning about, and anything unreadable
// is unknown.
func TestNFS4State(t *testing.T) {
	cases := []struct {
		name string
		acl  []byte
		want string
	}{
		{
			// The ordinary ZFS object, and the control for the end-of-loop length
			// check: an attribute whose ACEs account for exactly its bytes is
			// read, not refused.
			"the three mode classes alone, at exactly the declared length, are trivial",
			nfs4ACL(ace{0, "OWNER@"}, ace{0, "GROUP@"}, ace{0, "EVERYONE@"}),
			fsx.ACLNFS4Trivial,
		},
		{
			"a named user is a real ACL",
			nfs4ACL(ace{0, "OWNER@"}, ace{0, "alice@example.com"}, ace{0, "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"an unmapped numeric who is a real ACL",
			nfs4ACL(ace{0, "OWNER@"}, ace{0, "1003"}),
			fsx.ACLNFS4,
		},
		{
			"FILE_INHERIT on a mode class is still a real ACL",
			nfs4ACL(ace{nfs4FileInherit, "OWNER@"}, ace{0, "GROUP@"}),
			fsx.ACLNFS4,
		},
		{
			"DIRECTORY_INHERIT likewise",
			nfs4ACL(ace{nfs4DirInherit, "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"an empty attribute is unknown, never none",
			nil,
			fsx.ACLUnknown,
		},
		{
			"a count with no entries is not what the mode describes",
			[]byte{0, 0, 0, 0},
			fsx.ACLNFS4,
		},
		{
			// An encoder that counts the terminating NUL in the XDR length. If
			// the trim were missing, none of the three special principals would
			// match, every object on a hero dataset would badge as a real ACL,
			// and every hero chmod would be promoted to a typed phrase for
			// nothing (round-4 review).
			"a who whose length counts its terminating NUL is still trivial",
			nfs4ACL(ace{0, "OWNER@\x00"}, ace{0, "GROUP@\x00"}, ace{0, "EVERYONE@\x00"}),
			fsx.ACLNFS4Trivial,
		},
		{
			"a NUL-counted who that names somebody else is still a real ACL",
			nfs4ACL(ace{0, "OWNER@\x00"}, ace{0, "alice@example.com\x00"}),
			fsx.ACLNFS4,
		},
		{
			// An encoder that does not pad the LAST who. Padding that is simply
			// not there is not truncation: nothing this needs to read is missing.
			"an unpadded final who is read rather than called unknown",
			unpadLast(nfs4ACL(ace{0, "OWNER@"}, ace{0, "GROUP@"})),
			fsx.ACLNFS4Trivial,
		},
		{
			"an unpadded final who on a non-trivial ACL still reads as one",
			unpadLast(nfs4ACL(ace{0, "OWNER@"}, ace{nfs4DirInherit, "GROUP@"})),
			fsx.ACLNFS4,
		},
		{
			// The tolerance above must not become a hole: padding missing in the
			// MIDDLE is a genuinely short attribute, and the next ACE's header is
			// what catches it.
			"an unpadded who with another ACE still to come is unknown",
			func() []byte {
				b := unpadLast(nfs4ACL(ace{0, "OWNER@"}))
				binary.BigEndian.PutUint32(b[:4], 2)
				return b
			}(),
			fsx.ACLUnknown,
		},
		{
			// An HONEST count — one ACE, correctly padded — followed by a byte
			// that belongs to nothing. The count rewrite is deliberately absent
			// here: with it, ACE 1 failed its header check and the trailing byte
			// was inert, so the row proved nothing about trailing bytes at all
			// (round-5 review). What makes this unknown is the end-of-loop check
			// that the attribute was accounted for in full.
			"an honest count with a trailing byte after the last ACE is unknown",
			append(nfs4ACL(ace{0, "OWNER@"}), 0x7f),
			fsx.ACLUnknown,
		},
		{
			"and several trailing bytes likewise",
			append(nfs4ACL(ace{0, "OWNER@"}, ace{0, "GROUP@"}), 0, 0, 0, 0),
			fsx.ACLUnknown,
		},
		{
			"a truncated header is unknown",
			nfs4ACL(ace{0, "OWNER@"})[:12],
			fsx.ACLUnknown,
		},
		{
			"a who that runs off the end is unknown",
			append(nfs4ACL(ace{0, "OWNER@"})[:20], 'O', 'W'),
			fsx.ACLUnknown,
		},
		{
			"a count larger than the entries is unknown",
			func() []byte {
				b := nfs4ACL(ace{0, "OWNER@"})
				binary.BigEndian.PutUint32(b[:4], 4)
				return b
			}(),
			fsx.ACLUnknown,
		},
		{
			"a truncated attribute is unknown even when the entries read so far are not trivial",
			func() []byte {
				b := nfs4ACL(ace{0, "alice"}, ace{0, "GROUP@"})
				binary.BigEndian.PutUint32(b[:4], 5)
				return b
			}(),
			fsx.ACLUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NFS4State(c.acl); got != c.want {
				t.Fatalf("NFS4State = %q, want %q", got, c.want)
			}
		})
	}
}

// TestNFS4StateReadsTypeAndMask is finding 3 of the M3 Astra review: the
// heuristic used to look at the who and the inheritance flags alone, so
// "EVERYONE@ DENY DELETE" and "GROUP@ ALLOW WRITE_ACL" were both trivial — and a
// chmod on an aclmode=discard dataset destroyed them with no level-2
// confirmation, because there was nothing to confirm.
//
// Everything here is one ACE among otherwise ordinary mode classes, which is how
// it arrives in life: a ZFS object with its three trivial entries and one more
// that somebody added.
func TestNFS4StateReadsTypeAndMask(t *testing.T) {
	owner := rawACE{typ: aceTypeAllow, mask: maskFull, who: "OWNER@"}
	group := rawACE{typ: aceTypeAllow, mask: maskNoAdmin, who: "GROUP@"}
	every := rawACE{typ: aceTypeAllow, mask: maskNoAdmin, who: "EVERYONE@"}

	const (
		writeACL   uint32 = 0x00040000
		writeOwner uint32 = 0x00080000
		deleteBit  uint32 = 0x00010000
	)

	cases := []struct {
		name string
		acl  []byte
		want string
	}{
		{
			// The control: the three classes as ZFS writes them, OWNER@ with the
			// administrative bits it always has.
			"the three mode classes, owner with WRITE_ACL and WRITE_OWNER, are trivial",
			nfs4ACLRaw(owner, group, every),
			fsx.ACLNFS4Trivial,
		},
		{
			"EVERYONE@ DENY DELETE is a protection the mode cannot hold",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeDeny, mask: deleteBit, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"a DENY of nothing at all is still not an ALLOW",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeDeny, mask: 0, who: "OWNER@"}),
			fsx.ACLNFS4,
		},
		{
			"an AUDIT entry is not something a mode can ask for",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeAudit, mask: maskNoAdmin, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"nor an ALARM entry",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeAlarm, mask: maskNoAdmin, who: "GROUP@"}),
			fsx.ACLNFS4,
		},
		{
			"GROUP@ ALLOW WRITE_ACL delegates what no rwx triple can say",
			nfs4ACLRaw(owner, rawACE{typ: aceTypeAllow, mask: maskNoAdmin | writeACL, who: "GROUP@"}, every),
			fsx.ACLNFS4,
		},
		{
			"EVERYONE@ ALLOW WRITE_OWNER likewise",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeAllow, mask: maskNoAdmin | writeOwner, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			// The narrowness of the rule, pinned: OWNER@ holds both bits on every
			// ordinary ZFS object, so asking about them there would badge the whole
			// NAS — the exact failure §6.1 exists to avoid.
			"OWNER@ with only the administrative bits is still trivial",
			nfs4ACLRaw(rawACE{typ: aceTypeAllow, mask: writeACL | writeOwner, who: "OWNER@"}, group, every),
			fsx.ACLNFS4Trivial,
		},
		{
			"a group that is merely writable is trivial: WRITE_DATA is what 0770 means",
			nfs4ACLRaw(owner, rawACE{typ: aceTypeAllow, mask: maskNoAdmin, who: "GROUP@"}, every),
			fsx.ACLNFS4Trivial,
		},
		// Round 2 #3: excluding the two administrative bits was not
		// mode-equivalence. An ALLOW mask is trivial only if every bit in it is
		// one the three mode classes can express.
		{
			"EVERYONE@ ALLOW DELETE is a grant no rwx triple holds",
			nfs4ACLRaw(owner, group, rawACE{typ: aceTypeAllow, mask: maskNoAdmin | maskDelete, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"GROUP@ with DELETE_CHILD likewise: 'may unlink what is in here' is not a mode bit",
			nfs4ACLRaw(owner, rawACE{typ: aceTypeAllow, mask: maskNoAdmin | maskDeleteChl, who: "GROUP@"}, every),
			fsx.ACLNFS4,
		},
		{
			// An append-only file: add to the log, never rewrite it. A "w" that
			// is granted or taken whole cannot say it.
			"APPEND_DATA without WRITE_DATA is append-only, which a mode cannot express",
			nfs4ACLRaw(owner, group,
				rawACE{typ: aceTypeAllow, mask: maskReadExec | maskAppend, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			"WRITE_DATA without APPEND_DATA is the mirror image and just as unsayable",
			nfs4ACLRaw(owner, group,
				rawACE{typ: aceTypeAllow, mask: maskNoAdmin &^ maskAppend, who: "EVERYONE@"}),
			fsx.ACLNFS4,
		},
		{
			// The control the whole rule is shaped around: 0755 as ZFS writes
			// it. If this ever classified as nfs4, every hero chmod would ask
			// for a typed phrase for nothing.
			"a ZFS-shaped rwx/r-x/r-x triple is trivial",
			nfs4ACLRaw(
				rawACE{typ: aceTypeAllow, mask: maskFull, who: "OWNER@"},
				rawACE{typ: aceTypeAllow, mask: maskReadExec, who: "GROUP@"},
				rawACE{typ: aceTypeAllow, mask: maskReadExec, who: "EVERYONE@"}),
			fsx.ACLNFS4Trivial,
		},
		{
			// The pessimistic direction survives the new clauses: an attribute that
			// cannot be read to the end is unknown whether or not the ACEs read so
			// far were trivial.
			"a DENY inside a truncated attribute is still unknown, not nfs4",
			func() []byte {
				b := nfs4ACLRaw(rawACE{typ: aceTypeDeny, mask: deleteBit, who: "EVERYONE@"})
				binary.BigEndian.PutUint32(b[:4], 3)
				return b
			}(),
			fsx.ACLUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NFS4State(c.acl); got != c.want {
				t.Fatalf("NFS4State = %q, want %q", got, c.want)
			}
		})
	}
}

// TestACLPresentIsTheBadge pins which states light the badge, and in particular
// that a parse failure lights it (pessimistic) while a trivial ZFS ACL — which
// every object on a dataset has — does not.
func TestACLPresentIsTheBadge(t *testing.T) {
	for state, want := range map[string]bool{
		"":                   false,
		fsx.ACLNone:          false,
		fsx.ACLNFS4Trivial:   false,
		fsx.ACLPosix:         true,
		fsx.ACLNFS4:          true,
		fsx.ACLUnknown:       true,
		"something-invented": false,
	} {
		if got := fsx.ACLPresent(state); got != want {
			t.Fatalf("ACLPresent(%q) = %v, want %v", state, got, want)
		}
	}
}

// TestEntryModeParsesWhatTheAPIPublishes: the wire carries the mode as the octal
// string the listing shows, so this is the one parse and it must not invent
// agreement out of a value it cannot read.
func TestEntryModeParsesWhatTheAPIPublishes(t *testing.T) {
	if got := EntryMode(fsx.Entry{Mode: "2755"}); got != 0o2755 {
		t.Fatalf("EntryMode = %s", Octal(got))
	}
	if got := EntryMode(fsx.Entry{Mode: ""}); got != 0 {
		t.Fatalf("an unparsable mode must read as 0, got %s", Octal(got))
	}
	if got := EntryMode(fsx.Entry{Mode: "not a mode"}); got != 0 {
		t.Fatalf("an unparsable mode must read as 0, got %s", Octal(got))
	}
}
