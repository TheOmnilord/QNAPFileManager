// Package perm is the mode arithmetic of the permissions feature (M3 contract
// §1): how a requested change is expressed, what it does to a current mode,
// what the kernel did differently, and what a session may plausibly ask for.
//
// It touches no filesystem and makes no syscall. That is deliberate and it is
// what makes it the one part of M3 that is fully testable on the dev box: every
// decision here is arithmetic over numbers the kernel already reported, so a
// Windows box can exercise all of it without simulating a single permission
// check (INV-2 — the kernel decides, this only predicts and explains).
//
// It is imported by internal/wproto (the wire), internal/fsops (the engine) and
// internal/web (the routes), and imports none of them; it depends on internal/fsx
// for the entry shape and the mode rendering, which keeps one spelling of
// "drwxr-sr-x" in the app rather than two.
package perm

import (
	"encoding/binary"
	"io/fs"
	"strconv"
	"strings"

	"qnapfilemanager/internal/fsx"
)

// ModeSpec is a mode change expressed as a mask and a value, never as an
// absolute mode (contract §1.1).
//
// The reason is that three different requests are one operation once it is
// spelled this way. A mixed selection whose current modes differ — #dlgPerms
// renders indeterminate checkboxes — applies only the bits the user touched. A
// recursive apply changes bits of entries whose current modes the front end has
// never seen. And the three special-bit checkboxes are ordinary bits of the same
// mask instead of three flags with three code paths. An absolute set is simply
// Mask 07777.
//
// A zero Mask is the identity, and that is load bearing too: "apply to files
// only" is a job whose Dirs.Mask is 0, and "folders only" its mirror (§1.2).
type ModeSpec struct {
	Mask  uint32 `json:"m"`
	Value uint32 `json:"v"`
}

// ModeBits is everything chmod(2) can set: the nine permission bits plus
// setuid, setgid and sticky. Nothing outside it is ever read from a spec.
const ModeBits uint32 = 0o7777

// SpecialBits are setuid, setgid and sticky.
const SpecialBits uint32 = 0o7000

// Individual special bits, in the positions chmod states them.
const (
	Setuid uint32 = 0o4000
	Setgid uint32 = 0o2000
	Sticky uint32 = 0o1000
)

// Apply computes the mode this spec produces from a current one:
// (cur &^ Mask) | (Value & Mask), with both sides confined to ModeBits so a
// caller that hands in a full st_mode (with the S_IFMT type field in it) cannot
// smuggle a file type through a chmod.
func (s ModeSpec) Apply(cur uint32) uint32 {
	mask := s.Mask & ModeBits
	return (cur&ModeBits)&^mask | (s.Value & mask)
}

// Touches reports whether this spec changes anything at all. A zero mask is the
// "files only / folders only" case and is not an error — it is the absence of a
// request.
func (s ModeSpec) Touches() bool { return s.Mask&ModeBits != 0 }

// SetsSpecial reports whether this spec SETS setuid, setgid or sticky — a
// masked bit whose value is 1. Clearing one (masked, value 0) is not setting it.
//
// It exists for one rule (§1.3): a recursive chmod may clear a special bit but
// never set one. Setting setuid across a tree is the most effective way to make
// a NAS exploitable and no legitimate workflow needs it in a single call, while
// clearing them recursively is the cleanup that does get needed.
func (s ModeSpec) SetsSpecial() bool {
	return s.Mask&s.Value&SpecialBits != 0
}

// Octal renders a mode the way chmod states it, four digits with a leading zero
// ("0755", "2755").
func Octal(mode uint32) string {
	s := strconv.FormatUint(uint64(mode&ModeBits), 8)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// Bits reduces an fs.FileMode to the 07777 chmod sees: the permission bits plus
// setuid, setgid and sticky in their Unix positions. It is the portable half of
// what fsops's syscallMode does on Linux, and it is here so that the arithmetic
// and its tests run on every OS.
func Bits(m fs.FileMode) uint32 {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= Setuid
	}
	if m&fs.ModeSetgid != 0 {
		v |= Setgid
	}
	if m&fs.ModeSticky != 0 {
		v |= Sticky
	}
	return v
}

// FileMode is Bits' inverse: the fs.FileMode flags for a 07777 mode, with the
// directory bit added when dir says so. It is what Symbolic renders.
func FileMode(mode uint32, dir bool) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&Setuid != 0 {
		m |= fs.ModeSetuid
	}
	if mode&Setgid != 0 {
		m |= fs.ModeSetgid
	}
	if mode&Sticky != 0 {
		m |= fs.ModeSticky
	}
	if dir {
		m |= fs.ModeDir
	}
	return m
}

// EntryMode reads an entry's mode back off the wire. fsx.Entry carries it as
// the octal string the API publishes, so this is the one place that parse
// happens; an unparsable value is 0, which makes a diff report the difference
// rather than inventing agreement.
func EntryMode(e fsx.Entry) uint32 {
	v, err := strconv.ParseUint(e.Mode, 8, 32)
	if err != nil {
		return 0
	}
	return uint32(v) & ModeBits
}

// Symbolic renders a mode the way ls -l does, e.g. "drwxr-sr-x". It delegates to
// fsx.ModeString so there is exactly one such rendering in the app: the listing
// and the permissions dialog can never disagree about what 2755 looks like.
func Symbolic(mode uint32, dir bool) string {
	return fsx.ModeString(FileMode(mode, dir))
}

// Diff is one thing the caller asked for that the kernel did not do (contract
// §3). Field is "mode", "setuid", "setgid", "sticky", "uid" or "gid"; Want and
// Got are display strings — an octal mode, "on"/"off", or a decimal id.
//
// It is a 200 with warnings and never an error: the call SUCCEEDED, and what is
// being reported is that the result is not what was asked for. A call the kernel
// REFUSED is the kernel's error and surfaces unchanged.
type Diff struct {
	Field string `json:"field"`
	Want  string `json:"want"`
	Got   string `json:"got"`
}

// Diff field names.
const (
	FieldMode   = "mode"
	FieldSetuid = "setuid"
	FieldSetgid = "setgid"
	FieldSticky = "sticky"
	FieldUID    = "uid"
	FieldGID    = "gid"
)

// DiffOf compares what was asked against what the same inode became.
//
// before and after must be two stats of ONE descriptor, taken either side of the
// call — that is the worker's job and the whole reason the diff is computed
// there (§3.1): re-stating by name would describe whatever answers to that name
// now, which is the class of bug the descriptor discipline exists to close, and
// here it would be a lie shown to the user rather than a mere nuisance.
//
// want is the mode change that was requested (a zero mask for a pure chown, in
// which case the expected mode is simply the one before). wantUID and wantGID
// are the requested ids with -1 meaning "leave this half alone", exactly as
// chown(2) reads them.
//
// The three silent cases identity plan §3.1 names all fall out of this without
// being special-cased: a non-member's setgid silently dropped, a chown clearing
// setuid (and setgid on a group-executable file), and a ZFS aclmode=groupmask
// chmod landing on different bits than asked.
func DiffOf(want ModeSpec, wantUID, wantGID int, before, after fsx.Entry) []Diff {
	var out []Diff

	cur := EntryMode(before)
	got := EntryMode(after)
	wantMode := want.Apply(cur)
	// The whole-mode field is reported only when a mode change was actually
	// ASKED for. A chown asks for none — its spec is empty, so wantMode is just
	// the mode that was already there — and when the kernel clears setuid as it
	// always does, saying "mode is 0755, not the 4755 that was asked for" claims
	// a request nobody made. The setuid/setgid/sticky fields below still report
	// it, which is the true sentence: the kernel took the bit away (round-2
	// review, P3).
	if want.Mask&ModeBits != 0 && wantMode != got {
		out = append(out, Diff{Field: FieldMode, Want: Octal(wantMode), Got: Octal(got)})
	}
	for _, b := range []struct {
		field string
		bit   uint32
	}{
		{FieldSetuid, Setuid},
		{FieldSetgid, Setgid},
		{FieldSticky, Sticky},
	} {
		if wantMode&b.bit != got&b.bit {
			out = append(out, Diff{Field: b.field, Want: onOff(wantMode&b.bit != 0), Got: onOff(got&b.bit != 0)})
		}
	}
	if wantUID >= 0 && after.UID != wantUID {
		out = append(out, Diff{Field: FieldUID, Want: strconv.Itoa(wantUID), Got: strconv.Itoa(after.UID)})
	}
	if wantGID >= 0 && after.GID != wantGID {
		out = append(out, Diff{Field: FieldGID, Want: strconv.Itoa(wantGID), Got: strconv.Itoa(after.GID)})
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// Caps are the capability HINTS a session has over one entry (contract §5).
//
// They are hints and nothing enforces them. An ACL, a read-only mount or an
// immutable attribute can grant or refuse where this uid arithmetic says
// otherwise, so the rwx grid stays editable, Apply stays enabled and the kernel
// decides (PLAN decision 12, superseding ui-ux §3.3). What they are for is
// explaining a refusal before it happens, not preventing the attempt.
//
// ChgrpTo nil means "no constraint this function can state": for root that is
// "any group", and for a non-owner it is "none that will work" — the Reason
// says which, and the front end renders it.
type Caps struct {
	Chmod    bool   `json:"chmod"`
	ChownUID bool   `json:"chownUid"`
	ChgrpTo  []int  `json:"chgrpTo,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// CapsFor computes the hints for a session over one entry.
//
// Chmod is root or the owner; ChownUID is root alone; ChgrpTo is nil for root
// ("any"), the session's own group set for the owner, and nil for anybody else.
//
// Reason is the sentence ui-ux §3.3 shows when the session is not the owner. It
// names the owner and states the rule, and it deliberately stops short of the
// "You are signed in as <name>" clause of the example: the session's display
// NAME is not one of this function's arguments (the wire carries numbers only,
// §5.4), so the front end — which does hold it — appends that half. Everything
// this function can honestly say, it says.
func CapsFor(uid int, groups []int, root bool, e fsx.Entry) Caps {
	owner := uid == e.UID
	c := Caps{Chmod: root || owner, ChownUID: root}
	switch {
	case root:
		// nil ChgrpTo: any group at all.
	case owner:
		c.ChgrpTo = append([]int(nil), groups...)
	}
	if !c.Chmod {
		c.Reason = "Owned by " + ownerName(e) + ". Only the owner or an administrator can change permissions."
	}
	return c
}

// ownerName spells an entry's owner the way the dialog does: the name when the
// id resolved, and always the number, because the number is what the wire
// carries and what the audit records (§5.4).
func ownerName(e fsx.Entry) string {
	if e.User != "" {
		return e.User + " (uid " + strconv.Itoa(e.UID) + ")"
	}
	return "uid " + strconv.Itoa(e.UID)
}

// ---- the NFSv4 ACL judgement (contract §6.1) --------------------------------

// NFSv4 ACE flags. Only the two inheritance bits matter here: an entry that is
// passed down to new children describes more than the mode ever could.
const (
	nfs4FileInherit = 0x00000001
	nfs4DirInherit  = 0x00000002
	nfs4ACEHeader   = 16
)

// NFSv4 ACE types. ALLOW is the only one a mode can also express; DENY, AUDIT
// and ALARM say things the nine permission bits have no vocabulary for at all —
// "everyone@ may not delete this", "log every open" — so an ACL carrying one is
// never what the mode already describes.
const (
	nfs4TypeAllow = 0x00000000
)

// The NFSv4 access-mask bits, in the numbering RFC 8881 gives them. They are
// spelled out one by one rather than as a single blob because the question
// asked of them below is per bit: which of these does an rwx triple have a
// word for (Astra r2 #3).
const (
	nfs4ReadData       = 0x00000001
	nfs4WriteData      = 0x00000002
	nfs4AppendData     = 0x00000004
	nfs4ReadNamedAttrs = 0x00000008
	nfs4WriteNamedAttr = 0x00000010
	nfs4Execute        = 0x00000020
	nfs4DeleteChild    = 0x00000040
	nfs4ReadAttributes = 0x00000080
	nfs4WriteAttribute = 0x00000100
	nfs4Delete         = 0x00010000
	nfs4ReadACL        = 0x00020000
	nfs4WriteACL       = 0x00040000
	nfs4WriteOwner     = 0x00080000
	nfs4Synchronize    = 0x00100000
)

// The three halves of the REPRESENTABLE set: the bits an rwx triple actually
// spells (§6.1 as amended in round 2).
//
// "r" on a ZFS object is not READ_DATA alone — it is READ_DATA together with
// the attribute and ACL reads and SYNCHRONIZE, which every ordinary object
// carries and which no chmod ever varies — so those travel with it. "w" is the
// matching write set. Everything outside the three is something the mode has no
// vocabulary for: DELETE and DELETE_CHILD above all, which is where the round-1
// rule was still wrong.
const (
	nfs4ReadBits  = nfs4ReadData | nfs4ReadNamedAttrs | nfs4ReadAttributes | nfs4ReadACL | nfs4Synchronize
	nfs4WriteBits = nfs4WriteData | nfs4AppendData | nfs4WriteNamedAttr | nfs4WriteAttribute
	// nfs4OwnerBits are the two a mode cannot express and that OWNER@ holds on
	// every ordinary ZFS object anyway: the right to rewrite the ACL and the
	// right to take ownership. Refusing them on OWNER@ would badge the whole
	// NAS, which is the failure §6.1 exists to avoid; granting them to GROUP@ or
	// EVERYONE@ is a delegation no rwx triple can state.
	nfs4OwnerBits = nfs4WriteACL | nfs4WriteOwner
)

// The three special principals an NFSv4 ACL uses for what the mode describes.
var nfs4TrivialWho = map[string]bool{"OWNER@": true, "GROUP@": true, "EVERYONE@": true}

// nfs4Owner is the one special principal for which the two mask bits above are
// ordinary.
const nfs4Owner = "OWNER@"

// NFS4State classifies a system.nfs4_acl attribute as fsx.ACLNFS4Trivial,
// fsx.ACLNFS4 or fsx.ACLUnknown.
//
// "Is there an ACL" is the wrong question on ZFS: every object on a dataset
// carries one, so presence would badge the entire NAS. The question that means
// something is whether the ACL says anything the MODE does not — which is what
// ls -V calls trivial, and which is our heuristic and not the kernel's (§6.1).
//
// Four things are such a thing, and an ACE showing any of them makes the whole
// attribute non-trivial:
//
//   - An ACE that is not ALLOW. A DENY, an AUDIT or an ALARM entry states
//     something no rwx triple can: "everyone@ DENY DELETE" is a protection the
//     mode cannot hold, and a discard chmod destroys it without a word.
//   - A who other than OWNER@, GROUP@ or EVERYONE@ — a named user or group.
//   - FILE_INHERIT or DIRECTORY_INHERIT: an entry passed down to new children
//     describes more than any mode ever could.
//   - A mask outside the REPRESENTABLE set — the bits an rwx triple can spell,
//     plus WRITE_ACL and WRITE_OWNER on OWNER@ alone. DELETE, DELETE_CHILD and
//     an append-only grant are the ones that arrive in life, and none of them
//     survives a chmod that regenerates the three mode classes (M3 Astra
//     round 1 finding 3, narrowed to mode-equivalence in round 2 #3).
//
// The attribute is a big-endian ACE count followed by that many entries of type,
// flag, access mask, who-length and the who string padded up to four bytes. A
// truncated or otherwise unparsable attribute is "unknown", never "none": the
// badge then shows with the pessimistic text, which is the half that matters
// (residual 4). An ACL with no entries at all is NOT trivial — the mode always
// describes three classes and an empty list describes none of them — so it
// classifies as a real ACL and warns.
func NFS4State(acl []byte) string {
	if len(acl) < 4 {
		return fsx.ACLUnknown
	}
	count := binary.BigEndian.Uint32(acl[:4])
	if count == 0 {
		return fsx.ACLNFS4
	}
	off := 4
	trivial := true
	for i := uint32(0); i < count; i++ {
		if off+nfs4ACEHeader > len(acl) {
			return fsx.ACLUnknown
		}
		aceType := binary.BigEndian.Uint32(acl[off : off+4])
		flag := binary.BigEndian.Uint32(acl[off+4 : off+8])
		mask := binary.BigEndian.Uint32(acl[off+8 : off+12])
		whoLen := int(binary.BigEndian.Uint32(acl[off+12 : off+16]))
		off += nfs4ACEHeader
		if whoLen < 0 || off+whoLen > len(acl) {
			return fsx.ACLUnknown
		}
		// The trailing NUL an encoder may or may not count in the XDR length is
		// trimmed before the lookup. Getting this wrong is not a near miss: the
		// three special principals would stop matching, every object on a hero
		// dataset would badge as a real ACL, and every hero chmod would be
		// promoted to a typed-phrase confirmation for nothing (round-4 review).
		who := strings.TrimRight(string(acl[off:off+whoLen]), "\x00")
		off += whoLen
		if pad := whoLen % 4; pad != 0 {
			off += 4 - pad
			if off > len(acl) {
				// The LAST who, unpadded. Padding that is simply not there is not
				// truncation: nothing is missing that this needs to read, and
				// calling it unknown would badge the whole NAS for an encoder's
				// choice. Padding missing in the MIDDLE is a different thing, and
				// the next ACE's header check below still catches it.
				off = len(acl)
			}
		}
		if !trivialACE(aceType, flag, mask, who) {
			// Judged rather than returned at once, because a later ACE may still
			// be truncated — and "unknown" is the more pessimistic answer of the
			// two, so an attribute this cannot finish reading must not be
			// downgraded to a confident "nfs4".
			trivial = false
		}
	}
	if off != len(acl) {
		// The ACEs the count promised were all read, and bytes are left over (or,
		// after the final-who tolerance above, the attribute ended somewhere this
		// did not expect). Either way this is not the structure it claims to be,
		// and an attribute this cannot account for in full is one it may not
		// pronounce trivial — the same direction every other failure here takes
		// (round-5 review).
		return fsx.ACLUnknown
	}
	if trivial {
		return fsx.ACLNFS4Trivial
	}
	return fsx.ACLNFS4
}

// trivialACE reports whether one ACE says nothing the mode does not already
// say. Every clause is the same question asked of a different field, and all
// four have to answer yes for the ACE to be trivial; the caller makes a single
// non-trivial ACE decide the whole attribute.
func trivialACE(aceType, flag, mask uint32, who string) bool {
	if aceType != nfs4TypeAllow {
		// DENY, AUDIT, ALARM. A mode grants; it has no way to deny, and no way
		// to ask for a log line.
		return false
	}
	if flag&(nfs4FileInherit|nfs4DirInherit) != 0 {
		return false
	}
	if !nfs4TrivialWho[who] {
		return false
	}
	return representableMask(mask, who == nfs4Owner)
}

// representableMask reports whether an ALLOW mask for a special principal says
// only what an rwx triple says (Astra r2 #3).
//
// Excluding the two administrative bits was not the same question, and that is
// what round 1 got wrong: EVERYONE@ ALLOW DELETE carries neither of them and is
// still a grant no mode can hold, so a chmod on an aclmode=discard dataset threw
// it away with nothing to confirm. The rule asked here is the whole of it —
// every bit set has to be one the three mode classes can express — so a bit
// nobody has thought about yet is non-trivial by default, which is the direction
// this file's every other failure takes.
//
// owner widens the set by WRITE_ACL and WRITE_OWNER, which OWNER@ holds on every
// ordinary ZFS object.
func representableMask(mask uint32, owner bool) bool {
	allowed := uint32(nfs4ReadBits | nfs4WriteBits | nfs4Execute)
	if owner {
		allowed |= nfs4OwnerBits
	}
	if mask&^allowed != 0 {
		// DELETE, DELETE_CHILD, the administrative bits on a principal that may
		// not hold them, and anything the standard adds later.
		return false
	}
	if mask&nfs4WriteData == 0 != (mask&nfs4AppendData == 0) {
		// An APPEND_DATA grant without WRITE_DATA is an append-only file — a
		// log somebody may add to and may not rewrite — and "w" cannot say that;
		// a chmod would either hand over the whole write or take it all away.
		// WRITE_DATA without APPEND_DATA is the mirror image and just as
		// unsayable.
		return false
	}
	return true
}
