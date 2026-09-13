package fsops

// What a directory's ACLs say, and the one comparison the staging directory
// rests on: everything it will pass DOWN has to have come from the destination
// it was made in.
//
// The judgement is here, away from the syscalls, because it is the part worth
// testing on every platform — and because a planted inheritable entry is the
// last shape of the substitution this engine keeps closing. An attacker who
// cannot write a directory of the right kind, owner, mode and group can still
// try one that carries a DEFAULT ACL of their own: the staging directory itself
// looks private, and every object created inside it quietly inherits their
// entries and keeps them through the rename that publishes it.

import "bytes"

// aclFacts is what one directory's ACLs say about the questions this engine
// asks of them.
type aclFacts struct {
	// otherWriter: somebody other than the owner may create, rename or remove
	// entries here, so this is not a private place to build.
	otherWriter bool
	// noPropagate: something this directory passes down stops one generation
	// later, so an object built INSIDE it and renamed out would not carry what
	// an object created at the far end would have carried. A rename recomputes
	// no ACL, so such a directory is no place to stage anything.
	noPropagate bool
	// defaultACL is the raw system.posix_acl_default, nil where there is none.
	// POSIX inheritance copies it to a child directory exactly, so the bytes
	// are the comparison.
	defaultACL []byte
	// inheritable are the NFSv4 ACEs this directory passes down, with the
	// INHERITED_ACE flag cleared so that a parent's entry and the child's copy
	// of it compare equal.
	inheritable []nfs4ACE
}

// nfs4ACE is one ACE, reduced to what decides whether it may be passed down.
type nfs4ACE struct {
	aceType uint32
	flag    uint32
	mask    uint32
	who     string
}

// NFSv4 ACE types and the flag bits the inheritance rules turn on. They are
// repeated here rather than shared with the Linux parser because this file is
// the judgement and is compiled everywhere.
const (
	aceAllow           = 0
	aceDeny            = 1
	aceFileInherit     = 0x00000001
	aceDirInherit      = 0x00000002
	aceNoPropagate     = 0x00000004
	aceInheritOnly     = 0x00000008
	aceInheritedMarker = 0x00000080
)

// inheritedFrom reports whether everything a freshly created directory will
// pass down came from the directory it was created in.
//
// POSIX: a child directory's default ACL is an exact copy of its parent's, so
// the bytes have to match — including both being absent.
//
// NFSv4 is ORDERED, and that is the whole of round 18's first finding. An ACL
// is evaluated entry by entry until one answers, so what an ACL grants is not
// the set of its entries: a DENY dropped, a DENY narrowed, or an ALLOW moved in
// front of a DENY all grant MORE while every individual entry still looks like
// one the destination has. So the child's inheritable entries are compared with
// the parent's as a sequence, one to one and in order, and any entry missing,
// added or moved refuses.
//
// What each entry is allowed to differ in depends on which way it points:
//
//   - an ALLOW may grant a SUBSET of the parent's, because ZFS's aclinherit
//     modes (restricted, noallow) strip bits on the way down. Less access than
//     the destination already grants is not something anybody smuggled in.
//   - a DENY must deny at least as much: equal, or a superset. A stronger deny
//     only ever takes access away.
//   - anything else (AUDIT, ALARM) has to match exactly. They grant nothing,
//     and a difference there is still a difference this job cannot explain.
//
// The flags are compared against what the kernel would have GIVEN the child,
// not against the parent's own (expectedChildACEs), and the INHERITED_ACE
// marker is cleared on both sides because it records where an entry came from
// rather than what it permits.
func inheritedFrom(child, parent aclFacts) bool {
	if !bytes.Equal(child.defaultACL, parent.defaultACL) {
		return false
	}
	if len(child.inheritable) == 0 {
		// Nothing is passed on at all, which is what `aclinherit=discard`
		// produces: a directory created at the destination directly would come
		// out exactly the same way, so there is nothing here that staging
		// changes.
		//
		// The residual, stated rather than hidden: a planted directory with no
		// inheritable entries is indistinguishable from that policy, and an
		// object built in it would then miss an inheritable DENY the
		// destination meant it to carry. It needs a destination somebody else
		// can write and a race won against the mkdir, and everything else about
		// the directory — creator, emptiness, mode, group, identity — still has
		// to hold.
		return true
	}
	want := expectedChildACEs(parent.inheritable)
	// An ordered SUBSEQUENCE, because a policy may drop entries on the way
	// down but never reorder them: `noallow` omits the ALLOW entries and
	// `restricted` narrows their masks. So an expected ALLOW that the child
	// does not have may be skipped — omitting an ALLOW only removes access —
	// while a missing DENY, an entry out of order, or an entry the destination
	// never had refuses.
	next := 0
	for _, w := range want {
		if next < len(child.inheritable) && passedDown(child.inheritable[next], w) {
			next++
			continue
		}
		if w.aceType == aceAllow {
			continue
		}
		return false
	}
	// Nothing of the child's is left over: an entry the parent cannot account
	// for is one somebody put there.
	return next == len(child.inheritable)
}

// expectedChildACEs is the inheritable part of the ACL a new DIRECTORY created
// inside a directory with these entries should come out with, in order (RFC
// 7530 §6.2.1.4.1).
//
// Two rules do the work. An entry marked NO_PROPAGATE_INHERIT reaches the child
// and stops, so it appears in no child's inheritable set at all — a destination
// carrying one is refused for staging long before this (aclFacts.noPropagate),
// and dropping it here keeps the two answers consistent. An entry that says
// FILE_INHERIT and not DIRECTORY_INHERIT describes files further down and not
// this directory, so the child carries it as INHERIT_ONLY; one that says
// DIRECTORY_INHERIT applies to the child itself and is carried as it stands.
func expectedChildACEs(parent []nfs4ACE) []nfs4ACE {
	out := make([]nfs4ACE, 0, len(parent))
	for _, p := range parent {
		flag := p.flag &^ aceInheritedMarker
		if flag&aceNoPropagate != 0 {
			continue
		}
		if flag&aceDirInherit != 0 {
			// DIRECTORY_INHERIT: the entry applies to this directory now, so
			// the copy it gets is not inherit-only any more, whatever the
			// parent's own entry said. passedDown accepts the flag being
			// retained as well, because some policies leave it set and either
			// spelling grants exactly what the destination said.
			flag &^= aceInheritOnly
		} else {
			// FILE_INHERIT alone: it is about files below, not about this
			// directory.
			flag |= aceInheritOnly
		}
		p.flag = flag
		out = append(out, p)
	}
	return out
}

// passedDown reports whether one inheritable ACE of a child is the one the
// parent would have given it in that position.
func passedDown(got, want nfs4ACE) bool {
	if got.aceType != want.aceType || got.who != want.who {
		return false
	}
	gf := got.flag &^ aceInheritedMarker
	if gf != want.flag {
		// A DIRECTORY_INHERIT entry may reach the child with INHERIT_ONLY
		// cleared — it applies to that directory now — or still set, depending
		// on the policy. The latitude is given to ALLOW entries only, and that
		// is not the same statement for the two kinds: INHERIT_ONLY means "not
		// about this directory", so on an ALLOW it hands out LESS than the
		// destination does, and on a DENY it would hand out MORE by not denying
		// the directory itself. A FILE_INHERIT-only entry has no latitude at
		// all: it MUST arrive inherit-only, because it is not about this
		// directory in the first place.
		if got.aceType != aceAllow || want.flag&aceDirInherit == 0 || gf != want.flag|aceInheritOnly {
			return false
		}
	}
	switch got.aceType {
	case aceAllow:
		// No more than the destination already allows.
		return got.mask&^want.mask == 0
	case aceDeny:
		// No less than the destination already denies.
		return want.mask&^got.mask == 0
	default:
		return got.mask == want.mask
	}
}
