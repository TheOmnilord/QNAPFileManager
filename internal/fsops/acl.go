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
	want := expectedChildACEs(parent.inheritable)
	if len(child.inheritable) != len(want) {
		return false
	}
	for i, got := range child.inheritable {
		if !passedDown(got, want[i]) {
			return false
		}
	}
	return true
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
		if flag&aceDirInherit == 0 {
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
	if got.flag&^aceInheritedMarker != want.flag {
		return false
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
