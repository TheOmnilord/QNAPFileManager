package fsops

// Reading an extended attribute to answer one question: can anybody but this
// worker CHANGE what is in this directory?
//
// It exists for the private staging directory (stagingIn). Mode 0700 means
// "only the owner" only when no ACL says otherwise: an entry granting somebody
// else access is access the mode bits do not describe, a chown does not strip
// it, and a directory prepared that way passes every stat check this engine
// makes.
//
// What matters is WRITE, and only write. The staging directory exists so that
// nothing can be substituted for the object being built in it, and substituting
// means creating, renaming or removing an entry — so an ACE that grants a group
// read, list or execute is harmless here: whoever holds it can see that a
// staged name exists and can read a half-made object whose final permissions
// they would have been given anyway by the directory this is inside of. It buys
// them nothing they do not already have, and refusing it would refuse every
// share whose dataset hands new directories an inherited read ACE — which is
// most of them on QuTS hero. An ACE that grants ADD_FILE, ADD_SUBDIRECTORY,
// DELETE_CHILD, DELETE, WRITE_ACL or WRITE_OWNER is the whole attack: it is
// permission to put something else where this job is about to look.
//
// DENY ordering is not evaluated. A DENY can only take access away, so ignoring
// it can never make this answer too permissive; a write-capable ALLOW refuses
// even where an earlier DENY would have cancelled it, which fails closed on
// exactly the half that matters.
//
// There is a second question here, and it is about INHERITANCE rather than
// access: does everything this directory passes down reach a grandchild
// unchanged? An NFSv4 ACE flagged NO_PROPAGATE_INHERIT reaches a child and
// stops, so a directory built inside a staging directory and renamed out would
// carry a different ACL from one created at the destination directly — an
// inherit-only DENY of read for one user, say, would simply be missing from the
// published folder, because a rename recomputes no ACL. A destination that says
// that is one this job does not stage in at all. POSIX default ACLs are the
// easy case: they propagate to every generation, so they disqualify nothing.

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"qnapfilemanager/internal/platform"
)

// fgetxattr is fgetxattr(2), which the syscall package does not export. A nil
// buffer asks for the size, which is how every xattr read starts. The unsafe
// shape is the sanctioned one — the pointer is converted inside the call's
// argument list — and both the name and the buffer are kept alive across it.
func fgetxattr(fd int, name string, dest []byte) (int, error) {
	np, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	var (
		r     uintptr
		errno syscall.Errno
	)
	if len(dest) == 0 {
		r, _, errno = syscall.Syscall6(syscall.SYS_FGETXATTR,
			uintptr(fd), uintptr(unsafe.Pointer(np)), 0, 0, 0, 0)
	} else {
		r, _, errno = syscall.Syscall6(syscall.SYS_FGETXATTR,
			uintptr(fd), uintptr(unsafe.Pointer(np)), uintptr(unsafe.Pointer(&dest[0])), uintptr(len(dest)), 0, 0)
	}
	runtime.KeepAlive(np)
	runtime.KeepAlive(dest)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// aclXattrNames are the attributes an ACL can live in on the filesystems this
// app writes to. They are asked in this order and any of them answering with
// data is an ACL to judge.
var aclXattrNames = []string{platform.XattrPosixACL, platform.XattrNFS4ACL, platform.XattrRichACL, xattrPosixDefaultACL}

// xattrPosixDefaultACL holds what a POSIX-ACL directory passes down. The
// platform package probes only the access attribute, because that is what says
// which ACL backend a mount has; this one is read for a different question —
// what a directory this job creates will INHERIT — and it exists only on
// directories.
const xattrPosixDefaultACL = "system.posix_acl_default"

// aclFactsFor reads a directory's ACLs once and answers both questions this
// engine asks of them.
//
// An error is a question that could not be asked at all, which the callers
// treat as the unfavourable answer to both.
//
// The read goes through a readable descriptor opened from the held O_PATH
// handle (fgetxattr on an O_PATH fd is EBADF), so it asks about that inode and
// never about a name.
func aclFactsFor(d *dirRef) (aclFacts, error) {
	var facts aclFacts
	f, err := enumerable(d)
	if err != nil {
		return aclFacts{otherWriter: true, noPropagate: true}, err
	}
	defer f.Close()
	fd := int(f.Fd())
	for _, name := range aclXattrNames {
		size, gerr := fgetxattr(fd, name, nil)
		if gerr != nil {
			if absentXattr(gerr) {
				continue
			}
			return aclFacts{otherWriter: true, noPropagate: true}, gerr
		}
		if size == 0 {
			continue
		}
		buf := make([]byte, size)
		n, gerr := fgetxattr(fd, name, buf)
		if gerr != nil {
			if absentXattr(gerr) {
				continue
			}
			return aclFacts{otherWriter: true, noPropagate: true}, gerr
		}
		one := aclFactsOfXattr(name, buf[:n])
		facts.otherWriter = facts.otherWriter || one.otherWriter
		facts.noPropagate = facts.noPropagate || one.noPropagate
		if one.defaultACL != nil {
			facts.defaultACL = one.defaultACL
		}
		facts.inheritable = append(facts.inheritable, one.inheritable...)
	}
	return facts, nil
}

// absentXattr reports the errnos that mean "there is no such attribute here",
// as opposed to a read that failed. ENODATA is "no ACL"; EOPNOTSUPP (ENOTSUP)
// is a filesystem that has no such attribute at all; ENOSYS is a kernel
// without xattrs.
func absentXattr(err error) bool {
	return errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS)
}

// aclFactsOfXattr judges one ACL attribute.
func aclFactsOfXattr(name string, b []byte) aclFacts {
	switch name {
	case platform.XattrPosixACL:
		// POSIX default ACLs propagate all the way down: a directory created
		// inside another inherits the same default ACL and passes it on
		// unchanged, so an intermediate directory consumes nothing.
		return aclFacts{otherWriter: !posixNoOtherWriter(b)}
	case platform.XattrNFS4ACL:
		return aclFacts{
			otherWriter: !nfs4NoOtherWriter(b),
			noPropagate: nfs4NoPropagate(b),
			inheritable: nfs4Inheritable(b),
		}
	case xattrPosixDefaultACL:
		// What this directory passes down, kept as the kernel wrote it. It
		// grants nobody anything HERE — it is a template for children — so it
		// says nothing about who may write this directory, and POSIX defaults
		// propagate to every generation, so it disqualifies no staging either.
		return aclFacts{defaultACL: append([]byte(nil), b...)}
	default:
		// system.richacl, or anything else that turns up: not a format this
		// reads, so not one it may call harmless — and richacl has inheritance
		// flags of its own that this cannot see either.
		return aclFacts{otherWriter: true, noPropagate: true}
	}
}

// POSIX ACL entry tags and permission bits, from <sys/acl.h>. The owner's own
// entry says nothing about anybody else; every other class — the owning group,
// a named user, a named group, the mask, and everybody — is somebody else, and
// only their WRITE bit matters here.
const (
	posixACLVersion  = 2
	posixACLUserObj  = 0x01
	posixACLUser     = 0x02
	posixACLGroupObj = 0x04
	posixACLGroup    = 0x08
	posixACLMask     = 0x10
	posixACLOther    = 0x20
	posixACLWrite    = 0x02
	posixACLEntryLen = 8
)

// posixNoOtherWriter parses system.posix_acl_access: a 4-byte little-endian
// version followed by 8-byte entries of tag (2), permissions (2) and id (4).
//
// A conservatism worth naming: a named entry's write bit is refused even when
// the MASK would cancel it, which on a 0700 directory it always does. Working
// out the effective permission means evaluating the mask exactly as the kernel
// does, and this engine does not reproduce the kernel's decisions (INV-2); it
// fails closed on write instead, which costs a staging directory and never data.
func posixNoOtherWriter(b []byte) bool {
	if len(b) < 4 || (len(b)-4)%posixACLEntryLen != 0 {
		return false
	}
	if binary.LittleEndian.Uint32(b[:4]) != posixACLVersion {
		return false
	}
	self := uint32(os.Geteuid())
	for off := 4; off < len(b); off += posixACLEntryLen {
		tag := binary.LittleEndian.Uint16(b[off : off+2])
		perm := binary.LittleEndian.Uint16(b[off+2 : off+4])
		id := binary.LittleEndian.Uint32(b[off+4 : off+8])
		switch tag {
		case posixACLUserObj:
			// The owner, which is this worker (createdByUs proved it).
			continue
		case posixACLUser:
			if id == self {
				continue
			}
		case posixACLGroupObj, posixACLGroup, posixACLMask, posixACLOther:
		default:
			// A tag this does not know is one it may not wave through.
			return false
		}
		if perm&posixACLWrite != 0 {
			return false
		}
	}
	return true
}

// NFSv4 ACE types and the access-mask bits that amount to "may change what is
// in this directory", from <linux/nfs4.h>.
const (
	nfs4TypeAllow      = 0
	nfs4AddFile        = 0x00000002 // WRITE_DATA / ADD_FILE
	nfs4AddSubdir      = 0x00000004 // APPEND_DATA / ADD_SUBDIRECTORY
	nfs4DeleteChild    = 0x00000040
	nfs4Delete         = 0x00010000
	nfs4WriteACL       = 0x00040000
	nfs4WriteOwner     = 0x00080000
	nfs4WriteMask      = nfs4AddFile | nfs4AddSubdir | nfs4DeleteChild | nfs4Delete | nfs4WriteACL | nfs4WriteOwner
	nfs4ACEHeaderBytes = 16

	// ACE flags. NO_PROPAGATE_INHERIT is the one that makes a directory a bad
	// place to build in: what it passes down stops at one generation, so an
	// entry created inside it and renamed out would lose it (aclFacts).
	// IDENTIFIER_GROUP says the who names a GROUP, which is never the owner
	// however the number reads.
	nfs4FileInherit        = 0x00000001
	nfs4DirInherit         = 0x00000002
	nfs4NoPropagateInherit = 0x00000004
	nfs4IdentifierGroup    = 0x00000040
	// INHERITED_ACE says an entry arrived by inheritance rather than having
	// been set here. It is a statement about provenance, not a permission, and
	// it is cleared before a parent's entry and a child's copy are compared.
	nfs4InheritedACE = 0x00000080
)

// nfs4NoOtherWriter parses system.nfs4_acl: a big-endian count followed by that
// many ACEs of type, flag, access mask, who-length and the who string padded to
// four bytes.
//
// ZFS gives every object one of these, so "is there an ACL" cannot be the
// question; "does it let anybody else change this directory" is. OWNER@ — and a
// who spelled as this worker's own uid, which is how an unmapped id is written
// — is the owner and grants nothing to anybody else. DENY, AUDIT and ALARM
// entries grant nothing at all, so only ALLOW is judged.
func nfs4NoOtherWriter(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	self := itoaUint(uint32(os.Geteuid()))
	count := binary.BigEndian.Uint32(b[:4])
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+nfs4ACEHeaderBytes > len(b) {
			return false
		}
		aceType := binary.BigEndian.Uint32(b[off : off+4])
		flag := binary.BigEndian.Uint32(b[off+4 : off+8])
		mask := binary.BigEndian.Uint32(b[off+8 : off+12])
		whoLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
		off += nfs4ACEHeaderBytes
		if whoLen < 0 || off+whoLen > len(b) {
			return false
		}
		who := string(b[off : off+whoLen])
		off += whoLen
		if pad := whoLen % 4; pad != 0 {
			off += 4 - pad
		}
		if off > len(b) {
			return false
		}
		if aceType != nfs4TypeAllow || mask&nfs4WriteMask == 0 {
			continue
		}
		// A GROUP is never the owner, whatever its number reads like: gid 0
		// names every member of the root group, and a root worker calling that
		// "itself" would have declared a directory half the system can write
		// into private.
		if flag&nfs4IdentifierGroup != 0 {
			return false
		}
		if who != "OWNER@" && who != self {
			return false
		}
	}
	return true
}

// nfs4Inheritable is every ACE this directory passes down: the ones flagged
// FILE_INHERIT or DIRECTORY_INHERIT, reduced to what decides whether a child's
// copy of one could have come from it. The INHERITED_ACE flag is cleared,
// because the kernel and ZFS set it on the copy to say where it came from and
// it would otherwise make every parent and child disagree.
//
// A malformed attribute yields nothing, which refuses rather than admits: the
// caller requires every inheritable ACE of a staging directory to be found in
// this list.
func nfs4Inheritable(b []byte) []nfs4ACE {
	if len(b) < 4 {
		return nil
	}
	var out []nfs4ACE
	count := binary.BigEndian.Uint32(b[:4])
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+nfs4ACEHeaderBytes > len(b) {
			return out
		}
		ace := nfs4ACE{
			aceType: binary.BigEndian.Uint32(b[off : off+4]),
			flag:    binary.BigEndian.Uint32(b[off+4:off+8]) &^ nfs4InheritedACE,
			mask:    binary.BigEndian.Uint32(b[off+8 : off+12]),
		}
		whoLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
		off += nfs4ACEHeaderBytes
		if whoLen < 0 || off+whoLen > len(b) {
			return out
		}
		ace.who = string(b[off : off+whoLen])
		off += whoLen
		if pad := whoLen % 4; pad != 0 {
			off += 4 - pad
		}
		if off > len(b) {
			return out
		}
		if ace.flag&(nfs4FileInherit|nfs4DirInherit) != 0 {
			out = append(out, ace)
		}
	}
	return out
}

// nfs4NoPropagate reports whether any ACE stops one generation down
// (NO_PROPAGATE_INHERIT). A directory carrying one is no place to build
// something that will be renamed out of it: what it passes to its children is
// not what those children pass on, so an object created inside it and moved to
// where it belongs would carry a different ACL from one created there directly.
// Rename recomputes nothing.
func nfs4NoPropagate(b []byte) bool {
	if len(b) < 4 {
		// Unreadable is unanswerable, and this question fails towards "do not
		// build here".
		return true
	}
	count := binary.BigEndian.Uint32(b[:4])
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+nfs4ACEHeaderBytes > len(b) {
			return true
		}
		flag := binary.BigEndian.Uint32(b[off+4 : off+8])
		whoLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
		off += nfs4ACEHeaderBytes
		if whoLen < 0 || off+whoLen > len(b) {
			return true
		}
		off += whoLen
		if pad := whoLen % 4; pad != 0 {
			off += 4 - pad
		}
		if off > len(b) {
			return true
		}
		if flag&nfs4NoPropagateInherit != 0 {
			return true
		}
	}
	return false
}

// itoaUint spells a uid the way an unmapped NFSv4 who is spelled.
func itoaUint(n uint32) string {
	return fdString(int(n))
}
