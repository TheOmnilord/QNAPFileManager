package fsops

// The one piece of an object's identity that a recycled inode number cannot
// forge: when it was created (M2-C review round 14 adversarial, finding 3).
//
// Device and inode identify an object perfectly while it exists, and not at all
// across a gap: the number is freed when the object is unlinked and the kernel
// is free to hand it straight back. That matters here because the gaps in M2-C
// are CLIENT-CONTROLLED. The front-end takes a directory's identity and the
// worker opens it when the upload's body headers arrive; the archive records a
// root's identity and reaches it minutes later while earlier members stream. In
// both, somebody who can create and remove entries in the parent can sit in a
// loop removing and recreating a directory of the same name until the allocator
// gives back the number that was recorded — and the identity check then agrees
// about an object that is not the one that was authorized.
//
// STATX_BTIME is the answer, and it is free: statx is already how the mount id
// is read. Birth time is set once when an inode is created and there is no
// interface for changing it — no utimensat, no ioctl — so a recycled number
// carries a different one.
//
// Not every filesystem records it. ext4 does (it has had a crtime since the
// 256-byte inode), and so do XFS, btrfs and ZFS; a filesystem without one
// simply reports the field as absent, and the comparison degrades to device and
// inode, which is exactly what it was before this existed. That is the honest
// answer for a bound this app cannot enforce on a filesystem that does not keep
// the fact.

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// statxBtime is STATX_BTIME, the request mask bit (and the reply mask bit) for
// the creation time. It is stable across Linux architectures.
const statxBtime = 0x800

// statxNoBtime records that statx(2) ITSELF is not there — a kernel before
// 4.11, which answers the syscall with ENOSYS. It is deliberately its own flag
// and not statxNoMntID (M2-C review round 15).
//
// The two facts are different and the kernels that separate them are the ones
// this app runs on. STATX_MNT_ID arrived in 5.8; STATX_BTIME has been there
// since statx itself in 4.11. On everything in between — which is a great many
// QTS kernels — statxMountID reports "no mount id" as ENOSYS, mountIDOf caches
// that, and birth time is perfectly available all the same. Keying this on that
// flag switched the inode-reuse protection off on exactly the older ext4
// systems that most need it, because FSIdentity asks for the mount id first.
//
// A missing MASK BIT is never cached at all: it is a property of the
// filesystem, not of the kernel, and one worker sees several — ext4 with a
// birth time and a tmpfs without one, in the same session.
var statxNoBtime atomic.Bool

// birthTimeOf reads an open descriptor's creation time in unix nanoseconds.
//
// ok is false for a kernel without statx, an architecture whose syscall number
// is not compiled in here, and — the ordinary case this is written for — a
// filesystem that does not record the fact. None of the three is an error: the
// caller compares what it has.
func birthTimeOf(fd int) (int64, bool) {
	if sysStatx == 0 || statxNoBtime.Load() {
		return 0, false
	}
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return 0, false
	}
	var stx statxData
	_, _, errno := syscall.Syscall6(sysStatx,
		uintptr(fd), uintptr(unsafe.Pointer(empty)),
		uintptr(atEmptyPath|atSymlinkNoFollow), uintptr(statxBtime),
		uintptr(unsafe.Pointer(&stx)), 0)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(&stx)

	btime, ok, disable := btimeFromStatx(errno, &stx)
	if disable {
		statxNoBtime.Store(true)
	}
	return btime, ok
}

// btimeFromStatx is the decision birthTimeOf makes about one statx result, on
// its own so that the combinations it has to get right can be stated as a table
// rather than as three kernels nobody has.
//
// disable is true for one case only: statx itself is not implemented. Every
// other failure is about this call or this filesystem and must not switch the
// feature off process-wide — least of all the reply that says "no birth time in
// the mask", which is what a tmpfs says while the ext4 volume beside it answers
// perfectly.
func btimeFromStatx(errno syscall.Errno, stx *statxData) (btime int64, ok, disable bool) {
	if errno == syscall.ENOSYS {
		return 0, false, true
	}
	if errno != 0 || stx.Mask&statxBtime == 0 {
		return 0, false, false
	}
	// Seconds and nanoseconds, combined the way a Go time would be, without
	// going through time.Time: this is a number to compare, not a date to show.
	return stx.Btime.Sec*1e9 + int64(stx.Btime.Nsec), true, false
}
