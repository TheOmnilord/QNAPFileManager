package fsops

// lgetxattr(2) for the ACL badge. It is the one read in M3 that goes through a
// PATHNAME rather than a descriptor, and the reason is stated in aclstate.go:
// there is no fgetxattrat, and opening every entry of a directory to read an
// attribute would ask for read permission the user may not have.

import (
	"runtime"
	"syscall"
	"unsafe"
)

// xattrProbeAvailable says this platform can read an extended attribute at all.
const xattrProbeAvailable = true

// lgetxattr is lgetxattr(2), which the syscall package does not export. It does
// not follow a final symlink, so a link is described by its own attributes
// rather than its target's — the same rule every other classification in this
// package follows. A nil buffer asks for the size, which is how every xattr read
// starts.
//
// The unsafe shape is the one the vet rules sanction for a syscall call (a
// Pointer converted to uintptr inside the argument list), and both the name and
// the buffer are kept alive across it.
func lgetxattr(path, name string, dest []byte) (int, error) {
	pp, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	np, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	var buf unsafe.Pointer
	if len(dest) > 0 {
		buf = unsafe.Pointer(&dest[0])
	}
	r, _, errno := syscall.Syscall6(syscall.SYS_LGETXATTR,
		uintptr(unsafe.Pointer(pp)), uintptr(unsafe.Pointer(np)),
		uintptr(buf), uintptr(len(dest)), 0, 0)
	runtime.KeepAlive(pp)
	runtime.KeepAlive(np)
	runtime.KeepAlive(dest)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// lgetxattrSize asks how big the attribute is, which is the whole answer for a
// POSIX ACL and the buffer size for an NFSv4 one.
func lgetxattrSize(path, name string) (int, error) {
	return lgetxattr(path, name, nil)
}

// lgetxattrRead reads the attribute. The size came from a separate call, so the
// attribute may have grown in between; the buffer is generous enough for the
// ordinary case and an ERANGE is reported as a read failure, which classifies as
// fsx.ACLUnknown — the pessimistic answer, which is the right one here.
func lgetxattrRead(path, name string, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := lgetxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	return buf[:n], nil
}

// absentXattrErr reports "there is no such attribute here", as opposed to a read
// that failed. It is acl_linux.go's absentXattr under the name the portable half
// calls it by, so there is one list of those errnos rather than two.
func absentXattrErr(err error) bool {
	if err == nil {
		return false
	}
	return absentXattr(err)
}
