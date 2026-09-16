package fsops

// lgetxattr(2) for the ACL badge, and its descriptor-bound counterpart.
//
// A LISTING reads the attribute through a pathname, and the reason is stated in
// aclstate.go: there is no fgetxattrat, and opening every entry of a directory
// to read an attribute would ask for read permission the user may not have.
//
// A caller that already HOLDS the object reads it through /proc/self/fd/N of
// that O_PATH descriptor instead — the same idiom chmodViaProc and chownViaProc
// use, and for the same reason: the magic link jumps to the dentry the
// descriptor refers to, so no directory is consulted and nothing can be
// substituted at the name. That route uses the FOLLOWING getxattr(2), because
// the one thing being followed is /proc's own magic link; it is never taken for
// a symlink leaf, where following it once more would read the TARGET's
// attribute (aclTarget.link).

import (
	"os"
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
	return getxattrCall(syscall.SYS_LGETXATTR, path, name, dest)
}

// getxattr is getxattr(2), which DOES follow a final symlink. Its only caller is
// the held-descriptor route, where the final component is /proc/self/fd/N and
// following it is the whole point.
func getxattr(path, name string, dest []byte) (int, error) {
	return getxattrCall(syscall.SYS_GETXATTR, path, name, dest)
}

func getxattrCall(trap uintptr, path, name string, dest []byte) (int, error) {
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
	r, _, errno := syscall.Syscall6(trap,
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

// xattrSize asks how big the attribute is on this target, and reports whether
// the answer came from the held DESCRIPTOR.
//
// viaFD false with a held descriptor means the /proc route was not available —
// a container without /proc, or a symlink leaf, which is deliberately never
// asked that way — and the caller downgrades a reassuring answer accordingly
// (aclTarget.grade).
func (t aclTarget) xattrSize(name string) (size int, viaFD bool, err error) {
	if t.held != nil && !t.link && !noProcFD {
		n, perr := onProcFD(t.held, func(p string) (int, error) { return getxattr(p, name, nil) })
		if !procUnavailable(perr) {
			return n, true, perr
		}
	}
	n, perr := lgetxattr(t.osPath, name, nil)
	return n, false, perr
}

// xattrRead reads the attribute, by the same two routes and in the same order.
//
// The size came from a separate call, so the attribute may have grown in
// between; the buffer is generous enough for the ordinary case and an ERANGE is
// reported as a read failure, which classifies as fsx.ACLUnknown — the
// pessimistic answer, which is the right one here.
func (t aclTarget) xattrRead(name string, size int) (buf []byte, viaFD bool, err error) {
	if size <= 0 {
		return nil, false, nil
	}
	b := make([]byte, size)
	if t.held != nil && !t.link && !noProcFD {
		n, perr := onProcFD(t.held, func(p string) (int, error) { return getxattr(p, name, b) })
		if !procUnavailable(perr) {
			if perr != nil {
				return nil, true, perr
			}
			return b[:clampLen(n, len(b))], true, nil
		}
	}
	n, perr := lgetxattr(t.osPath, name, b)
	if perr != nil {
		return nil, false, perr
	}
	return b[:clampLen(n, len(b))], false, nil
}

// onProcFD runs one pathname syscall against the /proc name of a held
// descriptor. The name is only valid inside the callback, which is why the
// syscall is made there rather than the path handed back.
func onProcFD(f *os.File, fn func(procPath string) (int, error)) (int, error) {
	var (
		n    int
		serr error
	)
	if cerr := onFD(f, func(fd int) error {
		n, serr = fn("/proc/self/fd/" + fdString(fd))
		return nil
	}); cerr != nil {
		return 0, cerr
	}
	return n, serr
}

// clampLen keeps a kernel-reported length inside the buffer that was offered.
func clampLen(n, max int) int {
	if n < 0 {
		return 0
	}
	if n > max {
		return max
	}
	return n
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
