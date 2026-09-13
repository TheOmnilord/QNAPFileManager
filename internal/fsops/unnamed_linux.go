package fsops

// Creating something at the destination without ever exposing a half-made
// object under its final name: an unnamed file (O_TMPFILE) published by linkat,
// and directories and symlinks made under an unguessable name and renamed into
// place. Between them they close the "swap what was just created before it is
// opened" class by construction rather than by another check — the checks stay,
// as defence in depth.

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// oTmpfile is O_TMPFILE, which the syscall package does not export: the generic
// __O_TMPFILE (020000000) or'd with this architecture's O_DIRECTORY, exactly as
// asm-generic/fcntl.h defines it. Every architecture this app is built for
// (amd64, arm, arm64) uses the generic value.
const oTmpfile = 0o20000000 | syscall.O_DIRECTORY

// atSymlinkFollow is AT_SYMLINK_FOLLOW, which the syscall package does not
// export either. It tells linkat to link what the path REFERS to, which is what
// makes /proc/self/fd/N name the unnamed inode rather than the magic symlink.
const atSymlinkFollow = 0x400

// atFDCWD is AT_FDCWD, which the syscall package does not export on Linux. The
// value is the same on every architecture the kernel supports.
const atFDCWD = -0x64

// errNoUnnamed says this filesystem cannot make an unnamed file, so the caller
// has to fall back to creating one under a name. It never leaves this package.
var errNoUnnamed = errors.New("fsops: this filesystem has no unnamed files")

// openUnnamed creates a regular file with NO NAME inside a held directory
// (O_TMPFILE), which is what closes the window between a file being created and
// its owner being installed.
//
// The window was real and needed no privileges: root moving alice's 0640 file
// into a setgid `public` directory created it root:public 0640 at its final
// name, and a member of `public` had only to open it before the chown landed —
// a descriptor a later fchown does not revoke — to read whatever was written
// into it afterwards. An inode with no name cannot be opened by anybody: it is
// given its owner, filled, flushed and verified while it is unreachable, and
// only then linked into place (linkUnnamed), by which time it is complete and
// already belongs to the right user.
//
// Not every filesystem has O_TMPFILE (it arrived in 3.11, and some still do not
// implement it), which is what errNoUnnamed reports; the caller then creates the
// file under a name as this engine always did.
func openUnnamed(d *dirRef, mode os.FileMode) (*os.File, error) {
	fd, err := openatPerm(d.f, ".", os.O_WRONLY|oTmpfile|syscall.O_CLOEXEC, syscallMode(mode))
	if err != nil {
		if unsupportedTmpfile(err) {
			return nil, errNoUnnamed
		}
		return nil, &fs.PathError{Op: "openat", Path: d.rel, Err: err}
	}
	return os.NewFile(uintptr(fd), relJoin(d.rel, "(unnamed)")), nil
}

// unsupportedTmpfile reports the errnos that mean "this kernel or this
// filesystem does not do O_TMPFILE", as opposed to a failure worth reporting.
// An old kernel answers EINVAL or EISDIR (it sees a plain O_DIRECTORY opened
// for writing); a filesystem without the operation answers EOPNOTSUPP, which is
// ENOTSUP on Linux.
func unsupportedTmpfile(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EISDIR) ||
		errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EPERM)
}

// linkUnnamed gives an unnamed inode a name inside a held directory, which is
// the atomic publication of a file nobody could see until now.
//
// linkat of /proc/self/fd/N with AT_SYMLINK_FOLLOW is the form the kernel
// documents for an O_TMPFILE inode, and the only one an unprivileged process
// can use (AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH, which a per-user worker
// does not have). It needs /proc mounted — QTS always has it, and this package
// already reads /proc/self/fdinfo for mount identities — and where it is
// missing, unnamedOK finds out with one probe before a single file is written
// that way.
//
// EEXIST means somebody took the name between the placement and now, which is
// the same race the O_EXCL create has always answered with `exists`.
func linkUnnamed(f *os.File, d *dirRef, name string) error {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return err
	}
	src := "/proc/self/fd/" + fdString(int(f.Fd()))
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = linkatIn(atFDCWD, src, int(pfd), name, atSymlinkFollow)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	runtime.KeepAlive(f)
	if serr != nil {
		return &fs.PathError{Op: "linkat", Path: relJoin(d.rel, name), Err: serr}
	}
	return nil
}

// linkatIn is linkat(2), which the syscall package does not export in the form
// this needs. The unsafe shape is the one the vet rules sanction for a syscall
// call, and both names are kept alive across it.
func linkatIn(oldDirFD int, oldPath string, newDirFD int, newName string, flags int) error {
	op, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT,
		uintptr(oldDirFD), uintptr(unsafe.Pointer(op)),
		uintptr(newDirFD), uintptr(unsafe.Pointer(np)),
		uintptr(flags), 0)
	runtime.KeepAlive(op)
	runtime.KeepAlive(np)
	if errno != 0 {
		return errno
	}
	return nil
}

// fdString is strconv.Itoa without the import, for the one number this file
// spells.
func fdString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// stagedCreate says this platform creates directories and symlinks under an
// unguessable temporary name and renames them into place. It is a Linux answer:
// a dirRef here is a DESCRIPTOR, so renaming the object it refers to changes
// nothing about the handle the copy goes on using. Off Linux a dirRef is a
// jail-relative pathname that os.Root resolves every time, and renaming out
// from under it would break every operation that followed.
const stagedCreate = true
