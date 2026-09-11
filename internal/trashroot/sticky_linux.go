package trashroot

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// stickyEnforced is true where the sticky bit is real. On Linux — the only
// platform this app runs on for real — a trash directory without it would let
// any user rename any other user's deleted files, so its absence is an error
// rather than a detail.
const stickyEnforced = true

// openDirNoFollow opens a directory by pathname without following a symlink at
// its FINAL component (F3).
//
// The intermediate components are the kernel's own resolution of a path that
// came out of /proc/self/mountinfo — a mount point, not anything a user chose —
// but the last component is the one an attacker could have replaced, and
// O_NOFOLLOW is what refuses it. O_DIRECTORY refuses anything that is not a
// directory in may_open(2), before the fifo machinery could park this process
// inside open(2); O_CLOEXEC keeps the descriptor out of anything the daemon
// execs.
func openDirNoFollow(p string) (*os.File, error) {
	fd, err := sysOpen(p, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}

// openDirIn opens a subdirectory of an already-open directory with openat,
// under the same flags and for the same reasons.
func openDirIn(dir *os.File, name string) (*os.File, error) {
	rc, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fd   int
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			fd, serr = syscall.Openat(int(pfd), name,
				syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: serr}
	}
	return os.NewFile(uintptr(fd), dir.Name()+"/"+name), nil
}

// mkdirIn is mkdirat(2) relative to an already-open directory, so the new
// directory lands inside the object that descriptor refers to and nowhere else.
func mkdirIn(dir *os.File, name string, mode uint32) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = syscall.Mkdirat(int(pfd), name, mode)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "mkdirat", Path: name, Err: serr}
	}
	return nil
}

// applyMode sets the mode through the DESCRIPTOR — os.File.Chmod is fchmod(2) on
// Linux — so it cannot land on something that replaced the name after the mkdir
// (F3). The sticky bit is carried across: os.syscallMode maps os.ModeSticky to
// S_ISVTX.
func applyMode(f *os.File, _ string, mode fs.FileMode) error { return f.Chmod(mode) }

// ownerOf pulls the uid out of the stat structure behind a FileInfo.
func ownerOf(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return int(st.Uid), true
}

// There was an nlinkOf here, and B3's provenance check asked it for "exactly
// two links, therefore empty". R3-BA1 retired it: nlink == 2 is equally true of
// a directory holding nothing but regular files, so emptiness is now READ
// through the descriptor instead (trashroot.provenance).

// atRemoveDir is AT_REMOVEDIR, the unlinkat flag that removes a directory
// rather than a file. It is stable across Linux architectures.
const atRemoveDir = 0x200

// oPath is O_PATH: an open that asks the kernel for nothing but whether the
// name resolves. It is the existence check the no-replace rename falls back to.
const oPath = 0x200000

// renameNoReplace is RENAME_NOREPLACE, the renameat2(2) flag that makes the
// kernel refuse a rename onto an existing name instead of silently replacing it.
const renameNoReplace = 0x1

// removeDirIn is rmdir relative to an already-open directory (B3 step f): the
// unpublished temporary directory goes away again through the same descriptor it
// was created under, so a failure leaves no litter and no pathname is re-walked.
func removeDirIn(dir *os.File, name string) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = rawUnlinkat(int(pfd), name, atRemoveDir)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "unlinkat", Path: name, Err: serr}
	}
	return nil
}

// renameNoReplaceIn publishes the prepared directory under its final name, both
// ends relative to the one held mount-root descriptor (B3 step e).
//
// RENAME_NOREPLACE is what makes the publication a decision the KERNEL makes:
// the name is either free, in which case this process owns it, or occupied, in
// which case EEXIST sends the caller back to validate whatever is there by the
// ordinary rules. A plain rename would have replaced it — which, at this name,
// means detaching a trash directory full of other people's deleted files.
//
// Where renameat2 or the flag is unavailable (an old kernel, a filesystem that
// does not implement it) the fallback is an fstatat pre-check against that same
// held descriptor rather than a fresh walk of the pathname, with the narrow
// TOCTOU PLAN.md §2.4 already accepts for the same reason.
func renameNoReplaceIn(dir *os.File, from, to string) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		fd := int(pfd)
		for {
			serr = renameat2(fd, from, fd, to, renameNoReplace)
			if serr != syscall.EINTR {
				break
			}
		}
		if !errors.Is(serr, syscall.ENOSYS) && !errors.Is(serr, syscall.EINVAL) {
			return
		}
		var exists bool
		if exists, serr = existsIn(fd, to); serr != nil {
			return
		}
		if exists {
			serr = syscall.EEXIST
			return
		}
		for {
			serr = syscall.Renameat(fd, from, fd, to)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "renameat", Path: to, Err: serr}
	}
	return nil
}

// existsIn reports whether name resolves inside the directory fd refers to. The
// open is O_PATH|O_NOFOLLOW, so a symlink standing at the name is an existing
// entry rather than something followed — the same answer renameat2 would give.
func existsIn(fd int, name string) (bool, error) {
	nfd, err := syscall.Openat(fd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		syscall.Close(nfd)
		return true, nil
	}
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return false, err
}

// renameat2 is renameat2(2), which the syscall package does not export. The
// unsafe shape is the one the vet rules sanction for a syscall call (a Pointer
// converted to uintptr in the argument list); both names are kept alive across
// the call rather than trusted to escape analysis.
func renameat2(fromFD int, fromName string, toFD int, toName string, flags uint) error {
	if sysRenameat2 == 0 {
		// The syscall number is not compiled in for this architecture; behave as
		// an old kernel would and let the caller take the pre-check fallback.
		return syscall.ENOSYS
	}
	fromPtr, err := syscall.BytePtrFromString(fromName)
	if err != nil {
		return err
	}
	toPtr, err := syscall.BytePtrFromString(toName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(sysRenameat2,
		uintptr(fromFD), uintptr(unsafe.Pointer(fromPtr)),
		uintptr(toFD), uintptr(unsafe.Pointer(toPtr)), uintptr(flags), 0)
	runtime.KeepAlive(fromPtr)
	runtime.KeepAlive(toPtr)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawUnlinkat is unlinkat(2), including the flags word the exported
// syscall.Unlinkat drops — AT_REMOVEDIR is the one flag that separates deleting
// a file from removing a directory.
func rawUnlinkat(dirfd int, name string, flags int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
	runtime.KeepAlive(p)
	if errno != 0 {
		return errno
	}
	return nil
}

// sysOpen is open(2), retried over EINTR.
func sysOpen(p string, flags int) (int, error) {
	for {
		fd, err := syscall.Open(p, flags, 0)
		if err != syscall.EINTR {
			return fd, err
		}
	}
}
