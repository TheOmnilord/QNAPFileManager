package trashroot

import (
	"io/fs"
	"os"
	"syscall"
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

// sysOpen is open(2), retried over EINTR.
func sysOpen(p string, flags int) (int, error) {
	for {
		fd, err := syscall.Open(p, flags, 0)
		if err != syscall.EINTR {
			return fd, err
		}
	}
}
