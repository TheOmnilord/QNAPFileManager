package fsops

import (
	"os"
	"syscall"
)

// openReadFlags is what OpenRead passes to open(2).
//
// O_NOFOLLOW makes the kernel refuse a symlink as the final component with
// ELOOP instead of following it, so the descriptor handed up to the root
// front-end is always the file the guard classified, not something a symlink
// swapped in after the check.
//
// O_NONBLOCK is what keeps a fifo from taking a worker hostage: opening one
// for reading with no writer blocks inside open(2) itself, before the
// regular-file check can reject it, and nothing above can interrupt a blocked
// syscall. With the flag the open returns immediately and fstat gets its turn.
// It has no effect on a regular file, which is the only kind that survives
// that check.
func openReadFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }

// clearNonblock puts a descriptor opened with O_NONBLOCK back into blocking
// mode, so the streaming read above behaves like every other file read. It is
// called only after fstat has proved the file is regular; a regular file is
// never registered with the runtime's poller, so changing the flag underneath
// os.File is safe here in a way it would not be for a fifo or a socket.
//
// The flag is changed through SyscallConn rather than File.Fd, which would
// detach the file from the runtime poller as a side effect.
func clearNonblock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return serr
}
