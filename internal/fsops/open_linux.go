package fsops

import (
	"os"
	"syscall"
)

// openReadFlags is what OpenRead passes to open(2).
//
// O_NOFOLLOW asks the kernel to refuse a symlink as the final component with
// ELOOP instead of following it. It is defence in depth rather than the rule
// itself: os.Root puts the flag on every openat it makes and then follows the
// link anyway when it stays inside the root, so OpenRead enforces the no-follow
// with an lstat and an os.SameFile check on the descriptor it gets back.
//
// O_NONBLOCK is what keeps a fifo from taking a worker hostage: opening one
// for reading with no writer blocks inside open(2) itself, and nothing above
// can interrupt a blocked syscall. With the flag the open returns immediately
// and fstat gets its turn. It has no effect on a regular file, which is the
// only kind that survives that check.
func openReadFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }

// openDirFlags is what List passes to open(2) for the directory it enumerates.
//
// O_DIRECTORY makes the kernel refuse anything that is not a directory, and it
// refuses it in may_open(2) — before the fifo machinery runs. That is what
// stops "list /path/to/a/fifo" from parking a worker goroutine inside open(2)
// with no writer on the other end, where no deadline in this process can reach
// it; sixty-four such requests would otherwise take every slot the worker has.
func openDirFlags() int { return os.O_RDONLY | syscall.O_DIRECTORY }

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
