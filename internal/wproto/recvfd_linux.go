package wproto

import (
	"os"
	"syscall"
)

// receivedFile wraps a descriptor that arrived over SCM_RIGHTS.
//
// The non-blocking flag is set *before* os.NewFile, and that ordering is the
// whole of it. NewFile decides once, from the flags the descriptor already
// carries, whether to hand it to the runtime's poller; a descriptor that was
// blocking at that moment is never registered, and SetNonblock afterwards
// cannot change its mind — the file has to be re-created from the descriptor
// to be registered at all.
//
// An unregistered descriptor is one whose read cannot be interrupted. A worker
// may pass back a pipe or a fifo (a /proc file, a named pipe under a share),
// and read(2) on one with no writer parks the goroutine inside the syscall
// where no Close, no HTTP deadline and no call timeout can reach it — in the
// root front-end, holding a descriptor and the request that owns it, for as
// long as the peer likes. Registered, the same read comes back with
// ErrClosed as soon as the file is closed.
//
// Regular files — every download — ignore O_NONBLOCK for reads, and epoll
// refuses to register them, so NewFile puts them straight back on the ordinary
// blocking read path. The flag costs them nothing.
func receivedFile(fd int, name string) *os.File {
	// A descriptor the kernel will not let us set the flag on is still a
	// descriptor: hand it over as it is rather than lose the file it names.
	_ = syscall.SetNonblock(fd, true)
	return os.NewFile(uintptr(fd), name)
}
