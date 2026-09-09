package wproto

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"

	"qnapfilemanager/internal/fsx"
)

// Transport is one framed connection between the front-end and a worker. Two
// implementations exist and both sides pick between them with NewTransport:
//
//   - a Unix socketpair on Linux, which is production and the only shape that
//     can carry a file descriptor;
//   - any other io.ReadWriter — a net.Pipe in the in-process mode used by the
//     Windows dev loop and by tests — which speaks the identical framing minus
//     the ancillary data.
//
// Read must be called from a single goroutine. Write is safe for concurrent
// use: it holds a mutex, because one frame has to reach the peer as one write
// for SCM_RIGHTS to stay attached to the frame it belongs to.
type Transport interface {
	// Read returns the next frame plus any files that arrived with it. The
	// files belong to the caller, which must close them.
	Read() (Frame, []*os.File, error)
	// Write sends one frame. The caller keeps ownership of files: they are
	// duplicated into the peer and the sender still closes its own copies.
	Write(f Frame, files []*os.File) error
	// PassesFDs reports whether this transport can carry descriptors at all,
	// so a caller can fall back rather than fail.
	PassesFDs() bool
	Close() error
}

// NewTransport wraps rw. A *net.UnixConn on Linux gets the fd-passing
// implementation; everything else gets the plain framed one.
func NewTransport(rw io.ReadWriter) Transport {
	if c, ok := rw.(*net.UnixConn); ok && runtime.GOOS == "linux" {
		return &unixTransport{c: c}
	}
	return &streamTransport{rw: rw}
}

type unixTransport struct {
	mu sync.Mutex
	c  *net.UnixConn
}

func (t *unixTransport) Read() (Frame, []*os.File, error) {
	f, fds, err := ReadFrame(t.c)
	if len(fds) == 0 {
		return f, nil, err
	}
	files := make([]*os.File, 0, len(fds))
	for i, fd := range fds {
		files = append(files, os.NewFile(uintptr(fd), fmt.Sprintf("wproto-fd-%d-%d", f.ID, i)))
	}
	return f, files, err
}

func (t *unixTransport) Write(f Frame, files []*os.File) error {
	fds := make([]int, 0, len(files))
	for _, file := range files {
		fds = append(fds, int(file.Fd()))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return WriteFrame(t.c, f, fds)
}

func (t *unixTransport) PassesFDs() bool { return true }
func (t *unixTransport) Close() error    { return t.c.Close() }

type streamTransport struct {
	mu sync.Mutex
	rw io.ReadWriter
}

func (t *streamTransport) Read() (Frame, []*os.File, error) {
	f, err := Decode(t.rw)
	if err != nil {
		return Frame{}, nil, err
	}
	if f.NFD > 0 {
		// The peer promised descriptors on a transport that cannot carry
		// them. Framing is intact but the exchange is not, so say so rather
		// than hand back a reply that is missing its payload.
		return Frame{}, nil, fmt.Errorf("frame declared %d file descriptors on a transport without ancillary data: %w", f.NFD, ErrProtocol)
	}
	return f, nil, nil
}

func (t *streamTransport) Write(f Frame, files []*os.File) error {
	if len(files) > 0 {
		return fmt.Errorf("passing file descriptors on this transport: %w", fsx.ErrUnsupported)
	}
	f.NFD = 0
	t.mu.Lock()
	defer t.mu.Unlock()
	return Encode(t.rw, f)
}

func (t *streamTransport) PassesFDs() bool { return false }

func (t *streamTransport) Close() error {
	if c, ok := t.rw.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
