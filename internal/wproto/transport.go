package wproto

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

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
// use: it takes a write slot, because one frame has to reach the peer as one
// write for SCM_RIGHTS to stay attached to the frame it belongs to.
type Transport interface {
	// Read returns the next frame plus any files that arrived with it. The
	// files belong to the caller, which must close them.
	Read() (Frame, []*os.File, error)
	// Write sends one frame. The caller keeps ownership of files: they are
	// duplicated into the peer and the sender still closes its own copies.
	Write(f Frame, files []*os.File) error
	// WriteWithin is Write bounded by d — the whole of it, including the wait
	// for the write slot.
	//
	// A stream socket's send buffer fills when the peer stops reading, and a
	// net.Pipe has no buffer at all, so an unbounded Write is a wait on the
	// peer's goodwill. That is fine inside a worker, which has nothing else to
	// do; it is not fine in the root front-end, where one wedged worker would
	// otherwise park the goroutine that was trying to shut it down.
	//
	// d is a budget, not a timer that starts when the writing does. One frame
	// reaches the peer at a time, so a caller with a 10 ms budget queued behind
	// a caller with a ten-second one used to wait the ten seconds and then be
	// given a fresh 10 ms of its own — which made the bound meaningless for
	// exactly the two callers that need it, the cancellation and the bye on the
	// kill path. The deadline is therefore computed before the slot is asked
	// for and the same absolute instant bounds both halves.
	//
	// A frame that does not go out in time may have gone out in part, which
	// desynchronises the framing for everything after it. There is no way to
	// resynchronise, so a caller that gets an error here must close the
	// transport and retire the worker rather than write to it again.
	WriteWithin(d time.Duration, f Frame, files []*os.File) error
	// PassesFDs reports whether this transport can carry descriptors at all,
	// so a caller can fall back rather than fail.
	PassesFDs() bool
	Close() error
}

// deadlineWriter is the part of net.Conn that lets a write be bounded. Both
// transports the daemon really uses have it: the socketpair is a *net.UnixConn,
// and the in-process pipe is a net.Pipe, whose deadlines have been real since
// Go 1.10. Anything else falls back to a goroutine and a timer.
type deadlineWriter interface {
	SetWriteDeadline(t time.Time) error
}

// NewTransport wraps rw. A *net.UnixConn on Linux gets the fd-passing
// implementation; everything else gets the plain framed one.
func NewTransport(rw io.ReadWriter) Transport {
	if c, ok := rw.(*net.UnixConn); ok && runtime.GOOS == "linux" {
		return &unixTransport{slot: newWriteSlot(), c: c}
	}
	return &streamTransport{slot: newWriteSlot(), rw: rw}
}

// writeSlot is the "one frame at a time" rule, held as a buffered channel
// rather than a sync.Mutex so that waiting for it can be given up on.
//
// A frame has to reach the peer as one write for SCM_RIGHTS to stay attached to
// the frame it belongs to, so there is exactly one writer at a time either way.
// The difference is what a second writer can do about it: sync.Mutex.Lock has no
// deadline and no cancellation, so a bounded write was only bounded once it had
// already waited however long the write in front of it took.
type writeSlot chan struct{}

func newWriteSlot() writeSlot { return make(writeSlot, 1) }

// acquire takes the slot, giving up at deadline. The error is
// os.ErrDeadlineExceeded, the same one the transports themselves report, so a
// caller cannot tell (and must not care) whether the budget went on waiting for
// the slot or on the write itself: either way the frame did not go out and the
// worker has to be retired.
func (s writeSlot) acquire(deadline time.Time) error {
	select {
	case s <- struct{}{}:
		return nil
	default:
	}
	left := time.Until(deadline)
	if left <= 0 {
		return os.ErrDeadlineExceeded
	}
	t := time.NewTimer(left)
	defer t.Stop()
	select {
	case s <- struct{}{}:
		return nil
	case <-t.C:
		return os.ErrDeadlineExceeded
	}
}

// hold takes the slot however long that takes, for the callers that have no
// budget (Write, and the worker's own replies).
func (s writeSlot) hold() { s <- struct{}{} }

func (s writeSlot) release() { <-s }

// slotError names the frame that could not even get to the front of the queue.
func slotError(f Frame, d time.Duration, err error) error {
	return fmt.Errorf("the write slot did not come free for a %s frame within %s: %w", f.Kind, d, err)
}

type unixTransport struct {
	slot writeSlot
	c    *net.UnixConn
}

func (t *unixTransport) Read() (Frame, []*os.File, error) {
	f, fds, err := ReadFrame(t.c)
	if len(fds) == 0 {
		return f, nil, err
	}
	files := make([]*os.File, 0, len(fds))
	for i, fd := range fds {
		files = append(files, receivedFile(fd, fmt.Sprintf("wproto-fd-%d-%d", f.ID, i)))
	}
	return f, files, err
}

func (t *unixTransport) Write(f Frame, files []*os.File) error {
	t.slot.hold()
	defer t.slot.release()
	return t.writeLocked(f, files)
}

func (t *unixTransport) WriteWithin(d time.Duration, f Frame, files []*os.File) error {
	deadline := time.Now().Add(d)
	if err := t.slot.acquire(deadline); err != nil {
		return slotError(f, d, err)
	}
	defer t.slot.release()
	// The absolute deadline is what goes on the socket, so the write gets
	// whatever is left of the budget rather than a fresh copy of it.
	if err := t.c.SetWriteDeadline(deadline); err != nil {
		return err
	}
	// The deadline is cleared again so an unbounded Write from another caller
	// is not silently given this one's expiry.
	defer func() { _ = t.c.SetWriteDeadline(time.Time{}) }()
	return t.writeLocked(f, files)
}

func (t *unixTransport) writeLocked(f Frame, files []*os.File) error {
	fds := make([]int, 0, len(files))
	for _, file := range files {
		fds = append(fds, int(file.Fd()))
	}
	return WriteFrame(t.c, f, fds)
}

func (t *unixTransport) PassesFDs() bool { return true }
func (t *unixTransport) Close() error    { return t.c.Close() }

type streamTransport struct {
	slot writeSlot
	rw   io.ReadWriter
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
	t.slot.hold()
	defer t.slot.release()
	return Encode(t.rw, f)
}

func (t *streamTransport) WriteWithin(d time.Duration, f Frame, files []*os.File) error {
	if len(files) > 0 {
		return fmt.Errorf("passing file descriptors on this transport: %w", fsx.ErrUnsupported)
	}
	f.NFD = 0
	deadline := time.Now().Add(d)
	if err := t.slot.acquire(deadline); err != nil {
		return slotError(f, d, err)
	}
	if dw, ok := t.rw.(deadlineWriter); ok {
		defer t.slot.release()
		if err := dw.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer func() { _ = dw.SetWriteDeadline(time.Time{}) }()
		return Encode(t.rw, f)
	}
	// Nothing to set a deadline on. The write goes on its own goroutine, which
	// keeps the write slot until the peer takes the bytes or the transport is
	// closed — and closing it is exactly what the caller has to do next, since
	// a frame that timed out here may have gone out in part. Anyone queued
	// behind it still gets an answer inside their own budget: acquire above is
	// what they are waiting in, and it has a deadline.
	done := make(chan error, 1)
	go func() {
		defer t.slot.release()
		done <- Encode(t.rw, f)
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("the peer did not accept a %s frame within %s: %w", f.Kind, d, os.ErrDeadlineExceeded)
	}
}

func (t *streamTransport) PassesFDs() bool { return false }

func (t *streamTransport) Close() error {
	if c, ok := t.rw.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
