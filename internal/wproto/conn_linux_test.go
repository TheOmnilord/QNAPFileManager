package wproto

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shortWriter accepts at most max bytes per call, which is what a stream
// socket with a full send buffer does and what the old WriteFrame treated as a
// fatal protocol error.
type shortWriter struct {
	buf bytes.Buffer
	max int
	// stall makes the writer claim it wrote nothing without reporting an
	// error, the one shape that could spin writeRest forever.
	stall bool
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.stall {
		return 0, nil
	}
	n := len(p)
	if n > w.max {
		n = w.max
	}
	w.buf.Write(p[:n])
	return n, nil
}

func TestWriteRestFinishesAShortWrite(t *testing.T) {
	payload := []byte(strings.Repeat("abcdefgh", 4096)) // 32 KiB
	for _, sent := range []int{0, 1, len(payload) - 1, len(payload)} {
		w := &shortWriter{max: 7}
		if err := writeRest(w, payload, sent); err != nil {
			t.Fatalf("writeRest(sent=%d): %v", sent, err)
		}
		if got := w.buf.Bytes(); !bytes.Equal(got, payload[sent:]) {
			t.Fatalf("writeRest(sent=%d) wrote %d bytes, want the remaining %d", sent, len(got), len(payload)-sent)
		}
	}
	// A writer that accepts nothing and reports nothing must be given up on,
	// not looped over.
	if err := writeRest(&shortWriter{stall: true}, payload, 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a stalled writer = %v, want ErrProtocol", err)
	}
}

// TestWriteFrameLargerThanTheSendBuffer is the real thing: a frame far bigger
// than the socket's send buffer, which sendmsg can only take a piece of. A
// supported 5 000-entry listing is about 1.5 MB, so this is the everyday case
// on the NAS rather than a corner of it.
func TestWriteFrameLargerThanTheSendBuffer(t *testing.T) {
	a, b := unixPair(t)
	// Linux doubles what it is given and enforces a floor, so this ends up a
	// few kilobytes — still tiny against the megabyte below.
	setSockBuf(t, a, syscall.SO_SNDBUF, 4096)
	setSockBuf(t, b, syscall.SO_RCVBUF, 4096)

	f, err := NewOK(9, strings.Repeat("x", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- WriteFrame(a, f, nil) }()
	// Let the send buffer fill before draining it, so sendmsg is guaranteed to
	// come back having taken only part of the frame rather than racing the
	// reader for the whole of it.
	time.Sleep(50 * time.Millisecond)

	_ = b.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, fds, err := ReadFrame(b)
	closeFDs(fds)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if got.ID != f.ID || got.Kind != f.Kind {
		t.Fatalf("frame = %+v, want id %d kind %q", got, f.ID, f.Kind)
	}
	if !bytes.Equal(got.Body, f.Body) {
		t.Fatalf("body came back as %d bytes, want %d", len(got.Body), len(f.Body))
	}
	// The framing must still be intact afterwards: the failure this guards
	// against showed up as the *next* reply being garbage.
	next, err := NewOK(10, "after")
	if err != nil {
		t.Fatal(err)
	}
	go func() { sent <- WriteFrame(a, next, nil) }()
	got, fds, err = ReadFrame(b)
	closeFDs(fds)
	if err != nil {
		t.Fatalf("the frame after a split one: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if got.ID != 10 || string(got.Body) != `"after"` {
		t.Fatalf("frame = %+v, want id 10 body \"after\"", got)
	}
}

// unixPair is a connected socketpair as two *net.UnixConn, the same shape the
// pool gives a worker.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	out := make([]*net.UnixConn, 0, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("wproto-test-%d", i))
		c, err := net.FileConn(f)
		f.Close() // FileConn duplicates it
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			t.Fatalf("socket came back as %T", c)
		}
		t.Cleanup(func() { uc.Close() })
		out = append(out, uc)
	}
	return out[0], out[1]
}

func setSockBuf(t *testing.T, c *net.UnixConn, opt, size int) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, size)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("setsockopt: %v", serr)
	}
}
