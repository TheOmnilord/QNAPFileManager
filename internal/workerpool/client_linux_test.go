package workerpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// socketPair is the transport production actually uses: an anonymous Unix
// socketpair, the same shape spawnProcess hands a worker. The buffers are
// shrunk to the kernel's floor on the way out, because a socket is nothing like
// the net.Pipe the portable tests use — a pipe blocks on its first byte, while
// a socket with default buffers swallows a couple of hundred kilobytes before a
// peer that never reads makes any difference at all. Without the shrink, "the
// worker stopped reading" would be a test that sometimes writes and sometimes
// blocks, depending on how much the runner's kernel felt like buffering.
func socketPair(t *testing.T) (ours, theirs *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	out := make([]*net.UnixConn, 0, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("workerpool-test-%d", i))
		c, err := net.FileConn(f)
		f.Close() // FileConn duplicates it
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			t.Fatalf("the socket came back as %T", c)
		}
		t.Cleanup(func() { uc.Close() })
		shrinkBuf(t, uc)
		out = append(out, uc)
	}
	return out[0], out[1]
}

func shrinkBuf(t *testing.T, c *net.UnixConn) {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		for _, opt := range []int{syscall.SO_SNDBUF, syscall.SO_RCVBUF} {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, 4096); e != nil {
				serr = e
			}
		}
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("setsockopt: %v", serr)
	}
}

// TestAWriteOverASocketpairToAWorkerThatNeverReadsTimesOut is the portable
// test's subject over the transport the NAS actually runs: a worker wedged in a
// handler stops reading, a reply it will never take fills the socket and holds
// the write slot, and the next request must still come back inside its own
// budget rather than inside the wedged worker's.
//
// Every wait here is bounded, and deliberately so: the failure this guards
// against is a goroutine that never returns, and an unbounded wait for one of
// those is reported by the runner as the whole package timing out with no
// assertion to read.
func TestAWriteOverASocketpairToAWorkerThatNeverReadsTimesOut(t *testing.T) {
	p := NewWithOptions(Options{InProcess: true, CallTimeout: 500 * time.Millisecond, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })

	ours, theirs := socketPair(t)
	c := newClient(alice())
	c.tr = wproto.NewTransport(ours)
	if !c.tr.PassesFDs() {
		t.Fatal("a socketpair must get the fd-passing transport, or this test proves nothing about it")
	}
	killed := terminates(c, theirs)
	go c.readLoop(nil)

	// A large reply on its way to a peer that never reads. It fills the send
	// buffer, blocks, and keeps the write slot until the transport is closed —
	// which is exactly the state a wedged worker leaves the front-end in.
	big, err := wproto.NewOK(1, strings.Repeat("x", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	stalled := make(chan error, 1)
	go func() { stalled <- c.tr.Write(big, nil) }()
	time.Sleep(200 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, _, err := p.call(context.Background(), c, wproto.OpPing, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrWorkerGone) {
			t.Fatalf("err = %v, want ErrWorkerGone", err)
		}
	case <-time.After(testWait):
		t.Fatal("a write to a worker that never reads blocked the caller indefinitely")
	}
	select {
	case <-killed:
	case <-time.After(testWait):
		t.Fatal("the worker that never read was never terminated")
	}
	// Retiring the worker closed the transport, which is what releases the
	// reply that was still parked in the write slot.
	select {
	case <-stalled:
	case <-time.After(testWait):
		t.Fatal("retiring the worker left the stalled reply blocked on the socket")
	}
}
