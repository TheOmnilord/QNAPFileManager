package wproto

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The production transport is a Unix socketpair, not a net.Pipe, and the two
// behave nothing alike when the peer stops reading: a pipe has no buffer at all
// and blocks on the first byte, while a socket swallows a couple of hundred
// kilobytes before it blocks at all. Every bounded-write test that used a pipe
// therefore proved the bound for the one transport production does not use.
// These prove it for the one it does — and they prove it in bounded time by
// shrinking the socket's buffers first, so "the peer never reads" really does
// mean "the write blocks" rather than "the write blocks once the kernel happens
// to run out of room".

// smallPair is a socketpair whose send and receive buffers are as small as
// Linux allows. The kernel doubles what it is given and enforces a floor, so
// the real capacity ends up a few kilobytes — tiny against the payload below,
// which is the point.
func smallPair(t *testing.T) (ours, theirs *net.UnixConn) {
	t.Helper()
	a, b := unixPair(t)
	setSockBuf(t, a, syscall.SO_SNDBUF, 4096)
	setSockBuf(t, b, syscall.SO_RCVBUF, 4096)
	return a, b
}

// bigFrame is a frame far larger than the shrunken buffers can hold, so a peer
// that never reads is guaranteed to leave the write blocked rather than
// probably blocked.
func bigFrame(t *testing.T, id uint64) Frame {
	t.Helper()
	f, err := NewOK(id, strings.Repeat("x", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestWriteWithinBoundsASocketpairWriteToAPeerThatNeverReads is the shape the
// front-end actually meets on the NAS: a worker wedged in a handler stops
// reading its socket, the send buffer fills, and the goroutine trying to cancel
// or to say goodbye is the one left holding it.
func TestWriteWithinBoundsASocketpairWriteToAPeerThatNeverReads(t *testing.T) {
	ours, _ := smallPair(t)
	tr := NewTransport(ours)
	t.Cleanup(func() { _ = tr.Close() })
	if !tr.PassesFDs() {
		t.Fatal("a socketpair must get the fd-passing transport, or this test proves nothing about it")
	}

	const budget = 300 * time.Millisecond
	start := time.Now()
	err := tr.WriteWithin(budget, bigFrame(t, 1), nil)
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	// Generous, because CI is shared and this is about "returns at all", not
	// about timer accuracy. What it guards against did not return at all.
	if elapsed > 10*time.Second {
		t.Fatalf("a %s write to a peer that never reads took %s", budget, elapsed)
	}
}

// TestWriteWithinBoundsTheSocketpairWriteSlot: the budget has to cover the
// queue in front of the write as well as the write itself. An unbounded Write
// against a peer that never reads holds the slot until the transport is closed,
// and the cancellation queued behind it is the one caller that must not wait.
func TestWriteWithinBoundsTheSocketpairWriteSlot(t *testing.T) {
	ours, _ := smallPair(t)
	tr := NewTransport(ours)

	big := bigFrame(t, 1)
	stuck := make(chan error, 1)
	go func() { stuck <- tr.Write(big, nil) }()
	// Long enough for the unbounded write to take the slot and fill the buffer.
	time.Sleep(200 * time.Millisecond)

	small, err := NewReq(2, OpCancel, CancelReq{ReqID: 1})
	if err != nil {
		t.Fatal(err)
	}
	const budget = 300 * time.Millisecond
	start := time.Now()
	err = tr.WriteWithin(budget, small, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("a %s write waited %s behind an unbounded one", budget, elapsed)
	}

	// Closing the transport is what a caller must do next, and it is also what
	// releases the write still parked in the slot.
	_ = tr.Close()
	select {
	case <-stuck:
	case <-time.After(30 * time.Second):
		t.Fatal("closing the transport did not release the unbounded write")
	}
}

// TestAReceivedPipeCanBeClosedOutOfABlockedRead: a descriptor that arrives over
// SCM_RIGHTS is wrapped with os.NewFile, and NewFile decides *at that moment*,
// from the flags the descriptor already carries, whether to register it with
// the runtime poller. A blocking descriptor is never registered, and an
// unregistered read cannot be interrupted: Close returns, the goroutine stays
// parked inside read(2), and the root front-end holds the request open for as
// long as the peer likes. A worker can legitimately hand back a pipe or a fifo,
// so this is reachable from a URL.
func TestAReceivedPipeCanBeClosedOutOfABlockedRead(t *testing.T) {
	a, b := unixPair(t)
	recv := NewTransport(a)
	send := NewTransport(b)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The sender keeps its own copy, exactly as the protocol says; the writer
	// stays open for the whole test, so a read that comes back early came back
	// because of the Close and not because of an EOF.
	defer r.Close()
	defer w.Close()

	f, err := NewOK(1, "pipe")
	if err != nil {
		t.Fatal(err)
	}
	if err := send.Write(f, []*os.File{r}); err != nil {
		t.Fatalf("sending the pipe: %v", err)
	}

	_ = a.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, files, err := recv.Read()
	if err != nil {
		t.Fatalf("receiving the pipe: %v", err)
	}
	if got.ID != 1 || len(files) != 1 {
		t.Fatalf("frame = %+v with %d files, want exactly one", got, len(files))
	}
	pipe := files[0]
	defer pipe.Close()

	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := pipe.Read(buf)
		read <- err
	}()
	// Let the read reach the kernel before the close does.
	time.Sleep(200 * time.Millisecond)
	if err := pipe.Close(); err != nil {
		t.Fatalf("closing the received pipe: %v", err)
	}
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("the read returned data from a pipe nothing was written to")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing a received pipe did not interrupt the read blocked on it: the descriptor was never registered with the poller")
	}
}
