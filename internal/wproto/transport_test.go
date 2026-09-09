package wproto

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestWriteWithinBoundsTheWaitForTheWriteSlot: one frame reaches the peer at a
// time, so a bounded write is only bounded if the queue in front of it counts
// against its budget. With a mutex it did not: a 100 ms cancellation queued
// behind a ten-second write waited the ten seconds and was then given a fresh
// 100 ms of its own — which is exactly the case the bound exists for, because
// the cancellation and the bye on the kill path are what queue up behind a
// worker that has stopped reading.
func TestWriteWithinBoundsTheWaitForTheWriteSlot(t *testing.T) {
	ours, theirs := net.Pipe()
	defer theirs.Close()
	tr := NewTransport(ours)
	defer tr.Close()

	f, err := NewReq(1, OpPing, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Nobody ever reads theirs, so this write sits in the slot for its whole
	// budget.
	const stalled = 4 * time.Second
	stuck := make(chan error, 1)
	go func() { stuck <- tr.WriteWithin(stalled, f, nil) }()

	// Give the first write time to take the slot. It cannot complete: net.Pipe
	// is unbuffered and there is no reader.
	time.Sleep(200 * time.Millisecond)

	const budget = 300 * time.Millisecond
	start := time.Now()
	err = tr.WriteWithin(budget, f, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the queued write must fail rather than wait out the one in front of it")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed > stalled/2 {
		t.Fatalf("a %s write waited %s: its budget did not cover the queue in front of it", budget, elapsed)
	}

	if err := <-stuck; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the stalled write = %v, want os.ErrDeadlineExceeded", err)
	}
}

// blockedWriter is a transport with no deadlines to set — the fallback path,
// where the write goes on its own goroutine. A caller queued behind it must
// still get an answer inside its own budget.
type blockedWriter struct {
	release chan struct{}
	entered chan struct{}
	once    bool
}

func (w *blockedWriter) Read([]byte) (int, error) { return 0, io.EOF }

func (w *blockedWriter) Write(p []byte) (int, error) {
	if !w.once {
		w.once = true
		close(w.entered)
		<-w.release
	}
	return len(p), nil
}

func TestWriteWithinBoundsTheSlotWithoutDeadlineSupport(t *testing.T) {
	w := &blockedWriter{release: make(chan struct{}), entered: make(chan struct{})}
	defer close(w.release)
	tr := NewTransport(w)

	f, err := NewReq(1, OpPing, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tr.WriteWithin(10*time.Second, f, nil) }()
	select {
	case <-w.entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the first write never started")
	}

	const budget = 300 * time.Millisecond
	start := time.Now()
	err = tr.WriteWithin(budget, f, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("a %s write waited %s behind a stalled one", budget, elapsed)
	}
}

// A write that has the slot to itself still gets the whole budget, and a peer
// that reads still gets its frame.
func TestWriteWithinDeliversWhenThePeerReads(t *testing.T) {
	ours, theirs := net.Pipe()
	tr := NewTransport(ours)
	defer tr.Close()
	peer := NewTransport(theirs)
	defer peer.Close()

	f, err := NewReq(7, OpPing, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tr.WriteWithin(10*time.Second, f, nil) }()

	got, files, err := peer.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("%d files on a transport that carries none", len(files))
	}
	if got.ID != 7 || got.Op != OpPing {
		t.Fatalf("frame = %+v, want the ping that was sent", got)
	}
}
