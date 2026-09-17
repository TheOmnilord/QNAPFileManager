package audit

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// --- Astra r4 #2: an error from a durable write does not mean it was lost ----

// waitFor spins until cond holds or the test's patience runs out. Every use
// below waits on an observable state — a taken slot, a queued admission — so the
// bound is a failure report, never a timing assumption.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A call that gave up on an ADMITTED write is not a call whose event was lost:
// the worker owns the event and goes on to fsync it. A caller that cleared the
// counters the line stands for must not put them back, or the same burst is
// reported twice — which is the failure round 4 found in the break-glass door.
func TestAnAdmittedWriteIsStillInFlightWhenTheCallerGivesUp(t *testing.T) {
	l, _ := openTest(t, false)
	releaseSink := l.HoldSink()
	defer releaseSink()

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		inFlight bool
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		inFlight, err := l.WriteSyncInFlight(ctx, Event{Op: "mkdir", Path: "/etc/config/x", Phase: "result", Result: "ok"})
		done <- outcome{inFlight, err}
	}()
	// Admitted: the slot is taken and the worker is inside the frozen sink. Only
	// then is the caller's cancellation the interesting one.
	waitFor(t, "the durable writer to be admitted", func() bool { return len(l.syncSem) == 1 })
	cancel()

	got := <-done
	if got.err == nil {
		t.Fatal("the cancelled caller was told the write succeeded")
	}
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", got.err)
	}
	if !got.inFlight {
		t.Fatal("an admitted write was reported as definitely lost; a caller would now report its burst a second time")
	}

	// And the proof that in flight is the truth: released, the line lands.
	releaseSink()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 1 || evs[0].Path != "/etc/config/x" {
		t.Fatalf("the abandoned write did not land after all: %+v", evs)
	}
}

// The timeout half of the same thing, and the case the break-glass door actually
// meets: writeSyncTimeout expires while the worker is inside a wedged sink. Same
// verdict — in flight, not lost.
func TestATimedOutAdmittedWriteIsInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("this one waits out the two-second durable-write timeout")
	}
	l, _ := openTest(t, false)
	releaseSink := l.HoldSink()
	defer releaseSink()

	start := time.Now()
	inFlight, err := l.WriteSyncInFlight(context.Background(), Event{Op: "mkdir", Path: "/etc/config/slow", Phase: "result", Result: "ok"})
	if !errors.Is(err, ErrSyncTimeout) {
		t.Fatalf("err = %v after %v, want ErrSyncTimeout", err, time.Since(start))
	}
	if !inFlight {
		t.Fatal("a write that timed out INSIDE the sink was reported as definitely lost")
	}

	releaseSink()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 1 || evs[0].Path != "/etc/config/slow" {
		t.Fatalf("the timed-out write did not land: %+v", evs)
	}
}

// The other direction, and the one a caller may act on: nothing got a slot, so
// nothing was written and nothing will be. It is staged with the slots genuinely
// held, because with one free a ready context and a ready semaphore are two
// ready cases of a single select and Go is entitled to pick either.
func TestAWriteThatWasNeverAdmittedIsDefinitelyLost(t *testing.T) {
	l, _ := openTest(t, false)
	releaseSlots := l.HoldSyncSlots()
	defer releaseSlots()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inFlight, err := l.WriteSyncInFlight(ctx, Event{Op: "mkdir", Path: "/etc/config/never", Phase: "result", Result: "ok"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	if inFlight {
		t.Fatal("a call that never got a slot was reported as in flight; its caller would keep a burst nobody will ever write")
	}

	// A closed logger is the same verdict by the route the door's refused-summary
	// test uses, and the one place the answer is unambiguous without staging
	// anything at all.
	releaseSlots()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f, err := l.WriteSyncInFlight(context.Background(), Event{Op: "mkdir", Phase: "result", Result: "ok"}); !errors.Is(err, os.ErrClosed) || f {
		t.Fatalf("a closed logger = (inFlight %v, %v), want (false, os.ErrClosed)", f, err)
	}
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("a write that was never admitted reached the sink anyway: %+v", evs)
	}
}

// SyncWaiting is the observable the break-glass tests synchronise on, so it has
// to mean what it says: one call queued for a slot, back to none once it is let
// through.
func TestSyncWaitingCountsTheQueuedCalls(t *testing.T) {
	l, _ := openTest(t, false)
	releaseSlots := l.HoldSyncSlots()
	defer releaseSlots()
	if n := l.SyncWaiting(); n != 0 {
		t.Fatalf("SyncWaiting = %d on an idle logger", n)
	}
	done := make(chan error, 1)
	go func() {
		done <- l.WriteSync(context.Background(), Event{Op: "mkdir", Path: "/etc/config/queued", Phase: "result", Result: "ok"})
	}()
	waitFor(t, "the call to queue for a slot", func() bool { return l.SyncWaiting() == 1 })
	releaseSlots()
	if err := <-done; err != nil {
		t.Fatalf("the released call = %v", err)
	}
	if n := l.SyncWaiting(); n != 0 {
		t.Fatalf("SyncWaiting = %d once the call was admitted", n)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
