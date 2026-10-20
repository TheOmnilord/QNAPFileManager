package jobs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestACancelledJobHoldsItsSlotUntilItsWorkReturns is stabilization contract
// §2.3 at the manager: Cancel REQUESTS the stop, and the concurrency slot stays
// taken until the work function has returned, however long the work takes to
// notice. A worker job's function returns only once the worker has reported
// where its walk stopped (the pool drains a cancelled job for its terminal
// frame), so a cancelled measurement that is still walking keeps counting
// against its class. Giving the slot back at the request instead would let a
// burst of cancel-and-resubmit clicks put any number of full-tree walks on a
// NAS that deliberately allows four.
func TestACancelledJobHoldsItsSlotUntilItsWorkReturns(t *testing.T) {
	m, _ := newManager(t, Limits{Metadata: 1, QueueDepth: 4})

	started := make(chan struct{})
	told := make(chan struct{})
	finish := make(chan struct{})
	walking, err := m.Submit(KindSize, "measuring", Meta{}, func(ctx context.Context, _ *Progress) (any, error) {
		close(started)
		<-ctx.Done()
		close(told)
		// Told, and still on its way out: the worker is finishing the directory
		// read it was in when the cancellation arrived.
		<-finish
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("the measurement never started")
	}
	if !m.Cancel(walking.ID) {
		t.Fatal("Cancel reported nothing to cancel")
	}
	select {
	case <-told:
	case <-time.After(testWait):
		t.Fatal("the cancellation never reached the work function")
	}

	var ran atomic.Bool
	next, err := m.Submit(KindSize, "next", Meta{}, func(context.Context, *Progress) (any, error) {
		ran.Store(true)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both the queued job and an admission now want the class's one slot. If
	// the cancel had given it back, one of them would have it at once.
	admit, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if release, err := m.Admit(admit, ClassMetadata); err == nil {
		release()
		t.Fatal("the slot was free while the cancelled work was still running")
	}
	if j, _ := m.Get(next.ID); j.State != StateQueued || ran.Load() {
		t.Fatalf("the next job is %s (ran %v) while the cancelled one still holds the slot", j.State, ran.Load())
	}
	if j, _ := m.Get(walking.ID); j.State != StateRunning {
		t.Fatalf("the cancelled job is %s before its work returned, want it still running", j.State)
	}

	close(finish)
	if got := waitState(t, m, walking.ID, StateCancelled); !got.Partial {
		t.Errorf("job = %+v, want a partial cancellation", got)
	}
	waitState(t, m, next.ID, StateDone)
	if !ran.Load() {
		t.Fatal("the queued job never ran once the slot came back")
	}
}
