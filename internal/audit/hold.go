package audit

import (
	"sync"
	"sync/atomic"
)

// The three grips below exist so a test in ANOTHER package can put the durable
// write path into the states a wedged sink produces (Astra r4 #3). Nothing in
// cmd, internal/web or any other caller uses them, and none of them is reachable
// from a request: they are here because the two things a test has to hold — the
// admission slots and the sink lock — are unexported, and a test that cannot
// hold them has to reach for a sleep instead, which is exactly the flakiness
// round 4 found in the break-glass cancellation test.
//
// The states they stage are real ones. A sink that has stopped acknowledging is
// how a full disk or a hung filesystem presents, and the break-glass door's
// aggregate refusal lines resolve their claims on what WriteSync returns in
// precisely that state, so it is the state their tests have to be able to
// create on purpose.
//
// Two rules for a caller: RELEASE BEFORE CLOSE — Close joins the drain and the
// admitted durable writers, so a held sink turns shutdown into a five-second
// timeout — and hold the sink before the slots, never the other way round, since
// a held sink is what makes a real writer keep its slot.

// HoldSyncSlots occupies every durable-writer admission slot until the returned
// release is called. While it is held no WriteSync can be admitted: each one
// waits, and the wait is what makes a cancelled context or an expired timeout
// take the NON-ADMISSION exit deterministically instead of racing a free slot
// for it. Calling release more than once is harmless.
func (l *Logger) HoldSyncSlots() (release func()) {
	for i := 0; i < syncWriters; i++ {
		l.syncSem <- struct{}{}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := 0; i < syncWriters; i++ {
				<-l.syncSem
			}
		})
	}
}

// HoldSink freezes the file itself: an admitted durable writer reaches its
// write+fsync and stops there, holding its slot, which is how WriteSync comes to
// return ErrSyncTimeout for an event that is nevertheless still on its way to
// the disk. Releasing lets those writes complete, so a test can show that the
// line really did land after the call that gave up on it. Calling release more
// than once is harmless.
func (l *Logger) HoldSink() (release func()) {
	l.drainMu.Lock()
	var once sync.Once
	return func() { once.Do(l.drainMu.Unlock) }
}

// SyncWaiting is how many WriteSync calls are queued for an admission slot right
// now. A test waits on this rather than on the clock: it is the exact moment the
// call under test is inside the admission wait, and therefore the only moment at
// which releasing the slots proves anything about which branch that wait takes.
func (l *Logger) SyncWaiting() int { return int(atomic.LoadInt64(&l.syncWaiting)) }
