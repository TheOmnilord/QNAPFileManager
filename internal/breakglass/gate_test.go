package breakglass

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock is the injected time seam every ladder and bucket assertion runs on.
// Nothing here waits on a real clock except the timing-floor test, which is
// measuring wall-clock latency and therefore must.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// The peer the ladder tests walk. Named, because the ladder is now keyed by it.
const testIP = "192.168.1.40"

func TestLockoutLadder(t *testing.T) {
	c := newClock()
	g := &Gate{Now: c.now}

	// Four failures do not lock: an operator who fat-fingers a long passphrase
	// a few times must not be shut out of their own emergency door.
	for i := 1; i < LockoutAfter; i++ {
		if locked, _, entered := g.Failed(testIP); locked || entered {
			t.Fatalf("failure %d locked the source", i)
		}
	}
	// Then 60 s, doubling per further failure, capped at 1800 s.
	want := []time.Duration{60, 120, 240, 480, 960, 1800, 1800, 1800}
	for i, seconds := range want {
		locked, retry, entered := g.Failed(testIP)
		if !locked || !entered {
			t.Fatalf("failure %d did not lock", LockoutAfter+i)
		}
		if retry != seconds*time.Second {
			t.Fatalf("failure %d locked for %v, want %v", LockoutAfter+i, retry, seconds*time.Second)
		}
		// The lock is live for exactly that long, and reported so.
		if l, r, _ := g.Locked(testIP); !l || r != seconds*time.Second {
			t.Fatalf("Locked after failure %d = %v, %v", LockoutAfter+i, l, r)
		}
		c.advance(seconds * time.Second)
		locked, _, left := g.Locked(testIP)
		if locked || !left {
			t.Fatalf("the lockout did not expire after %v (locked=%v left=%v)", seconds*time.Second, locked, left)
		}
		// "Left" is reported exactly once, so the milestone is written once.
		if _, _, again := g.Locked(testIP); again {
			t.Fatal("the lockout-left transition was reported twice")
		}
	}
}

// Astra r1 #4: the ladder is keyed by SOURCE. With one emergency account and an
// account-wide ladder, any LAN peer could spend five wrong passwords and shut
// the sole door — renewing the exclusion at each expiry well inside its own
// 10/min budget — and the operator's correct password would be refused at the
// moment they needed it most. A peer can now only lock itself out.
func TestTheLockoutIsPerSource(t *testing.T) {
	c := newClock()
	g := &Gate{Now: c.now}
	const attacker, operator = "192.168.1.99", "192.168.1.5"

	for i := 0; i < LockoutAfter; i++ {
		g.Failed(attacker)
	}
	if l, _, _ := g.Locked(attacker); !l {
		t.Fatal("five failures from one source must lock that source")
	}
	// The operator's laptop is untouched, and so is every other address.
	if l, _, _ := g.Locked(operator); l {
		t.Fatal("one peer locked another peer out: the ladder is still account-wide")
	}
	if n := g.Failures(operator); n != 0 {
		t.Fatalf("the operator carries %d failures from someone else's attempts", n)
	}
	// The attacker's own further failures keep climbing its own rung, and still
	// never reach the operator.
	for i := 0; i < 3; i++ {
		c.advance(2 * LockoutCap)
		g.Failed(attacker)
	}
	if l, _, _ := g.Locked(operator); l {
		t.Fatal("a sustained attempt from one source eventually locked another")
	}
	// A source nobody has ever seen is not tracked at all; asking must not be
	// what creates the entry.
	before := g.TrackedSources()
	if l, _, _ := g.Locked("10.0.0.1"); l {
		t.Fatal("an unseen source is locked")
	}
	if after := g.TrackedSources(); after != before {
		t.Fatalf("asking about a source tracked it (%d -> %d)", before, after)
	}
}

func TestSuccessResetsTheLadder(t *testing.T) {
	c := newClock()
	g := &Gate{Now: c.now}
	for i := 0; i < LockoutAfter; i++ {
		g.Failed(testIP)
	}
	if l, _, _ := g.Locked(testIP); !l {
		t.Fatal("five failures must lock")
	}
	g.Succeeded(testIP)
	if l, _, _ := g.Locked(testIP); l {
		t.Fatal("a success must clear the lockout")
	}
	if g.Failures(testIP) != 0 {
		t.Fatalf("Failures = %d after a success, want 0", g.Failures(testIP))
	}
	// A success clears the SOURCE that offered it and nobody else: one peer
	// getting in must not hand another a clean slate.
	const other = "10.0.0.9"
	for i := 0; i < LockoutAfter; i++ {
		g.Failed(other)
	}
	g.Succeeded(testIP)
	if l, _, _ := g.Locked(other); !l {
		t.Fatal("a success from one source cleared another source's lockout")
	}
	// And the ladder restarts at the bottom rung, not where it left off.
	for i := 1; i < LockoutAfter; i++ {
		if l, _, _ := g.Failed(testIP); l {
			t.Fatalf("failure %d locked after a reset", i)
		}
	}
	if _, retry, _ := g.Failed(testIP); retry != LockoutBase {
		t.Fatalf("the ladder resumed at %v, want %v", retry, LockoutBase)
	}
}

func TestSourceBucketRefillsAndRefuses(t *testing.T) {
	c := newClock()
	g := &Gate{Now: c.now}
	const ip = testIP
	for i := 0; i < BucketCapacity; i++ {
		if err := g.AllowSource(ip); err != nil {
			t.Fatalf("attempt %d refused: %v", i+1, err)
		}
	}
	if err := g.AllowSource(ip); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("attempt %d = %v, want ErrRateLimited", BucketCapacity+1, err)
	}
	// Another source is unaffected: the bound is per source, and one attacker
	// must not lock the operator's own laptop out.
	if err := g.AllowSource("10.0.0.9"); err != nil {
		t.Fatalf("a different source was refused: %v", err)
	}
	// One token back per BucketWindow/BucketCapacity.
	c.advance(BucketWindow / BucketCapacity)
	if err := g.AllowSource(ip); err != nil {
		t.Fatalf("after one refill interval: %v", err)
	}
	if err := g.AllowSource(ip); !errors.Is(err, ErrRateLimited) {
		t.Fatal("the refill gave back more than one token")
	}
	// A full window refills the whole burst but never more.
	c.advance(10 * BucketWindow)
	for i := 0; i < BucketCapacity; i++ {
		if err := g.AllowSource(ip); err != nil {
			t.Fatalf("post-refill attempt %d: %v", i+1, err)
		}
	}
	if err := g.AllowSource(ip); !errors.Is(err, ErrRateLimited) {
		t.Fatal("the bucket refilled past its capacity")
	}
}

func TestSourceTableIsLRUBounded(t *testing.T) {
	g := &Gate{Now: newClock().now}
	for i := 0; i < MaxSources*3; i++ {
		if err := g.AllowSource(fmt.Sprintf("10.1.%d.%d", i/256, i%256)); err != nil {
			t.Fatalf("source %d: %v", i, err)
		}
	}
	if n := g.TrackedSources(); n > MaxSources {
		t.Fatalf("tracked %d sources, want at most %d", n, MaxSources)
	}
}

func TestAdmissionIsBoundedAndTheVerificationIsSerial(t *testing.T) {
	g := &Gate{Now: newClock().now}
	var held []func()
	for i := 0; i < InFlight; i++ {
		release, err := g.Admit()
		if err != nil {
			t.Fatalf("admission %d refused: %v", i+1, err)
		}
		held = append(held, release)
	}
	// The fifth concurrent attempt is refused rather than queued behind a
	// cost-11 bcrypt (contract §5.1).
	if _, err := g.Admit(); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("admission %d = %v, want ErrRateLimited", InFlight+1, err)
	}
	held[0]()
	if release, err := g.Admit(); err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	} else {
		held[0] = release
	}
	for _, release := range held {
		release()
	}

	// One verification at a time, whatever the admission allows.
	var mu sync.Mutex
	var concurrent, peak int
	var wg sync.WaitGroup
	for i := 0; i < InFlight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = g.Verify(context.Background(), testIP, func() Outcome {
				mu.Lock()
				concurrent++
				if concurrent > peak {
					peak = concurrent
				}
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				concurrent--
				mu.Unlock()
				return OutcomeNeutral
			})
		}()
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("%d verifications ran at once, want 1", peak)
	}
}

// Astra r1 #7: the lockout verdict and the outcome are decided INSIDE the
// serialised turn. Four concurrent wrong attempts after four failures used to
// read the same "unlocked, 4 failures" before queueing and commit their
// failures after releasing, so they all skipped straight past the first rung.
// Exactly one of them may enter a lockout, and it must be the first rung.
func TestConcurrentFailuresEnterExactlyOneRung(t *testing.T) {
	g := &Gate{Now: newClock().now}
	for i := 0; i < LockoutAfter-1; i++ {
		g.Failed(testIP)
	}
	var mu sync.Mutex
	var entered []time.Duration
	var locked int
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := g.Verify(context.Background(), testIP, func() Outcome { return OutcomeFailed })
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if v.Entered {
				entered = append(entered, v.RetryAfter)
			}
			if v.Locked {
				locked++
			}
		}()
	}
	wg.Wait()
	if len(entered) != 1 {
		t.Fatalf("%d attempts entered a lockout, want exactly 1 (rungs: %v)", len(entered), entered)
	}
	if entered[0] != LockoutBase {
		t.Fatalf("the lockout entered was %v, want the first rung %v", entered[0], LockoutBase)
	}
	// The other three found the source already locked and never verified.
	if locked != 3 {
		t.Fatalf("%d attempts were answered locked, want 3", locked)
	}
	if n := g.Failures(testIP); n != LockoutAfter {
		t.Fatalf("Failures = %d, want %d: a locked attempt must not advance the ladder", n, LockoutAfter)
	}
}

// The other half of #7: a CORRECT password queued behind the failure that
// enters a lockout is refused as locked, rather than being let in during a
// lockout it arrived before.
func TestACorrectPasswordQueuedBehindALockoutIsRefused(t *testing.T) {
	g := &Gate{Now: newClock().now}
	for i := 0; i < LockoutAfter-1; i++ {
		g.Failed(testIP)
	}
	// The failing attempt holds the turn until the correct one is provably
	// queued behind it — a sleep here would be a guess about scheduling.
	inside, queued := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		v, err := g.Verify(context.Background(), testIP, func() Outcome {
			close(inside)
			<-queued
			return OutcomeFailed
		})
		if err != nil || !v.Entered {
			t.Errorf("the failing attempt did not enter a lockout: %+v %v", v, err)
		}
	}()
	<-inside

	result := make(chan Verdict, 1)
	go func() {
		v, err := g.Verify(context.Background(), testIP, func() Outcome {
			t.Error("a correct password ran its verification during a lockout")
			return OutcomeSucceeded
		})
		if err != nil {
			t.Error(err)
		}
		result <- v
	}()
	// Let the first attempt finish and commit its lockout.
	close(queued)
	<-done

	select {
	case v := <-result:
		if !v.Locked {
			t.Fatalf("the queued attempt was not refused: %+v", v)
		}
		if v.RetryAfter <= 0 || v.RetryAfter > LockoutBase {
			t.Fatalf("Retry-After = %v, want at most the first rung %v", v.RetryAfter, LockoutBase)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the queued attempt never returned")
	}
}

func TestVerifyHonoursTheContext(t *testing.T) {
	g := &Gate{Now: newClock().now}
	// inside is closed by the holder BEFORE it blocks, so the second caller
	// queues only once the semaphore is provably taken. A sleep here would be a
	// guess about scheduling, and the test it guards would fail on a loaded CI
	// runner rather than on a real defect (round-2 P3-9).
	inside := make(chan struct{})
	blocked := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_, _ = g.Verify(context.Background(), testIP, func() Outcome {
			close(inside)
			<-blocked
			return OutcomeNeutral
		})
		close(done)
	}()
	<-inside

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := g.Verify(ctx, testIP, func() Outcome {
		t.Error("a cancelled caller must not run the verification")
		return OutcomeNeutral
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify on a cancelled context = %v", err)
	}
	close(blocked)
	<-done
}

// MeasureCost is what sizes the door's request deadline, so it has to return
// something plausible rather than zero.
func TestMeasureCostReturnsAPlausibleDuration(t *testing.T) {
	got := MeasureCost(MinCost)
	if got <= 0 {
		t.Fatalf("MeasureCost(%d) = %v, want a positive duration", MinCost, got)
	}
	if got > 30*time.Second {
		t.Fatalf("MeasureCost(%d) = %v; the door's deadline would be absurd", MinCost, got)
	}
	// An invalid cost falls back to the default rather than returning zero,
	// because a zero would silently shrink the deadline back to its floor.
	if MeasureCost(99) <= 0 {
		t.Fatal("MeasureCost must fall back to the default cost, not to zero")
	}
}

// The floor is a wall-clock guarantee to a remote attacker, so this is the one
// test here that measures real time. Every failure path shares it: without the
// floor, "no password is configured", "wrong password" and "locked out" are
// distinguishable by latency (contract §5.2).
func TestFailureFloorIsMeasuredFromRequestStart(t *testing.T) {
	floor := 60 * time.Millisecond
	g := &Gate{Now: newClock().now, Floor: floor}
	for _, c := range []struct {
		name  string
		spent time.Duration
	}{
		{"nothing done yet", 0},
		{"half spent already", floor / 2},
		{"already over the floor", 2 * floor},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now().Add(-c.spent)
			g.Wait(context.Background(), start)
			if elapsed := time.Since(start); elapsed < floor && c.spent < floor {
				t.Fatalf("returned after %v, want at least %v from request start", elapsed, floor)
			}
		})
	}
	// A cancelled request does not hold the goroutine for the whole floor.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	g.Wait(ctx, start)
	if elapsed := time.Since(start); elapsed > floor {
		t.Fatalf("a cancelled wait took %v, want a prompt return", elapsed)
	}
	// A negative floor is the explicit opt-out tests use; it must not sleep.
	fast := &Gate{Floor: -1}
	start = time.Now()
	fast.Wait(context.Background(), start.Add(-time.Millisecond))
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("a disabled floor waited %v", elapsed)
	}
}

func TestDefaultFloorIsFourHundredMilliseconds(t *testing.T) {
	if FailureFloor != 400*time.Millisecond {
		t.Fatalf("FailureFloor = %v, want 400ms (contract §5.2)", FailureFloor)
	}
	if LockoutAfter != 5 || LockoutBase != 60*time.Second || LockoutCap != 1800*time.Second {
		t.Fatal("the lockout ladder no longer matches the contract")
	}
	if BucketCapacity != 10 || BucketWindow != time.Minute || MaxSources != 256 {
		t.Fatal("the per-source bucket no longer matches the contract")
	}
}
