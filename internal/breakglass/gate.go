package breakglass

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// The three bounds of §5.1 and the floor of §5.2, all of them live in the
// break-glass listener alone: the main listener keeps auth_limits.go unchanged.
const (
	// BucketCapacity attempts per source IP, refilled over BucketWindow. The
	// peer here is a real LAN address — this listener is not behind the QTS
	// proxy — so unlike the main listener's budget it can key on something
	// honest.
	BucketCapacity = 10
	BucketWindow   = time.Minute
	// MaxSources bounds the tracked source table; the least recently seen is
	// evicted, so a spray from a forged-source flood cannot grow memory.
	MaxSources = 256

	// LockoutAfter consecutive failures lock the ACCOUNT (there is only one)
	// for LockoutBase, doubling per further failure to LockoutCap. A success
	// resets it. The state is in memory and a restart clears it, deliberately:
	// persisting it would let an attacker lock the operator out of their own
	// emergency door across restarts, which is the worse failure (§5.3).
	LockoutAfter = 5
	LockoutBase  = 60 * time.Second
	LockoutCap   = 1800 * time.Second

	// InFlight is how many login attempts may be admitted at once; exactly one
	// of them runs bcrypt at a time (§5.1's semaphore of 1 and queue of 4).
	// bcrypt at cost 11 is the most expensive thing an unauthenticated caller
	// can ask this process to do.
	InFlight = 4

	// FailureFloor is the minimum latency of EVERY failed attempt, measured
	// from request start (§5.2). Without it, "no password is configured",
	// "wrong password" and "locked out" are distinguishable by latency.
	FailureFloor = 400 * time.Millisecond
)

// ErrRateLimited is the per-IP bucket or the verification queue refusing an
// attempt. It maps to 429 rate_limited.
var ErrRateLimited = errors.New("breakglass: too many attempts")

// ErrLockedOut is the account lockout. It maps to 429 locked_out with a
// Retry-After, and the response body never reveals whether the password offered
// was right.
var ErrLockedOut = errors.New("breakglass: locked out")

// Gate holds every bound the break-glass door applies before and around a
// bcrypt verification. Its zero value is usable; Now and Floor are seams so the
// ladder and the timing floor are testable without waiting on a real clock.
type Gate struct {
	// Now is the clock. nil means time.Now.
	Now func() time.Time
	// Floor overrides FailureFloor. Zero means FailureFloor; a negative value
	// disables the wait entirely, which only a test that is not measuring it
	// should do.
	Floor time.Duration

	mu      sync.Mutex
	sources map[string]*list.Element
	lru     list.List

	failures    int
	lockedUntil time.Time
	// lockAnnounced is true while the current lockout has already been
	// reported as entered, so "entered" and "left" are each reported exactly
	// once per lockout rather than on every request during it.
	lockAnnounced bool

	admitOnce sync.Once
	admit     chan struct{} // InFlight slots: total attempts in flight
	verify    chan struct{} // 1 slot: one bcrypt at a time
}

type sourceBucket struct {
	key    string
	tokens float64
	last   time.Time
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) init() {
	g.admitOnce.Do(func() {
		g.admit = make(chan struct{}, InFlight)
		g.verify = make(chan struct{}, 1)
	})
}

// AllowSource consumes one token from ip's bucket. It is the first check, before
// anything reads a body or touches bcrypt.
func (g *Gate) AllowSource(ip string) error {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sources == nil {
		g.sources = make(map[string]*list.Element, MaxSources)
	}
	elem, ok := g.sources[ip]
	if !ok {
		for len(g.sources) >= MaxSources {
			oldest := g.lru.Front()
			if oldest == nil {
				break
			}
			delete(g.sources, oldest.Value.(*sourceBucket).key)
			g.lru.Remove(oldest)
		}
		elem = g.lru.PushBack(&sourceBucket{key: ip, tokens: BucketCapacity, last: now})
		g.sources[ip] = elem
	} else {
		g.lru.MoveToBack(elem)
	}
	b := elem.Value.(*sourceBucket)
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * (BucketCapacity / BucketWindow.Seconds())
		if b.tokens > BucketCapacity {
			b.tokens = BucketCapacity
		}
	}
	b.last = now
	if b.tokens < 1 {
		return ErrRateLimited
	}
	b.tokens--
	return nil
}

// TrackedSources reports how many source IPs the bucket table holds, so the LRU
// bound is assertable.
func (g *Gate) TrackedSources() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sources)
}

// Locked reports whether the account is currently locked and for how much
// longer. left is true on the one call that observes a lockout expiring, so the
// caller can write the "lockout left" milestone exactly once.
func (g *Gate) Locked() (locked bool, retryAfter time.Duration, left bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lockedUntil.IsZero() {
		return false, 0, false
	}
	if now.Before(g.lockedUntil) {
		return true, g.lockedUntil.Sub(now), false
	}
	g.lockedUntil = time.Time{}
	wasAnnounced := g.lockAnnounced
	g.lockAnnounced = false
	return false, 0, wasAnnounced
}

// Failed records one failed verification and returns the lockout state after
// it. entered is true only on the attempt that starts a lockout (or lengthens
// it to a new ladder rung), so each transition is a single milestone.
func (g *Gate) Failed() (locked bool, retryAfter time.Duration, entered bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failures++
	if g.failures < LockoutAfter {
		return false, 0, false
	}
	d := LockoutBase << (g.failures - LockoutAfter)
	// The shift overflows long before the ladder does anything useful; clamp on
	// the negative as well as on the cap so a very long run of failures cannot
	// produce a lock in the past.
	if d > LockoutCap || d <= 0 {
		d = LockoutCap
	}
	g.lockedUntil = now.Add(d)
	g.lockAnnounced = true
	return true, d, true
}

// Succeeded clears the ladder. Only a verified password does this.
func (g *Gate) Succeeded() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failures = 0
	g.lockedUntil = time.Time{}
	g.lockAnnounced = false
}

// Failures reports the consecutive-failure count, for the status line and the
// tests.
func (g *Gate) Failures() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures
}

// Admit takes one of the InFlight slots. It never waits: the caller beyond the
// bound is refused outright rather than queued behind a cost-11 bcrypt.
func (g *Gate) Admit() (release func(), err error) {
	g.init()
	select {
	case g.admit <- struct{}{}:
		return func() { <-g.admit }, nil
	default:
		return nil, ErrRateLimited
	}
}

// Verify runs fn as the single verification in flight. Admitted callers wait
// here (bounded by ctx), which is what the queue depth is for.
func (g *Gate) Verify(ctx context.Context, fn func() error) error {
	g.init()
	select {
	case g.verify <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-g.verify }()
	return fn()
}

// Wait holds until the failure floor has elapsed since start, or ctx ends. It is
// applied to EVERY failure path — wrong password, no password configured,
// locked out, malformed body — so none of them is distinguishable by latency.
func (g *Gate) Wait(ctx context.Context, start time.Time) {
	floor := g.Floor
	if floor == 0 {
		floor = FailureFloor
	}
	if floor < 0 {
		return
	}
	// Deliberately the real clock, not the Now seam: this is a wall-clock
	// latency guarantee to a remote attacker, and a frozen test clock must not
	// be able to turn it into an unbounded sleep. Tests that do not measure it
	// set Floor negative instead.
	remaining := floor - time.Since(start)
	if remaining <= 0 {
		return
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
