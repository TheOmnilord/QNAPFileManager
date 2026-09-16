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

	// LockoutAfter consecutive failures lock ONE SOURCE for LockoutBase,
	// doubling per further failure from that source to LockoutCap. A success
	// from that source resets it.
	//
	// Per source, not per account (Astra r1 #4). The ladder used to be
	// account-wide, and with exactly one emergency account that made it a
	// weapon: any LAN peer could spend five wrong passwords, lock the sole door
	// for 60 s, renew the exclusion at each expiry well inside its own 10/min
	// budget, and the operator's correct password — or even a fresh
	// set-password — would be refused at the moment they needed it most. Keyed
	// by peer address, a peer can only lock ITSELF out; what still bounds
	// account-wide guessing is the serialised bcrypt (one at a time, queue 4)
	// plus the per-source token bucket, which together cap the whole LAN at a
	// few guesses a second however many hosts join in.
	//
	// The state is in memory and a restart clears it, deliberately: persisting
	// it would let an attacker lock the operator out of their own emergency door
	// across restarts, which is the worse failure (§5.3).
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

// ErrLockedOut is the per-source lockout. It maps to 429 locked_out with a
// Retry-After, and the response body never reveals whether the password offered
// was right.
var ErrLockedOut = errors.New("breakglass: locked out")

// Outcome is what one serialised verification turn concluded about the
// credential. Only OutcomeFailed walks the ladder: a malformed body, an
// unreadable config file or a door with no password configured at all are our
// problem or a broken client's, and letting five of them reach the cap would
// hand a peer a way to shut its own emergency door without ever guessing
// anything (round-1 P2-7).
type Outcome int

const (
	// OutcomeNeutral reached no credential verdict.
	OutcomeNeutral Outcome = iota
	// OutcomeFailed is a password the stored hash rejected.
	OutcomeFailed
	// OutcomeSucceeded is a verified password.
	OutcomeSucceeded
)

// Verdict is the lockout state one verification turn observed and produced. It
// is decided and committed INSIDE the turn (Astra r1 #7), so a queued attempt
// can never act on a verdict that another attempt has since changed.
type Verdict struct {
	// Locked is true when the source was already locked out when its turn came
	// up; the verification never ran.
	Locked bool
	// RetryAfter is how long the source must wait: the remaining lockout when
	// Locked, or the rung this turn just entered when Entered.
	RetryAfter time.Duration
	// Left is true on the one turn that observed a lockout expiring, so the
	// caller writes the "lockout ended" milestone exactly once.
	Left bool
	// Entered is true on the turn that started a lockout or lengthened it to a
	// new rung, so each transition is a single milestone.
	Entered bool
	// Failures is the source's consecutive-failure count after this turn.
	Failures int
}

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

	admitOnce sync.Once
	admit     chan struct{} // InFlight slots: total attempts in flight
	verify    chan struct{} // 1 slot: one bcrypt at a time
}

// sourceState is everything the gate tracks about one peer address: its token
// bucket and its own rung of the lockout ladder (Astra r1 #4). Both live in the
// same bounded LRU table, so a spray from many addresses can neither grow
// memory nor buy extra state.
//
// The bound has one honest consequence: a source whose entry is evicted loses
// its lockout with it. Doing that deliberately means making requests from
// MaxSources other addresses, and a peer that controls 256 LAN addresses could
// simply guess from them instead — the per-source ladder was never what bounded
// account-wide guessing (that is the serialised bcrypt), so the eviction buys
// an attacker nothing it did not already have.
type sourceState struct {
	key    string
	tokens float64
	last   time.Time

	failures    int
	lockedUntil time.Time
	// lockAnnounced is true while this source's current lockout has already
	// been reported as entered, so "entered" and "left" are each reported
	// exactly once per lockout rather than on every request during it.
	lockAnnounced bool
}

// lockedAt reports this source's lockout state, clearing one that has expired.
// The caller holds g.mu.
func (s *sourceState) lockedAt(now time.Time) (locked bool, retryAfter time.Duration, left bool) {
	if s.lockedUntil.IsZero() {
		return false, 0, false
	}
	if now.Before(s.lockedUntil) {
		return true, s.lockedUntil.Sub(now), false
	}
	s.lockedUntil = time.Time{}
	wasAnnounced := s.lockAnnounced
	s.lockAnnounced = false
	return false, 0, wasAnnounced
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

// sourceLocked finds or creates ip's entry, evicting the least recently seen
// when the table is full. The caller holds g.mu.
func (g *Gate) sourceLocked(ip string, now time.Time) *sourceState {
	if g.sources == nil {
		g.sources = make(map[string]*list.Element, MaxSources)
	}
	if elem, ok := g.sources[ip]; ok {
		g.lru.MoveToBack(elem)
		return elem.Value.(*sourceState)
	}
	for len(g.sources) >= MaxSources {
		oldest := g.lru.Front()
		if oldest == nil {
			break
		}
		delete(g.sources, oldest.Value.(*sourceState).key)
		g.lru.Remove(oldest)
	}
	s := &sourceState{key: ip, tokens: BucketCapacity, last: now}
	g.sources[ip] = g.lru.PushBack(s)
	return s
}

// AllowSource consumes one token from ip's bucket. It is the first check, before
// anything reads a body or touches bcrypt.
func (g *Gate) AllowSource(ip string) error {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.sourceLocked(ip, now)
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

// Locked reports whether ip is currently locked out and for how much longer.
// left is true on the one call that observes a lockout expiring, so the caller
// can write the "lockout left" milestone exactly once.
//
// A source nobody has seen is not tracked and is not locked: asking must never
// be what creates an entry, or a status query would evict a real one.
func (g *Gate) Locked(ip string) (locked bool, retryAfter time.Duration, left bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	elem, ok := g.sources[ip]
	if !ok {
		return false, 0, false
	}
	return elem.Value.(*sourceState).lockedAt(now)
}

// Failed records one failed verification from ip and returns that source's
// lockout state after it. entered is true only on the attempt that starts a
// lockout (or lengthens it to a new ladder rung), so each transition is a
// single milestone.
func (g *Gate) Failed(ip string) (locked bool, retryAfter time.Duration, entered bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failedLocked(ip, now)
}

func (g *Gate) failedLocked(ip string, now time.Time) (locked bool, retryAfter time.Duration, entered bool) {
	s := g.sourceLocked(ip, now)
	s.failures++
	if s.failures < LockoutAfter {
		return false, 0, false
	}
	d := LockoutBase << (s.failures - LockoutAfter)
	// The shift overflows long before the ladder does anything useful; clamp on
	// the negative as well as on the cap so a very long run of failures cannot
	// produce a lock in the past.
	if d > LockoutCap || d <= 0 {
		d = LockoutCap
	}
	s.lockedUntil = now.Add(d)
	s.lockAnnounced = true
	return true, d, true
}

// Succeeded clears ip's ladder. Only a verified password does this, and it
// clears only the source that offered it.
func (g *Gate) Succeeded(ip string) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.succeededLocked(ip, now)
}

func (g *Gate) succeededLocked(ip string, now time.Time) {
	s := g.sourceLocked(ip, now)
	s.failures = 0
	s.lockedUntil = time.Time{}
	s.lockAnnounced = false
}

// Failures reports ip's consecutive-failure count, for the audit line and the
// tests. An untracked source has none.
func (g *Gate) Failures(ip string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failuresLocked(ip)
}

func (g *Gate) failuresLocked(ip string) int {
	elem, ok := g.sources[ip]
	if !ok {
		return 0
	}
	return elem.Value.(*sourceState).failures
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

// Verify runs fn as the single verification in flight for ip, and owns the
// whole lockout decision for that turn. Admitted callers wait here (bounded by
// ctx), which is what the queue depth is for.
//
// The verdict is read and the outcome committed INSIDE the turn (Astra r1 #7).
// Before, the door asked Locked() before queueing and called Failed() after
// releasing, so four attempts queued behind one another all saw the same
// "unlocked" and the same failure count: they skipped rungs of the ladder, and
// a correct password queued behind the failure that entered a lockout was
// accepted during that lockout. Holding the verification slot across the read,
// the compare and the commit makes those three one atomic step, which is what
// the ladder always assumed they were.
//
// g.mu is deliberately NOT held across fn: that would put every source-bucket
// check on the far side of a cost-15 bcrypt. The verification semaphore is what
// serialises; the mutex only guards the table.
func (g *Gate) Verify(ctx context.Context, ip string, fn func() Outcome) (Verdict, error) {
	g.init()
	select {
	case g.verify <- struct{}{}:
	case <-ctx.Done():
		return Verdict{}, ctx.Err()
	}
	defer func() { <-g.verify }()

	now := g.now()
	g.mu.Lock()
	s := g.sourceLocked(ip, now)
	locked, retry, left := s.lockedAt(now)
	failures := s.failures
	g.mu.Unlock()
	if locked {
		// The verification never runs: a locked source may not spend the
		// process's bcrypt on a guess.
		return Verdict{Locked: true, RetryAfter: retry, Left: left, Failures: failures}, nil
	}

	outcome := fn()

	v := Verdict{Left: left}
	now = g.now()
	g.mu.Lock()
	switch outcome {
	case OutcomeFailed:
		_, v.RetryAfter, v.Entered = g.failedLocked(ip, now)
	case OutcomeSucceeded:
		g.succeededLocked(ip, now)
	}
	v.Failures = g.failuresLocked(ip)
	g.mu.Unlock()
	return v, nil
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
