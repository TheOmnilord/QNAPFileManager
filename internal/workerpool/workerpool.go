// Package workerpool owns the per-uid worker processes and is the production
// implementation of backend.Backend.
//
// One worker per uid, never per session (identity plan §2.3): several browser
// tabs, several QTS sessions and the reconnect after a re-login all share one
// process. An administrator who has armed root mode gets a worker spawned with
// no Credential at all — the same code path, not a bypass, so there is exactly
// one way filesystem work happens in this app.
//
// The pool runs in two modes. "process" re-executes the binary over an
// anonymous socketpair and is what the NAS does. "inprocess" runs the same
// worker loop as a goroutine over a net.Pipe, which is what the Windows dev
// box and the tests use: it exercises the whole protocol and the whole
// lifecycle, and only impersonation and descriptor passing are missing,
// because those are exactly the two things that cannot be simulated without
// lying about what the kernel would do (INV-2).
package workerpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/worker"
	"qnapfilemanager/internal/wproto"
)

// Modes.
const (
	// ModeProcess spawns a real process with the user's credentials.
	ModeProcess = "process"
	// ModeInProcess runs the worker loop as a goroutine in this process. It
	// impersonates nobody: everything runs as whoever started the daemon.
	ModeInProcess = "inprocess"
)

// Defaults, all overridable through Options.
const (
	DefaultMax             = 8
	DefaultIdleTimeout     = 10 * time.Minute
	DefaultCallTimeout     = 2 * time.Minute
	DefaultRestartBudget   = 5
	DefaultRestartWindow   = time.Minute
	DefaultRestartCooldown = time.Minute
	// helloTimeout bounds the first round trip with a new worker. A worker
	// that cannot answer hello is not going to answer anything.
	helloTimeout = 20 * time.Second
	// byeTimeout bounds the graceful half of a shutdown.
	byeTimeout = 2 * time.Second
	// termGrace is how long SIGTERM is given before SIGKILL (§2.6).
	termGrace = 5 * time.Second
	// pingAfterIdle is how long a worker may sit unused before the next
	// acquire proves it is alive. Pinging on every acquire would double the
	// round trips of every listing to catch a case that only happens after
	// the worker has been sitting idle.
	pingAfterIdle = 5 * time.Second
)

// Errors the pool adds to the fsx vocabulary.
var (
	// ErrWorkerUnavailable: the restart budget is spent. Something about this
	// user's worker is broken and retrying immediately would fork-bomb a NAS.
	ErrWorkerUnavailable = errors.New("the worker for this user is unavailable: it stopped repeatedly")
	// ErrWorkerBusy: the pool is at max and every worker has work in flight.
	ErrWorkerBusy = errors.New("every worker slot is busy")
	// ErrClosed: the pool has been shut down.
	ErrClosed = errors.New("the worker pool is shut down")
)

// Options is the full configuration of a Pool. New fills it from config.Config;
// tests use NewWithOptions to inject a clock and shorter timers.
type Options struct {
	// Root is the -jail mapping. Its base is sent to every worker in the
	// hello frame and applied there, so nothing above the worker can address
	// a path outside it.
	Root     fsx.Root
	Platform *platform.Platform
	IDs      *idmap.Map

	// Mode is ModeProcess or ModeInProcess. Empty picks ModeProcess on Linux
	// and ModeInProcess everywhere else.
	Mode string
	// InProcess forces ModeInProcess. -impersonate on the dev box sets it.
	InProcess bool

	Max         int
	IdleTimeout time.Duration
	CallTimeout time.Duration

	Umask  uint32
	Limits wproto.Limits

	RestartBudget   int
	RestartWindow   time.Duration
	RestartCooldown time.Duration

	Logger  *log.Logger
	Version string

	// Executable is the binary to re-execute in process mode. Empty means
	// os.Executable(), which is what production does; a test that wants a
	// real worker process points this at a freshly built one, because its own
	// test binary does not understand -worker.
	Executable string

	// Now is the clock. Nil means time.Now; tests replace it to age workers
	// without sleeping.
	Now func() time.Time
}

func (o Options) normalise() Options {
	if o.Mode == "" {
		o.Mode = ModeProcess
		if runtime.GOOS != "linux" {
			o.Mode = ModeInProcess
		}
	}
	if o.InProcess {
		o.Mode = ModeInProcess
	}
	if o.Max <= 0 {
		o.Max = DefaultMax
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = DefaultCallTimeout
	}
	if o.RestartBudget <= 0 {
		o.RestartBudget = DefaultRestartBudget
	}
	if o.RestartWindow <= 0 {
		o.RestartWindow = DefaultRestartWindow
	}
	if o.RestartCooldown <= 0 {
		o.RestartCooldown = DefaultRestartCooldown
	}
	if o.Logger == nil {
		o.Logger = log.New(io.Discard, "", 0)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Pool is the backend.Backend implementation. The zero value is not usable.
type Pool struct {
	opts Options

	mu       sync.Mutex
	workers  map[string]*client
	spawning map[string]chan struct{}
	budgets  map[string]*budget
	closed   bool

	nextID atomic.Uint64

	stopJanitor chan struct{}
	janitorGone chan struct{}
}

// budget is one uid's restart history.
type budget struct {
	times        []time.Time
	blockedUntil time.Time
}

// New builds the pool the daemon runs with. plat and ids may be nil; the
// worker then detects the mount table itself and reports numeric ownership.
func New(cfg config.Config, root fsx.Root, plat *platform.Platform, ids *idmap.Map) *Pool {
	idle, err := cfg.Worker.IdleTimeoutDuration()
	if err != nil {
		idle = 0 // Validate rejects this at startup; be harmless if it slips through.
	}
	umask, err := cfg.Worker.UmaskValue()
	if err != nil {
		umask = 0o022
	}
	return NewWithOptions(Options{
		Root:        root,
		Platform:    plat,
		IDs:         ids,
		Max:         cfg.Worker.Max,
		IdleTimeout: idle,
		Umask:       umask,
		Limits: wproto.Limits{
			ListMax:      cfg.Limits.ListMax,
			MaxTextBytes: cfg.Limits.MaxTextBytes,
		},
	})
}

// NewWithOptions builds a pool from an explicit Options.
func NewWithOptions(o Options) *Pool {
	p := &Pool{
		opts:        o.normalise(),
		workers:     map[string]*client{},
		spawning:    map[string]chan struct{}{},
		budgets:     map[string]*budget{},
		stopJanitor: make(chan struct{}),
		janitorGone: make(chan struct{}),
	}
	go p.janitor()
	return p
}

// Mode reports which of the two modes this pool runs in.
func (p *Pool) Mode() string { return p.opts.Mode }

// Max reports the worker ceiling.
func (p *Pool) Max() int { return p.opts.Max }

func (p *Pool) now() time.Time { return p.opts.Now() }

// janitor reaps idle workers. The interval is derived from the idle timeout so
// a test with a one-second timeout does not wait a minute for the sweep.
func (p *Pool) janitor() {
	defer close(p.janitorGone)
	every := p.opts.IdleTimeout / 4
	if every > time.Minute {
		every = time.Minute
	}
	if every < time.Second {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-p.stopJanitor:
			return
		case <-t.C:
			p.reapIdle()
		}
	}
}

// reapIdle retires every worker that has been unused for the idle timeout. A
// worker with a call in flight is never reaped, whatever its last-used time
// says (§2.6).
func (p *Pool) reapIdle() {
	now := p.now()
	var dead []*client
	p.mu.Lock()
	for key, c := range p.workers {
		if !c.idleSince(now, p.opts.IdleTimeout) {
			continue
		}
		delete(p.workers, key)
		dead = append(dead, c)
	}
	p.mu.Unlock()
	for _, c := range dead {
		p.opts.Logger.Printf("workerpool: reaping the idle worker for %s (pid %d)", c.key, c.pid)
		go p.terminate(c)
	}
}

// Shutdown stops every worker: bye first, then the signals. It is safe to call
// twice and it never blocks longer than ctx allows.
func (p *Pool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	all := make([]*client, 0, len(p.workers))
	for key, c := range p.workers {
		all = append(all, c)
		delete(p.workers, key)
	}
	p.mu.Unlock()

	close(p.stopJanitor)
	<-p.janitorGone

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, c := range all {
			wg.Add(1)
			go func(c *client) { defer wg.Done(); p.terminate(c) }(c)
		}
		wg.Wait()
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats is one worker's line in /api/diag.
type Stats struct {
	Key      string    `json:"key"`
	UID      int       `json:"uid"`
	Root     bool      `json:"root"`
	Mode     string    `json:"mode"`
	PID      int       `json:"pid"`
	HelloUID int       `json:"helloUid"`
	HelloGID int       `json:"helloGid"`
	Groups   []int     `json:"groups,omitempty"`
	Started  time.Time `json:"started"`
	LastUsed time.Time `json:"lastUsed"`
	InFlight int       `json:"inFlight"`
	Calls    uint64    `json:"calls"`
	Restarts int       `json:"restarts"`
	Blocked  bool      `json:"blocked,omitempty"`
}

// Stats reports the live workers, newest state first read under the lock so a
// diagnostic page can never see a half-updated worker.
func (p *Pool) Stats() []Stats {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Stats, 0, len(p.workers))
	for key, c := range p.workers {
		s := c.stats()
		s.Key = key
		s.Mode = p.opts.Mode
		if b := p.budgets[key]; b != nil {
			s.Restarts = len(b.times)
			s.Blocked = now.Before(b.blockedUntil)
		}
		out = append(out, s)
	}
	return out
}

// --- backend.Backend ---------------------------------------------------

var _ backend.Backend = (*Pool)(nil)

// List returns one page of a directory listing, read by the user's worker.
func (p *Pool) List(ctx context.Context, who backend.Principal, dir string, opts fsx.ListOptions) (fsx.Listing, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return fsx.Listing{}, err
	}
	defer p.release(c)
	f, _, err := p.call(ctx, c, wproto.OpList, wproto.ListReq{Dir: []byte(dir), Opts: opts})
	if err != nil {
		return fsx.Listing{}, err
	}
	var resp wproto.ListResp
	if err := f.Unmarshal(&resp); err != nil {
		return fsx.Listing{}, err
	}
	return resp.Listing, nil
}

// Stat returns a single entry without following the final symlink.
func (p *Pool) Stat(ctx context.Context, who backend.Principal, path string) (fsx.Entry, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return fsx.Entry{}, err
	}
	defer p.release(c)
	f, _, err := p.call(ctx, c, wproto.OpStat, wproto.StatReq{Path: []byte(path)})
	if err != nil {
		return fsx.Entry{}, err
	}
	var resp wproto.StatResp
	if err := f.Unmarshal(&resp); err != nil {
		return fsx.Entry{}, err
	}
	return resp.Entry, nil
}

// Readlink returns the raw target of a symlink.
func (p *Pool) Readlink(ctx context.Context, who backend.Principal, path string) (string, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return "", err
	}
	defer p.release(c)
	f, _, err := p.call(ctx, c, wproto.OpReadlink, wproto.ReadlinkReq{Path: []byte(path)})
	if err != nil {
		return "", err
	}
	var resp wproto.ReadlinkResp
	if err := f.Unmarshal(&resp); err != nil {
		return "", err
	}
	return string(resp.Target), nil
}

// OpenRead opens a regular file as the principal and returns the descriptor.
//
// In process mode the worker performs the open — so the kernel checks the
// user's permissions — and passes the descriptor back over SCM_RIGHTS; the
// front-end only ever streams from a descriptor it was given. In in-process
// mode there is no second process and no descriptor passing, so the file is
// opened here; that mode impersonates nobody anyway, which is why it is
// confined to the dev loop and the tests.
func (p *Pool) OpenRead(ctx context.Context, who backend.Principal, path string) (*os.File, fsx.Entry, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	defer p.release(c)

	if p.opts.Mode == ModeInProcess {
		return fsops.OpenRead(ctx, p.opts.Root, path)
	}

	f, files, err := p.call(ctx, c, wproto.OpOpenRead, wproto.OpenReadReq{Path: []byte(path)})
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	if len(files) != 1 {
		closeAll(files)
		return nil, fsx.Entry{}, fmt.Errorf("the worker returned %d descriptors for %s: %w", len(files), path, wproto.ErrFDMismatch)
	}
	var resp wproto.OpenReadResp
	if err := f.Unmarshal(&resp); err != nil {
		closeAll(files)
		return nil, fsx.Entry{}, err
	}
	return files[0], resp.Entry, nil
}

// Ping proves the principal's worker is alive, spawning it if needed.
func (p *Pool) Ping(ctx context.Context, who backend.Principal) error {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return err
	}
	defer p.release(c)
	_, _, err = p.call(ctx, c, wproto.OpPing, nil)
	return err
}

// --- lifecycle ---------------------------------------------------------

// acquire returns a live worker for who, spawning one if necessary, with the
// caller counted as in flight so the janitor cannot reap it underneath.
// release must be called for every successful acquire.
func (p *Pool) acquire(ctx context.Context, who backend.Principal) (*client, error) {
	// Two attempts: a worker that turns out to be dead on the liveness check
	// is retired and the second pass spawns a fresh one. A third failure in a
	// row is a real fault, not a race.
	for attempt := 0; attempt < 2; attempt++ {
		c, fresh, idleFor, err := p.get(ctx, who)
		if err != nil {
			return nil, err
		}
		if fresh || idleFor < pingAfterIdle {
			return c, nil
		}
		// The worker has been sitting; prove it is there before a request
		// waits on it.
		pctx, cancel := context.WithTimeout(ctx, helloTimeout)
		_, _, err = p.call(pctx, c, wproto.OpPing, nil)
		cancel()
		if err == nil {
			return c, nil
		}
		p.opts.Logger.Printf("workerpool: the worker for %s did not answer a ping: %v", c.key, err)
		p.release(c)
		p.retire(c, err)
	}
	return nil, fmt.Errorf("%s: %w", who.Key(), ErrWorkerUnavailable)
}

func (p *Pool) release(c *client) { c.done(p.now()) }

// get finds or creates the worker for who. It returns whether the worker was
// just spawned and, if not, how long it had been idle.
func (p *Pool) get(ctx context.Context, who backend.Principal) (c *client, fresh bool, idleFor time.Duration, err error) {
	key := who.Key()
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, 0, err
		}
		now := p.now()
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, false, 0, ErrClosed
		}
		if c := p.workers[key]; c != nil {
			if !c.isDead() {
				idle := c.hold(now)
				p.mu.Unlock()
				return c, false, idle, nil
			}
			// It crashed. Remove it, charge the restart budget, and fall
			// through to a respawn.
			delete(p.workers, key)
			p.noteRestartLocked(key, now)
			corpse := c
			p.mu.Unlock()
			go p.terminate(corpse)
			continue
		}
		if wait, ok := p.spawning[key]; ok {
			// Single-flight: ten parallel requests from one page load spawn
			// one worker, not ten.
			p.mu.Unlock()
			select {
			case <-wait:
			case <-ctx.Done():
				return nil, false, 0, ctx.Err()
			}
			continue
		}
		if b := p.budgets[key]; b != nil && now.Before(b.blockedUntil) {
			left := b.blockedUntil.Sub(now).Round(time.Second)
			p.mu.Unlock()
			return nil, false, 0, fmt.Errorf("%s stopped %d times in %s, not restarting it for another %s: %w",
				key, len(b.times), p.opts.RestartWindow, left, ErrWorkerUnavailable)
		}
		if err := p.makeRoomLocked(now); err != nil {
			p.mu.Unlock()
			return nil, false, 0, err
		}
		wait := make(chan struct{})
		p.spawning[key] = wait
		p.mu.Unlock()

		nc, err := p.spawn(ctx, who)

		p.mu.Lock()
		delete(p.spawning, key)
		switch {
		case err != nil:
		case p.closed:
			err = ErrClosed
		default:
			p.workers[key] = nc
			nc.hold(p.now())
		}
		p.mu.Unlock()
		close(wait)

		if err != nil {
			if nc != nil {
				go p.terminate(nc)
			}
			return nil, false, 0, err
		}
		return nc, true, 0, nil
	}
}

// makeRoomLocked evicts the least recently used idle worker when the pool is
// full. If every worker is busy the caller is told so rather than queued
// behind an unbounded wait (§2.6).
func (p *Pool) makeRoomLocked(now time.Time) error {
	if len(p.workers) < p.opts.Max {
		return nil
	}
	var (
		victimKey string
		victim    *client
	)
	for key, c := range p.workers {
		if c.busy() {
			continue
		}
		if victim == nil || c.lastUse().Before(victim.lastUse()) {
			victimKey, victim = key, c
		}
	}
	if victim == nil {
		return fmt.Errorf("%d workers are running and all of them are busy: %w", len(p.workers), ErrWorkerBusy)
	}
	delete(p.workers, victimKey)
	p.opts.Logger.Printf("workerpool: evicting the least recently used idle worker %s (pid %d)", victimKey, victim.pid)
	go p.terminate(victim)
	return nil
}

// noteRestartLocked charges one crash to a uid and blocks further restarts
// once the budget is spent, so a worker that crashes on startup cannot
// fork-bomb the NAS.
func (p *Pool) noteRestartLocked(key string, now time.Time) {
	b := p.budgets[key]
	if b == nil {
		b = &budget{}
		p.budgets[key] = b
	}
	cut := now.Add(-p.opts.RestartWindow)
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	b.times = append(kept, now)
	if len(b.times) > p.opts.RestartBudget {
		b.blockedUntil = now.Add(p.opts.RestartCooldown)
	}
}

// retire removes a worker from the map (if it is still the current one for its
// key) and terminates it.
func (p *Pool) retire(c *client, cause error) {
	p.mu.Lock()
	if cur, ok := p.workers[c.key]; ok && cur == c {
		delete(p.workers, c.key)
		p.noteRestartLocked(c.key, p.now())
	}
	p.mu.Unlock()
	c.fail(cause)
	go p.terminate(c)
}

// spawn creates one worker and completes the hello handshake, so a worker that
// is returned to a caller is one that has already answered.
func (p *Pool) spawn(ctx context.Context, who backend.Principal) (*client, error) {
	var (
		c   *client
		err error
	)
	if p.opts.Mode == ModeInProcess {
		c, err = p.spawnInProcess(who)
	} else {
		c, err = p.spawnProcess(who)
	}
	if err != nil {
		return nil, err
	}
	go c.readLoop(p.opts.Logger)

	hctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	f, _, err := p.call(hctx, c, wproto.OpHello, wproto.HelloReq{
		JailRoot: p.opts.Root.Base(),
		Umask:    p.opts.Umask,
		Limits:   p.opts.Limits,
	})
	if err != nil {
		return c, fmt.Errorf("the worker for %s did not answer hello: %w", who.Key(), err)
	}
	var hello wproto.HelloResp
	if err := f.Unmarshal(&hello); err != nil {
		return c, err
	}
	if p.opts.Mode == ModeProcess && !who.Root && hello.UID != who.UID {
		// The worker reports what the kernel made it, not what it was asked
		// to be. A mismatch means the Credential did not take, and serving
		// that worker would be serving the wrong identity.
		return c, fmt.Errorf("the worker for %s came up as uid %d, not %d", who.Key(), hello.UID, who.UID)
	}
	c.setHello(hello)
	p.opts.Logger.Printf("workerpool: worker %s ready (mode=%s pid=%d uid=%d gid=%d groups=%v)",
		c.key, p.opts.Mode, hello.PID, hello.UID, hello.GID, hello.Groups)
	return c, nil
}

// spawnInProcess runs the worker loop as a goroutine on the other end of a
// net.Pipe. Everything but impersonation and fd passing is identical.
func (p *Pool) spawnInProcess(who backend.Principal) (*client, error) {
	ours, theirs := net.Pipe()
	c := newClient(who)
	c.tr = wproto.NewTransport(ours)
	c.pid = os.Getpid()

	ctx, cancel := context.WithCancel(context.Background())
	c.kill = func(context.Context) {
		cancel()
		_ = theirs.Close()
	}
	go func() {
		defer close(c.exited)
		defer theirs.Close()
		err := worker.Run(ctx, theirs, worker.Options{
			Version:   p.opts.Version,
			Log:       p.opts.Logger,
			Platform:  p.opts.Platform,
			IDs:       p.opts.IDs,
			InProcess: true,
		})
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
			p.opts.Logger.Printf("workerpool: the in-process worker for %s stopped: %v", c.key, err)
		}
	}()
	return c, nil
}

// terminate ends one worker: bye, then close, then (in process mode) the
// signal ladder. It is idempotent.
func (p *Pool) terminate(c *client) {
	if !c.startTerminating() {
		return
	}
	if !c.isDead() {
		ctx, cancel := context.WithTimeout(context.Background(), byeTimeout)
		if _, _, err := p.call(ctx, c, wproto.OpBye, nil); err != nil {
			p.opts.Logger.Printf("workerpool: %s did not acknowledge bye: %v", c.key, err)
		}
		cancel()
	}
	c.fail(fmt.Errorf("the worker was stopped: %w", fsx.ErrWorkerGone))
	_ = c.tr.Close()
	if c.kill != nil {
		ctx, cancel := context.WithTimeout(context.Background(), termGrace+termGrace)
		c.kill(ctx)
		cancel()
	}
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
