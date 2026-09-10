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
	// InProcess forces ModeInProcess. The daemon's -dev flag sets it, and that
	// flag is also what allows -impersonate and jailed identity files: nothing
	// in this mode carries kernel credentials, so nothing in it can be trusted
	// to establish an identity either.
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

	// TmpDir is the tmpfs the worker binary is staged into so a non-root worker
	// can exec it even when the install tree (a QTS shared folder) denies that.
	// Empty means /tmp. Tests point it at t.TempDir().
	TmpDir string

	// Now is the clock. Nil means time.Now; tests replace it to age workers
	// without sleeping.
	Now func() time.Time

	// newWorker replaces the spawn half of bringing a worker up (the hello
	// handshake still runs). Production leaves it nil; tests inject one that
	// fails, or one that blocks, to exercise the accounting around it.
	newWorker func(backend.Principal) (*client, error)
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
	spawning map[string]*startup
	// retiring holds the workers that have left p.workers but whose process is
	// not gone yet: one superseded by a credential change and still finishing
	// the calls it accepted, one evicted to make room, one reaped as idle, one
	// that crashed. They are still processes on the NAS holding a user's
	// credentials, so they count against Max and Shutdown waits for them. An
	// entry lives until the client's exited channel closes.
	retiring map[*client]struct{}
	budgets  map[string]*budget
	closed   bool

	// stagedExe is the tmpfs copy of the worker binary. It is created lazily by
	// workerExes and cached only on success, so a transient failure (a full
	// /tmp) does not disable non-root workers until a restart.
	stageMu   sync.Mutex
	stagedExe string

	nextID atomic.Uint64

	stopJanitor chan struct{}
	janitorGone chan struct{}

	// There is exactly one shutdown operation, however many callers ask for
	// one. shutdownOnce starts it, shutdownDone is closed when it has finished
	// and shutdownErr is its result; every caller waits on shutdownDone with a
	// context of its own, so a caller that gives up early gives up on the wait
	// and not on the work. A second call after a timeout therefore waits again
	// rather than reporting a success that never happened.
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
	// shutdownCtx is the context every worker process is started against. It is
	// cancelled when the shutdown has finished with everything it could see, so
	// a process whose fork returned after the last sweep — the one nothing in
	// the pool has a handle for yet — is still killed by os/exec rather than
	// outliving the pool that spawned it.
	shutdownCtx context.Context
	endWorkers  context.CancelFunc
}

// budget is one uid's restart history.
type budget struct {
	times        []time.Time
	blockedUntil time.Time
}

// startup is one worker coming up: the channel every other caller for that uid
// waits on, and the handle Shutdown needs to stop waiting for the NAS.
//
// The cancel is the point. A startup runs on the context of whichever request
// asked for the worker, so a shutdown had nothing to pull on: it collected the
// workers it could see, reported success, and closed the jail root while a
// process it had never heard of was still finishing its handshake — and that
// process was then registered for termination by a goroutine running after the
// pool was supposed to be gone.
type startup struct {
	done   chan struct{}
	cancel context.CancelFunc
}

// New builds the pool the daemon runs with. plat and ids may be nil; the
// worker then detects the mount table itself and reports numeric ownership.
//
// inProcess is the daemon's -dev switch (and is implied off Linux). It picks
// ModeInProcess, where the "workers" are goroutines in this process and nobody
// is impersonated — which is why the caller must also refuse to trust anything
// identity-shaped that only exists in that mode.
//
// logger is the daemon's own logger and must be passed: a worker's stdout and
// stderr, its panic stacks and every lifecycle event are written through it,
// and normalise would otherwise substitute io.Discard and throw away exactly
// the diagnostics an operator who started the daemon with -log came for. A nil
// logger is still tolerated, for a caller that genuinely wants silence.
func New(cfg config.Config, root fsx.Root, plat *platform.Platform, ids *idmap.Map, logger *log.Logger, inProcess bool) *Pool {
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
		InProcess:   inProcess,
		Max:         cfg.Worker.Max,
		IdleTimeout: idle,
		Umask:       umask,
		Limits: wproto.Limits{
			ListMax:      cfg.Limits.ListMax,
			MaxTextBytes: cfg.Limits.MaxTextBytes,
		},
		Logger: logger,
	})
}

// NewWithOptions builds a pool from an explicit Options.
func NewWithOptions(o Options) *Pool {
	p := &Pool{
		opts:         o.normalise(),
		workers:      map[string]*client{},
		spawning:     map[string]*startup{},
		retiring:     map[*client]struct{}{},
		budgets:      map[string]*budget{},
		stopJanitor:  make(chan struct{}),
		janitorGone:  make(chan struct{}),
		shutdownDone: make(chan struct{}),
	}
	p.shutdownCtx, p.endWorkers = context.WithCancel(context.Background())
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
		p.retiring[c] = struct{}{}
		dead = append(dead, c)
	}
	p.mu.Unlock()
	for _, c := range dead {
		p.opts.Logger.Printf("workerpool: reaping the idle worker for %s (pid %d)", c.key, c.pid)
		go p.stopRetired(c)
	}
}

// stopRetired terminates a worker that is being tracked in p.retiring and gives
// its slot back only once the process is really gone. Releasing the slot at
// terminate time instead — which is where the accounting used to end — let the
// replacement start while the old process was still alive, so an operator's
// Max was quietly a ceiling on registered workers rather than on processes.
//
// It waits for exited however long that takes. A worker parked in
// uninterruptible filesystem I/O — a wedged NFS mount, a disk that stopped
// answering — survives SIGKILL until the kernel lets go of it, and it is still a
// process holding a user's credentials, its memory and the jail's descriptor
// while it does. Handing its slot to a replacement anyway put the pool over the
// Max an operator set on a 1 GB NAS and, worse, lost the last reference to it:
// Shutdown could then find nothing to wait for. So the slot stays reserved and
// the fact is logged, loudly and repeatedly, which is the honest report of a
// machine that has a real problem.
func (p *Pool) stopRetired(c *client) {
	p.terminate(c)
	p.awaitExit(c)
	p.mu.Lock()
	delete(p.retiring, c)
	p.mu.Unlock()
}

// stuckWorkerReport is how often a worker that will not die is complained about.
const stuckWorkerReport = termGrace + termGrace

// awaitExit waits for a terminated worker's process to be gone, complaining
// once per stuckWorkerReport until it is.
func (p *Pool) awaitExit(c *client) {
	t := time.NewTicker(stuckWorkerReport)
	defer t.Stop()
	for {
		select {
		case <-c.exited:
			return
		case <-t.C:
			p.opts.Logger.Printf("workerpool: the retired worker for %s (pid %d) has not exited after the full signal ladder — it is probably stuck in uninterruptible I/O. Its slot stays reserved until the kernel releases it.", c.key, c.pid)
		}
	}
}

// stopRetiredWait stops a retired worker and waits for it, but not for ever:
// the callers are requests, and a request must not hang on a process that will
// not die. Only the wait is bounded. The slot is released by stopRetired and by
// nothing else, so giving up here leaves the worker counted — which is what
// makes the next makeRoomLocked refuse rather than exceed Max.
func (p *Pool) stopRetiredWait(ctx context.Context, c *client) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.stopRetired(c)
	}()
	t := time.NewTimer(stuckWorkerReport)
	defer t.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-t.C:
	}
}

// Shutdown stops every worker: bye first, then the signals. It is safe to call
// from several goroutines and safe to call again, and it never blocks longer
// than ctx allows.
//
// The work itself runs once, in the background, and every caller waits on that
// one operation. Doing it on the caller's goroutine meant a caller whose
// deadline expired took the shutdown with it: it returned while workers it had
// not reached yet were still running, and because `closed` was already set the
// next call reported an immediate success over them. A caller that gives up
// here gives up only on the waiting; the termination carries on, and a second
// call waits for it to finish rather than pretending it has.
func (p *Pool) Shutdown(ctx context.Context) error {
	p.shutdownOnce.Do(func() {
		// Set under the lock and before anything else, so that from the moment
		// the first caller returns — whatever it returns — no further worker can
		// be spawned: get checks this while holding the same lock it registers
		// a startup under.
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		go p.runShutdown()
	})
	select {
	case <-p.shutdownDone:
		return p.shutdownErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runShutdown is the single shutdown operation. It terminates everything the
// pool is holding a process for and closes the jail root, and it does not stop
// for anybody's deadline: the callers have their own contexts to give up on.
func (p *Pool) runShutdown() {
	defer close(p.shutdownDone)

	close(p.stopJanitor)
	<-p.janitorGone

	var wg sync.WaitGroup
	for {
		// A worker that is still coming up is a process (or, in-process, a
		// goroutine) that is in p.spawning and nowhere else: it is not in
		// p.workers until its hello has been answered. Cancelling those startups
		// turns them into workers this can collect — without it, Shutdown
		// reported success and closed the jail root while a handshake was still
		// running, and the process it produced was registered for termination
		// afterwards, by a goroutine belonging to a pool that was supposed to be
		// gone.
		//
		// The workers that already exist are collected in the same breath and
		// terminated beside the cancellation, not after it. Waiting for the
		// startups first was the defect: a spawn that cannot be cancelled — one
		// parked in fork(2) or in a blocked cmd.Start — spent the whole deadline
		// on its own, and the workers that were running and killable at the top
		// of the function were still running when the deadline expired.
		p.mu.Lock()
		starting := make([]*startup, 0, len(p.spawning))
		for _, s := range p.spawning {
			starting = append(starting, s)
		}
		all := make([]*client, 0, len(p.workers)+len(p.retiring))
		for key, c := range p.workers {
			all = append(all, c)
			delete(p.workers, key)
		}
		// A worker that is on its way out is still a process holding a user's
		// credentials and still holding the jail's descriptor. Collecting only
		// p.workers left those behind, and Shutdown reported success over them.
		// A startup that finishes late lands here too: p.closed is set by now,
		// so whatever it produced goes straight into p.retiring — which is why
		// this sweep repeats until it finds nothing left.
		for c := range p.retiring {
			all = append(all, c)
			delete(p.retiring, c)
		}
		p.mu.Unlock()

		if len(starting) == 0 && len(all) == 0 {
			break
		}
		for _, c := range all {
			wg.Add(1)
			go func(c *client) {
				defer wg.Done()
				p.terminate(c)
				// terminate returns straight away for a worker somebody else is
				// already stopping, so the exit is waited for rather than
				// assumed: the promise is that nothing of this pool is still
				// running when the operation completes. It is an unbounded wait
				// by design — a worker wedged in uninterruptible I/O is a process
				// that still exists, and saying otherwise would be a lie. The
				// caller's context is what bounds the caller.
				<-c.exited
			}(c)
		}
		for _, s := range starting {
			s.cancel()
		}
		for _, s := range starting {
			<-s.done
		}
	}
	wg.Wait()

	// Everything this pool knows about is gone. Cancelling the workers' context
	// is the backstop for what it might not know about: a fork that returned
	// after the last sweep looked.
	p.endWorkers()

	// The jail's descriptor is the pool's to release: every worker resolved its
	// paths through it, and they are all stopped by now.
	if err := p.opts.Root.Close(); err != nil {
		p.opts.Logger.Printf("workerpool: closing the jail root: %v", err)
		p.shutdownErr = err
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

// --- backend.Mutator ---------------------------------------------------

var _ backend.Mutator = (*Pool)(nil)

// Mkdir creates a directory as the user's worker and returns the new entry.
// mkdir passes no descriptor, so the ordinary RPC path carries it in both
// modes: in-process it travels the net.Pipe to the worker goroutine exactly as
// a real socketpair would.
func (p *Pool) Mkdir(ctx context.Context, who backend.Principal, dir, name string, mode os.FileMode, parents bool) (fsx.Entry, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return fsx.Entry{}, err
	}
	defer p.release(c)
	f, _, err := p.call(ctx, c, wproto.OpMkdir, wproto.MkdirReq{
		Dir:     []byte(dir),
		Name:    []byte(name),
		Mode:    uint32(mode),
		Parents: parents,
	})
	if err != nil {
		return fsx.Entry{}, err
	}
	var resp wproto.StatResp
	if err := f.Unmarshal(&resp); err != nil {
		return fsx.Entry{}, err
	}
	return resp.Entry, nil
}

// Rename moves from to to as the user's worker.
func (p *Pool) Rename(ctx context.Context, who backend.Principal, from, to string, overwrite bool) error {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return err
	}
	defer p.release(c)
	_, _, err = p.call(ctx, c, wproto.OpRename, wproto.RenameReq{
		From:      []byte(from),
		To:        []byte(to),
		Overwrite: overwrite,
	})
	return err
}

// Delete removes one item as the user's worker (M1: single, non-recursive).
func (p *Pool) Delete(ctx context.Context, who backend.Principal, path string) error {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return err
	}
	defer p.release(c)
	_, _, err = p.call(ctx, c, wproto.OpDelete, wproto.DeleteOneReq{Path: []byte(path)})
	return err
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

// release ends one caller's hold. A worker retired for a credential change
// while this call was in flight is stopped here, once it is the last one out.
func (p *Pool) release(c *client) {
	if c.done(p.now()) {
		p.opts.Logger.Printf("workerpool: stopping the superseded worker for %s (pid %d) now that its calls have finished", c.key, c.pid)
		go p.stopRetired(c)
	}
}

// get finds or creates the worker for who. It returns whether the worker was
// just spawned and, if not, how long it had been idle.
func (p *Pool) get(ctx context.Context, who backend.Principal) (c *client, fresh bool, idleFor time.Duration, err error) {
	key := who.Key()
	want := credsOf(who)
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
				if c.cred != want {
					// The user's primary group or supplementary groups
					// changed. A process's credentials are fixed at fork
					// time, so this worker would keep the memberships the
					// user has just lost — and lack the ones just granted —
					// for as long as it lived. It is dropped from the map
					// here, which makes the next pass spawn a fresh one, and
					// stopped as soon as its in-flight calls are done.
					//
					// It stays counted against Max until its process is gone.
					// Dropping it from the accounting the moment it left the
					// map meant that with Max: 1 a credential change during a
					// request immediately allowed a second live worker, and
					// repeating the change accumulated processes outside the
					// limit an operator had set.
					delete(p.workers, key)
					p.retiring[c] = struct{}{}
					stale := c
					p.mu.Unlock()
					p.opts.Logger.Printf("workerpool: retiring the worker for %s: credentials changed from %s to %s",
						key, stale.cred, want)
					if stale.markRetired() {
						// Nothing is in flight, so it can go now — and it goes
						// before the retry rather than beside it, because the
						// slot it still holds is the one the replacement is
						// about to ask for.
						p.stopRetiredWait(ctx, stale)
					}
					continue
				}
				idle := c.hold(now)
				p.mu.Unlock()
				return c, false, idle, nil
			}
			// It crashed. Remove it, charge the restart budget, and fall
			// through to a respawn.
			delete(p.workers, key)
			p.retiring[c] = struct{}{}
			p.noteRestartLocked(key, now)
			corpse := c
			p.mu.Unlock()
			go p.stopRetired(corpse)
			continue
		}
		if s, ok := p.spawning[key]; ok {
			// Single-flight: ten parallel requests from one page load spawn
			// one worker, not ten.
			p.mu.Unlock()
			select {
			case <-s.done:
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
		victim, err := p.makeRoomLocked(now)
		if err != nil {
			p.mu.Unlock()
			return nil, false, 0, err
		}
		if victim != nil {
			p.mu.Unlock()
			// The evicted worker's slot is the one this request is about to
			// take, so it is not handed over until its process has actually
			// gone. Starting the replacement beside it was how Max became a
			// count of map entries rather than of processes.
			p.stopRetiredWait(ctx, victim)
			continue
		}
		// The startup runs on a context of its own, derived from the caller's,
		// so that Shutdown can end a handshake nobody else can reach.
		sctx, scancel := context.WithCancel(ctx)
		s := &startup{done: make(chan struct{}), cancel: scancel}
		p.spawning[key] = s
		p.mu.Unlock()

		nc, err := p.spawn(sctx, who)
		scancel()

		p.mu.Lock()
		delete(p.spawning, key)
		blocked := false
		switch {
		case err != nil:
			// A worker that died before answering hello never entered
			// p.workers, so the crash-accounting path in the branch above
			// cannot charge it. Without this, a worker that fails at startup
			// — a bad binary, an impossible credential, a hung handshake —
			// could be respawned on every request forever.
			//
			// What is charged is the cost that was actually paid: nc is
			// non-nil exactly when a process (or, in-process, a goroutine) was
			// started, and starting one is the expensive part whether or not
			// the caller is still there to receive it. Making that conditional
			// on the caller's context was a way through the budget: an
			// authenticated user who disconnected after the fork and before
			// hello could have replacement processes started for ever without
			// spending anything. A spawn that never got that far, on the other
			// hand, is not charged to a caller who simply gave up — six
			// abandoned page loads must not lock a user out for a minute.
			if nc != nil || ctx.Err() == nil {
				blocked = p.noteRestartLocked(key, p.now())
			}
		case p.closed:
			err = ErrClosed
		default:
			p.workers[key] = nc
			nc.hold(p.now())
		}
		if err != nil && nc != nil {
			// It never reached p.workers, but it is a live process all the
			// same until it has been reaped, so it counts against Max.
			p.retiring[nc] = struct{}{}
		}
		p.mu.Unlock()
		// Closing this is what releases both the other callers for this uid and
		// a Shutdown waiting for the startup. Everything the two of them need to
		// see — p.workers on success, p.retiring on failure — is already in
		// place above, under the lock.
		close(s.done)

		if err != nil {
			if nc != nil {
				go p.stopRetired(nc)
			}
			if blocked {
				err = fmt.Errorf("%s failed to start (%v), not restarting it for another %s: %w",
					key, err, p.opts.RestartCooldown, ErrWorkerUnavailable)
			}
			return nil, false, 0, err
		}
		return nc, true, 0, nil
	}
}

// makeRoomLocked evicts the least recently used idle worker when the pool is
// full. If every worker is busy the caller is told so rather than queued
// behind an unbounded wait (§2.6).
//
// A worker that is still being spawned counts against Max exactly as a running
// one does. It is a reservation, not a hint: twenty simultaneous logins all
// pass this check before any of their workers has finished coming up, and
// counting only p.workers let them all through — twenty-two processes with
// Max: 1, and the memory ceiling an operator set on a 1 GB ARM NAS gone.
//
// A worker on its way out counts for the same reason and for as long as its
// process is alive. Max is a bound on processes on the NAS, not on entries in a
// map, and a worker being evicted or superseded is still holding its memory,
// its descriptors and a user's credentials until the kernel says otherwise.
// It returns the worker it evicted, if any. Stopping it is the caller's job,
// with the pool lock released and before the replacement is reserved.
func (p *Pool) makeRoomLocked(now time.Time) (*client, error) {
	if len(p.workers)+len(p.spawning)+len(p.retiring) < p.opts.Max {
		return nil, nil
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
		return nil, fmt.Errorf("%d workers are running (%d more are starting, %d are stopping) and none of them is idle: %w",
			len(p.workers), len(p.spawning), len(p.retiring), ErrWorkerBusy)
	}
	delete(p.workers, victimKey)
	p.retiring[victim] = struct{}{}
	p.opts.Logger.Printf("workerpool: evicting the least recently used idle worker %s (pid %d)", victimKey, victim.pid)
	return victim, nil
}

// noteRestartLocked charges one crash to a uid and blocks further restarts
// once the budget is spent, so a worker that crashes on startup cannot
// fork-bomb the NAS. It reports whether the key is blocked from here on.
func (p *Pool) noteRestartLocked(key string, now time.Time) bool {
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
	return now.Before(b.blockedUntil)
}

// retire removes a worker from the map (if it is still the current one for its
// key) and terminates it.
func (p *Pool) retire(c *client, cause error) {
	p.mu.Lock()
	if cur, ok := p.workers[c.key]; ok && cur == c {
		delete(p.workers, c.key)
		_ = p.noteRestartLocked(c.key, p.now())
	}
	p.retiring[c] = struct{}{}
	p.mu.Unlock()
	c.fail(cause)
	p.stopRetiredWait(context.Background(), c)
}

// spawn creates one worker and completes the hello handshake, so a worker that
// is returned to a caller is one that has already answered.
func (p *Pool) spawn(ctx context.Context, who backend.Principal) (*client, error) {
	var (
		c   *client
		err error
	)
	switch {
	case p.opts.newWorker != nil:
		c, err = p.opts.newWorker(who)
	case p.opts.Mode == ModeInProcess:
		c, err = p.spawnInProcess(who)
	default:
		c, err = p.spawnProcess(who)
	}
	if err != nil {
		// A fork/exec failure (a non-root worker that cannot traverse the
		// install tree or execute the binary) is otherwise invisible: the
		// caller only sees the mapped error code. Name it here so the reason
		// is in the log the first time, not after a round trip.
		p.opts.Logger.Printf("workerpool: could not start the worker for %s (uid %d): %v", who.Key(), who.UID, err)
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

	// Derived from the pool's context for the same reason the process mode's
	// exec.CommandContext is: a worker loop whose startup finished after the
	// shutdown had swept must not be left reading the filesystem.
	ctx, cancel := context.WithCancel(p.shutdownCtx)
	c.kill = func(kctx context.Context) {
		cancel()
		_ = theirs.Close()
		// Wait for the loop to actually stop, the way the signal ladder does in
		// process mode. Until it returns it still holds the jail's descriptor,
		// and a Shutdown that reported success while a goroutine was still
		// reading the filesystem would be reporting the wrong thing.
		select {
		case <-c.exited:
		case <-kctx.Done():
		case <-time.After(termGrace):
		}
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
