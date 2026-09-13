package workerpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// clock is the injectable time source: the idle reaper and the restart budget
// are the two pieces of lifecycle that would otherwise need a test to sleep.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)}
}

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

// crashForTest kills a worker the way a segfault would: the connection breaks
// without a bye, so the pool has to notice it through the reader goroutine.
func (p *Pool) crashForTest(t *testing.T, key string) {
	t.Helper()
	p.mu.Lock()
	c := p.workers[key]
	p.mu.Unlock()
	if c == nil {
		t.Fatalf("no worker for %q to crash", key)
	}
	_ = c.tr.Close()
	select {
	case <-c.gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the pool did not notice the crash")
	}
}

func testTree(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	if err := os.MkdirAll(filepath.Join(base, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "dir", "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "top.txt"), []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	return r, base
}

func testPool(t *testing.T, tweak func(*Options)) (*Pool, *clock) {
	t.Helper()
	root, _ := testTree(t)
	c := newClock()
	o := Options{
		Root:        root,
		InProcess:   true,
		Max:         4,
		IdleTimeout: 10 * time.Minute,
		CallTimeout: 20 * time.Second,
		Limits:      wproto.Limits{ListMax: 5000},
		Logger:      log.New(io.Discard, "", 0),
		Now:         c.now,
	}
	if tweak != nil {
		tweak(&o)
	}
	p := NewWithOptions(o)
	t.Cleanup(func() { shutdownForTest(t, p) })
	return p, c
}

// testWait is the longest anything in this package's tests may wait for
// anything. Shutdown waits for a worker's process however long that takes —
// which is right in production and fatal in a test, because a fixture whose
// exit never comes turns a cleanup into a hang, and a hang is reported by the
// runner as the whole package timing out ten minutes later with no failing
// assertion to read. Every wait here is bounded by this, and a wait that
// expires fails the test that owns it and says what it was waiting for.
const testWait = 30 * time.Second

// shutdownForTest stops a pool inside testWait and reports what it found. It
// is what every cleanup uses: an unbounded Shutdown in a t.Cleanup is the one
// call in this file that can hang without ever naming a test.
func shutdownForTest(t *testing.T, p *Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// stopForTest is shutdownForTest for the fixtures that are deliberately left
// broken — a worker with no process behind it, a transport that was closed
// under the pool — where the shutdown's own complaint is expected and only the
// hang is a failure.
func stopForTest(t *testing.T, p *Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	if err := p.Shutdown(ctx); errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("shutdown did not finish within %s: something is waiting for an exit that never comes", testWait)
	} else if err != nil {
		t.Logf("shutdown: %v", err)
	}
}

// workerForTest is the current worker for a key, read under the pool lock.
func (p *Pool) workerForTest(t *testing.T, key string) *client {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.workers[key]
	if c == nil {
		t.Fatalf("no worker for %q", key)
	}
	return c
}

func alice() backend.Principal {
	return backend.Principal{User: "alice", UID: 1001, GID: 1001, Groups: []int{1001, 100}}
}

// terminates gives a hand-made client the one thing every real one has: a
// termination that actually ends it. A fixture without it is a worker that can
// never exit, and the moment anything registers it — a failed write now retires
// the client that made it — a shutdown waits on that impossible exit for as long
// as the test runner allows. It closes the transports it was given, closes
// exited, and does both exactly once, because terminate is not the only thing
// that reaches for a kill.
//
// The returned channel is closed when the termination has run, so a test can
// synchronise on a retirement instead of racing the goroutine that starts it.
func terminates(c *client, closers ...io.Closer) <-chan struct{} {
	killed := make(chan struct{})
	var once sync.Once
	c.kill = func(context.Context) {
		once.Do(func() {
			for _, cl := range closers {
				_ = cl.Close()
			}
			close(c.exited)
			close(killed)
		})
	}
	return killed
}

func TestRoundTrips(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	if p.Mode() != ModeInProcess {
		t.Fatalf("mode = %q", p.Mode())
	}
	if err := p.Ping(ctx, who); err != nil {
		t.Fatalf("ping: %v", err)
	}

	l, err := p.List(ctx, who, "/", fsx.ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if l.Total != 2 || l.Path != "/" {
		t.Fatalf("listing = %+v", l)
	}
	// The jail root reached the worker in the hello frame: "/" is the fixture
	// directory, not this machine's root.
	found := map[string]fsx.Entry{}
	for _, e := range l.Entries {
		found[e.Name] = e
	}
	if found["dir"].Type != "dir" || found["top.txt"].Type != "file" {
		t.Fatalf("entries = %+v", l.Entries)
	}

	e, err := p.Stat(ctx, who, "/dir/file.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if e.Size != 5 || e.Name != "file.txt" || e.Path != "/dir/file.txt" {
		t.Fatalf("entry = %+v", e)
	}

	f, oe, err := p.OpenRead(ctx, who, "/dir/file.txt")
	if err != nil {
		t.Fatalf("openread: %v", err)
	}
	defer f.Close()
	if oe.Size != 5 {
		t.Errorf("entry = %+v", oe)
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q, %v", b, err)
	}

	// One worker served all of that.
	if s := p.Stats(); len(s) != 1 || s[0].Key != who.Key() || s[0].Calls == 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestReadlinkRoundTrip(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	// Learn the base through the pool rather than reaching around it.
	p.mu.Lock()
	base := p.opts.Root.Base()
	p.mu.Unlock()
	if err := os.Symlink(filepath.Join(base, "dir"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	target, err := p.Readlink(ctx, who, "/link")
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target == "" {
		t.Fatal("readlink returned nothing")
	}
	if _, err := p.Readlink(ctx, who, "/top.txt"); err == nil {
		t.Error("readlink of a regular file must fail")
	}
}

// TestResolveRoundTrip exercises OpResolve end to end through the in-process
// pool: the request crosses the net.Pipe to the worker goroutine, is resolved as
// the user by fsops.ResolvePath, and the canonical API path comes back. This is
// the front-end's replacement for resolving symlinks in the root process
// (round-3 finding 2).
func TestResolveRoundTrip(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	// A plain existing directory resolves to itself under followLeaf.
	if got, err := p.Resolve(ctx, who, "/dir", true); err != nil {
		t.Fatalf("Resolve(/dir, followLeaf=true): %v", err)
	} else if got != "/dir" {
		t.Errorf("got %q, want /dir", got)
	}
	// A not-yet-existing leaf is kept literal under !followLeaf (a mkdir target).
	if got, err := p.Resolve(ctx, who, "/dir/newname", false); err != nil {
		t.Fatalf("Resolve(/dir/newname, followLeaf=false): %v", err)
	} else if got != "/dir/newname" {
		t.Errorf("got %q, want /dir/newname", got)
	}

	// A symlinked parent comes back under its canonical spelling.
	p.mu.Lock()
	base := p.opts.Root.Base()
	p.mu.Unlock()
	if err := os.Symlink(filepath.Join(base, "dir"), filepath.Join(base, "plink")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if got, err := p.Resolve(ctx, who, "/plink/file.txt", false); err != nil {
		t.Fatalf("Resolve(/plink/file.txt, followLeaf=false): %v", err)
	} else if got != "/dir/file.txt" {
		t.Errorf("got %q, want /dir/file.txt", got)
	}

	// A missing path still surfaces the honest error across the wire.
	if _, err := p.Resolve(ctx, who, "/nope/child", true); err == nil {
		t.Error("resolving through a missing directory must fail")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want an ErrNotExist", err)
	}
}

func TestErrorsCrossTheWire(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	_, err := p.List(ctx, who, "/nope", fsx.ListOptions{})
	if err == nil {
		t.Fatal("listing a missing directory must fail")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want an ErrNotExist", err)
	}
	if code := fsx.Code(err); code != "not_found" {
		t.Errorf("code = %q, want not_found", code)
	}
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("err = %T, want a *RemoteError", err)
	}
	if re.Path != "/nope" || re.Message == "" {
		t.Errorf("remote error = %+v", re)
	}

	_, _, err = p.OpenRead(ctx, who, "/dir")
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Errorf("opening a directory = %v, want ErrUnsupported", err)
	}
	if _, err := p.Stat(ctx, who, "relative"); !errors.Is(err, fsx.ErrNotAbsolute) && fsx.Code(err) != "bad_request" {
		t.Errorf("a relative path = %v", err)
	}
}

func TestConcurrentCallsShareOneWorker(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	const n = 40
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			switch i % 3 {
			case 0:
				_, err = p.List(ctx, who, "/", fsx.ListOptions{})
			case 1:
				_, err = p.Stat(ctx, who, "/top.txt")
			default:
				err = p.Ping(ctx, who)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent call: %v", err)
		}
	}
	// Single-flight: ten parallel requests from one page load spawn one
	// worker, not ten.
	if s := p.Stats(); len(s) != 1 {
		t.Fatalf("%d workers were spawned, want 1", len(s))
	}
}

func TestIdleReap(t *testing.T) {
	p, clk := testPool(t, func(o *Options) { o.IdleTimeout = 30 * time.Second })
	ctx := context.Background()
	who := alice()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	p.reapIdle()
	if len(p.Stats()) != 1 {
		t.Fatal("a worker that was just used must not be reaped")
	}

	clk.advance(29 * time.Second)
	p.reapIdle()
	if len(p.Stats()) != 1 {
		t.Fatal("reaped before the idle timeout")
	}

	clk.advance(2 * time.Second)
	p.reapIdle()
	if s := p.Stats(); len(s) != 0 {
		t.Fatalf("the idle worker was not reaped: %+v", s)
	}

	// And the next request brings one back.
	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	if len(p.Stats()) != 1 {
		t.Fatal("the pool did not respawn")
	}
}

// TestNeverReapABusyWorker holds a call open across a reap sweep.
func TestNeverReapABusyWorker(t *testing.T) {
	p, clk := testPool(t, func(o *Options) { o.IdleTimeout = time.Second })
	who := alice()

	c, err := p.acquire(context.Background(), who)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Hour)
	p.reapIdle()
	if len(p.Stats()) != 1 {
		t.Fatal("a worker with a call in flight was reaped")
	}
	p.release(c)
	p.reapIdle()
	if len(p.Stats()) != 1 {
		t.Fatal("the release restarts the idle clock, it does not reap immediately")
	}
	clk.advance(2 * time.Second)
	p.reapIdle()
	if len(p.Stats()) != 0 {
		t.Fatal("it should be reapable once the call is done and the timeout has passed")
	}
}

func TestMaxAndLRUEviction(t *testing.T) {
	p, clk := testPool(t, func(o *Options) { o.Max = 2 })
	ctx := context.Background()
	a := backend.Principal{User: "a", UID: 101, GID: 101}
	b := backend.Principal{User: "b", UID: 102, GID: 102}
	c := backend.Principal{User: "c", UID: 103, GID: 103}

	if err := p.Ping(ctx, a); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second)
	if err := p.Ping(ctx, b); err != nil {
		t.Fatal(err)
	}
	if len(p.Stats()) != 2 {
		t.Fatalf("stats = %+v", p.Stats())
	}
	clk.advance(time.Second)
	// a is the least recently used idle worker, so it goes.
	if err := p.Ping(ctx, c); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, s := range p.Stats() {
		keys[s.Key] = true
	}
	if len(keys) != 2 || keys[a.Key()] || !keys[b.Key()] || !keys[c.Key()] {
		t.Fatalf("after eviction the pool holds %v, want b and c", keys)
	}

	// With every worker busy there is nothing to evict and the caller is told
	// so rather than queued.
	held := make([]*client, 0, 2)
	for _, who := range []backend.Principal{b, c} {
		w, err := p.acquire(ctx, who)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, w)
	}
	if err := p.Ping(ctx, a); !errors.Is(err, ErrWorkerBusy) {
		t.Fatalf("err = %v, want ErrWorkerBusy", err)
	}
	for _, w := range held {
		p.release(w)
	}
}

func TestCrashGivesWorkerGoneThenRespawns(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	before := p.Stats()[0]

	// An in-flight call must be released with the worker_gone sentinel rather
	// than hang until its deadline.
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := p.call(ctx, c, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
		done <- err
	}()
	// The call may well have completed already; either way the crash below
	// must not leave anything waiting.
	p.crashForTest(t, who.Key())
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, fsx.ErrWorkerGone) {
			t.Fatalf("in-flight call = %v, want nil or ErrWorkerGone", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight call did not come back after the crash")
	}
	p.release(c)

	// A call on the dead worker is worker_gone...
	if _, _, err := p.call(ctx, c, wproto.OpPing, nil); !errors.Is(err, fsx.ErrWorkerGone) {
		t.Fatalf("call on a dead worker = %v", err)
	}
	// ...and the next request through the pool respawns.
	if err := p.Ping(ctx, who); err != nil {
		t.Fatalf("respawn: %v", err)
	}
	after := p.Stats()[0]
	if after.Restarts != 1 {
		t.Errorf("restarts = %d, want 1", after.Restarts)
	}
	if after.Started.Equal(before.Started) && after.Calls >= before.Calls+100 {
		t.Error("the pool kept the dead worker")
	}
}

func TestRestartBudget(t *testing.T) {
	p, clk := testPool(t, func(o *Options) {
		o.RestartBudget = 3
		o.RestartWindow = time.Minute
		o.RestartCooldown = time.Minute
	})
	ctx := context.Background()
	who := alice()

	// The budget allows three restarts; the fourth crash locks the uid out.
	for i := 0; i < 4; i++ {
		if err := p.Ping(ctx, who); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
		p.crashForTest(t, who.Key())
	}
	err := p.Ping(ctx, who)
	if !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("err = %v, want ErrWorkerUnavailable", err)
	}
	// Still refused while the cooldown runs.
	clk.advance(30 * time.Second)
	if err := p.Ping(ctx, who); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("err = %v, want the cooldown to hold", err)
	}
	// And allowed again afterwards.
	clk.advance(31 * time.Second)
	if err := p.Ping(ctx, who); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
}

func TestShutdown(t *testing.T) {
	root, _ := testTree(t)
	p := NewWithOptions(Options{
		Root:      root,
		InProcess: true,
		Logger:    log.New(io.Discard, "", 0),
	})
	ctx := context.Background()
	who := alice()
	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c := p.workers[who.Key()]

	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if len(p.Stats()) != 0 {
		t.Fatal("shutdown left workers behind")
	}
	select {
	case <-c.gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker was not stopped")
	}
	if err := p.Ping(ctx, who); !errors.Is(err, ErrClosed) {
		t.Fatalf("after shutdown, ping = %v, want ErrClosed", err)
	}
	// Idempotent.
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

func TestProcessModeIsLinuxOnly(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("process mode works here; this asserts the refusal elsewhere")
	}
	root, _ := testTree(t)
	p := NewWithOptions(Options{Root: root, Mode: ModeProcess, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })
	err := p.Ping(context.Background(), alice())
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestPrincipalKeyIsThePoolKey(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	// Two sessions of the same user share one worker; root mode gets its own.
	one := backend.Principal{User: "alice", UID: 1001, GID: 1001}
	two := backend.Principal{User: "alice", UID: 1001, GID: 1001, Groups: []int{100}}
	adm := backend.Principal{User: "admin", UID: 0, GID: 0, Root: true}
	for _, who := range []backend.Principal{one, two, adm} {
		if err := p.Ping(ctx, who); err != nil {
			t.Fatal(err)
		}
	}
	if s := p.Stats(); len(s) != 2 {
		t.Fatalf("%d workers, want 2 (uid:1001 and root): %+v", len(s), s)
	}
	if adm.Key() != "root" || one.Key() != "uid:1001" {
		t.Fatalf("keys = %q, %q", adm.Key(), one.Key())
	}
}

// TestCancelledCallerIsNotSent: a request whose caller has gone away never
// reaches the worker, and the cancellation is what the caller sees.
func TestCancelledCallerIsNotSent(t *testing.T) {
	p, _ := testPool(t, func(o *Options) { o.CallTimeout = time.Second })
	who := alice()
	c, err := p.acquire(context.Background(), who)
	if err != nil {
		t.Fatal(err)
	}
	defer p.release(c)
	before := p.Stats()[0].Calls

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.call(ctx, c, wproto.OpPing, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := p.List(ctx, who, "/", fsx.ListOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list err = %v, want context.Canceled", err)
	}
	if after := p.Stats()[0].Calls; after != before {
		t.Errorf("calls went from %d to %d; nothing should have been sent", before, after)
	}
}

// TestCredentialChangeRetiresTheWorker: a worker's kernel credentials are
// fixed at fork time, so when the user's groups change the process has to go.
// Reusing it by uid alone kept revoked memberships alive for as long as the
// worker did.
func TestCredentialChangeRetiresTheWorker(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	before := backend.Principal{User: "alice", UID: 1001, GID: 1001, Groups: []int{100, 1001}}
	if err := p.Ping(ctx, before); err != nil {
		t.Fatal(err)
	}
	first := p.workerForTest(t, before.Key())

	// The same membership in another order, or listed twice, is the same
	// identity: respawning over that would be a self-inflicted restart storm.
	same := before
	same.Groups = []int{1001, 100, 100}
	if err := p.Ping(ctx, same); err != nil {
		t.Fatal(err)
	}
	if got := p.workerForTest(t, same.Key()); got != first {
		t.Fatal("reordered groups must not respawn the worker")
	}

	// Losing a group must retire it.
	after := before
	after.Groups = []int{1001}
	if err := p.Ping(ctx, after); err != nil {
		t.Fatal(err)
	}
	second := p.workerForTest(t, after.Key())
	if second == first {
		t.Fatal("the worker outlived a credential change")
	}
	if second.cred != credsOf(after) {
		t.Fatalf("the new worker carries %s, want %s", second.cred, credsOf(after))
	}
	select {
	case <-first.gone:
	case <-time.After(10 * time.Second):
		t.Fatal("the superseded worker was never stopped")
	}
	if s := p.Stats(); len(s) != 1 {
		t.Fatalf("%d workers, want exactly one for the key: %+v", len(s), s)
	}

	// The primary gid counts too, and so does root mode — which has its own
	// key, so it gets its own worker rather than retiring this one.
	gid := after
	gid.GID = 50
	if err := p.Ping(ctx, gid); err != nil {
		t.Fatal(err)
	}
	if third := p.workerForTest(t, gid.Key()); third == second {
		t.Fatal("a changed primary gid must retire the worker")
	}
}

// TestCredentialChangeWaitsForInFlightCalls: the retirement must not cut off
// work that was already accepted under the old credentials.
func TestCredentialChangeWaitsForInFlightCalls(t *testing.T) {
	p, _ := testPool(t, nil)
	ctx := context.Background()
	who := alice()
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}

	changed := who
	changed.Groups = []int{7}
	if err := p.Ping(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if p.workerForTest(t, changed.Key()) == c {
		t.Fatal("the pool kept handing out the stale worker")
	}
	if c.isDead() {
		t.Fatal("a worker with a call in flight was killed under its caller")
	}
	if _, _, err := p.call(ctx, c, wproto.OpPing, nil); err != nil {
		t.Fatalf("the retiring worker stopped serving the call it had accepted: %v", err)
	}

	p.release(c)
	select {
	case <-c.gone:
	case <-time.After(10 * time.Second):
		t.Fatal("the retiring worker was not stopped once its calls finished")
	}
}

// TestPendingSpawnsCountAgainstMax: twenty simultaneous first requests for
// twenty uids used to pass the capacity check together, because a reservation
// in p.spawning was not counted — twenty-two processes with Max: 1.
func TestPendingSpawnsCountAgainstMax(t *testing.T) {
	const max = 2
	gate := make(chan struct{})
	var (
		mu         sync.Mutex
		live, peak int
		p          *Pool
	)
	p, _ = testPool(t, func(o *Options) {
		o.Max = max
		o.newWorker = func(who backend.Principal) (*client, error) {
			mu.Lock()
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()
			defer func() {
				mu.Lock()
				live--
				mu.Unlock()
			}()
			// Hold the reservation open so every other request meets a pool
			// that is full of pending spawns rather than of workers.
			<-gate
			return p.spawnInProcess(who)
		}
	})

	const n = 20
	ctx := context.Background()
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- p.Ping(ctx, backend.Principal{User: fmt.Sprintf("u%d", i), UID: 3000 + i, GID: 100})
		}(i)
	}
	time.AfterFunc(300*time.Millisecond, func() { close(gate) })
	wg.Wait()
	close(errs)

	for err := range errs {
		// Being told the pool is full is the correct answer for the requests
		// that did not get a slot; anything else is not.
		if err != nil && !errors.Is(err, ErrWorkerBusy) {
			t.Fatalf("ping: %v", err)
		}
	}
	mu.Lock()
	got := peak
	mu.Unlock()
	if got > max {
		t.Fatalf("%d workers were being started at once, want at most Max=%d", got, max)
	}
	if s := p.Stats(); len(s) > max {
		t.Fatalf("%d live workers, want at most %d: %+v", len(s), max, s)
	}
}

// TestFailedStartupChargesTheRestartBudget: a worker that dies before
// answering hello never enters p.workers, so the crash-accounting path cannot
// see it. Uncharged, a permanently broken worker was respawned on every single
// request.
func TestFailedStartupChargesTheRestartBudget(t *testing.T) {
	boom := errors.New("the worker exited before hello")
	var spawns atomic.Int64
	p, _ := testPool(t, func(o *Options) {
		o.RestartBudget = 2
		o.RestartWindow = time.Minute
		o.RestartCooldown = time.Minute
		o.newWorker = func(backend.Principal) (*client, error) {
			spawns.Add(1)
			return nil, boom
		}
	})
	ctx := context.Background()
	who := alice()

	// The budget pays for the first two failures, which are reported as what
	// they are rather than as a lockout.
	for i := 0; i < 2; i++ {
		err := p.Ping(ctx, who)
		if !errors.Is(err, boom) {
			t.Fatalf("ping %d = %v, want the startup failure itself", i, err)
		}
		if errors.Is(err, ErrWorkerUnavailable) {
			t.Fatalf("ping %d locked the uid out while the budget still had room", i)
		}
	}
	// The one that spends it says so...
	if err := p.Ping(ctx, who); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("the failure that spends the budget = %v, want ErrWorkerUnavailable", err)
	}
	tried := spawns.Load()
	if tried != 3 {
		t.Fatalf("%d spawn attempts, want 3", tried)
	}
	// ...and afterwards nothing is even attempted until the cooldown passes.
	for i := 0; i < 3; i++ {
		if err := p.Ping(ctx, who); !errors.Is(err, ErrWorkerUnavailable) {
			t.Fatalf("during the cooldown, ping = %v, want ErrWorkerUnavailable", err)
		}
	}
	if n := spawns.Load() - tried; n != 0 {
		t.Fatalf("%d processes were started after the budget was spent, want none", n)
	}
}

// fakeTransport is a worker that never was: every frame written to it is
// recorded, and the test decides what comes back and when. It claims to pass
// descriptors so the ownership rules around them can be exercised without a
// Unix socket, which the dev box does not have.
type fakeTransport struct {
	mu     sync.Mutex
	writes []wproto.Frame
	in     chan result
	closed chan struct{}
	once   sync.Once
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{in: make(chan result, 4), closed: make(chan struct{})}
}

func (t *fakeTransport) Read() (wproto.Frame, []*os.File, error) {
	select {
	case r := <-t.in:
		return r.f, r.files, nil
	case <-t.closed:
		return wproto.Frame{}, nil, io.EOF
	}
}

func (t *fakeTransport) Write(f wproto.Frame, files []*os.File) error {
	t.mu.Lock()
	t.writes = append(t.writes, f)
	t.mu.Unlock()
	closeAll(files)
	return nil
}

// WriteWithin never has to wait here: the recorder always takes the frame.
func (t *fakeTransport) WriteWithin(_ time.Duration, f wproto.Frame, files []*os.File) error {
	return t.Write(f, files)
}

func (t *fakeTransport) PassesFDs() bool { return true }

func (t *fakeTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *fakeTransport) written() []wproto.Frame {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]wproto.Frame(nil), t.writes...)
}

// isClosed reports whether a descriptor has been released, by closing it again:
// a second Close is the one answer that is os.ErrClosed on every platform,
// where File.Stat on Windows just passes a stale handle to the kernel. It is
// destructive, so a test asks once and at the end.
func isClosed(f *os.File) bool {
	return errors.Is(f.Close(), os.ErrClosed)
}

func tempFile(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestACancelledCallNeverAbandonsADescriptor: deliver used to take the pending
// entry out of the map and then send on its channel with the lock released. A
// caller that cancelled in that window left the download's descriptor sitting
// in a buffered channel nobody would ever read — a file held open in the root
// front-end until the daemon restarted. Both orders now close it exactly once.
func TestACancelledCallNeverAbandonsADescriptor(t *testing.T) {
	c := newClient(alice())
	c.tr = newFakeTransport()

	deliverFD := func(id uint64, f *os.File) wproto.Frame {
		ok, err := wproto.NewOK(id, wproto.OpenReadResp{})
		if err != nil {
			t.Fatal(err)
		}
		ok.NFD = 1
		return ok
	}

	register := func(id uint64) *pending {
		p := &pending{ch: make(chan result, 1)}
		c.mu.Lock()
		c.pending[id] = p
		c.mu.Unlock()
		return p
	}

	// The reply lands first — taking the id out of the table with it — and the
	// caller gives up a moment later. This is the order that leaked.
	first := tempFile(t, "delivered")
	pend7 := register(7)
	c.deliver(deliverFD(7, first), []*os.File{first}, true, nil)
	c.abandon(7, pend7)
	if !isClosed(first) {
		t.Error("a descriptor delivered just before the caller gave up was left open")
	}

	// The caller gives up first and the reply lands afterwards.
	second := tempFile(t, "late")
	pend8 := register(8)
	c.abandon(8, pend8)
	c.deliver(deliverFD(8, second), []*os.File{second}, true, nil)
	if !isClosed(second) {
		t.Error("a descriptor that arrived after the cancellation was left open")
	}

	// A live caller still gets its descriptor, open.
	third := tempFile(t, "wanted")
	pend9 := register(9)
	c.deliver(deliverFD(9, third), []*os.File{third}, true, nil)
	r := <-pend9.ch
	if len(r.files) != 1 || isClosed(r.files[0]) {
		t.Fatalf("the caller must receive its descriptor open: %+v", r.files)
	}
}

// TestACancelledCallerTellsTheWorkerToStop is the front-end half of
// cancellation propagation: dropping the caller frees this end only, and the
// worker would otherwise keep the slot for a reply nobody will read.
func TestACancelledCallerTellsTheWorkerToStop(t *testing.T) {
	p := NewWithOptions(Options{InProcess: true, CallTimeout: time.Minute, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })

	c := newClient(alice())
	tr := newFakeTransport()
	c.tr = tr
	terminates(c, tr)
	t.Cleanup(func() { _ = tr.Close() })
	go c.readLoop(nil)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, _, err := p.call(ctx, c, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
		errc <- err
	}()

	var id uint64
	for deadline := time.Now().Add(10 * time.Second); ; {
		for _, f := range tr.written() {
			if f.Op == wproto.OpList {
				id = f.ID
			}
		}
		if id != 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == 0 {
		t.Fatal("the request was never sent")
	}

	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	var got *wproto.CancelReq
	for _, f := range tr.written() {
		if f.Op != wproto.OpCancel {
			continue
		}
		var req wproto.CancelReq
		if err := f.Unmarshal(&req); err != nil {
			t.Fatal(err)
		}
		got = &req
	}
	if got == nil {
		t.Fatal("a cancelled caller must send an OpCancel frame")
	}
	if got.ReqID != id {
		t.Errorf("the cancel names request %d, want %d", got.ReqID, id)
	}
}

// liveForTest counts everything the pool is holding a process for: registered
// workers, reservations for one being started, and the ones on their way out.
func (p *Pool) liveForTest() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.workers) + len(p.spawning) + len(p.retiring)
}

// TestARetiringWorkerStillCountsAgainstMax: a worker superseded by a credential
// change leaves p.workers immediately but keeps running until the calls it had
// already accepted are done. Untracked, that slot was handed straight to the
// replacement — so with Max=1 a credential change during a request produced two
// live workers, and repeating it accumulated processes past the ceiling an
// operator had set on a 1 GB ARM NAS.
func TestARetiringWorkerStillCountsAgainstMax(t *testing.T) {
	p, _ := testPool(t, func(o *Options) { o.Max = 1 })
	ctx := context.Background()
	who := alice()

	held, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	if n := p.liveForTest(); n != 1 {
		t.Fatalf("%d live workers, want 1", n)
	}

	changed := who
	changed.Groups = []int{7}
	if err := p.Ping(ctx, changed); !errors.Is(err, ErrWorkerBusy) {
		t.Fatalf("err = %v, want ErrWorkerBusy: the only slot is still held by the worker being retired", err)
	}
	if n := p.liveForTest(); n != 1 {
		t.Fatalf("%d live workers after the credential change, want 1", n)
	}
	if held.isDead() {
		t.Fatal("a worker with a call in flight was killed under its caller")
	}

	// Once the retiring process is really gone the slot comes back.
	p.release(held)
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := p.Ping(ctx, changed)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrWorkerBusy) {
			t.Fatalf("ping: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the retiring worker's slot was never released")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-held.gone:
	default:
		t.Error("the slot came back while the superseded worker was still running")
	}
	if n := p.liveForTest(); n != 1 {
		t.Fatalf("%d live workers, want 1", n)
	}
}

// TestShutdownStopsARetiringWorker: Shutdown used to collect p.workers only, so
// a superseded worker — a whole process holding a user's credentials and the
// jail's descriptor — was left running and Shutdown reported success over it.
func TestShutdownStopsARetiringWorker(t *testing.T) {
	root, _ := testTree(t)
	p := NewWithOptions(Options{
		Root:      root,
		InProcess: true,
		Logger:    log.New(io.Discard, "", 0),
	})
	ctx := context.Background()
	who := alice()

	held, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	changed := who
	changed.Groups = []int{7}
	if err := p.Ping(ctx, changed); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	_, tracked := p.retiring[held]
	p.mu.Unlock()
	if !tracked {
		t.Fatal("a superseded worker with a call in flight must stay tracked until its process is gone")
	}

	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := p.Shutdown(sctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case <-held.exited:
	default:
		t.Fatal("shutdown returned while the retiring worker was still running")
	}
}

// TestGoodbyeNeverHangsOnAWorkerThatStoppedReading is the shutdown deadlock the
// in-process pipe made concrete: a worker that has taken the goodbye stops
// reading while it waits for its handlers, the goodbye's own timeout then tried
// to write a cancellation into that pipe — synchronously and with no deadline —
// and terminate never reached the transport close or the kill.
func TestGoodbyeNeverHangsOnAWorkerThatStoppedReading(t *testing.T) {
	p := NewWithOptions(Options{InProcess: true, CallTimeout: time.Minute, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })

	ours, theirs := net.Pipe()
	c := newClient(alice())
	c.tr = wproto.NewTransport(ours)
	terminates(c, theirs)
	go c.readLoop(nil)

	peer := wproto.NewTransport(theirs)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			f, files, err := peer.Read()
			closeAll(files)
			if err != nil {
				return
			}
			if f.Op == wproto.OpBye {
				// Exactly what the worker does: take the goodbye, then stop
				// reading until the handlers it is waiting for have finished.
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); p.terminate(c) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("terminate never returned: the goodbye's cancellation blocked on a worker that had stopped reading")
	}
	<-stopped
	select {
	case <-c.exited:
	default:
		t.Error("terminate returned without reaching the kill")
	}
}

// TestAWriteToAWorkerThatNeverReadsTimesOut: every write the pool makes is
// bounded. A socket's send buffer fills and a net.Pipe has no buffer at all, so
// an unbounded write is a wait on a worker's goodwill — in the root front-end,
// on the goroutine serving a user's request.
func TestAWriteToAWorkerThatNeverReadsTimesOut(t *testing.T) {
	p := NewWithOptions(Options{InProcess: true, CallTimeout: 500 * time.Millisecond, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })

	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = theirs.Close() })
	c := newClient(alice())
	c.tr = wproto.NewTransport(ours)
	// The failed write retires this client, which puts it in the pool's
	// accounting — so it needs a termination that ends it, or the shutdown in
	// the cleanup below waits for an exit that can never happen and the test
	// hangs until the runner's timeout.
	killed := terminates(c, theirs)
	go c.readLoop(nil)

	done := make(chan error, 1)
	go func() {
		_, _, err := p.call(context.Background(), c, wproto.OpPing, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the write must fail rather than succeed against a peer that never read")
		}
		if !errors.Is(err, fsx.ErrWorkerGone) {
			t.Fatalf("err = %v, want ErrWorkerGone", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a write to a worker that never reads blocked the caller indefinitely")
	}
	// The retirement runs on a goroutine of its own. Waiting for it here is what
	// keeps the cleanup from racing it, and proves the write failure really did
	// end the worker rather than only the call.
	select {
	case <-killed:
	case <-time.After(30 * time.Second):
		t.Fatal("the worker that never read was never terminated")
	}
}

// TestACancelledStartupStillChargesTheRestartBudget: the charge used to be
// skipped whenever the caller's context had been cancelled, so an authenticated
// user who disconnected after the process had been forked and before hello
// completed could have replacement processes started for ever without ever
// spending the budget that exists to stop exactly that.
func TestACancelledStartupStillChargesTheRestartBudget(t *testing.T) {
	var spawns atomic.Int64
	p, _ := testPool(t, func(o *Options) {
		o.Max = 8
		o.RestartBudget = 2
		o.RestartWindow = time.Minute
		o.RestartCooldown = time.Minute
		o.newWorker = func(who backend.Principal) (*client, error) {
			// The process starts, and then never answers hello.
			spawns.Add(1)
			c := newClient(who)
			tr := newFakeTransport()
			c.tr = tr
			terminates(c, tr)
			return c, nil
		}
	})
	ctx := context.Background()
	who := alice()

	for i := 0; i < 3; i++ {
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err := p.Ping(cctx, who)
		cancel()
		if err == nil {
			t.Fatalf("ping %d succeeded against a worker that never answered hello", i)
		}
	}
	if n := spawns.Load(); n != 3 {
		t.Fatalf("%d processes were started, want 3", n)
	}
	// The budget is spent, and it was spent by cancelled callers.
	if err := p.Ping(ctx, who); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("err = %v, want ErrWorkerUnavailable", err)
	}
	if n := spawns.Load(); n != 3 {
		t.Fatalf("%d processes were started once the budget was spent, want 3", n)
	}
}

// TestUnknownOpIsUnsupported: the Op vocabulary is closed, so a frame naming
// something this worker does not implement is refused rather than interpreted.
//
// The op is deliberately invented rather than borrowed from the real list. It
// used to be OpChmod, which was unimplemented at the time — and when M3
// implemented it, this test stopped testing anything and started performing a
// real chmod inside the fixture instead.
func TestUnknownOpIsUnsupported(t *testing.T) {
	p, _ := testPool(t, nil)
	c, err := p.acquire(context.Background(), alice())
	if err != nil {
		t.Fatal(err)
	}
	defer p.release(c)
	_, _, err = p.call(context.Background(), c, wproto.Op("no-such-operation"), struct{}{})
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// stuckWorker is a worker that answers every frame and never dies: its kill
// closes the pipe and returns, and exited stays open — which is what a process
// parked in uninterruptible filesystem I/O looks like from here. Signals do not
// reach it, and no amount of waiting makes it go.
//
// It is the deliberate exception to the rule terminates enforces everywhere
// else, and the release is what keeps it honest: it is registered as a cleanup
// here, which runs before the pool's own shutdown cleanup (they run last in,
// first out), so the shutdown at the end of the test has something that can
// actually exit to wait for.
//
// The returned release ends the pretence, so the test can watch the slot come
// back and so nothing is left blocked when the test is over.
func stuckWorker(t *testing.T, who backend.Principal) (*client, func()) {
	t.Helper()
	ours, theirs := net.Pipe()
	c := newClient(who)
	c.tr = wproto.NewTransport(ours)
	c.pid = 4242
	c.kill = func(context.Context) { _ = theirs.Close() }

	peer := wproto.NewTransport(theirs)
	go func() {
		for {
			f, files, err := peer.Read()
			closeAll(files)
			if err != nil {
				return
			}
			var body any
			if f.Op == wproto.OpHello {
				body = wproto.HelloResp{PID: 4242, UID: who.UID, GID: who.GID}
			}
			resp, err := wproto.NewOK(f.ID, body)
			if err != nil {
				return
			}
			if err := peer.Write(resp, nil); err != nil {
				return
			}
		}
	}()

	var once sync.Once
	release := func() { once.Do(func() { close(c.exited) }) }
	t.Cleanup(release)
	return c, release
}

// TestAWorkerThatWillNotExitKeepsItsSlot: the retirement accounting used to
// give a slot back after a timeout whether or not the process had gone. A
// worker stuck in uninterruptible I/O therefore survived while its replacement
// started beside it — over the Max an operator set on a 1 GB NAS — and, worse,
// the pool had dropped its last reference to it, so the shutdown that followed
// could find nothing to wait for. The slot now stays reserved until the kernel
// says the process is gone.
func TestAWorkerThatWillNotExitKeepsItsSlot(t *testing.T) {
	var (
		mu      sync.Mutex
		release func()
	)
	p, clk := testPool(t, func(o *Options) {
		o.Max = 1
		// Short enough that the janitor's own sweep interval (a quarter of it,
		// floored at a second) comes round promptly.
		o.IdleTimeout = 4 * time.Second
		o.newWorker = func(who backend.Principal) (*client, error) {
			c, rel := stuckWorker(t, who)
			mu.Lock()
			release = rel
			mu.Unlock()
			return c, nil
		}
	})
	ctx := context.Background()
	if err := p.Ping(ctx, alice()); err != nil {
		t.Fatal(err)
	}
	c := p.workerForTest(t, alice().Key())

	// Let the janitor retire it, and wait until the signal ladder has run.
	clk.advance(time.Minute)
	select {
	case <-c.gone:
	case <-time.After(30 * time.Second):
		t.Fatal("the idle worker was never retired")
	}

	// It has been terminated and it has not exited. Nothing may take its place —
	// not now, and not after the grace the accounting used to give up at, which
	// is why this waits past stuckWorkerReport rather than sampling once.
	bob := backend.Principal{User: "bob", UID: 1002, GID: 1002}
	time.Sleep(stuckWorkerReport + 2*time.Second)
	if err := p.Ping(ctx, bob); !errors.Is(err, ErrWorkerBusy) {
		t.Fatalf("err = %v, want ErrWorkerBusy: a worker that has not exited still holds its slot", err)
	}
	if n := p.liveForTest(); n != 1 {
		t.Fatalf("%d live workers, want 1", n)
	}
	deadline := time.Now()

	// Once the kernel finally lets go, the slot comes back on its own.
	mu.Lock()
	rel := release
	mu.Unlock()
	rel()
	for {
		if err := p.Ping(ctx, bob); err == nil {
			break
		} else if !errors.Is(err, ErrWorkerBusy) {
			t.Fatalf("ping after the stuck worker exited: %v", err)
		}
		if time.Now().After(deadline.Add(20 * time.Second)) {
			t.Fatal("the slot was never released after the process exited")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestShutdownCancelsAndAwaitsAPendingStartup: a worker in the middle of its
// hello lives in p.spawning and nowhere else. Shutdown collected p.workers and
// p.retiring, so it walked straight past that startup, reported success and
// closed the jail root — and the process the handshake produced was then
// registered for termination by a goroutine belonging to a pool that was
// supposed to be gone.
func TestShutdownCancelsAndAwaitsAPendingStartup(t *testing.T) {
	root, _ := testTree(t)
	started := make(chan *client, 1)
	p := NewWithOptions(Options{
		Root:      root,
		InProcess: true,
		Logger:    log.New(io.Discard, "", 0),
		newWorker: func(who backend.Principal) (*client, error) {
			// The process comes up and then never answers hello — the slow NAS
			// a shutdown has to be able to interrupt.
			c := newClient(who)
			tr := newFakeTransport()
			c.tr = tr
			terminates(c, tr)
			started <- c
			return c, nil
		},
	})

	pinged := make(chan error, 1)
	go func() { pinged <- p.Ping(context.Background(), alice()) }()

	var c *client
	select {
	case c = <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("the startup never began")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	begin := time.Now()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if el := time.Since(begin); el >= helloTimeout {
		t.Fatalf("shutdown took %s: it waited for the handshake to time out rather than cancelling it", el)
	}
	select {
	case <-c.exited:
	default:
		t.Fatal("shutdown returned while a worker that was still starting up was running")
	}
	if n := p.liveForTest(); n != 0 {
		t.Fatalf("%d workers left behind by shutdown, want 0", n)
	}
	select {
	case <-pinged:
	case <-time.After(20 * time.Second):
		t.Fatal("the request that was starting the worker never returned")
	}
}

// TestShutdownStopsRunningWorkersWhileAStartupIsStuck: a startup that cannot be
// cancelled — one parked in fork(2), or in a cmd.Start that had no context to
// interrupt it — used to spend the whole shutdown deadline on its own. The
// workers that were running, registered and perfectly killable were collected
// only afterwards, so Shutdown returned the deadline error with every one of
// them still alive; and because the pool was already marked closed, the next
// call returned an immediate success over them.
func TestShutdownStopsRunningWorkersWhileAStartupIsStuck(t *testing.T) {
	root, _ := testTree(t)
	var (
		gate      = make(chan struct{})
		gateOnce  sync.Once
		open      = func() { gateOnce.Do(func() { close(gate) }) }
		stuck     = make(chan struct{})
		stuckOnce sync.Once
		p         *Pool
	)
	// However this test ends, the spawn must be let go of: the pool's shutdown
	// waits for it, and so would the runner.
	defer open()

	p = NewWithOptions(Options{
		Root:      root,
		InProcess: true,
		Max:       4,
		Logger:    log.New(io.Discard, "", 0),
		newWorker: func(who backend.Principal) (*client, error) {
			if who.UID == alice().UID {
				return p.spawnInProcess(who)
			}
			// The second spawn is stuck where nothing can reach it: there is no
			// client yet, so there is no transport to close and no process to
			// signal, and the startup's cancellation has nothing to act on.
			stuckOnce.Do(func() { close(stuck) })
			<-gate
			return nil, errors.New("the fork never came back")
		},
	})

	ctx := context.Background()
	if err := p.Ping(ctx, alice()); err != nil {
		t.Fatal(err)
	}
	running := p.workerForTest(t, alice().Key())

	bob := backend.Principal{User: "bob", UID: 1002, GID: 1002}
	pinged := make(chan error, 1)
	go func() { pinged <- p.Ping(ctx, bob) }()
	select {
	case <-stuck:
	case <-time.After(20 * time.Second):
		t.Fatal("the second startup never began")
	}

	// The deadline is spent on the startup nothing can cancel...
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := p.Shutdown(sctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown = %v, want the deadline error while a startup is stuck", err)
	}
	// ...and the worker that was running has still been stopped, inside it.
	select {
	case <-running.exited:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown spent its deadline waiting for a startup and left a running worker alive")
	}

	// A second call waits for the same operation. Returning nil here — which is
	// what a pool that only remembers "closed" does — would be a report that
	// everything had stopped while a spawn was still running.
	sctx2, cancel2 := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel2()
	begin := time.Now()
	if err := p.Shutdown(sctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the second shutdown = %v, want the deadline error: the startup has not finished", err)
	}
	if el := time.Since(begin); el < 400*time.Millisecond {
		t.Fatalf("the second shutdown returned after %s: it did not wait for the first", el)
	}

	// Once the spawn finally comes back, the operation completes and says so.
	open()
	fctx, fcancel := context.WithTimeout(ctx, 30*time.Second)
	defer fcancel()
	if err := p.Shutdown(fctx); err != nil {
		t.Fatalf("the shutdown after the startup returned: %v", err)
	}
	if n := p.liveForTest(); n != 0 {
		t.Fatalf("%d workers left behind by shutdown, want 0", n)
	}
	select {
	case <-pinged:
	case <-time.After(20 * time.Second):
		t.Fatal("the request whose worker was starting never returned")
	}
}

// TestAFailedWriteRetiresTheWorker: a write that fails or times out leaves the
// framing desynchronised and the worker on the other end still running its
// handler. Failing the client settles only this end of the conversation; the
// process was left for the next acquire or the idle sweep to notice, which for
// a worker wedged mid-handler could be never.
func TestAFailedWriteRetiresTheWorker(t *testing.T) {
	p := NewWithOptions(Options{InProcess: true, CallTimeout: 500 * time.Millisecond, Logger: log.New(io.Discard, "", 0)})
	t.Cleanup(func() { stopForTest(t, p) })

	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = theirs.Close() })
	c := newClient(alice())
	c.tr = wproto.NewTransport(ours)
	killed := terminates(c)
	go c.readLoop(nil)

	// Registered the way a completed spawn would leave it, so the retirement is
	// visible in the pool's own accounting rather than only in this client.
	p.mu.Lock()
	p.workers[c.key] = c
	p.mu.Unlock()

	if _, _, err := p.call(context.Background(), c, wproto.OpPing, nil); err == nil {
		t.Fatal("the write must fail against a peer that never reads")
	} else if !errors.Is(err, fsx.ErrWorkerGone) {
		t.Fatalf("err = %v, want ErrWorkerGone", err)
	}

	select {
	case <-killed:
	case <-time.After(30 * time.Second):
		t.Fatal("a terminal write failure left the worker process running")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if n := p.liveForTest(); n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker was never taken out of the pool's accounting")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRemoteErrorReconstructsOwnerUnset guards the worker->pool boundary the
// in-process fake mutator bypasses (high-effort review): an owner_unset error
// (a create that succeeded but whose chown to the real user failed) must keep
// that code across the wire, or the front-end's partial-create warning surfaces
// as a 500 on the real NAS. It exercises both halves: wproto.NewErr classifies
// the joined error, and remoteError reconstructs a value fsx.Code reads back.
func TestRemoteErrorReconstructsOwnerUnset(t *testing.T) {
	worker := errors.Join(fsx.ErrOwnerUnset, &fs.PathError{Op: "fchown", Path: "/share/x/new", Err: syscall.EPERM})
	frame := wproto.NewErr(7, worker, []byte("/share/x/new"))
	if frame.Err == nil || frame.Err.Code != "owner_unset" {
		t.Fatalf("NewErr wire code = %+v, want owner_unset", frame.Err)
	}
	got := remoteError(frame.Err)
	if !errors.Is(got, fsx.ErrOwnerUnset) {
		t.Fatalf("reconstructed error does not Is fsx.ErrOwnerUnset: %v", got)
	}
	if code := fsx.Code(got); code != "owner_unset" {
		t.Fatalf("fsx.Code(reconstructed) = %q, want owner_unset", code)
	}
	// A different code must not collide.
	if code := fsx.Code(remoteError(&wproto.Err{Code: "worker_gone", Message: "gone"})); code != "worker_gone" {
		t.Fatalf("worker_gone round trip = %q", code)
	}
}

// TestRemoteErrorReconstructsInvalidTarget is the same boundary guard for the
// M2-B engine's "destination is inside the source" refusal.
func TestRemoteErrorReconstructsInvalidTarget(t *testing.T) {
	worker := fmt.Errorf("copy %q into %q: %w", "/share/a", "/share/a/b", fsx.ErrInvalidTarget)
	frame := wproto.NewErr(8, worker, []byte("/share/a/b"))
	if frame.Err == nil || frame.Err.Code != "invalid_target" {
		t.Fatalf("NewErr wire code = %+v, want invalid_target", frame.Err)
	}
	got := remoteError(frame.Err)
	if !errors.Is(got, fsx.ErrInvalidTarget) {
		t.Fatalf("reconstructed error does not Is fsx.ErrInvalidTarget: %v", got)
	}
	if code := fsx.Code(got); code != "invalid_target" {
		t.Fatalf("fsx.Code(reconstructed) = %q, want invalid_target", code)
	}
}

// TestRemoteErrorReconstructsChanged is the same boundary guard for the
// upload's "what arrived is not what was declared" refusal (M2-C).
func TestRemoteErrorReconstructsChanged(t *testing.T) {
	frame := wproto.NewErr(9, fmt.Errorf("upload of %q: %w", "/share/x/f", fsx.ErrChanged), []byte("/share/x/f"))
	if frame.Err == nil || frame.Err.Code != "changed" {
		t.Fatalf("NewErr wire code = %+v, want changed", frame.Err)
	}
	got := remoteError(frame.Err)
	if !errors.Is(got, fsx.ErrChanged) {
		t.Fatalf("reconstructed error does not Is fsx.ErrChanged: %v", got)
	}
	if code := fsx.Code(got); code != "changed" {
		t.Fatalf("fsx.Code(reconstructed) = %q, want changed", code)
	}
}
