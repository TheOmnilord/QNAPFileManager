package workerpool

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return p, c
}

func alice() backend.Principal {
	return backend.Principal{User: "alice", UID: 1001, GID: 1001, Groups: []int{1001, 100}}
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
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
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

func TestUnknownOpIsUnsupported(t *testing.T) {
	p, _ := testPool(t, nil)
	c, err := p.acquire(context.Background(), alice())
	if err != nil {
		t.Fatal(err)
	}
	defer p.release(c)
	_, _, err = p.call(context.Background(), c, wproto.OpChmod, wproto.ChmodReq{Path: []byte("/top.txt"), Mode: 0o644})
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}
