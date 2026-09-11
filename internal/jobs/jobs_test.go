package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// testWait bounds every wait in this file. A job that never starts must fail
// the test that waited for it, not hang the package until the runner's timeout
// reports ten minutes of nothing with no assertion to read.
const testWait = 10 * time.Second

// clock is the injectable time source. Retention and the rate estimate are the
// two pieces of this package that would otherwise need a test to sleep.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)}
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

// gate is a job that reports when it has started and waits to be let go, which
// is how a test holds a semaphore slot without sleeping.
type gate struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGate() *gate {
	return &gate{started: make(chan struct{}), release: make(chan struct{})}
}

func (g *gate) fn(_ context.Context, _ *Progress) (any, error) {
	g.once.Do(func() { close(g.started) })
	<-g.release
	return nil, nil
}

func (g *gate) open() { close(g.release) }

func (g *gate) waitStarted(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.started:
	case <-time.After(testWait):
		t.Fatalf("%s never started", what)
	}
}

func newManager(t *testing.T, l Limits) (*Manager, *clock) {
	t.Helper()
	c := newClock()
	m := New(l)
	m.now = c.now
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return m, c
}

// waitFor polls until cond holds, so a test never sleeps a fixed amount for a
// goroutine that is usually instant.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitState(t *testing.T, m *Manager, id string, want State) Job {
	t.Helper()
	var got Job
	waitFor(t, fmt.Sprintf("job %s to reach %s", id, want), func() bool {
		j, ok := m.Get(id)
		if !ok {
			return false
		}
		got = j
		return j.State == want
	})
	return got
}

// TestKindsMatchTheWireVocabulary pins the one thing this package shares with
// wproto without importing it: a caller hands wproto.JobDelete to Submit and
// gets the metadata semaphore, so the two vocabularies must not drift.
func TestKindsMatchTheWireVocabulary(t *testing.T) {
	pairs := map[Kind]string{
		KindCopy:         wproto.JobCopy,
		KindMove:         wproto.JobMove,
		KindArchive:      wproto.JobArchive,
		KindDelete:       wproto.JobDelete,
		KindSize:         wproto.JobSize,
		KindSearch:       wproto.JobSearch,
		KindChmod:        wproto.JobChmod,
		KindChown:        wproto.JobChown,
		KindTrash:        wproto.JobTrash,
		KindTrashRestore: wproto.JobTrashRestore,
		KindTrashEmpty:   wproto.JobTrashEmpty,
	}
	for k, want := range pairs {
		if string(k) != want {
			t.Errorf("jobs.Kind %q != wproto %q", k, want)
		}
	}
	if WarnCap != wproto.WarnCap {
		t.Errorf("WarnCap = %d, wproto.WarnCap = %d: the two caps must agree", WarnCap, wproto.WarnCap)
	}
	byteMovers := []Kind{KindCopy, KindMove, KindArchive, KindExtract}
	for _, k := range byteMovers {
		if ClassOf(k) != ClassByteMover {
			t.Errorf("ClassOf(%s) = %s, want %s", k, ClassOf(k), ClassByteMover)
		}
	}
	metadata := []Kind{KindDelete, KindSize, KindSearch, KindChmod, KindChown, KindTrash, KindTrashRestore, KindTrashEmpty}
	for _, k := range metadata {
		if ClassOf(k) != ClassMetadata {
			t.Errorf("ClassOf(%s) = %s, want %s", k, ClassOf(k), ClassMetadata)
		}
	}
	// An unknown kind takes the cheaper pool rather than a byte-mover's slot.
	if ClassOf("something-new") != ClassMetadata {
		t.Error("an unrecognised kind must fall into the metadata class")
	}
}

func TestLimitsFromConfigAndDefaults(t *testing.T) {
	l := LimitsFrom(config.Default().Jobs)
	if l != (Limits{ByteMovers: 2, Metadata: 4, QueueDepth: 64, RetainMinutes: 60, RetainCount: 50}) {
		t.Fatalf("LimitsFrom(defaults) = %+v", l)
	}
	m := New(Limits{})
	if got := m.Limits(); got != (Limits{ByteMovers: 2, Metadata: 4, QueueDepth: 64}) {
		t.Fatalf("a zero Limits normalised to %+v", got)
	}
}

func TestSubmitRunsAndRecordsItsResult(t *testing.T) {
	m, _ := newManager(t, Limits{})
	type summary struct {
		Files int `json:"files"`
	}
	job, err := m.Submit(KindDelete, "Deleting 3 items", Meta{
		Src:   []string{"/share/Public/a", "/share/Public/b"},
		Actor: "alice",
		UID:   1001,
	}, func(_ context.Context, p *Progress) (any, error) {
		p.Phase(wproto.PhaseWorking)
		p.Current("/share/Public/a")
		p.Set(3, 3, 0, 0)
		return summary{Files: 3}, nil
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(job.ID) != 16 {
		t.Fatalf("job id = %q, want 16 hex characters", job.ID)
	}
	if job.FilesTotal != -1 || job.BytesTotal != -1 || job.ETA != -1 {
		t.Fatalf("a fresh job must be indeterminate: %+v", job)
	}

	done := waitState(t, m, job.ID, StateDone)
	if done.Files != 3 || done.Phase != wproto.PhaseWorking || done.Current != "/share/Public/a" {
		t.Fatalf("finished job = %+v", done)
	}
	if done.Actor != "alice" || done.UID != 1001 || done.Dst != "" || len(done.Src) != 2 {
		t.Fatalf("metadata was not carried: %+v", done)
	}
	var back summary
	if err := json.Unmarshal(done.Result, &back); err != nil || back.Files != 3 {
		t.Fatalf("result = %s (%v)", done.Result, err)
	}
	if done.Partial || done.Err != "" || done.FinishedAt.IsZero() {
		t.Fatalf("a clean job must not be partial: %+v", done)
	}
}

// TestAByteMoverNeverBlocksAMetadataJob is the reason there are two
// semaphores: a folder-size probe must not sit behind a 200 GB copy.
func TestAByteMoverNeverBlocksAMetadataJob(t *testing.T) {
	m, _ := newManager(t, Limits{ByteMovers: 1, Metadata: 1, QueueDepth: 4})

	copying := newGate()
	if _, err := m.Submit(KindCopy, "copy", Meta{}, copying.fn); err != nil {
		t.Fatal(err)
	}
	copying.waitStarted(t, "the copy")

	// A second byte-mover has to wait...
	queued := newGate()
	qj, err := m.Submit(KindMove, "move", Meta{}, queued.fn)
	if err != nil {
		t.Fatal(err)
	}
	// ...while a metadata job runs straight away.
	sizing := newGate()
	sj, err := m.Submit(KindSize, "size", Meta{}, sizing.fn)
	if err != nil {
		t.Fatal(err)
	}
	sizing.waitStarted(t, "the size probe")

	if j, _ := m.Get(qj.ID); j.State != StateQueued {
		t.Fatalf("the second byte-mover is %s, want queued behind the copy", j.State)
	}
	if j, _ := m.Get(sj.ID); j.State != StateRunning {
		t.Fatalf("the metadata job is %s, want running", j.State)
	}

	sizing.open()
	waitState(t, m, sj.ID, StateDone)
	copying.open()
	queued.waitStarted(t, "the queued move")
	queued.open()
	waitState(t, m, qj.ID, StateDone)
}

func TestQueueDepthIsRefusedRatherThanQueuedForEver(t *testing.T) {
	m, _ := newManager(t, Limits{ByteMovers: 1, Metadata: 1, QueueDepth: 1})

	running := newGate()
	if _, err := m.Submit(KindCopy, "running", Meta{}, running.fn); err != nil {
		t.Fatal(err)
	}
	running.waitStarted(t, "the first copy")

	// One waiting job fills the class's queue.
	waiting := newGate()
	if _, err := m.Submit(KindCopy, "waiting", Meta{}, waiting.fn); err != nil {
		t.Fatal(err)
	}
	_, err := m.Submit(KindCopy, "refused", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
	if !errors.Is(err, ErrQueueFull) || !errors.Is(err, fsx.ErrQueueFull) {
		t.Fatalf("err = %v, want ErrQueueFull", err)
	}
	if code := fsx.Code(err); code != "queue_full" {
		t.Fatalf("fsx.Code = %q, want queue_full", code)
	}
	// The other class is untouched by a full byte-mover queue.
	if _, err := m.Submit(KindSize, "size", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil }); err != nil {
		t.Fatalf("the metadata queue must not be full: %v", err)
	}

	running.open()
	waiting.waitStarted(t, "the queued copy")
	waiting.open()
}

// TestCancelStopsAJobAndSaysWhatWasLeftBehind: partial work is not rolled back
// (design §3), and the job says so in words the UI can show verbatim.
func TestCancelStopsAJobAndSaysWhatWasLeftBehind(t *testing.T) {
	m, _ := newManager(t, Limits{})

	started := make(chan struct{})
	job, err := m.Submit(KindDelete, "Deleting 8003 items", Meta{Actor: "alice"}, func(ctx context.Context, p *Progress) (any, error) {
		p.Set(412, 8003, 0, 0)
		close(started)
		<-ctx.Done()
		// A real job reports the failure it saw, wrapping the cancellation.
		return nil, fmt.Errorf("delete stopped: %w", ctx.Err())
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(testWait):
		t.Fatal("the job never started")
	}

	if !m.Cancel(job.ID) {
		t.Fatal("Cancel reported nothing to cancel")
	}
	got := waitState(t, m, job.ID, StateCancelled)
	if !got.Partial {
		t.Error("a cancelled job that had begun must be marked partial")
	}
	if !strings.Contains(got.Note, "412 of 8003") || !strings.Contains(got.Note, "partial work remains") {
		t.Errorf("note = %q, want the counts and the fact that nothing was rolled back", got.Note)
	}
	if got.ErrCode != "cancelled" {
		t.Errorf("error code = %q, want cancelled", got.ErrCode)
	}
	// A finished job cannot be cancelled again, and an unknown id is not a job.
	if m.Cancel(job.ID) {
		t.Error("a finished job must not report itself cancellable")
	}
	if m.Cancel("0123456789abcdef") {
		t.Error("an unknown id must not report itself cancellable")
	}
}

// TestCancelWhileQueuedIsNotPartial: nothing ran, so there is nothing to warn
// about. The distinction matters — the UI's wording differs.
func TestCancelWhileQueuedIsNotPartial(t *testing.T) {
	m, _ := newManager(t, Limits{ByteMovers: 1, Metadata: 1, QueueDepth: 4})

	running := newGate()
	if _, err := m.Submit(KindCopy, "running", Meta{}, running.fn); err != nil {
		t.Fatal(err)
	}
	running.waitStarted(t, "the first copy")

	var ran atomic.Bool
	queued, err := m.Submit(KindCopy, "queued", Meta{}, func(context.Context, *Progress) (any, error) {
		ran.Store(true)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Cancel(queued.ID) {
		t.Fatal("a queued job must be cancellable")
	}
	got := waitState(t, m, queued.ID, StateCancelled)
	if got.Partial {
		t.Error("a job that never ran must not be marked partial")
	}
	if !strings.Contains(got.Note, "nothing was changed") {
		t.Errorf("note = %q", got.Note)
	}
	running.open()
	if ran.Load() {
		t.Error("the cancelled job's work ran anyway")
	}
}

func TestAFailedJobCarriesTheApiErrorCode(t *testing.T) {
	m, _ := newManager(t, Limits{})
	job, err := m.Submit(KindSize, "size", Meta{}, func(_ context.Context, p *Progress) (any, error) {
		p.Set(2, 10, 0, 0)
		return nil, fmt.Errorf("/etc/shadow: %w", fs.ErrPermission)
	})
	if err != nil {
		t.Fatal(err)
	}
	got := waitState(t, m, job.ID, StateFailed)
	if got.ErrCode != "permission" || !strings.Contains(got.Err, "/etc/shadow") {
		t.Fatalf("failed job = %+v", got)
	}
	if !got.Partial || !strings.Contains(got.Note, "2 of 10") {
		t.Fatalf("a failure part-way through is partial too: %+v", got)
	}
}

// TestAPanicInTheWorkFunctionFailsOneJob: this daemon runs as root for every
// user on the NAS, so one user's bad copy must not take it down.
func TestAPanicInTheWorkFunctionFailsOneJob(t *testing.T) {
	m, _ := newManager(t, Limits{})
	job, err := m.Submit(KindCopy, "boom", Meta{}, func(context.Context, *Progress) (any, error) {
		panic("nil map write")
	})
	if err != nil {
		t.Fatal(err)
	}
	got := waitState(t, m, job.ID, StateFailed)
	if !strings.Contains(got.Err, "nil map write") {
		t.Fatalf("err = %q, want the panic's message", got.Err)
	}
	// The manager still works afterwards.
	next, err := m.Submit(KindCopy, "after", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, m, next.ID, StateDone)
}

func TestWarningsAreCappedButAlwaysCounted(t *testing.T) {
	m, _ := newManager(t, Limits{})
	const total = WarnCap + 37
	job, err := m.Submit(KindDelete, "delete", Meta{}, func(_ context.Context, p *Progress) (any, error) {
		for i := 0; i < total; i++ {
			p.Warn(fmt.Sprintf("/share/Public/f%d", i), "permission", "EACCES")
		}
		if got := p.Warnings(); got != total {
			return nil, fmt.Errorf("Progress.Warnings = %d, want %d", got, total)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got := waitState(t, m, job.ID, StateDone)
	if len(got.Warnings) != WarnCap {
		t.Fatalf("%d warnings kept, want the cap of %d", len(got.Warnings), WarnCap)
	}
	if got.WarningCount != total {
		t.Fatalf("WarningCount = %d, want %d", got.WarningCount, total)
	}
	if !strings.Contains(got.Warnings[0], "/share/Public/f0") || !strings.Contains(got.Warnings[0], "permission") {
		t.Fatalf("warning = %q, want the path and the code", got.Warnings[0])
	}
}

// TestListIsNewestFirstAndHandsOutCopies: a caller holding a Job must not be
// able to change the manager's state, and must not see it change underneath.
func TestListIsNewestFirstAndHandsOutCopies(t *testing.T) {
	m, _ := newManager(t, Limits{})
	var ids []string
	for i := 0; i < 3; i++ {
		j, err := m.Submit(KindSize, fmt.Sprintf("job %d", i), Meta{Src: []string{"/a"}}, func(context.Context, *Progress) (any, error) {
			return nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
		waitState(t, m, j.ID, StateDone)
	}
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("%d jobs listed, want 3", len(list))
	}
	for i, want := range []string{ids[2], ids[1], ids[0]} {
		if list[i].ID != want {
			t.Fatalf("list[%d] = %s, want %s (newest first)", i, list[i].ID, want)
		}
	}
	// Mutating the copy changes nothing.
	list[0].Src[0] = "/tampered"
	list[0].Title = "tampered"
	again, _ := m.Get(ids[2])
	if again.Src[0] != "/a" || again.Title == "tampered" {
		t.Fatalf("a handed-out Job aliased the manager's state: %+v", again)
	}
	if _, ok := m.Get("nope"); ok {
		t.Error("Get returned a job for an unknown id")
	}
}

// TestReapKeepsWhicheverIsMore: the time window and the count are an OR, not an
// AND — a job inside either one survives.
func TestReapKeepsWhicheverIsMore(t *testing.T) {
	m, clk := newManager(t, Limits{RetainMinutes: 60, RetainCount: 2})

	finish := func(title string) string {
		j, err := m.Submit(KindSize, title, Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
		if err != nil {
			t.Fatal(err)
		}
		waitState(t, m, j.ID, StateDone)
		return j.ID
	}

	old1, old2 := finish("old 1"), finish("old 2")
	clk.advance(2 * time.Hour)
	// Two hours later, both are outside the window — but the count keeps them.
	m.Reap()
	if _, ok := m.Get(old1); !ok {
		t.Fatal("the count-based retention must keep the two most recent")
	}

	recent1, recent2 := finish("recent 1"), finish("recent 2")
	m.Reap()
	// The two recent ones are the two most recent AND inside the window; the
	// old pair is outside both, so it goes.
	if _, ok := m.Get(old1); ok {
		t.Error("a job outside the window and outside the count must be reaped")
	}
	if _, ok := m.Get(old2); ok {
		t.Error("a job outside the window and outside the count must be reaped")
	}
	for _, id := range []string{recent1, recent2} {
		if _, ok := m.Get(id); !ok {
			t.Errorf("job %s was reaped while it was still inside the window", id)
		}
	}

	// With no count retention at all, only the window keeps anything.
	m2, clk2 := newManager(t, Limits{RetainMinutes: 30, RetainCount: 0})
	j, err := m2.Submit(KindSize, "windowed", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	waitState(t, m2, j.ID, StateDone)
	clk2.advance(29 * time.Minute)
	m2.Reap()
	if _, ok := m2.Get(j.ID); !ok {
		t.Fatal("a job inside the window must survive Reap")
	}
	clk2.advance(2 * time.Minute)
	m2.Reap()
	if _, ok := m2.Get(j.ID); ok {
		t.Fatal("a job past the window with no count retention must be reaped")
	}
}

// TestReapNeverTouchesALiveJob: a queued or running job is not history.
func TestReapNeverTouchesALiveJob(t *testing.T) {
	m, clk := newManager(t, Limits{ByteMovers: 1, Metadata: 1, QueueDepth: 4, RetainMinutes: 1, RetainCount: 0})
	running := newGate()
	rj, err := m.Submit(KindCopy, "running", Meta{}, running.fn)
	if err != nil {
		t.Fatal(err)
	}
	running.waitStarted(t, "the copy")
	queued, err := m.Submit(KindCopy, "queued", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}

	clk.advance(time.Hour)
	m.Reap()
	if _, ok := m.Get(rj.ID); !ok {
		t.Error("a running job was reaped")
	}
	if _, ok := m.Get(queued.ID); !ok {
		t.Error("a queued job was reaped")
	}
	running.open()
	waitState(t, m, queued.ID, StateDone)
}

// lockstep drives a work function one reported update at a time, so a test can
// inspect the job between updates without racing the goroutine that makes them.
type lockstep struct {
	go_   chan struct{}
	ready chan struct{}
}

func newLockstep() *lockstep {
	return &lockstep{go_: make(chan struct{}), ready: make(chan struct{})}
}

// wait is called by the work function: it blocks until the test asks for the
// next update, and the test blocks until that update has landed.
func (l *lockstep) wait() { <-l.go_ }
func (l *lockstep) done() { l.ready <- struct{}{} }

func (l *lockstep) step(t *testing.T) {
	t.Helper()
	select {
	case l.go_ <- struct{}{}:
	case <-time.After(testWait):
		t.Fatal("the job stopped asking for work")
	}
	select {
	case <-l.ready:
	case <-time.After(testWait):
		t.Fatal("the job never reported its update")
	}
}

// TestRateAndETA walks a job through a steady 1 MiB/s and checks that the
// estimate converges on it and that the ETA is the remaining bytes over that
// rate.
func TestRateAndETA(t *testing.T) {
	m, clk := newManager(t, Limits{})

	const mib = 1 << 20
	const steps = 20
	ls := newLockstep()
	job, err := m.Submit(KindCopy, "copy", Meta{}, func(_ context.Context, p *Progress) (any, error) {
		for i := 0; i < steps; i++ {
			ls.wait()
			p.Set(int64(i+1), steps, int64(i+1)*mib, steps*mib)
			ls.done()
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var half Job
	for i := 0; i < steps; i++ {
		clk.advance(time.Second)
		ls.step(t)
		if i == steps/2-1 {
			half, _ = m.Get(job.ID)
		}
	}
	last, _ := m.Get(job.ID)

	if last.Rate < 900_000 || last.Rate > 1_200_000 {
		t.Fatalf("rate = %d bytes/s after %d steady 1 MiB seconds, want about %d", last.Rate, steps, mib)
	}
	// Half way: ten of twenty megabytes left at about a megabyte a second.
	if half.ETA < 8 || half.ETA > 13 {
		t.Fatalf("ETA half way = %d s, want about 10 (rate %d)", half.ETA, half.Rate)
	}
	// At the end there is nothing left to wait for.
	if last.ETA != 0 {
		t.Fatalf("ETA = %d at completion, want 0", last.ETA)
	}
	waitState(t, m, job.ID, StateDone)
}

// TestETAIsUnknownUntilThereIsSomethingToEstimateFrom pins the -1 contract: an
// indeterminate total never produces an invented number, and a file count alone
// is enough to estimate from once the job has been running.
func TestETAIsUnknownUntilThereIsSomethingToEstimateFrom(t *testing.T) {
	m, clk := newManager(t, Limits{})
	ls := newLockstep()
	job, err := m.Submit(KindDelete, "delete", Meta{}, func(_ context.Context, p *Progress) (any, error) {
		ls.wait()
		p.Set(10, -1, 0, -1) // an indeterminate scan: no totals at all
		ls.done()

		ls.wait()
		p.Set(20, -1, 0, -1)
		ls.done()

		ls.wait()
		p.Set(40, 80, 0, -1) // now a file count, and no byte total at all
		ls.done()
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ls.step(t)
	if j, _ := m.Get(job.ID); j.ETA != -1 {
		t.Fatalf("ETA = %d with no totals, want -1", j.ETA)
	}
	clk.advance(2 * time.Second)
	ls.step(t)
	if j, _ := m.Get(job.ID); j.ETA != -1 {
		t.Fatalf("ETA = %d with no totals, want -1", j.ETA)
	}
	clk.advance(2 * time.Second)
	ls.step(t)
	// 40 of 80 files in four seconds of running is ten a second, so about four
	// seconds are left. The bound is loose on purpose; the point is that it is
	// finite and sane when only a file count exists.
	j, _ := m.Get(job.ID)
	if j.ETA < 2 || j.ETA > 8 {
		t.Fatalf("ETA = %d s from the file rate, want about 4", j.ETA)
	}
	waitState(t, m, job.ID, StateDone)
}

func TestCloseCancelsEverythingAndWaits(t *testing.T) {
	c := newClock()
	m := New(Limits{ByteMovers: 1, Metadata: 1, QueueDepth: 4})
	m.now = c.now

	stopped := make(chan struct{})
	running, err := m.Submit(KindCopy, "running", Meta{}, func(ctx context.Context, p *Progress) (any, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the copy to start", func() bool {
		j, ok := m.Get(running.ID)
		return ok && j.State == StateRunning
	})
	queued, err := m.Submit(KindCopy, "queued", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Close returned before the running job's context was cancelled")
	}
	if j, _ := m.Get(running.ID); j.State != StateCancelled {
		t.Fatalf("the running job is %s, want cancelled", j.State)
	}
	if j, _ := m.Get(queued.ID); j.State != StateCancelled {
		t.Fatalf("the queued job is %s, want cancelled", j.State)
	}
	if _, err := m.Submit(KindSize, "after", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
	// Closing twice is not an error.
	if err := m.Close(ctx); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestSubmitRejectsNonsense(t *testing.T) {
	m, _ := newManager(t, Limits{})
	if _, err := m.Submit("", "no kind", Meta{}, func(context.Context, *Progress) (any, error) { return nil, nil }); err == nil {
		t.Error("a job with no kind must be refused")
	}
	if _, err := m.Submit(KindSize, "no function", Meta{}, nil); err == nil {
		t.Error("a job with no work function must be refused")
	}
}

// TestConcurrentProgressAndReaders is the -race exercise: many goroutines
// reporting progress while others list and cancel.
func TestConcurrentProgressAndReaders(t *testing.T) {
	m, _ := newManager(t, Limits{ByteMovers: 4, Metadata: 8, QueueDepth: 64})

	var wg sync.WaitGroup
	ids := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		j, err := m.Submit(KindSize, fmt.Sprintf("job %d", i), Meta{Src: []string{"/a", "/b"}}, func(ctx context.Context, p *Progress) (any, error) {
			for n := 0; n < 200; n++ {
				if err := p.Step(); err != nil {
					return nil, err
				}
				p.Set(int64(n), 200, int64(n)*1024, 200*1024)
				p.Current(fmt.Sprintf("/f%d", n))
				p.Phase(wproto.PhaseWorking)
				if n%50 == 0 {
					p.Warn("/f", "permission", "EACCES")
				}
			}
			return map[string]int{"n": 200}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				_ = m.List()
				m.Reap()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, id := range ids[:3] {
			m.Cancel(id)
		}
	}()
	wg.Wait()

	for _, id := range ids {
		waitFor(t, "every job to finish", func() bool {
			j, ok := m.Get(id)
			return !ok || j.State.Terminal()
		})
	}
}
