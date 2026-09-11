// Package jobs is the front-end's manager for long-running operations
// (docs/design/backend-packaging-plan.md §3). It owns nothing on the
// filesystem: a job's work is a function the caller supplies, which in
// production is one long-lived RPC to the user's worker (INV-1 — user data is
// touched only in the worker). This package holds the bookkeeping around that
// call: the queue, the two concurrency classes, the progress a UI polls, the
// cancellation, and the retention of finished jobs.
//
// Jobs are in-memory only. A restart loses the history, which is deliberate:
// the audit log is the durable record, and nothing replayable is kept on disk.
//
// Two facts shape the design:
//
//   - Two independent semaphores, so a folder-size probe is never stuck behind
//     a 200 GB copy: byte-movers (copy, move, archive, extract) and metadata
//     (delete, size, search, trash, chmod, chown). Beyond the per-class queue
//     depth a submit is refused with ErrQueueFull rather than waiting silently.
//   - Partial work is NOT rolled back. A cancelled job says so, in its own
//     words ("Cancelled after 412 of 8003 files; partial work remains"),
//     because pretending otherwise would be worse than saying it.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
)

// Kind is what a job does. The values are exactly the wproto job kinds, so a
// caller can hand wproto.JobDelete straight to Submit; the package does not
// import wproto (it manages jobs, it does not speak the worker protocol) and a
// test pins the two vocabularies together.
type Kind string

const (
	KindCopy    Kind = "copy"
	KindMove    Kind = "move"
	KindArchive Kind = "archive"
	KindExtract Kind = "extract"

	KindDelete       Kind = "delete"
	KindSize         Kind = "size"
	KindSearch       Kind = "search"
	KindChmod        Kind = "chmod"
	KindChown        Kind = "chown"
	KindTrash        Kind = "trash"
	KindTrashRestore Kind = "trash-restore"
	KindTrashEmpty   Kind = "trash-empty"
)

// State is where a job is in its life. queued and running are live; done,
// failed and cancelled are terminal.
type State string

const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateDone      State = "done"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// Terminal reports whether a state is final — the only states Reap may remove.
func (s State) Terminal() bool {
	return s == StateDone || s == StateFailed || s == StateCancelled
}

// Class is one of the two concurrency pools.
type Class string

const (
	// ClassByteMover moves bytes: a spinning-disk NAS thrashes beyond two.
	ClassByteMover Class = "byteMover"
	// ClassMetadata touches metadata: delete, size, search, trash, chmod, chown.
	ClassMetadata Class = "metadata"
)

// ClassOf sorts a kind into its pool. An unrecognised kind is metadata, which
// is the cheaper pool to be wrong about: a mislabelled byte-mover would run
// with more concurrency than a disk likes, while a mislabelled metadata job
// would sit behind a copy for an hour.
func ClassOf(k Kind) Class {
	switch k {
	case KindCopy, KindMove, KindArchive, KindExtract:
		return ClassByteMover
	default:
		return ClassMetadata
	}
}

// WarnCap bounds Job.Warnings. Past it only WarningCount grows, so a job that
// fails on a million files reports the fact without holding a million strings.
// It is the same cap as wproto.WarnCap, for the same reason.
const WarnCap = 100

// Errors this package adds. Both wrap an fsx sentinel so fsx.Code maps them to
// the API vocabulary ("queue_full") with no translation table in the web layer.
var (
	// ErrQueueFull: the class's queue is at its depth limit.
	ErrQueueFull = fmt.Errorf("too many jobs of this kind are already waiting: %w", fsx.ErrQueueFull)
	// ErrClosed: the manager is shutting down and takes no new work.
	ErrClosed = errors.New("the job manager is shut down")
	// ErrDuplicateID: a caller-supplied Meta.ID is already held by this manager
	// (M2-A round 2, finding W7). Two live jobs sharing an id would make the
	// cancel route and the audit trail ambiguous, so the second is refused.
	ErrDuplicateID = errors.New("jobs: a job with that id already exists")
)

// ErrCoder lets a work function name the API error code its failure maps to.
// Without it a refusal the FRONT END made — the guard re-check a destructive
// job runs when it starts (finding W1) — would be recorded under the generic
// fsx spelling rather than the vocabulary the HTTP layer and the UI use
// ("read_only"). fsx.Code remains the fallback for everything else.
type ErrCoder interface{ ErrorCode() string }

// errCode is Job.ErrCode: the work function's own code where it named one.
func errCode(err error) string {
	var coder ErrCoder
	if errors.As(err, &coder) {
		if code := coder.ErrorCode(); code != "" {
			return code
		}
	}
	return fsx.Code(err)
}

// Limits is the manager's configuration, config.Jobs in this package's own
// vocabulary so nothing here depends on the shape of the config file.
type Limits struct {
	// ByteMovers caps concurrent copy/move/archive/extract jobs.
	ByteMovers int
	// Metadata caps concurrent delete/size/search/trash/chmod/chown jobs.
	Metadata int
	// QueueDepth caps QUEUED jobs per class; beyond it Submit returns
	// ErrQueueFull rather than growing an unbounded backlog.
	QueueDepth int
	// RetainMinutes keeps a finished job visible this long.
	RetainMinutes int
	// RetainCount keeps this many most recent finished jobs. Whichever of the
	// two keeps more, keeps.
	RetainCount int
}

// LimitsFrom converts the config file's section.
func LimitsFrom(j config.Jobs) Limits {
	return Limits{
		ByteMovers:    j.ByteMovers,
		Metadata:      j.Metadata,
		QueueDepth:    j.QueueDepth,
		RetainMinutes: j.RetainMinutes,
		RetainCount:   j.RetainCount,
	}
}

// normalise fills in the documented defaults for anything unset, so a zero
// Limits is usable rather than a manager that can run nothing.
func (l Limits) normalise() Limits {
	if l.ByteMovers <= 0 {
		l.ByteMovers = 2
	}
	if l.Metadata <= 0 {
		l.Metadata = 4
	}
	if l.QueueDepth <= 0 {
		l.QueueDepth = 64
	}
	if l.RetainMinutes < 0 {
		l.RetainMinutes = 0
	}
	if l.RetainCount < 0 {
		l.RetainCount = 0
	}
	return l
}

// Meta is what the submitter knows about a job that the work function does not:
// who asked for it and what it is aimed at.
type Meta struct {
	// Src are the API paths the job reads from.
	Src []string
	// Dst is the API path it writes to, where there is one.
	Dst string
	// Actor is the QTS username the job runs for.
	Actor string
	// UID is the Linux uid the worker ran as. It is recorded so a job list can
	// be filtered to its owner without re-resolving the name.
	UID int
	// ID, when set, is the job id to use instead of a freshly minted one
	// (finding W7). The web layer chooses the id BEFORE it writes the durable
	// audit INTENT line, so the intent and the result can be paired by id even
	// after a restart or a retention sweep. It must have the shape NewID mints
	// (16 lower-case hex characters, which is also what the /api/jobs/<id>
	// routes accept); a duplicate live id is refused with ErrDuplicateID.
	ID string
	// OnFinish, when set, is called exactly ONCE for this job, on EVERY
	// terminal transition — done, failed, cancelled while running, cancelled
	// while still queued, and cancelled by Close at shutdown — after the state
	// is final and after the job has released its concurrency slot (finding
	// W2). It is the only way to observe a job that finished without its work
	// function ever running: a job cancelled in the queue never calls fn at
	// all, so terminal bookkeeping done inside fn (the web layer's result audit
	// line) would simply be missing. It runs on the job's own goroutine, so
	// Close waits for it; it must not block indefinitely. A panic is contained.
	OnFinish func(Job)
}

// Job is one operation's public state. Every Job handed out by this package is
// a copy: the caller may hold it, marshal it and forget it.
type Job struct {
	ID    string `json:"id"` // 16 hex characters from crypto/rand
	Kind  Kind   `json:"kind"`
	State State  `json:"state"`
	Title string `json:"title"`

	Src []string `json:"src,omitempty"`
	Dst string   `json:"dst,omitempty"`

	Files int64 `json:"files"`
	// FilesTotal is -1 when the count is indeterminate (the scan was capped, or
	// the operation cannot know in advance). The UI shows an indeterminate bar.
	FilesTotal int64 `json:"filesTotal"`
	Bytes      int64 `json:"bytes"`
	// BytesTotal is -1 when indeterminate, as FilesTotal is.
	BytesTotal int64  `json:"bytesTotal"`
	Current    string `json:"current,omitempty"`
	// Rate is bytes per second, an EWMA over roughly five seconds.
	Rate int64 `json:"rate"`
	// ETA is seconds remaining, -1 when unknown.
	ETA int `json:"eta"`
	// Phase is one of the wproto phases: "scanning", "working", "finishing".
	Phase string `json:"phase,omitempty"`

	// Warnings holds the first WarnCap per-item failures, formatted for
	// display; WarningCount is the total however many were kept.
	Warnings     []string `json:"warnings,omitempty"`
	WarningCount int      `json:"warningCount,omitempty"`

	Err     string `json:"error,omitempty"`
	ErrCode string `json:"errorCode,omitempty"`

	Actor string `json:"actor,omitempty"`
	UID   int    `json:"uid"`

	StartedAt  time.Time `json:"startedAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`

	// Result is the work function's own summary, marshalled. For a worker job
	// it is the wproto.JobResult.
	Result json.RawMessage `json:"result,omitempty"`

	// Partial marks a job whose work was left half done — a cancellation, or a
	// failure part-way. Nothing is rolled back (design §3); Note says so in
	// words the UI can show verbatim.
	Partial bool   `json:"partial,omitempty"`
	Note    string `json:"note,omitempty"`
}

// entry is a job plus the state the manager needs and the caller never sees.
// Its mutex covers the job and the rate estimator; the manager's mutex covers
// the map, the queue counters and the closed flag. The order is always
// manager then entry, and nothing takes the manager's lock while holding an
// entry's.
type entry struct {
	seq uint64 // submission order, which is what "newest first" means

	mu     sync.Mutex
	job    Job
	cancel context.CancelFunc
	// cancelRequested records that somebody asked for this job to stop, so the
	// outcome is reported as a cancellation even when the work function
	// returned a wrapped error of its own rather than context.Canceled.
	cancelRequested bool

	// onFinish is Meta.OnFinish and notified is the exactly-once latch that
	// guards it (finding W2).
	onFinish func(Job)
	notified bool

	// rate estimator state.
	runStart   time.Time
	lastSample time.Time
	lastBytes  int64
	rate       float64
	rateSeen   bool
}

// Manager owns every job in this process.
type Manager struct {
	limits Limits
	// now is the clock. Tests replace it; production leaves it as time.Now.
	now func() time.Time

	// sem is the per-class concurrency semaphore, and the only thing that makes
	// a job wait.
	sem map[Class]chan struct{}

	mu     sync.Mutex
	jobs   map[string]*entry
	queued map[Class]int
	seq    uint64
	closed bool
	wg     sync.WaitGroup
}

// New builds a manager. A zero Limits gets the documented defaults.
func New(limits Limits) *Manager {
	l := limits.normalise()
	return &Manager{
		limits: l,
		now:    time.Now,
		sem: map[Class]chan struct{}{
			ClassByteMover: make(chan struct{}, l.ByteMovers),
			ClassMetadata:  make(chan struct{}, l.Metadata),
		},
		jobs:   map[string]*entry{},
		queued: map[Class]int{},
	}
}

// Limits reports the manager's effective limits, defaults filled in.
func (m *Manager) Limits() Limits { return m.limits }

// Submit queues a job and starts it as soon as its class has room.
//
// fn runs on a goroutine of its own, under a context that is cancelled by
// Cancel and by Close. It reports progress through p and must check p.Step()
// often enough that a cancellation is noticed promptly; the value it returns is
// marshalled into Job.Result.
//
// The returned Job is a snapshot taken at submission: by the time the caller
// reads it the job may already be running.
func (m *Manager) Submit(kind Kind, title string, meta Meta, fn func(ctx context.Context, p *Progress) (any, error)) (*Job, error) {
	if kind == "" {
		return nil, errors.New("jobs: a job needs a kind")
	}
	if fn == nil {
		return nil, errors.New("jobs: a job needs something to run")
	}
	// A caller may choose the id itself, so a durable audit intent line can name
	// the job before it is submitted (finding W7). Anything else is minted here.
	id := meta.ID
	if id == "" {
		var err error
		if id, err = NewID(); err != nil {
			return nil, err
		}
	} else if !ValidID(id) {
		return nil, fmt.Errorf("jobs: %q is not a usable job id", id)
	}
	class := ClassOf(kind)
	now := m.now()

	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		cancel:   cancel,
		onFinish: meta.OnFinish,
		job: Job{
			ID:         id,
			Kind:       kind,
			State:      StateQueued,
			Title:      title,
			Src:        append([]string(nil), meta.Src...),
			Dst:        meta.Dst,
			FilesTotal: -1,
			BytesTotal: -1,
			ETA:        -1,
			Actor:      meta.Actor,
			UID:        meta.UID,
			StartedAt:  now,
			UpdatedAt:  now,
		},
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		cancel()
		return nil, ErrClosed
	}
	// Refuse a duplicate under the SAME lock that registers it, so two
	// concurrent submits of one id cannot both pass. A finished-but-retained
	// job still holds its id: reusing it would make /api/jobs/<id> and the
	// audit trail ambiguous in exactly the way the id exists to prevent.
	if _, taken := m.jobs[id]; taken {
		m.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("%w: %s", ErrDuplicateID, id)
	}
	if m.queued[class] >= m.limits.QueueDepth {
		depth := m.queued[class]
		m.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("%d %s jobs are already queued: %w", depth, class, ErrQueueFull)
	}
	m.queued[class]++
	m.seq++
	e.seq = m.seq
	m.jobs[id] = e
	m.wg.Add(1)
	m.mu.Unlock()

	// The snapshot is taken before the work starts, so what the caller is handed
	// is the job as submitted rather than a racy glimpse of a job that may
	// already be reporting progress.
	snap := e.snapshot()
	go m.run(ctx, cancel, e, class, fn)
	return &snap, nil
}

// run waits for the class's semaphore, runs the work and records the outcome.
//
// Every path out of this goroutine passes through finishQueued or finish, so
// the deferred notifyFinish is the single terminal transition every job makes —
// including the two where fn never runs at all (cancelled in the queue, closed
// at shutdown). It is deferred AFTER the semaphore and the context, so a hook
// that writes a durable record does not hold a concurrency slot while it does;
// it is deferred BEFORE m.wg.Done, so Close still waits for it.
func (m *Manager) run(ctx context.Context, cancel context.CancelFunc, e *entry, class Class, fn func(context.Context, *Progress) (any, error)) {
	defer m.wg.Done()
	defer m.notifyFinish(e)
	defer cancel()

	sem := m.sem[class]
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		// Cancelled (or closed) while it was still waiting for a slot. Nothing
		// ran, so nothing is partial.
		m.leaveQueue(class)
		e.finishQueued(m.now())
		return
	}
	defer func() { <-sem }()
	m.leaveQueue(class)

	now := m.now()
	// Close publishes m.closed under m.mu BEFORE it cancels anyone, and a slot
	// held by a running job is only ever freed by that cancellation — so a
	// queued job that wins the slot after Close began always observes closed
	// here and ends cancelled, never done. Without this check it could take the
	// freed slot and run its function in the gap before Close's sequential
	// cancels reached its own context (CI, the race job: a queued job finished
	// "done" on Close). A job that took its slot before Close began is
	// legitimately running and is stopped through its context instead.
	if m.isClosed() || !e.start(now) {
		// Closed, or cancelled in the instant between taking the slot and
		// starting: nothing ran, so nothing is partial.
		e.finishQueued(now)
		return
	}

	p := &Progress{m: m, e: e, ctx: ctx}
	res, err := m.call(ctx, p, fn)
	e.finish(m.now(), res, err, ctx.Err())
}

// call runs the work function and turns a panic into a failed job. A panic in
// one user's copy must not take down a daemon that is running as root for
// everybody else.
func (m *Manager) call(ctx context.Context, p *Progress, fn func(context.Context, *Progress) (any, error)) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("the job panicked: %v", r)
		}
	}()
	return fn(ctx, p)
}

// notifyFinish runs the job's completion hook exactly once, after its state is
// final (finding W2). The snapshot handed over is the terminal one, so a hook
// that audits a result line sees the counts, the state and the error code the
// caller would read from Get.
//
// A hook is caller code running on the daemon's own goroutine: a panic in one
// user's completion bookkeeping must not take down a process that is root for
// everybody else, so it is contained here the way call() contains one in fn.
func (m *Manager) notifyFinish(e *entry) {
	e.mu.Lock()
	if e.notified {
		e.mu.Unlock()
		return
	}
	e.notified = true
	hook := e.onFinish
	if hook == nil {
		e.mu.Unlock()
		return
	}
	j := e.snapshotLocked()
	e.mu.Unlock()
	defer func() { _ = recover() }()
	hook(j)
}

func (m *Manager) leaveQueue(class Class) {
	m.mu.Lock()
	if m.queued[class] > 0 {
		m.queued[class]--
	}
	m.mu.Unlock()
}

// Get returns a copy of one job.
func (m *Manager) Get(id string) (Job, bool) {
	m.mu.Lock()
	e := m.jobs[id]
	m.mu.Unlock()
	if e == nil {
		return Job{}, false
	}
	return e.snapshot(), true
}

// List returns copies of every job the manager still holds, newest first.
func (m *Manager) List() []Job {
	m.mu.Lock()
	all := make([]*entry, 0, len(m.jobs))
	for _, e := range m.jobs {
		all = append(all, e)
	}
	m.mu.Unlock()

	sort.Slice(all, func(i, j int) bool { return all[i].seq > all[j].seq })
	out := make([]Job, 0, len(all))
	for _, e := range all {
		out = append(out, e.snapshot())
	}
	return out
}

// Cancel asks a job to stop. It reports whether there was a live job to ask;
// a job that has already finished is not cancellable and the work it did is
// not undone.
func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	e := m.jobs[id]
	m.mu.Unlock()
	if e == nil {
		return false
	}
	return e.requestCancel()
}

// Reap forgets finished jobs that are past their retention: kept for
// RetainMinutes, or as one of the RetainCount most recent, whichever keeps
// more. Live jobs are never removed. A ticker in the web layer calls it.
func (m *Manager) Reap() {
	cutoff := m.now().Add(-time.Duration(m.limits.RetainMinutes) * time.Minute)

	type finished struct {
		id  string
		at  time.Time
		seq uint64
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	done := make([]finished, 0, len(m.jobs))
	for id, e := range m.jobs {
		state, at := e.outcome()
		if !state.Terminal() {
			continue
		}
		done = append(done, finished{id: id, at: at, seq: e.seq})
	}
	sort.Slice(done, func(i, j int) bool {
		if !done[i].at.Equal(done[j].at) {
			return done[i].at.After(done[j].at)
		}
		return done[i].seq > done[j].seq
	})
	for i, f := range done {
		if i < m.limits.RetainCount {
			continue // among the most recent RetainCount
		}
		if f.at.After(cutoff) {
			continue // still inside the time window
		}
		delete(m.jobs, f.id)
	}
}

// Close stops taking new jobs, cancels everything still running or queued and
// waits for the work functions to return. It gives up waiting when ctx does —
// the daemon's shutdown has its own deadline — and says so; the goroutines it
// could not wait for are still cancelled.
// isClosed reports whether Close has begun. It reads m.closed under the same
// lock Close writes it under, which is what lets run treat "closed" as a
// happens-before fact when it decides whether a slot-winning queued job may
// start (see run).
func (m *Manager) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	live := make([]*entry, 0, len(m.jobs))
	for _, e := range m.jobs {
		live = append(live, e)
	}
	m.mu.Unlock()

	for _, e := range live {
		e.requestCancel()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.wg.Wait()
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- entry ---------------------------------------------------------------

// start moves a queued job to running. It reports false when the job has
// already been cancelled, so the caller does not run work nobody wants.
func (e *entry) start(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancelRequested {
		return false
	}
	e.job.State = StateRunning
	e.job.StartedAt = now
	e.job.UpdatedAt = now
	e.runStart = now
	return true
}

// finishQueued records a job that was cancelled before it ever ran. It is the
// one cancellation that is NOT partial: nothing happened.
func (e *entry) finishQueued(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.job.State.Terminal() {
		return
	}
	e.job.State = StateCancelled
	e.job.UpdatedAt = now
	e.job.FinishedAt = now
	e.job.Note = "Cancelled before it started; nothing was changed."
}

// finish records the outcome of a job that ran.
func (e *entry) finish(now time.Time, res any, err error, ctxErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	j := &e.job
	j.UpdatedAt = now
	j.FinishedAt = now

	switch {
	case err == nil:
		j.State = StateDone
		j.ETA = 0
		e.recordResult(res)
	case e.cancelRequested || errors.Is(err, context.Canceled) || errors.Is(ctxErr, context.Canceled):
		// Partial work is not rolled back, and the job says so itself.
		j.State = StateCancelled
		j.Partial = true
		j.ETA = -1
		j.Note = cancelNote(j.Files, j.FilesTotal)
		j.Err = err.Error()
		j.ErrCode = fsx.Code(context.Canceled)
		// A cancelled job's work function may return a result ALONGSIDE its
		// error, and for a worker job it does: wproto.JobResult with Cancelled
		// set, the partial counts and every warning the worker folded in
		// (M2-A review round 1, finding 7). Dropping it here — which is what
		// keying the record off err == nil did — threw away the only structured
		// account of what a half-finished delete actually deleted.
		e.recordResult(res)
	default:
		j.State = StateFailed
		j.ETA = -1
		j.Err = err.Error()
		j.ErrCode = errCode(err)
		if j.Files > 0 || j.Bytes > 0 {
			j.Partial = true
			j.Note = failNote(j.Files, j.FilesTotal)
		}
		// A failing work function may also hand back what it managed before it
		// failed, exactly as a cancelled one does (finding W3); keeping it is
		// the difference between "the delete failed" and "the delete failed
		// after moving these three items to Trash".
		e.recordResult(res)
	}
}

// recordResult marshals a work function's own summary into the job. The caller
// holds e.mu.
//
// A result that cannot be marshalled is recorded as a warning rather than
// dropped silently: the job itself happened, and the fact that its summary did
// not survive is a bug worth seeing.
func (e *entry) recordResult(res any) {
	if res == nil {
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		e.job.WarningCount++
		if len(e.job.Warnings) < WarnCap {
			e.job.Warnings = append(e.job.Warnings, "the job's result could not be recorded: "+err.Error())
		}
		return
	}
	e.job.Result = b
}

func cancelNote(files, total int64) string {
	if total >= 0 {
		return fmt.Sprintf("Cancelled after %d of %d files; partial work remains and was not rolled back.", files, total)
	}
	return fmt.Sprintf("Cancelled after %d files; partial work remains and was not rolled back.", files)
}

func failNote(files, total int64) string {
	if total >= 0 {
		return fmt.Sprintf("Stopped after %d of %d files; partial work remains and was not rolled back.", files, total)
	}
	return fmt.Sprintf("Stopped after %d files; partial work remains and was not rolled back.", files)
}

// requestCancel asks a live job to stop and reports whether there was one.
func (e *entry) requestCancel() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.job.State.Terminal() {
		return false
	}
	e.cancelRequested = true
	if e.cancel != nil {
		// Cancelling under the lock is safe: a context's cancellation only
		// closes a channel, it never calls back into this package.
		e.cancel()
	}
	return true
}

// outcome reports a job's state and the instant it finished, for Reap.
func (e *entry) outcome() (State, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.job.State, e.job.FinishedAt
}

// snapshot copies a job, slices and all, so nothing the caller holds can be
// mutated underneath it by the goroutine still running the work.
func (e *entry) snapshot() Job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

// snapshotLocked is snapshot with e.mu already held.
func (e *entry) snapshotLocked() Job {
	j := e.job
	j.Src = append([]string(nil), e.job.Src...)
	j.Warnings = append([]string(nil), e.job.Warnings...)
	j.Result = append(json.RawMessage(nil), e.job.Result...)
	return j
}

// NewID mints a job id: 16 hex characters from crypto/rand. A job id is quoted
// back by the UI and used to cancel, so it is unguessable rather than
// sequential. It is exported because the web layer chooses a job's id before it
// submits, so the durable audit intent line can name it (finding W7).
func NewID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("jobs: generating a job id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidID reports whether id has the shape NewID mints, which is also the shape
// the /api/jobs/<id> routes accept. A caller-supplied Meta.ID must match it, so
// a hand-made id can never widen that route's vocabulary.
func ValidID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
