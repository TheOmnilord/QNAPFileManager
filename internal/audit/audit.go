// Package audit records every mutation the daemon performs in the root
// front-end as JSON lines, with milestones mirrored to QuLog.
//
// The record is durable (jobs are in-memory only, so the audit log is the one
// replayable history) and it must never slow a request: Write hands the event
// to a buffered channel drained by a single goroutine, and drops with a count
// rather than blocking when the channel is full. Destructive operations are
// logged twice — an "intent" line before the work and a "result" line after —
// so a crash mid-delete still leaves evidence of what was attempted.
package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/logfile"
	"qnapfilemanager/internal/qnap"
)

// maxBytes and generations mirror the copied logfile defaults: rotate the
// audit log at 8 MiB and keep one previous generation as "<name>.1".
const maxBytes = 8 << 20

// bufferDepth is how many events may be queued before Write starts dropping.
// Deep enough to ride out a burst (a recursive job emits per-item warnings),
// shallow enough that a wedged drain cannot hold much memory.
const bufferDepth = 1024

// mirrorDepth is how many milestones may be waiting for QuLog before the mirror
// starts skipping them (Astra r7 #1).
//
// It is deliberately much shallower than bufferDepth, because the two queues
// hold different things. The file is the RECORD and must absorb a burst; the
// QuLog mirror is a notification, it costs an exec of log_tool that can take ten
// seconds, and a mirror that is a thousand events behind is not notifying anyone
// of anything. A skipped mirror is counted (MilestoneDrops) and the line is on
// disk regardless, so what deepening this queue would buy is latency, not
// evidence.
const mirrorDepth = 64

// dropReportInterval bounds how often the "N audit events dropped" notice is
// written, so a sustained overflow does not itself flood the log.
const dropReportInterval = 5 * time.Second

// mirrorNoticeInterval bounds how often the skipped-mirror notice reaches
// stderr (Astra r8 #5). Stderr on the NAS is `logs/startup.log`, which nothing
// rotates, so this notice is the one place a bounded overflow could still turn
// into unbounded disk: a minute between lines keeps the fact visible and the
// file small, and the count each line carries loses nothing.
const mirrorNoticeInterval = time.Minute

// writeSyncTimeout bounds how long WriteSync waits for a durable line to reach
// the sink (write + fsync) before giving up and returning an error. Long enough
// to ride out a brief rotation or a slow disk, short enough that a wedged drain
// cannot stall a mutation.
const writeSyncTimeout = 2 * time.Second

// closeDrainTimeout bounds how long Close waits for the drain goroutine and any
// admitted durable writers to finish before it gives up (adv 4). A wedged
// write/fsync holding drainMu must never hang shutdown forever; Close reports
// the timeout rather than blocking indefinitely.
const closeDrainTimeout = 5 * time.Second

// syncWriters bounds the number of concurrent durable writers. A wedged sink
// can hold at most this many goroutines, rather than one per call (adv 1): once
// all slots are held by stuck writes, further WriteSync calls fail closed on the
// admission timeout instead of piling up.
const syncWriters = 4

// bigDeleteFiles and bigDeleteBytes are the thresholds above which a delete is
// a milestone worth mirroring to QuLog.
const (
	bigDeleteFiles = 100
	bigDeleteBytes = 1 << 30 // 1 GiB
)

// The three doors an identity can arrive through (M4 contract §6.1).
//
// DoorQTS is the QTS session on the main listener; DoorCredential is the
// credential-proxy form (authLogin.cgi?user=&pwd=) on the same listener;
// DoorLocal is the break-glass bcrypt account, which exists on the break-glass
// listener alone. They never mix: one door per listener, and the local account
// has no route on the main one.
const (
	DoorQTS        = "qts"
	DoorCredential = "credential"
	DoorLocal      = "local"
)

// Event is one line of the audit log. Path and Dst hold UTF-8 paths; a value
// that is not valid UTF-8 is moved to PathB64 / DstB64 (base64 of the raw bytes)
// by prepare so it survives JSON round-tripping, which would otherwise replace
// the bad bytes with U+FFFD and lose the name — critical for a rename, where the
// destination distinguishes the target and an overwrite may destroy an existing
// entry (round-12).
type Event struct {
	T     time.Time `json:"t"`
	Actor string    `json:"actor"`
	UID   int       `json:"uid"`
	Admin bool      `json:"admin"`
	Root  bool      `json:"root"`
	IP    string    `json:"ip"`
	// Door is which door the acting session came through: DoorQTS, DoorCredential
	// or DoorLocal. It is set once at session creation and stamped on every event
	// that session produces (M4 contract §6.1). Without it the log cannot answer
	// the one question an operator actually asks after an incident: which door
	// did this come through?
	Door    string `json:"door,omitempty"`
	Op      string `json:"op"`
	Path    string `json:"path"`
	PathB64 string `json:"pathB64,omitempty"`
	Dst     string `json:"dst,omitempty"`
	DstB64  string `json:"dstB64,omitempty"`
	Job     string `json:"job,omitempty"`
	Phase   string `json:"phase"`  // "intent" | "result"
	Result  string `json:"result"` // "ok" | "error" | "denied" | "cancelled"
	Code    string `json:"code,omitempty"`
	Files   int64  `json:"files,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Detail  string `json:"detail,omitempty"`

	// ForceMilestone marks an event a milestone regardless of the automatic
	// classification (isMilestone). It is a decision flag, never serialised.
	ForceMilestone bool `json:"-"`

	// Quiet is the opposite decision, and it beats the other two (Astra r7 #1).
	// The line is written to the file exactly as any other, and it is never
	// mirrored to QuLog — not by the automatic classification, not by
	// ForceMilestone.
	//
	// It exists because the automatic classification makes every denial a
	// milestone, and one class of denial is produced by whoever is on the LAN
	// rather than by anyone who authenticated: the break-glass door's sessionless
	// refusal lines, their summaries and its overflow reports. Each of those used
	// to buy an exec of log_tool, so 256 sources refusing once a minute against a
	// QuLog that answers in ten seconds was a queue nobody could drain. A forged
	// request must not be able to spend the mirror, and this is how the writer of
	// such a line says so. Like the flag above it, it is a decision, never
	// serialised.
	Quiet bool `json:"-"`
}

// sink is the audit log's destination: an appending, rotating file that can be
// fsynced. *logfile.Writer is the only implementation the daemon ever uses.
//
// It is an interface for exactly one reason (Astra r5 #3): the failure that
// decides whether a caller may put its counters back is the fsync failing AFTER
// a complete line has been appended, and nothing a test can do to a real file
// produces that failure on demand. The three methods are the three the logger
// calls; nothing else is reachable through it.
type sink interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// Logger writes audit events without blocking the caller.
type Logger struct {
	path  string
	w     sink
	qulog bool

	ch      chan Event
	done    chan struct{}
	dropped int64 // atomic: events lost to a full queue (overflow)

	// writeErrors counts sink write failures (disk full, I/O error): a distinct
	// failure mode from a queue-overflow drop. milestoneDrops counts milestones
	// that could not be mirrored to QuLog. Both are atomic.
	writeErrors    int64
	milestoneDrops int64

	// logFn mirrors a milestone to QuLog. It is a field so tests can replace
	// it and avoid exec'ing /sbin/log_tool.
	logFn func(qnap.Severity, string) error

	// mirrorCh and mirrorDone are the QuLog mirror's own bounded worker (Astra r7
	// #1). Every path that used to call logFn inline now offers the event here
	// and moves on: the drain writes the next line without waiting for an exec
	// that qnap.Log allows ten seconds, and a durable writer gives its slot back
	// at once. A full queue means QuLog is further behind than the notification
	// is worth, so the mirror for that event is skipped and counted rather than
	// blocking anybody.
	mirrorCh   chan Event
	mirrorDone chan struct{}

	// errLog reports a sink failure somewhere other than the failing file
	// itself (writing the failure to the same file would only fail again). It
	// defaults to stderr; tests replace it to capture the notice.
	errLog func(string)

	mu     sync.RWMutex // guards closed / channel send vs. Close
	closed bool

	// syncSem bounds the number of durable (WriteSync) writers in flight, so a
	// wedged sink can never spawn goroutines without limit (adv 1). syncWG tracks
	// the admitted durable writers so Close can join them before closing the file.
	syncSem chan struct{}
	syncWG  sync.WaitGroup
	// syncWaiting counts the WriteSync calls queued for a slot right now — the
	// state a wedged sink produces, and the one a test in another package has to
	// be able to observe rather than sleep past (Astra r4 #3). Atomic.
	syncWaiting int64

	// drainMu is held by the drain goroutine around each file write. Tests
	// hold it to freeze the drain and prove Write drops instead of blocking.
	drainMu sync.Mutex

	// closeTimeout bounds Close's wait for the drain and admitted durable
	// writers (adv 4). Defaults to closeDrainTimeout; tests shorten it so a
	// deliberately wedged sink proves Close returns within its bound.
	closeTimeout time.Duration

	lastReported   int64
	lastReportAt   time.Time
	lastWriteErrAt time.Time // rate-limits the sink-failure notice (drain only)

	// mirrorNoticed and mirrorNoticeAt rate-limit the skipped-mirror notice
	// (Astra r8 #5). Touched only by the mirror worker, which is the only
	// goroutine that writes that notice, so they need no lock. mirrorClock is
	// the seam a test sets — before anything is written — to move the interval
	// without waiting a minute.
	mirrorNoticed  int64
	mirrorNoticeAt time.Time
	mirrorClock    func() time.Time
}

// Open prepares the JSON-lines audit log at path (mode 0600, rotated at 8 MiB
// keeping one generation) and starts the drain goroutine. When qulog is true,
// milestone events are also mirrored to the QNAP system event log.
func Open(path string, qulog bool) (*Logger, error) {
	w, err := logfile.Open(path, maxBytes)
	if err != nil {
		return nil, err
	}
	l := &Logger{
		path:       path,
		w:          w,
		qulog:      qulog,
		ch:         make(chan Event, bufferDepth),
		done:       make(chan struct{}),
		mirrorCh:   make(chan Event, mirrorDepth),
		mirrorDone: make(chan struct{}),
		syncSem:    make(chan struct{}, syncWriters),
		logFn: func(sev qnap.Severity, msg string) error {
			return qnap.Log(context.Background(), sev, msg)
		},
		errLog:       func(msg string) { fmt.Fprintln(os.Stderr, "qfm audit: "+msg) },
		closeTimeout: closeDrainTimeout,
	}
	go l.drain()
	go l.mirrorLoop()
	return l, nil
}

// prepare stamps a zero T and moves a non-UTF-8 Path to PathB64 so the event
// survives JSON round-tripping. Shared by Write and WriteSync.
func (l *Logger) prepare(ev Event) Event {
	if ev.T.IsZero() {
		ev.T = time.Now()
	}
	if ev.Path != "" && !utf8.ValidString(ev.Path) {
		ev.PathB64 = base64.StdEncoding.EncodeToString([]byte(ev.Path))
		ev.Path = ""
	}
	// The rename destination gets the same treatment (round-12): a non-UTF-8 Dst
	// must not be flattened to U+FFFD, or two distinct destinations become
	// indistinguishable in the trail.
	if ev.Dst != "" && !utf8.ValidString(ev.Dst) {
		ev.DstB64 = base64.StdEncoding.EncodeToString([]byte(ev.Dst))
		ev.Dst = ""
	}
	return ev
}

// Write records ev. It never blocks: if the buffer is full the event is
// dropped and the dropped counter incremented. A zero T is stamped now, and a
// non-UTF-8 Path is moved to PathB64.
func (l *Logger) Write(ev Event) { _ = l.WriteQueued(ev) }

// WriteQueued is Write with the one answer a caller that CLEARED SOMETHING in
// order to write the line needs (Astra r6 #2): whether the event was taken.
//
// The async verdict is immediate and has only two sides, which is what makes it
// so much simpler to account for than WriteSync's. Either the event is on the
// queue — the drain owns it from here, and nothing the caller does can affect
// it — or it was refused right here, because the buffer is full or the logger
// is closed, and the caller still holds the only record of whatever the line
// stood for. There is no third, in-flight state to weigh.
//
// What it does not promise is what no write path promises: a queued event can
// still fail at the sink (a full disk, an append error), and the drain reports
// that through WriteErrors and the app log rather than back to this caller.
// queued means accepted for writing, not written.
func (l *Logger) WriteQueued(ev Event) (queued bool) {
	ev = l.prepare(ev)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return false
	}
	select {
	case l.ch <- ev:
		return true
	default:
		atomic.AddInt64(&l.dropped, 1)
		return false
	}
}

// ErrSyncTimeout is returned by WriteSync when a durable write cannot reach the
// sink (write + fsync, or even a writer slot) within writeSyncTimeout. A caller
// that must not proceed without a durable record — a mutation's intent line, a
// safety-setting milestone — treats it, and any other WriteSync error, as a hard
// failure and refuses the operation (adv 1).
//
// It does NOT mean the event was not written: the timeout may have expired
// while the event was already with a worker that goes on to fsync it. A caller
// that needs to know which happened — one that cleared the state the line stands
// for — uses WriteSyncInFlight (Astra r4 #2) rather than guessing from the error.
var ErrSyncTimeout = errors.New("audit: durable write timed out")

// ErrCloseTimeout is returned by Close when the drain and admitted durable
// writers did not finish within closeTimeout, so a wedged write/fsync could not
// hang shutdown forever (adv 4). The failure is also surfaced through errLog.
var ErrCloseTimeout = errors.New("audit: close timed out draining the sink")

// WriteSync writes ev straight to the sink AND fsyncs it, synchronously,
// returning nil only once it is durably persisted. It is the path for the lines
// a crash must not lose: a mutation's INTENT line, written before the work is
// dispatched, and every milestone (a denial, a read-only toggle, a large
// delete). Ordinary result lines stay on the async Write path.
//
// It observes ctx: once the caller's request is cancelled or times out, WriteSync
// returns ctx.Err() promptly rather than spending the full writeSyncTimeout on a
// record no one is waiting for any more (adv 4). Admission is bounded by syncSem,
// so a wedged sink holds at most syncWriters goroutines rather than one per call
// (adv 1). The actual write+fsync runs on a worker goroutine that owns its
// semaphore slot until it finishes, so a stuck write cannot be abandoned back
// into the pool; WriteSync itself stops waiting after writeSyncTimeout and
// returns ErrSyncTimeout, or sooner on ctx cancellation. On a closed logger it
// returns os.ErrClosed. The write runs under drainMu, serialised with the drain
// goroutine so the two never interleave on the file.
func (l *Logger) WriteSync(ctx context.Context, ev Event) error {
	_, err := l.WriteSyncInFlight(ctx, ev)
	return err
}

// WriteSyncInFlight is WriteSync with the one extra bit of truth a caller that
// CLEARS STATE in order to write a line needs (Astra r4 #2).
//
// An error from WriteSync does not mean the event was not written. Two of them —
// a cancelled context and ErrSyncTimeout — are returned by a call that has
// already handed the event to a worker goroutine, and that worker owns its
// semaphore slot until its write and fsync finish, which they very often do a
// moment later. The caller merely stopped waiting. A caller that treats every
// error as "nothing was recorded" and puts its counters back therefore reports
// the same burst a second time when the first line lands after all.
//
// inFlight is true in that case — the event is with a worker and may yet reach
// the sink, so it must not be written again — and in one more: the append
// succeeded and the FSYNC then failed (Astra r5 #3). The line is in the file and
// any reader will see it; only its survival of a power cut is in doubt. Treating
// that as "nothing was written" put the burst back and reported it again in the
// very next line, one line below the first, so it is reported here as the
// not-definite outcome it is.
//
// inFlight is false for every definite outcome — the write succeeded, or the
// write itself failed with nothing readable in the file, or the call never got
// past admission at all (a closed logger, a context already done, the admission
// timeout with every writer slot held). On inFlight false with a non-nil error,
// nothing was written and nothing will be.
//
// In flight means the outcome is UNKNOWN, not that the line will be recorded
// (Astra r6 #3). The worker that still holds the event may yet fail its append —
// a full disk, an I/O error, a logger closed under it — and the appended line
// whose fsync failed may not survive the power cut that the fsync was there to
// answer for. Nothing comes back to the caller in either case: the drain reports
// the failure through WriteErrors and the app log, and the caller has already
// moved on. So a caller that cleared state to write the line is choosing, when
// it declines to restore that state on inFlight, to LOSE the record rather than
// risk reporting it twice (M4 contract §18.16). That is the trade this bit
// exists to make deliberately; it is not a promise of eventual recording.
func (l *Logger) WriteSyncInFlight(ctx context.Context, ev Event) (inFlight bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ev = l.prepare(ev)
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return false, os.ErrClosed
	}
	// Register as an in-flight durable writer while still holding the read lock,
	// so Close (which takes the write lock, sets closed, then Waits) cannot begin
	// its Wait between this check and the Add.
	l.syncWG.Add(1)
	l.mu.RUnlock()

	timer := time.NewTimer(writeSyncTimeout)
	defer timer.Stop()

	// Bounded admission. A slot is held by the worker below until its write
	// finishes, so at most syncWriters durable writes exist at once.
	//
	// Nothing here started a worker, so every exit is a definite non-admission:
	// the event was not written and cannot be (Astra r4 #2).
	atomic.AddInt64(&l.syncWaiting, 1)
	select {
	case l.syncSem <- struct{}{}:
		atomic.AddInt64(&l.syncWaiting, -1)
	case <-ctx.Done():
		atomic.AddInt64(&l.syncWaiting, -1)
		l.syncWG.Done()
		return false, ctx.Err()
	case <-l.done:
		atomic.AddInt64(&l.syncWaiting, -1)
		l.syncWG.Done()
		return false, os.ErrClosed
	case <-timer.C:
		atomic.AddInt64(&l.syncWaiting, -1)
		l.syncWG.Done()
		return false, ErrSyncTimeout
	}

	res := make(chan syncResult, 1)
	go func() {
		defer l.syncWG.Done()
		defer func() { <-l.syncSem }()
		l.drainMu.Lock()
		appended, err := l.emitSync(ev)
		l.drainMu.Unlock()
		// Acknowledge durability BEFORE mirroring: the line is fsynced, so the
		// caller may proceed. Handing the event to the mirror worker is then a
		// channel send that either fits or does not (Astra r7 #1), so this slot is
		// given back at the speed of the fsync rather than at the speed of QuLog —
		// a wedged log_tool no longer holds a durable writer at all.
		res <- syncResult{appended: appended, err: err}
		if err == nil {
			l.mirror(ev)
		}
	}()

	select {
	case out := <-res:
		// The worker finished and said what happened. Two outcomes are definite —
		// it wrote the line, or it failed before anything reached the file — and
		// one is not: an fsync that failed over a line already appended (Astra r5
		// #3). That line IS readable, so a caller that cleared its counters to
		// write it must not put them back and report the same thing twice; it is
		// reported here in the same way as a write still with a worker, which is
		// the outcome it most resembles. Only durability is unknown, and an
		// unreadable audit log is not a thing a counter can repair.
		return out.appended && out.err != nil, out.err
	case <-ctx.Done():
		// The write goroutine keeps its slot until it finishes (so a stuck write
		// is not abandoned back into the pool); the caller simply stops waiting.
		// The event is still with that worker — in flight, not lost.
		return true, ctx.Err()
	case <-timer.C:
		return true, ErrSyncTimeout
	}
}

// Dropped returns how many events have been dropped due to buffer overflow.
func (l *Logger) Dropped() int64 { return atomic.LoadInt64(&l.dropped) }

// WriteErrors returns how many events failed to reach the sink (disk full, I/O
// error). It is distinct from Dropped: an overflow drop never reached the drain,
// while a write error means the drain could not persist a dequeued event.
func (l *Logger) WriteErrors() int64 { return atomic.LoadInt64(&l.writeErrors) }

// MilestoneDrops returns how many milestone events could not be mirrored to
// QuLog: log_tool refused them, or the mirror's own bounded queue was full and
// the event was skipped rather than made to wait (Astra r7 #1). The audit line
// still lands in the file; only the QuLog mirror was lost.
func (l *Logger) MilestoneDrops() int64 { return atomic.LoadInt64(&l.milestoneDrops) }

// Close stops the drain, flushing every queued event, and closes the file. The
// wait for the drain and admitted durable writers is bounded by closeTimeout: a
// wedged write/fsync holding drainMu must not hang shutdown forever (adv 4). On
// timeout Close surfaces the failure through errLog, returns ErrCloseTimeout, and
// leaves the file open rather than closing a sink a writer may still be inside.
func (l *Logger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.ch)
	l.mu.Unlock()

	timeout := l.closeTimeout
	if timeout <= 0 {
		timeout = closeDrainTimeout
	}
	// Join the drain goroutine and the admitted durable writers before closing the
	// file, so an in-flight WriteSync cannot write into a closed sink (adv 1) — but
	// under a bound, so a wedged fsync cannot block Close indefinitely (adv 4).
	drained := make(chan struct{})
	go func() {
		<-l.done
		l.syncWG.Wait()
		close(drained)
	}()
	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		l.errLog("close timed out draining the audit sink; some events may be unflushed and the file is left open")
		return ErrCloseTimeout
	}
	// Every sender is finished — the drain returned and the durable writers were
	// joined — so the mirror queue can be closed and its worker joined too (Astra
	// r7 #1). The wait shares the SAME deadline rather than starting a fresh one:
	// shutdown is bounded by closeTimeout in total, not by it twice.
	close(l.mirrorCh)
	mirrorTimer := time.NewTimer(time.Until(deadline))
	defer mirrorTimer.Stop()
	select {
	case <-l.mirrorDone:
	case <-mirrorTimer.C:
		// The worker is inside log_tool and nothing can hurry it. It never touches
		// the sink, though, so the file is closed anyway: leaving it open to wait
		// on QuLog would be the mirror gating the record all over again.
		l.errLog("close timed out waiting for the QuLog mirror; the last milestones may not be mirrored")
		_ = l.w.Close()
		return ErrCloseTimeout
	}
	return l.w.Close()
}

func (l *Logger) drain() {
	defer close(l.done)
	for ev := range l.ch {
		l.drainMu.Lock()
		l.emit(ev)
		l.reportDropped(false)
		l.drainMu.Unlock()
		// Offered to the mirror's own worker, which is what keeps a slow QuLog off
		// this goroutine entirely (Astra r7 #1). Outside drainMu as before, and now
		// also outside the ten seconds log_tool may take, so the next line is
		// written at the speed of the file.
		l.mirror(ev)
	}
	// Final pass: record any drops that accumulated after the last notice.
	l.drainMu.Lock()
	l.reportDropped(true)
	l.drainMu.Unlock()
}

// emit writes one event as a JSON line. A sink write failure is counted and
// surfaced (adv 10) rather than silently swallowed. The QuLog mirror is NOT done
// here: callers invoke mirror(ev) separately, OUTSIDE drainMu, so a slow QuLog
// (qnap.Log has its own 10s timeout) cannot hold the sink lock (standard P2).
func (l *Logger) emit(ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	if _, err := l.w.Write(b); err != nil {
		n := atomic.AddInt64(&l.writeErrors, 1)
		l.reportWriteErr(err, n)
	}
}

// mirror OFFERS a milestone to QuLog and returns immediately. It never calls
// log_tool itself (Astra r7 #1).
//
// Calling it outside drainMu was not enough. The drain is a single goroutine, so
// an inline exec that qnap.Log allows ten seconds to answer held up the NEXT
// event just as surely as the lock would have: a few hundred denials a minute —
// which is what a handful of LAN sources produce without trying — put the file
// hours behind the events it records and then overflowed the buffer, dropping
// the results of real work. So the mirror has its own worker and its own bounded
// queue: the caller hands the event over or, when QuLog is too far behind for the
// notification to mean anything, does not, and counts that.
//
// A skipped mirror is counted and surfaced exactly as a failed one is (adv 10);
// the audit line itself is on disk either way, which is what makes skipping the
// right answer rather than a loss.
func (l *Logger) mirror(ev Event) {
	if !l.qulog || l.logFn == nil || !isMilestone(ev) {
		return
	}
	select {
	case l.mirrorCh <- ev:
	default:
		// COUNTED here, reported elsewhere (Astra r8 #5). This runs on the drain
		// goroutine and on every durable writer, and the notice it used to write
		// went to stderr — which on the NAS is `logs/startup.log`, a file the QPKG
		// never rotates. So the one thing the bounded queue was for, turning an
		// overflow into a counter instead of unbounded work, was undone one line
		// later: each skipped milestone bought a synchronous write to a file that
		// only ever grows, on the path that is already behind. The mirror worker
		// aggregates the count into at most one notice per minute.
		atomic.AddInt64(&l.milestoneDrops, 1)
	}
}

// mirrorLoop is the one goroutine that ever execs log_tool. Nothing it does can
// reach the sink, the drain or a durable writer, so however long QuLog takes,
// the only thing that falls behind is QuLog.
//
// It is also the only goroutine that writes the drop notice (Astra r8 #5), which
// is why lastErr and the two notice fields need no lock: a burst of skipped
// mirrors costs the drain an atomic increment each and this worker one stderr
// line a minute, whatever the rate.
func (l *Logger) mirrorLoop() {
	defer close(l.mirrorDone)
	// The tick is what reports a burst that ended in silence — the queue filled,
	// the sources stopped, and nothing arrives to carry the count out. Stopping it
	// is deferred before the drain of the queue, so the final forced notice below
	// still runs.
	tick := time.NewTicker(mirrorNoticeInterval)
	defer tick.Stop()
	var lastErr error
	for {
		select {
		case ev, ok := <-l.mirrorCh:
			if !ok {
				// Closed: report whatever is still uncounted, regardless of the
				// interval, so a shutdown does not swallow the last burst.
				l.reportMirrorDrops(true, lastErr)
				return
			}
			fn := l.logFn
			if fn == nil {
				continue
			}
			if err := fn(severity(ev), message(ev)); err != nil {
				atomic.AddInt64(&l.milestoneDrops, 1)
				lastErr = err
			}
			l.reportMirrorDrops(false, lastErr)
		case <-tick.C:
			l.reportMirrorDrops(false, lastErr)
		}
	}
}

// reportMirrorDrops surfaces the milestones that never reached QuLog, at most
// one notice per mirrorNoticeInterval, each carrying the number dropped since
// the last one (Astra r8 #5). force is used on shutdown.
//
// MilestoneDrops() still counts every one of them: the aggregation is about how
// often stderr is written to, not about what is known.
func (l *Logger) reportMirrorDrops(force bool, lastErr error) {
	total := atomic.LoadInt64(&l.milestoneDrops)
	if total <= l.mirrorNoticed {
		return
	}
	now := time.Now()
	if l.mirrorClock != nil {
		now = l.mirrorClock()
	}
	if !force && !l.mirrorNoticeAt.IsZero() && now.Sub(l.mirrorNoticeAt) < mirrorNoticeInterval {
		return
	}
	since := total - l.mirrorNoticed
	l.mirrorNoticed, l.mirrorNoticeAt = total, now
	msg := fmt.Sprintf("%d milestones not mirrored to QuLog (%d total)", since, total)
	if lastErr != nil {
		// The last failure, not one per failure: a QuLog that is refusing calls
		// refuses them all the same way, and the notice is a summary.
		msg += fmt.Sprintf("; the last failure was: %v", lastErr)
	}
	l.errLog(msg)
}

// SetQuLogMirror replaces the function the mirror worker calls, so a test in
// another package can observe what the door offers to QuLog without exec'ing
// /sbin/log_tool. It must be called before anything is written, which is the
// fixture convention everywhere here: the worker reads the field, and nothing
// else may be writing it while it does.
func (l *Logger) SetQuLogMirror(fn func(qnap.Severity, string) error) { l.logFn = fn }

// emitSync writes one event as a JSON line and fsyncs it, returning an error if
// either the write or the fsync fails. It is the durable counterpart of emit,
// used by WriteSync so an acknowledged intent line is truly on stable storage,
// not merely in the OS page cache (adv 1 / standard P1). It does NOT mirror to
// QuLog: the caller acknowledges durability first and then calls mirror(ev)
// outside drainMu (standard P2), so the 10s QuLog path never gates the ack.
//
// appended is the other half of the answer, and the reason it exists is the
// counters (Astra r5 #3). "The fsync failed" and "nothing was written" are not
// the same outcome: once the append has returned, the complete line is in the
// file and any reader will see it — only its survival of a power cut is in
// doubt. A caller that CLEARED state in order to write that line must not put
// the state back on that error, or the burst is reported a second time by a line
// sitting immediately below the first. So: appended is false while the EVENT
// cannot be read back — a failed append leaves at worst a torn fragment, which
// Tail discards as unparseable — and true from the moment the append succeeds.
func (l *Logger) emitSync(ev Event) (appended bool, err error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return false, err
	}
	b = append(b, '\n')
	if _, err := l.w.Write(b); err != nil {
		n := atomic.AddInt64(&l.writeErrors, 1)
		l.reportWriteErr(err, n)
		return false, err
	}
	if err := l.w.Sync(); err != nil {
		n := atomic.AddInt64(&l.writeErrors, 1)
		l.reportWriteErr(err, n)
		return true, err
	}
	return true, nil
}

// syncResult is what a durable writer goroutine reports back: the error, and
// whether the line reached the file before it (Astra r5 #3).
type syncResult struct {
	appended bool
	err      error
}

// reportWriteErr surfaces a sink write failure through errLog, rate-limited to
// dropReportInterval so a run of failures does not itself flood stderr. It runs
// under drainMu (the drain goroutine's serial section), so lastWriteErrAt needs
// no further guard.
func (l *Logger) reportWriteErr(err error, total int64) {
	now := time.Now()
	if !l.lastWriteErrAt.IsZero() && now.Sub(l.lastWriteErrAt) < dropReportInterval {
		return
	}
	l.lastWriteErrAt = now
	l.errLog(fmt.Sprintf("sink write failed (%d total): %v", total, err))
}

// reportDropped periodically writes a synthetic line noting how many events
// have been dropped, so a lost burst is itself visible in the log. force is
// used on shutdown to flush the final count regardless of the interval.
func (l *Logger) reportDropped(force bool) {
	d := atomic.LoadInt64(&l.dropped)
	if d <= l.lastReported {
		return
	}
	now := time.Now()
	if !force && !l.lastReportAt.IsZero() && now.Sub(l.lastReportAt) < dropReportInterval {
		return
	}
	ev := Event{
		T:      now,
		Op:     "audit",
		Phase:  "result",
		Result: "error",
		Code:   "overflow",
		Files:  d - l.lastReported,
		Detail: fmt.Sprintf("%d audit events dropped", d-l.lastReported),
	}
	if b, err := json.Marshal(ev); err == nil {
		_, _ = l.w.Write(append(b, '\n'))
	}
	l.lastReported = d
	l.lastReportAt = now
}

// Tail returns the last n events, reading back the current file and, if it
// holds fewer than n lines, the previous generation. Unparseable lines are
// skipped so a torn final write cannot break the whole read.
func (l *Logger) Tail(n int) ([]Event, error) {
	if n <= 0 {
		return nil, nil
	}
	var lines []string
	// Oldest generation first so the tail comes out in chronological order.
	for _, p := range []string{l.path + ".1", l.path} {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, ln := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			lines = append(lines, ln)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]Event, 0, len(lines))
	for _, ln := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

// isMilestone reports whether ev is worth an exec of log_tool. QuLog must never
// be written per file, so only sign-ins, the first-run claim, read-only
// toggles, any denial, big deletes, chowns and writes under /etc/config
// qualify — plus anything the caller forces.
func isMilestone(ev Event) bool {
	// The explicit refusal first, so it beats the force flag as well as the
	// automatic classification (Astra r7 #1). A caller that has said this line is
	// not for QuLog has said the last word on it.
	if ev.Quiet {
		return false
	}
	if ev.ForceMilestone {
		return true
	}
	if ev.Result == "denied" {
		// A routine confirmation challenge (a token was demanded, none was
		// presented yet) is recorded but is not a QuLog-worthy security event; an
		// invalid presented token and every other denial are.
		return ev.Code != "confirm_required"
	}
	switch ev.Op {
	case "signin", "claim", "readonly", "chown":
		return true
	}
	if isDelete(ev.Op) && (ev.Files > bigDeleteFiles || ev.Bytes > bigDeleteBytes) {
		return true
	}
	if underEtcConfig(effPath(ev.Path, ev.PathB64)) || underEtcConfig(effPath(ev.Dst, ev.DstB64)) {
		return true
	}
	return false
}

func isDelete(op string) bool {
	return op == "delete" || op == "trash-empty" || strings.HasPrefix(op, "delete-")
}

func underEtcConfig(p string) bool {
	return p == "/etc/config" || strings.HasPrefix(p, "/etc/config/")
}

// effPath returns the path bytes to CLASSIFY on: the plain field, or the decoded
// base64 companion when prepare() moved a non-UTF-8 value there and cleared the
// plain field. Milestone and severity classification must see the real bytes, or
// a rename/write to a non-UTF-8 path under /etc/config would silently lose its
// QuLog milestone mirroring (round-13). JSON fidelity is handled separately by
// the b64 companions; this is only for the in-process prefix tests.
func effPath(plain, b64 string) string {
	if plain != "" || b64 == "" {
		return plain
	}
	if dec, err := base64.StdEncoding.DecodeString(b64); err == nil {
		return string(dec)
	}
	return plain
}

// severity maps an event to a QuLog level: failures are errors, denials and
// cancellations warnings, sensitive-but-successful milestones warnings too, and
// routine successes info.
func severity(ev Event) qnap.Severity {
	switch ev.Result {
	case "error":
		return qnap.Error
	case "denied", "cancelled":
		return qnap.Warning
	}
	switch {
	case ev.Op == "chown", ev.Op == "claim",
		isDelete(ev.Op) && (ev.Files > bigDeleteFiles || ev.Bytes > bigDeleteBytes),
		underEtcConfig(effPath(ev.Path, ev.PathB64)) || underEtcConfig(effPath(ev.Dst, ev.DstB64)):
		return qnap.Warning
	}
	return qnap.Info
}

// message renders a one-line summary for QuLog. qnap.Log bounds and prefixes it.
func message(ev Event) string {
	p := ev.Path
	if p == "" && ev.PathB64 != "" {
		p = "b64:" + ev.PathB64
	}
	d := ev.Dst
	if d == "" && ev.DstB64 != "" {
		d = "b64:" + ev.DstB64
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s", ev.Result, ev.Op, p)
	if d != "" {
		fmt.Fprintf(&b, " -> %s", d)
	}
	if ev.Actor != "" {
		fmt.Fprintf(&b, " by %s (uid %d)", ev.Actor, ev.UID)
	}
	if ev.Door != "" {
		// The QuLog line has to answer "which door" on its own: an operator
		// scanning QuLog Center is not reading the JSON beside it.
		fmt.Fprintf(&b, " via %s", ev.Door)
	}
	if ev.Root {
		b.WriteString(" [root]")
	}
	if ev.IP != "" {
		fmt.Fprintf(&b, " from %s", ev.IP)
	}
	if ev.Code != "" {
		fmt.Fprintf(&b, " code=%s", ev.Code)
	}
	if ev.Detail != "" {
		fmt.Fprintf(&b, " (%s)", ev.Detail)
	}
	return b.String()
}
