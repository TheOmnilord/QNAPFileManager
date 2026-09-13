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

// dropReportInterval bounds how often the "N audit events dropped" notice is
// written, so a sustained overflow does not itself flood the log.
const dropReportInterval = 5 * time.Second

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
}

// Logger writes audit events without blocking the caller.
type Logger struct {
	path  string
	w     *logfile.Writer
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
		path:    path,
		w:       w,
		qulog:   qulog,
		ch:      make(chan Event, bufferDepth),
		done:    make(chan struct{}),
		syncSem: make(chan struct{}, syncWriters),
		logFn: func(sev qnap.Severity, msg string) error {
			return qnap.Log(context.Background(), sev, msg)
		},
		errLog:       func(msg string) { fmt.Fprintln(os.Stderr, "qfm audit: "+msg) },
		closeTimeout: closeDrainTimeout,
	}
	go l.drain()
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
func (l *Logger) Write(ev Event) {
	ev = l.prepare(ev)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return
	}
	select {
	case l.ch <- ev:
	default:
		atomic.AddInt64(&l.dropped, 1)
	}
}

// ErrSyncTimeout is returned by WriteSync when a durable write cannot reach the
// sink (write + fsync, or even a writer slot) within writeSyncTimeout. A caller
// that must not proceed without a durable record — a mutation's intent line, a
// safety-setting milestone — treats it, and any other WriteSync error, as a hard
// failure and refuses the operation (adv 1).
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
	if ctx == nil {
		ctx = context.Background()
	}
	ev = l.prepare(ev)
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return os.ErrClosed
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
	select {
	case l.syncSem <- struct{}{}:
	case <-ctx.Done():
		l.syncWG.Done()
		return ctx.Err()
	case <-l.done:
		l.syncWG.Done()
		return os.ErrClosed
	case <-timer.C:
		l.syncWG.Done()
		return ErrSyncTimeout
	}

	res := make(chan error, 1)
	go func() {
		defer l.syncWG.Done()
		defer func() { <-l.syncSem }()
		l.drainMu.Lock()
		err := l.emitSync(ev)
		l.drainMu.Unlock()
		// Acknowledge durability BEFORE mirroring: the line is fsynced, so the
		// caller may proceed. The QuLog mirror then runs best-effort, outside
		// drainMu and off the ack path, still holding this syncSem slot so a
		// wedged QuLog is bounded to syncWriters goroutines (standard P2).
		res <- err
		if err == nil {
			l.mirror(ev)
		}
	}()

	select {
	case err := <-res:
		return err
	case <-ctx.Done():
		// The write goroutine keeps its slot until it finishes (so a stuck write
		// is not abandoned back into the pool); the caller simply stops waiting.
		return ctx.Err()
	case <-timer.C:
		return ErrSyncTimeout
	}
}

// Dropped returns how many events have been dropped due to buffer overflow.
func (l *Logger) Dropped() int64 { return atomic.LoadInt64(&l.dropped) }

// WriteErrors returns how many events failed to reach the sink (disk full, I/O
// error). It is distinct from Dropped: an overflow drop never reached the drain,
// while a write error means the drain could not persist a dequeued event.
func (l *Logger) WriteErrors() int64 { return atomic.LoadInt64(&l.writeErrors) }

// MilestoneDrops returns how many milestone events could not be mirrored to
// QuLog. The audit line still lands in the file; only the QuLog mirror was lost.
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
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
		return l.w.Close()
	case <-timer.C:
		l.errLog("close timed out draining the audit sink; some events may be unflushed and the file is left open")
		return ErrCloseTimeout
	}
}

func (l *Logger) drain() {
	defer close(l.done)
	for ev := range l.ch {
		l.drainMu.Lock()
		l.emit(ev)
		l.reportDropped(false)
		l.drainMu.Unlock()
		// Mirror outside drainMu so a slow QuLog cannot hold the sink lock and
		// stall the drain of the next event (standard P2).
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

// mirror best-effort-copies a milestone to QuLog. It is deliberately called
// OUTSIDE drainMu and, on the durable path, AFTER the caller has been told the
// write is persisted (standard P2): qnap.Log blocks up to 10s, and that latency
// must never hold the sink lock, stall the async drain, or turn a successfully
// fsynced intent into a false ErrSyncTimeout. A dropped mirror is counted and
// surfaced (adv 10); the audit line itself is already on disk regardless.
func (l *Logger) mirror(ev Event) {
	if !l.qulog || l.logFn == nil || !isMilestone(ev) {
		return
	}
	if err := l.logFn(severity(ev), message(ev)); err != nil {
		n := atomic.AddInt64(&l.milestoneDrops, 1)
		l.errLog(fmt.Sprintf("milestone not mirrored to QuLog (%d total): %v", n, err))
	}
}

// emitSync writes one event as a JSON line and fsyncs it, returning an error if
// either the write or the fsync fails. It is the durable counterpart of emit,
// used by WriteSync so an acknowledged intent line is truly on stable storage,
// not merely in the OS page cache (adv 1 / standard P1). It does NOT mirror to
// QuLog: the caller acknowledges durability first and then calls mirror(ev)
// outside drainMu (standard P2), so the 10s QuLog path never gates the ack.
func (l *Logger) emitSync(ev Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := l.w.Write(b); err != nil {
		n := atomic.AddInt64(&l.writeErrors, 1)
		l.reportWriteErr(err, n)
		return err
	}
	if err := l.w.Sync(); err != nil {
		n := atomic.AddInt64(&l.writeErrors, 1)
		l.reportWriteErr(err, n)
		return err
	}
	return nil
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
