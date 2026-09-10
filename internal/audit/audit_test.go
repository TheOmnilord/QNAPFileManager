package audit

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/qnap"
)

// recorder captures milestone mirror calls in place of qnap.Log.
type recorder struct {
	mu   sync.Mutex
	msgs []string
	sevs []qnap.Severity
}

func (r *recorder) log(sev qnap.Severity, msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sevs = append(r.sevs, sev)
	r.msgs = append(r.msgs, msg)
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

func openTest(t *testing.T, qulog bool) (*Logger, *recorder) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, qulog)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rec := &recorder{}
	l.logFn = rec.log
	return l, rec
}

func TestWriteAndTail(t *testing.T) {
	l, _ := openTest(t, false)
	for i := 0; i < 5; i++ {
		l.Write(Event{Actor: "alice", UID: 1000, Op: "mkdir", Path: "/etc/x", Phase: "result", Result: "ok"})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 5 {
		t.Fatalf("got %d events, want 5", len(evs))
	}
	if evs[0].Actor != "alice" || evs[0].Op != "mkdir" || evs[0].Result != "ok" {
		t.Fatalf("unexpected event: %+v", evs[0])
	}
	if evs[0].T.IsZero() {
		t.Fatalf("timestamp not stamped")
	}
}

func TestTailLimit(t *testing.T) {
	l, _ := openTest(t, false)
	for i := 0; i < 20; i++ {
		l.Write(Event{Op: "stat", Path: "/a", Phase: "result", Result: "ok", Files: int64(i)})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(3)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d, want 3", len(evs))
	}
	// Tail returns the most recent events in chronological order.
	if evs[2].Files != 19 {
		t.Fatalf("last event Files=%d, want 19", evs[2].Files)
	}
}

func TestIntentAndResultPair(t *testing.T) {
	l, _ := openTest(t, false)
	l.Write(Event{Op: "delete", Path: "/data", Phase: "intent", Result: "ok", Files: 3})
	l.Write(Event{Op: "delete", Path: "/data", Phase: "result", Result: "ok", Files: 3})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 2 || evs[0].Phase != "intent" || evs[1].Phase != "result" {
		t.Fatalf("intent+result not both recorded: %+v", evs)
	}
}

func TestWriteNeverBlocks(t *testing.T) {
	l, _ := openTest(t, false)
	// Freeze the drain so the buffer cannot be emptied.
	l.drainMu.Lock()

	const n = bufferDepth * 3
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			l.Write(Event{Op: "stat", Path: "/x", Phase: "result", Result: "ok"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		l.drainMu.Unlock()
		t.Fatal("Write blocked while drain was frozen")
	}
	if l.Dropped() == 0 {
		l.drainMu.Unlock()
		t.Fatalf("expected drops with a frozen drain, got 0")
	}
	l.drainMu.Unlock()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestMilestoneMirror(t *testing.T) {
	cases := []struct {
		name      string
		ev        Event
		milestone bool
	}{
		{"ordinary-op", Event{Op: "mkdir", Path: "/data/x", Phase: "result", Result: "ok"}, false},
		{"denied", Event{Op: "chmod", Path: "/etc/hosts", Phase: "result", Result: "denied"}, true},
		{"big-delete-files", Event{Op: "delete", Path: "/data", Phase: "result", Result: "ok", Files: 500}, true},
		{"big-delete-bytes", Event{Op: "delete", Path: "/data", Phase: "result", Result: "ok", Bytes: 2 << 30}, true},
		{"small-delete", Event{Op: "delete", Path: "/data", Phase: "result", Result: "ok", Files: 3}, false},
		{"etc-config-write", Event{Op: "write", Path: "/etc/config/uLinux.conf", Phase: "result", Result: "ok"}, true},
		{"chown", Event{Op: "chown", Path: "/data/x", Phase: "result", Result: "ok"}, true},
		{"signin", Event{Op: "signin", Actor: "bob", Phase: "result", Result: "ok"}, true},
		{"forced", Event{Op: "mkdir", Path: "/data/y", Phase: "result", Result: "ok", ForceMilestone: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, rec := openTest(t, true)
			l.Write(tc.ev)
			if err := l.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			got := rec.count()
			if tc.milestone && got != 1 {
				t.Fatalf("milestone: mirror called %d times, want 1", got)
			}
			if !tc.milestone && got != 0 {
				t.Fatalf("non-milestone: mirror called %d times, want 0", got)
			}
		})
	}
}

func TestMilestoreNotMirroredWhenDisabled(t *testing.T) {
	l, rec := openTest(t, false)
	l.Write(Event{Op: "chown", Path: "/data/x", Phase: "result", Result: "ok"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("mirror called with qulog disabled")
	}
}

func TestNonUTF8Path(t *testing.T) {
	l, _ := openTest(t, false)
	raw := "/data/\xff\xfename"
	l.Write(Event{Op: "stat", Path: raw, Phase: "result", Result: "ok"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	evs, err := l.Tail(1)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].Path != "" {
		t.Fatalf("Path should be cleared for non-UTF-8, got %q", evs[0].Path)
	}
	if evs[0].PathB64 == "" {
		t.Fatalf("PathB64 not populated")
	}
	dec, err := base64.StdEncoding.DecodeString(evs[0].PathB64)
	if err != nil {
		t.Fatalf("PathB64 decode: %v", err)
	}
	if string(dec) != raw {
		t.Fatalf("round-trip mismatch: %q != %q", dec, raw)
	}
}

// TestMilestoneDropSurfaced proves the adv 10 fix: a milestone whose QuLog
// mirror fails is counted and surfaced through errLog, not silently swallowed.
// The audit line itself still lands in the file.
func TestMilestoneDropSurfaced(t *testing.T) {
	l, _ := openTest(t, true)
	l.logFn = func(qnap.Severity, string) error { return errors.New("log_tool unavailable") }
	var mu sync.Mutex
	var notices []string
	l.errLog = func(msg string) { mu.Lock(); notices = append(notices, msg); mu.Unlock() }

	l.Write(Event{Op: "chown", Path: "/data/x", Phase: "result", Result: "ok"}) // a milestone
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if l.MilestoneDrops() != 1 {
		t.Fatalf("MilestoneDrops = %d, want 1", l.MilestoneDrops())
	}
	mu.Lock()
	got := len(notices)
	mu.Unlock()
	if got == 0 {
		t.Fatal("a dropped milestone was not surfaced through errLog")
	}
	// The audit line still made it to the file.
	evs, err := l.Tail(1)
	if err != nil || len(evs) != 1 || evs[0].Op != "chown" {
		t.Fatalf("audit line missing after milestone drop: %v %+v", err, evs)
	}
}

// TestSinkWriteFailureSurfaced proves the adv 10 fix: a sink write failure is
// counted (distinct from a queue-overflow drop) and surfaced through errLog.
func TestSinkWriteFailureSurfaced(t *testing.T) {
	l, _ := openTest(t, false)
	var mu sync.Mutex
	var notices []string
	l.errLog = func(msg string) { mu.Lock(); notices = append(notices, msg); mu.Unlock() }
	// Close the underlying sink so every subsequent write fails, then drive one
	// event through emit directly (deterministic, no drain timing).
	if err := l.w.Close(); err != nil {
		t.Fatalf("closing sink: %v", err)
	}
	l.emit(Event{Op: "delete", Path: "/data/x", Phase: "result", Result: "ok"})

	if l.WriteErrors() != 1 {
		t.Fatalf("WriteErrors = %d, want 1", l.WriteErrors())
	}
	if l.Dropped() != 0 {
		t.Fatalf("Dropped = %d, want 0 (a write error is not an overflow drop)", l.Dropped())
	}
	mu.Lock()
	got := len(notices)
	mu.Unlock()
	if got == 0 {
		t.Fatal("a sink write failure was not surfaced through errLog")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file mode not enforced on Windows (INV-2: never simulate the kernel)")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.Write(Event{Op: "stat", Path: "/a", Phase: "result", Result: "ok"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}
}

// TestWriteSyncDurable proves WriteSync persists an event to the sink before it
// returns, without waiting for Close or the drain — the durability the intent
// line and milestones rely on (adv 10). An ordinary async Write makes no such
// promise; only the synchronous path is asserted here.
func TestWriteSyncDurable(t *testing.T) {
	l, rec := openTest(t, true)
	defer l.Close()
	l.WriteSync(Event{Actor: "alice", UID: 1000, Op: "delete", Path: "/x", Phase: "intent"})
	// Readable immediately, with no Close in between.
	evs, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	var found bool
	for _, e := range evs {
		if e.Op == "delete" && e.Phase == "intent" && e.Actor == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("WriteSync event not durable before Close: %d events", len(evs))
	}
	// A forced milestone written synchronously is mirrored to QuLog.
	l.WriteSync(Event{Op: "readonly", Phase: "result", Result: "ok", ForceMilestone: true})
	if rec.count() == 0 {
		t.Fatal("WriteSync milestone not mirrored to QuLog")
	}
}

// TestConfirmChallengeNotMilestone proves a routine confirmation challenge
// (denied with code confirm_required) is recorded but is not a QuLog milestone,
// while an invalid presented token (confirm_invalid) and other denials are.
func TestConfirmChallengeNotMilestone(t *testing.T) {
	if isMilestone(Event{Result: "denied", Code: "confirm_required"}) {
		t.Fatal("a confirmation challenge must not be a milestone")
	}
	if !isMilestone(Event{Result: "denied", Code: "confirm_invalid"}) {
		t.Fatal("an invalid confirmation token is a milestone")
	}
	if !isMilestone(Event{Result: "denied", Code: "protected"}) {
		t.Fatal("a protected denial is a milestone")
	}
}
