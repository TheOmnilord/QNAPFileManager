package audit

import (
	"encoding/base64"
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
