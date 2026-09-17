package audit

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/qnap"
)

// --- Astra r7 #1: the QuLog mirror is not on the path of the record ----------

// mirrorSeam is a log_tool that can be stopped. enter fires on the first call so
// a test knows the worker is inside the exec, and nothing returns until release
// is closed — which is what a QuLog that answers in ten seconds looks like from
// here, without waiting ten seconds for it.
type mirrorSeam struct {
	enter   chan struct{}
	release chan struct{}
	calls   int64

	mu   sync.Mutex
	msgs []string
}

func newMirrorSeam() *mirrorSeam {
	return &mirrorSeam{enter: make(chan struct{}, 1), release: make(chan struct{})}
}

func (m *mirrorSeam) log(_ qnap.Severity, msg string) error {
	m.mu.Lock()
	m.msgs = append(m.msgs, msg)
	m.mu.Unlock()
	if atomic.AddInt64(&m.calls, 1) == 1 {
		m.enter <- struct{}{}
	}
	<-m.release
	return nil
}

func (m *mirrorSeam) seen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.msgs...)
}

// A mirror that has stopped answering must cost the FILE nothing. It used to
// cost it everything: the drain called log_tool inline between events, so a
// hundred queued lines were a hundred execs long — 256 LAN sources denied once a
// minute against a ten-second QuLog is a file hours behind the events it records,
// and then a full buffer, and then the results of real work being dropped. The
// mirror has its own worker now, so the only thing a wedged log_tool delays is
// log_tool.
func TestTheFileDrainsWhileTheMirrorIsStuck(t *testing.T) {
	const events = 100
	l, _ := openTest(t, true)
	seam := newMirrorSeam()
	l.logFn = seam.log
	var notices int64
	l.errLog = func(string) { atomic.AddInt64(&notices, 1) }

	for i := 0; i < events; i++ {
		l.Write(Event{Op: "chown", Path: fmt.Sprintf("/data/%d", i), Phase: "result", Result: "ok"})
	}
	// The mirror worker is inside the exec and is not coming out. Everything
	// below happens while it is stuck there, so no part of this is a measurement
	// of how fast the machine is.
	<-seam.enter

	deadline := time.Now().Add(10 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		lines, err := l.Tail(events + 16)
		if err != nil {
			t.Fatalf("Tail: %v", err)
		}
		got = 0
		for _, ev := range lines {
			if ev.Op == "chown" {
				got++
			}
		}
		if got == events {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got != events {
		t.Fatalf("%d of %d lines reached the file with the mirror wedged; the drain is still waiting for log_tool", got, events)
	}
	if n := atomic.LoadInt64(&seam.calls); n != 1 {
		t.Fatalf("the mirror made %d calls while blocked inside its first; the seam is not holding it", n)
	}
	// And the mirrors that could not fit behind the stuck one were SKIPPED, not
	// queued without limit: the queue is a notification path, and one that is a
	// thousand events behind is notifying nobody. Each skip is counted and
	// surfaced.
	if drops := l.MilestoneDrops(); drops == 0 {
		t.Error("a hundred milestones fitted behind a wedged mirror; the mirror queue is not bounded")
	}
	if atomic.LoadInt64(&notices) == 0 {
		t.Error("a skipped mirror was not surfaced through errLog")
	}

	close(seam.release)
	l.closeTimeout = 5 * time.Second
	if err := l.Close(); err != nil {
		t.Fatalf("Close after releasing the mirror: %v", err)
	}
}

// Close is bounded even when the mirror never answers: the worker holds nothing
// the sink needs, so shutdown reports the timeout instead of waiting on QuLog.
func TestCloseIsNotHeldByAWedgedMirror(t *testing.T) {
	l, _ := openTest(t, true)
	seam := newMirrorSeam()
	l.logFn = seam.log
	l.errLog = func(string) {}
	l.closeTimeout = 250 * time.Millisecond

	l.Write(Event{Op: "chown", Path: "/data/x", Phase: "result", Result: "ok"})
	<-seam.enter

	start := time.Now()
	err := l.Close()
	elapsed := time.Since(start)
	if err != ErrCloseTimeout {
		t.Fatalf("Close = %v, want %v", err, ErrCloseTimeout)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Close took %v with the mirror wedged; it is waiting on QuLog", elapsed)
	}
	close(seam.release)
}

// --- Astra r7 #1: an event may refuse the mirror outright --------------------

// Every denial is a milestone by the automatic classification, and that made a
// QuLog exec out of a line anybody on the LAN can produce without a password or
// a session. Quiet is how the writer of such a line says it is for the record
// and not for the notification — and it beats the force flag, because it is the
// more specific statement of the two.
func TestQuietEventsAreWrittenButNeverMirrored(t *testing.T) {
	l, _ := openTest(t, true)
	var mu sync.Mutex
	var mirrored []string
	l.logFn = func(_ qnap.Severity, msg string) error {
		mu.Lock()
		defer mu.Unlock()
		mirrored = append(mirrored, msg)
		return nil
	}

	// A sessionless denial in the shape the break-glass door writes it.
	l.Write(Event{Op: "auth", Path: "/api/fs/mkdir", Phase: "result", Result: "denied", Code: "unauthorized", Quiet: true})
	// The same line, forced — Quiet still wins.
	l.Write(Event{Op: "auth", Path: "/api/fs/mkdir", Phase: "result", Result: "denied", Code: "unauthorized", Quiet: true, ForceMilestone: true})
	// And a real use of the door, which is what QuLog is for.
	l.Write(Event{Op: "breakglass-login", Phase: "result", Result: "ok", Detail: "door=local", ForceMilestone: true})

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mu.Lock()
	seen := append([]string(nil), mirrored...)
	mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("%d events reached QuLog, want only the forced milestone: %v", len(seen), seen)
	}
	if !strings.Contains(seen[0], "breakglass-login") {
		t.Errorf("the mirrored line is %q, want the door's own event", seen[0])
	}
	// All three are in the FILE: quiet is about the mirror, never about the
	// record.
	lines, err := l.Tail(10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("%d lines in the log, want all 3", len(lines))
	}
	for _, ev := range lines {
		if ev.Quiet {
			t.Error("Quiet was serialised; it is a decision flag, not part of the record")
		}
	}
}

// isMilestone is the one place the marking has to be honoured, so it is asserted
// there directly as well: the classification above it is what a future denial
// code would otherwise inherit.
func TestIsMilestoneHonoursQuiet(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   Event
		want bool
	}{
		{"a denial is a milestone", Event{Op: "auth", Result: "denied", Code: "unauthorized"}, true},
		{"a quiet denial is not", Event{Op: "auth", Result: "denied", Code: "unauthorized", Quiet: true}, false},
		{"quiet beats forced", Event{Op: "mkdir", Result: "ok", Quiet: true, ForceMilestone: true}, false},
		{"forced still works", Event{Op: "mkdir", Result: "ok", ForceMilestone: true}, true},
		{"and an ordinary result is neither", Event{Op: "mkdir", Result: "ok"}, false},
	} {
		if got := isMilestone(tc.ev); got != tc.want {
			t.Errorf("%s: isMilestone = %v, want %v", tc.name, got, tc.want)
		}
	}
}
