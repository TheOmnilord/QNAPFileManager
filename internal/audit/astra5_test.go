package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// --- Astra r5 #3: a durable write has three outcomes, not two -----------------

// A caller that CLEARS state in order to write a line — the break-glass door's
// aggregate refusal summaries are the only ones, and they are the reason
// WriteSyncInFlight exists at all — decides on inFlight whether to put that
// state back. So the question inFlight answers has to be "can this event be read
// out of the log", not "did the call return nil": a line that was appended and
// then failed its fsync is in the file and every reader will see it, and putting
// the counters back for it reports the same burst twice, in two adjacent lines.

// failingSink is the real file with one of its two steps made to fail. Nothing a
// test can do to an actual file fails the fsync alone — a full disk fails the
// write, a closed handle fails both — which is why the logger's sink is an
// interface.
type failingSink struct {
	sink
	writeErr error
	syncErr  error
}

func (s *failingSink) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.sink.Write(p)
}

func (s *failingSink) Sync() error {
	if s.syncErr != nil {
		return s.syncErr
	}
	return s.sink.Sync()
}

// astra5Logger is a logger writing to a real file, with its sink wrapped and its
// failure notices captured rather than printed.
func astra5Logger(t *testing.T, wrap func(sink) sink) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	l.errLog = func(string) {}
	l.w = wrap(l.w)
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// astra5Event is a summary line of the shape the refusal aggregates write: the
// detail is what a reader would go looking for.
func astra5Event(detail string) Event {
	return Event{Op: "auth", Phase: "result", Result: "denied", Code: "unauthorized", Detail: detail, ForceMilestone: true}
}

// The fsync fails over a line that is already in the file. The call still fails —
// durability really is unproven — but it is NOT the definite "nothing was
// written" the counters may be restored on.
func TestAnFsyncFailureOverAnAppendedLineIsNotDefinite(t *testing.T) {
	const detail = "4 further refusals suppressed; the source is inside its budget again"
	l, path := astra5Logger(t, func(w sink) sink {
		return &failingSink{sink: w, syncErr: errors.New("fsync: input/output error")}
	})

	inFlight, err := l.WriteSyncInFlight(context.Background(), astra5Event(detail))
	if err == nil {
		t.Fatal("a failing fsync was reported as a durable write")
	}
	if !inFlight {
		t.Fatalf("a line that was appended and then failed its fsync came back as definitely unwritten (err %v); every caller that cleared a counter to write it would report the burst again", err)
	}

	// And it really is readable: this is the whole reason the outcome is not
	// definite.
	events, terr := l.Tail(10)
	if terr != nil {
		t.Fatalf("reading %s back: %v", path, terr)
	}
	found := 0
	for _, ev := range events {
		if strings.Contains(ev.Detail, detail) {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("%d lines in the log carry the summary, want the appended one: %+v", found, events)
	}
}

// The append itself fails, so nothing readable reached the file and nothing ever
// will. That outcome IS definite, and the counters go back on it.
func TestAnAppendThatFailedIsDefinite(t *testing.T) {
	const detail = "5 further refusals suppressed; the source is inside its budget again"
	l, path := astra5Logger(t, func(w sink) sink {
		return &failingSink{sink: w, writeErr: errors.New("write: no space left on device")}
	})

	inFlight, err := l.WriteSyncInFlight(context.Background(), astra5Event(detail))
	if err == nil {
		t.Fatal("a failing append was reported as a durable write")
	}
	if inFlight {
		t.Fatal("an append that failed with nothing in the file came back as still in flight; the burst it stood for would be dropped rather than restored")
	}

	events, terr := l.Tail(10)
	if terr != nil {
		t.Fatalf("reading %s back: %v", path, terr)
	}
	for _, ev := range events {
		if strings.Contains(ev.Detail, detail) {
			t.Fatalf("the log holds a line the write said it had not written: %+v", ev)
		}
	}
}
