package audit

import (
	"path/filepath"
	"testing"
)

// --- Astra r6 #2: the async path answers, so a caller can account for it ------

// The break-glass door's sessionless refusal lines moved off the durable path:
// a forged mutation is not a use of the door and must not spend a writer slot on
// one. But those lines still stand for counters the door CLEARS as it writes
// them, so the async path has to answer the one question the durable one does —
// was this event taken — and it has to answer it without an in-flight case,
// which is the whole reason that accounting becomes trivial.

func astra6Logger(t *testing.T) *Logger {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "queued.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestWriteQueuedAnswersWhetherTheEventWasTaken(t *testing.T) {
	l := astra6Logger(t)
	if !l.WriteQueued(Event{Op: "auth", Phase: "result", Result: "denied", Code: "unauthorized"}) {
		t.Fatal("an ordinary event was refused by an open logger")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Closed: definitely not taken, and the caller is the only place the line's
	// counters still exist.
	if l.WriteQueued(Event{Op: "auth", Phase: "result", Result: "denied"}) {
		t.Error("a closed logger claimed to have queued an event")
	}
	events, err := l.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("%d lines in the log, want the one that was accepted", len(events))
	}
}

// A queue that is full refuses, rather than blocking the request goroutine that
// is writing the line — which is the property the door relies on when a flood is
// what produced the line in the first place.
func TestWriteQueuedRefusesAFullQueue(t *testing.T) {
	l := astra6Logger(t)
	// The drain takes one event and stops inside the sink, so everything after it
	// accumulates in the channel.
	releaseSink := l.HoldSink()
	defer releaseSink()

	var refused int
	for i := 0; i < bufferDepth+64; i++ {
		if !l.WriteQueued(Event{Op: "auth", Phase: "result", Result: "denied"}) {
			refused++
		}
	}
	if refused == 0 {
		t.Fatalf("%d events all fitted in a queue of %d with the sink frozen", bufferDepth+64, bufferDepth)
	}
	if dropped := l.Dropped(); int(dropped) != refused {
		t.Errorf("%d events refused but the drop counter says %d", refused, dropped)
	}
	releaseSink()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
