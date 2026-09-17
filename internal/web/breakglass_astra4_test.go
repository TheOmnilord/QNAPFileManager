package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Astra r4 #1 and #2: a claimed burst is neither dropped nor reported twice -

// bgWaitFor spins until cond holds or the test's patience runs out. Every use
// waits on an observable state — a queued durable write, a tracked source — so
// the bound is a failure report and never a timing assumption.
func bgWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// bgReturningRequest is the request a returning peer's login would carry, built
// but not served. The two tests below drive flushRefusals directly: what they are
// about is the order of three things against one another — a claim, a competing
// deletion and a write's verdict — and the handler has no seam that would let a
// test stand between them.
func bgReturningRequest(source string) *http.Request {
	r := httptest.NewRequest("POST", bgLoginPath, strings.NewReader(`{"password":"x"}`))
	r.RemoteAddr = net.JoinHostPort(source, "40000")
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	// The mark the outermost break-glass handler sets, which is what doorOf reads:
	// a summary written for this listener has to carry this listener's door, and a
	// request built by hand would otherwise be stamped as the QTS one.
	return r.WithContext(context.WithValue(r.Context(), breakGlassKey{}, true))
}

// bgTracked is the tracked state for one source, read under the door's lock.
func bgTracked(s *Server, ip string) (opened time.Time, suppressed, claimed int, present bool) {
	s.bg.mu.Lock()
	defer s.bg.mu.Unlock()
	st := s.bg.refusals[ip]
	if st == nil {
		return time.Time{}, 0, 0, false
	}
	return st.opened, st.suppressed, st.claimed, true
}

// Astra r4 #1: a flush takes the count out of the entry and then waits for the
// sink, and for as long as it waits that entry is the only place the burst
// exists. Two things used to delete it underneath: the very next login from the
// same source, which saw nothing suppressed and swept the closed window away,
// and another source's refusal, whose pruning of aged entries does not know or
// care that one of them is being reported on. Either one turned the rollback of
// a refused write into a silent loss of the whole flood.
//
// The burst is one of refused LOGINS (Astra r6 #2). A claim is only ever open
// while a DURABLE write is outstanding, and the sessionless shape no longer
// makes one: it queues, which is answered on the spot. Refusals at the door are
// still written durably — they are uses of the door — so this is where the
// window between claiming a count and learning its fate still exists, and it is
// the shape the test has to use to stand inside it.
func TestAClaimedBurstIsNotDeletedWhileItsSummaryIsInFlight(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	withAudit(t, s)
	const source = "192.0.2.94"
	const other = "192.0.2.95"

	for i := 0; i < suppressed+1; i++ {
		bgRefusedLogin(t, s, source)
	}
	// Two windows on, which is exactly the age at which the pruning sweep gives
	// up on an entry with a pending summary — the harshest case for the claim.
	now = now.Add(2 * refusalWindow)
	opened, _, _, ok := bgTracked(s, source)
	if !ok {
		t.Fatal("the burst was not tracked at all")
	}

	// Every writer slot held, so the flush's summary waits in admission and the
	// claim stays open for as long as this test wants it to.
	releaseSlots := s.auditor.HoldSyncSlots()
	defer releaseSlots()
	flushed := make(chan struct{})
	go func() {
		s.bg.flushRefusals(bgReturningRequest(source), source)
		close(flushed)
	}()
	bgWaitFor(t, "the summary to queue for a writer slot", func() bool { return s.auditor.SyncWaiting() == 1 })
	if _, sup, claimed, ok := bgTracked(s, source); !ok || sup != 0 || claimed != suppressed {
		t.Fatalf("with the summary in flight the entry is (present %v, suppressed %d, claimed %d), want the burst claimed", ok, sup, claimed)
	}

	// The returning-source path: the same peer knocks again, finds nothing
	// suppressed, and must leave the claimed entry alone.
	s.bg.flushRefusals(bgReturningRequest(source), source)
	if _, _, claimed, ok := bgTracked(s, source); !ok || claimed != suppressed {
		t.Fatalf("a second return deleted the claimed entry (present %v, claimed %d)", ok, claimed)
	}

	// The pruning path: a refusal from a different source sweeps aged entries as
	// it opens its own window. Its own line is queued rather than durable now
	// (Astra r6 #2), so it no longer waits behind the held slots — but it still
	// reads s.auditor, and the two things this test does next are to close that
	// logger and to hand the server a different one. A goroutine reading the field
	// while the test writes it is a data race the Linux -race job can catch and a
	// write to the wrong logger everywhere else, so the goroutine signals and is
	// JOINED below, before the auditor is touched at all (Astra r5 #1).
	otherDone := make(chan struct{})
	go func() {
		s.bg.noteUnauthenticated(bgReturningRequest(other))
		close(otherDone)
	}()
	bgWaitFor(t, "the other source to be tracked", func() bool { _, _, _, ok := bgTracked(s, other); return ok })
	if _, _, claimed, ok := bgTracked(s, source); !ok || claimed != suppressed {
		t.Fatalf("another source's pruning deleted the claimed entry (present %v, claimed %d)", ok, claimed)
	}

	// Now the write is definitively refused: closing the logger answers every
	// queued admission with os.ErrClosed, which is a write that never happened
	// and never will. The burst has to come back.
	if err := s.auditor.Close(); err != nil {
		t.Fatalf("closing the sink: %v", err)
	}
	// Both goroutines are answered by that close, and both are joined here: no
	// goroutine this test started is still looking at s.auditor by the time the
	// replacement below lands, and none outlives the test (Astra r5 #1).
	<-flushed
	<-otherDone
	gotOpened, sup, claimed, ok := bgTracked(s, source)
	if !ok || sup != suppressed || claimed != 0 {
		t.Fatalf("after a refused summary the entry is (present %v, suppressed %d, claimed %d), want %d suppressed and no claim", ok, sup, claimed, suppressed)
	}
	if !gotOpened.Equal(opened) {
		t.Fatalf("the restored burst landed on a different window: %v, want %v", gotOpened, opened)
	}

	// A working sink, and the whole burst is reported — once, and at its real
	// size.
	read := withAudit(t, s)
	s.bg.flushRefusals(bgReturningRequest(source), source)
	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
	assertLoginShape(t, ev)
	if _, _, _, ok := bgTracked(s, source); ok {
		t.Error("the entry outlived the summary that emptied it")
	}
}

// Astra r4 #2: WriteSync answers ErrSyncTimeout for a write that was ADMITTED
// and is still on its way to the disk — the caller merely stopped waiting. The
// counters were cleared to write that line, and putting them back on that error
// reports the same burst a second time when the first line lands a moment later.
// A flood that doubles is as much a lie about the number as a flood that
// vanishes.
//
// Refused LOGINS again (Astra r6 #2): a timeout on a write that was admitted is
// a state only the durable path has, and that is now the login shape's path
// alone.
func TestASummaryThatTimedOutInTheSinkIsNotReportedTwice(t *testing.T) {
	if testing.Short() {
		t.Skip("this one waits out the two-second durable-write timeout")
	}
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const source = "192.0.2.96"

	for i := 0; i < suppressed+1; i++ {
		bgRefusedLogin(t, s, source)
	}
	now = now.Add(2 * refusalWindow)

	// The SINK is frozen, not admission: the summary gets a slot, reaches the
	// write, and stops there — so the call times out on a line that is going to
	// be written the moment the sink moves again.
	releaseSink := s.auditor.HoldSink()
	// Released on the way out as well as below, so a failing assertion cannot
	// leave the sink frozen: Close would then spend its whole timeout and hand
	// the cleanup a file still open.
	defer releaseSink()
	s.bg.flushRefusals(bgReturningRequest(source), source)
	if _, sup, claimed, ok := bgTracked(s, source); sup != 0 || claimed != 0 {
		t.Fatalf("a timed-out summary put the burst back (present %v, suppressed %d, claimed %d); the next flush would report it again", ok, sup, claimed)
	}
	releaseSink()

	// The source returns once more. There is nothing left to report, and the
	// line the first flush gave up on is the only one in the log.
	s.bg.flushRefusals(bgReturningRequest(source), source)
	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
	assertLoginShape(t, ev)
}
