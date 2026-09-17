package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
)

// --- Astra r3 #2: an aggregate refusal line outlives the request that carries
// it, and the counters it stands for outlive a write that was not admitted ----

// A per-source refusal is request-scoped on purpose: nobody is waiting on a
// denial, and a cancelled request must not go on waiting for a wedged sink. The
// two AGGREGATES are different. Each of them CLEARS what it counts as it is
// written, so a summary that never reached the sink is a burst nobody will ever
// hear about again — and the trigger for one is, by construction, a peer that
// has just come back after a flood, which is exactly the peer most likely to
// hang up mid-request.

// bgLoginWithContext is a returning login whose peer is already gone: the
// request context is cancelled before the handler ever runs, the way a
// disconnected connection's is. Everything else is bgRequestFrom's request.
func bgLoginWithContext(t *testing.T, s *Server, source string, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", bgLoginPath, strings.NewReader(fmt.Sprintf(`{"password":%q}`, bgTestPassword)))
	r.RemoteAddr = net.JoinHostPort(source, "40000")
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(w, r.WithContext(ctx))
	return w
}

// bgRefusingAuditor gives the server an auditor that refuses every write.
//
// A logger closed before anything uses it answers WriteSync with os.ErrClosed,
// which is the same verdict as the case this is about — all four durable-writer
// slots held by a wedged sink — without wedging anything or waiting two seconds
// for the admission timeout.
func bgRefusingAuditor(t *testing.T, s *Server) {
	t.Helper()
	logger, err := audit.Open(filepath.Join(t.TempDir(), "refused.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
}

// The flush summary is written for a source that came BACK inside its budget,
// so the request that triggers it is the returning peer's — and the summary was
// written under that peer's cancellable context. A peer that hung up while the
// four durable slots were busy took the whole window's count with it, because
// the counters had already been cleared to write the line.
func TestAFlushSummarySurvivesTheReturningPeerHangingUp(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil // no impersonation, so the requests really are sessionless
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const source = "192.0.2.90"

	for i := 0; i < suppressed+1; i++ {
		bgSessionlessMutation(t, s, source)
	}
	now = now.Add(2 * refusalWindow)

	// The property itself, asserted on the thing it is a property OF (Astra r5
	// #2): the context the durable write receives. Everything else about this
	// test is circumstantial — SyncWaiting counts a call that has reached the
	// admission attempt, not one that is parked inside it, so observing a waiter
	// does not prove the write is blocked, and a schedule exists in which
	// releasing the slots below hands a request-scoped write its admission before
	// it ever looks at the cancellation. Then the line lands, the test passes, and
	// nothing has been tested. A context either carries the peer's cancellation or
	// it does not, and that is decided here.
	//
	// Every refusal line the returning login writes is collected, not just the
	// summary: they are all written under this rule, and a login answered with the
	// rate answer writes a second one.
	var auditCtxs []context.Context
	originalAuditContext := bgAuditContext
	bgAuditContext = func(r *http.Request) context.Context {
		ctx := originalAuditContext(r)
		auditCtxs = append(auditCtxs, ctx)
		return ctx
	}
	t.Cleanup(func() { bgAuditContext = originalAuditContext })

	// Admission is SATURATED before the cancelled request arrives (Astra r4 #3),
	// which is now belt and braces over the assertion above rather than the proof
	// itself. With a writer slot free the summary's write and the peer's
	// cancellation are two ready cases of one select inside WriteSync and Go picks
	// either; with every slot held the write has to WAIT, and a request-scoped
	// context is then far likelier to take the cancellation exit and lose the
	// line. The slots are released once the summary is observably queued behind
	// them, so the end-to-end half of this test — the summary reaching the log —
	// exercises the wait rather than an idle sink.
	releaseSlots := s.auditor.HoldSyncSlots()
	defer releaseSlots()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- bgLoginWithContext(t, s, source, ctx) }()
	// flushRefusals is the first thing the login handler does that writes, so the
	// one call queued for a slot is the summary and nothing else. A request that
	// finished without ever queuing is the failing case and is not waited out:
	// it means the write took an exit instead of the wait, which is precisely
	// what a request-scoped context makes it do.
	bgWaitFor(t, "the flush summary to queue for a writer slot", func() bool {
		return s.auditor.SyncWaiting() == 1 || len(done) == 1
	})
	releaseSlots()

	// What the door answers a peer that is already gone is not the point and is
	// allowed to be the rate answer: the verification queue observes the request
	// context, so a cancelled one never reaches the credential. The SUMMARY is
	// the point, and it is written before any of that.
	if w := <-done; w.Code != http.StatusNoContent && w.Code != http.StatusTooManyRequests {
		t.Fatalf("the returning login = %d %s", w.Code, w.Body)
	}

	// The handler goroutine is joined, so what it appended is safe to read here.
	if len(auditCtxs) == 0 {
		t.Fatal("the returning login wrote no refusal line at all, so there was nothing to detach")
	}
	for i, c := range auditCtxs {
		if err := c.Err(); err != nil {
			t.Fatalf("refusal line %d of %d was written under the returning peer's own context (%v): a peer that hangs up takes the whole window's count with it", i+1, len(auditCtxs), err)
		}
		if c.Done() != nil {
			t.Errorf("refusal line %d of %d was written under a context something can still cancel; the request's cancellation must not reach the sink at all", i+1, len(auditCtxs))
		}
	}

	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
	assertSessionlessShape(t, ev)
}

// The other half: a summary that was NOT admitted leaves the burst where it
// was, so the next trigger reports it rather than reporting a flood that has
// silently shrunk to nothing.
func TestAFlushSummaryThatWasRefusedIsNotLost(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	bgRefusingAuditor(t, s)
	const source = "192.0.2.91"

	for i := 0; i < suppressed+1; i++ {
		bgSessionlessMutation(t, s, source)
	}
	now = now.Add(2 * refusalWindow)
	// The source returns and the sink refuses the summary.
	if w := bgRequestFrom(s, source, "POST", bgLoginPath, nil, fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusNoContent {
		t.Fatalf("the returning login = %d %s", w.Code, w.Body)
	}
	// The count is still on the window, not thrown away with the refused line.
	s.bg.mu.Lock()
	state := s.bg.refusals[source]
	s.bg.mu.Unlock()
	if state == nil || state.suppressed != suppressed {
		t.Fatalf("after a refused summary the tracked state is %+v, want %d suppressed", state, suppressed)
	}

	// A working sink, and the next return collects the whole burst.
	read := withAudit(t, s)
	if w := bgRequestFrom(s, source, "POST", bgLoginPath, nil, fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusNoContent {
		t.Fatalf("the second login = %d %s", w.Code, w.Body)
	}
	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
	assertSessionlessShape(t, ev)
}

// The same rule on the overflow report, which is the branch a distributed flood
// actually lands in: the untracked-source counter is reset as the line is
// written, so a refused write used to turn a burst of three into a report of
// one — and the rate stamp it set would then hold the next report off for a
// whole window.
func TestTheUntrackedSourceCountSurvivesARefusedReport(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	bgRefusingAuditor(t, s)

	// The table full of live windows, on a frozen clock so nothing is pruned.
	for i := 0; i < breakglass.MaxSources; i++ {
		bgSessionlessMutation(t, s, fmt.Sprintf("198.51.100.%d", i))
	}
	if n := len(s.bg.refusals); n != breakglass.MaxSources {
		t.Fatalf("%d tracked sources, want the table full at %d", n, breakglass.MaxSources)
	}
	// Two denials from sources that cannot be tracked, both reported into a sink
	// that refuses them.
	bgSessionlessMutation(t, s, "203.0.113.9")
	bgSessionlessMutation(t, s, "203.0.113.10")

	read := withAudit(t, s)
	bgSessionlessMutation(t, s, "203.0.113.11")

	ev := bgEventWith(t, read(), "3 refusals from untracked sources")
	assertSessionlessShape(t, ev)
}
