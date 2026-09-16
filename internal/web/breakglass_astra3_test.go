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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// What the door answers a peer that is already gone is not the point and is
	// allowed to be the rate answer: the verification queue observes the request
	// context, so a cancelled one never reaches the credential. The SUMMARY is
	// the point, and it is written before any of that.
	if w := bgLoginWithContext(t, s, source, ctx); w.Code != http.StatusNoContent && w.Code != http.StatusTooManyRequests {
		t.Fatalf("the returning login = %d %s", w.Code, w.Body)
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
