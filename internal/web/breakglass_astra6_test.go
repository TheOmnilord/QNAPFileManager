package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Astra r6 #1: an emergency session belongs to the address that signed in --

// A cookie is scoped to the HOST, not to the port, and the __Host- prefix does
// not change that: it constrains what may set the cookie, not who it is sent to.
// So after a break-glass login every browser-trusted HTTPS service on the NAS
// hostname — QTS on 443, another QPKG on its own port — receives a cookie that
// redeems a ROOT session, and /api/session hands the CSRF token to whoever
// presents it. The pin is what makes that replay worthless: it arrives from a
// different address and the door does not know it.

// bgSignInFrom logs in from a chosen source and returns the session cookie, so a
// test can then present that cookie from somewhere else.
func bgSignInFrom(t *testing.T, s *Server, source string) *http.Cookie {
	t.Helper()
	w := bgRequestFrom(s, source, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusNoContent {
		t.Fatalf("login from %s = %d %s", source, w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie {
			return c
		}
	}
	t.Fatalf("login from %s set no %s cookie", source, bgCookie)
	return nil
}

// bgWithCookie is the header set that presents one cookie by hand. bgRequestFrom
// takes headers rather than cookies, which is what a replay is anyway: the value
// copied out of one browser and sent from somewhere else.
func bgWithCookie(c *http.Cookie) map[string]string {
	return map[string]string{"Cookie": c.Name + "=" + c.Value}
}

// bgSessionAnswer reads /api/session as the page does.
func bgSessionAnswer(t *testing.T, w *httptest.ResponseRecorder) (authenticated bool, csrf string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("/api/session = %d %s", w.Code, w.Body)
	}
	var payload struct {
		Authenticated bool
		CSRF          string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Authenticated, payload.CSRF
}

func TestAnEmergencySessionIsPinnedToTheAddressThatSignedIn(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	const operator = "192.0.2.10"
	const elsewhere = "192.0.2.11"

	cookie := bgSignInFrom(t, s, operator)

	// The replay. Everything about this request is right except where it came
	// from, and that is enough.
	if w := bgRequestFrom(s, elsewhere, "GET", "/api/fs/list?path=/", bgWithCookie(cookie), ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("the replayed cookie from %s = %d %s, want 401", elsewhere, w.Code, w.Body)
	}
	// And the thing the replay was actually after: /api/session answers everyone,
	// so it is where a cookie holder collects the CSRF token that turns a stolen
	// session into a stream of root mutations. It must answer this one as a
	// stranger.
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, elsewhere, "GET", "/api/session", bgWithCookie(cookie), "")); authenticated || csrf != "" {
		t.Fatalf("/api/session from %s: authenticated %v, csrf handed over %v — the replay was answered as the operator", elsewhere, authenticated, csrf != "")
	}

	// The operator still has their session. A refused replay must not cost them
	// the door they are standing in, or anything holding a copy of the cookie
	// could sign them out mid-emergency.
	authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), ""))
	if !authenticated || csrf == "" {
		t.Fatalf("the original peer lost its session: authenticated %v, csrf %v", authenticated, csrf != "")
	}
	if w := bgRequestFrom(s, operator, "GET", "/api/fs/list?path=/", bgWithCookie(cookie), ""); w.Code != http.StatusOK {
		t.Fatalf("the original peer = %d %s, want 200", w.Code, w.Body)
	}

	// One line, in the shape of a request nobody authenticated for: whoever sent
	// it proved nothing, so it must not be recorded as the break-glass account
	// doing anything.
	ev := bgEventWith(t, read(), "presented from another address")
	assertSessionlessShape(t, ev)
	if ev.Code != bgPeerMismatch {
		t.Errorf("the mismatch line carries code %q, want %q", ev.Code, bgPeerMismatch)
	}
	if ev.IP != elsewhere {
		t.Errorf("the mismatch line names %q, want the address that presented the cookie (%s)", ev.IP, elsewhere)
	}
}

// Logging out is a mutation too, and it is the one route that reaches a live
// session without going through resolve — it looks the cookie up itself. A
// replay that somehow also had the token must not be able to close the door on
// the operator standing in it.
func TestTheLogoutRouteObeysThePinAsWell(t *testing.T) {
	s, _, _ := bgFixture(t)
	const operator = "192.0.2.14"
	const elsewhere = "192.0.2.15"

	cookie := bgSignInFrom(t, s, operator)
	_, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), ""))

	headers := bgWithCookie(cookie)
	headers["X-QFM-CSRF"] = csrf
	if w := bgRequestFrom(s, elsewhere, "POST", bgLogoutPath, headers, ""); w.Code != statusCode("permission") {
		t.Fatalf("logout from %s = %d %s, want %d", elsewhere, w.Code, w.Body, statusCode("permission"))
	}
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Fatal("a replayed logout destroyed the operator's session")
	}
	// And the operator's own logout still works, so the pin has not made the
	// route unusable.
	if w := bgRequestFrom(s, operator, "POST", bgLogoutPath, headers, ""); w.Code != http.StatusNoContent {
		t.Fatalf("the operator's own logout = %d %s", w.Code, w.Body)
	}
}

// A flood of replays is one line per source per window like every other refusal:
// a page on another port fetching in a loop must not write a line per fetch.
func TestRepeatedReplaysAreThrottledLikeEveryOtherRefusal(t *testing.T) {
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const operator = "192.0.2.12"
	const elsewhere = "192.0.2.13"

	cookie := bgSignInFrom(t, s, operator)
	for i := 0; i < 5; i++ {
		if w := bgRequestFrom(s, elsewhere, "GET", "/api/fs/list?path=/", bgWithCookie(cookie), ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("replay %d = %d %s, want 401", i+1, w.Code, w.Body)
		}
	}
	var lines int
	for _, ev := range read() {
		if strings.Contains(ev.Detail, "presented from another address") {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("%d audit lines for five replays from one source, want the throttle's one", lines)
	}
}

// The pin compares addresses, not the notation an address happens to arrive in.
// 2001:db8::1 and its fully written-out form are one host; so are 192.0.2.10 and
// the IPv4-mapped form a dual-stack listener reports for the same IPv4 peer.
// Getting this wrong locks the operator out of their own emergency session over
// punctuation.
//
// The spelled-out pair used to be ::1 against 0:0:0:0:0:0:0:1, which is no
// longer a case the door has: it refuses a loopback peer outright (Astra r7 #6).
// The documentation IPv6 range makes the same point about notation without
// testing an address that can never sign in.
func TestThePinAgreesAcrossAddressSpellings(t *testing.T) {
	for _, tc := range []struct{ name, signIn, again string }{
		{"an IPv6 peer abbreviated", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"and spelled out", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"an IPv4 peer mapped into IPv6", "192.0.2.10", "::ffff:192.0.2.10"},
		{"and back again", "::ffff:192.0.2.10", "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := bgFixture(t)
			cookie := bgSignInFrom(t, s, tc.signIn)
			authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, tc.again, "GET", "/api/session", bgWithCookie(cookie), ""))
			if !authenticated || csrf == "" {
				t.Fatalf("a session issued to %s was refused to %s: authenticated %v", tc.signIn, tc.again, authenticated)
			}
		})
	}
}

// --- Astra r6 #2: a forged mutation does not spend a durable writer ----------

// Four sources, four sessionless denials, every durable-writer slot already
// taken by something slow — a QuLog call that has not come back. Each denial
// used to demand a slot of its own and wait the full admission timeout for one,
// which is two seconds per line of writing about requests nobody authenticated
// for, and four of them held the slots an operator's real mutation needs for its
// intent line. They are queued now, so none of that happens.
func TestSessionlessDenialsDoNotSpendTheDurableWriters(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	// The pinned principal stays: the operator's own mutation below needs a
	// session on the MAIN listener, which is the whole comparison. It changes
	// nothing about the forged requests — the break-glass listener resolves its
	// own door and never looks at it.
	sources := []string{"198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23"}

	releaseSlots := s.auditor.HoldSyncSlots()
	defer releaseSlots()

	start := time.Now()
	for _, source := range sources {
		bgSessionlessMutation(t, s, source)
		if waiting := s.auditor.SyncWaiting(); waiting != 0 {
			t.Fatalf("a sessionless denial from %s left %d call queued for a durable writer", source, waiting)
		}
	}
	// A durable write cannot even be admitted here: it waits out writeSyncTimeout
	// (two seconds) and fails. Four of them is eight seconds, so this bound is not
	// a timing assumption — it is the difference between queuing a line and
	// standing in a queue for one.
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("four sessionless denials took %s with every writer slot held: they are still waiting for one", elapsed)
	}

	// The slots were never taken, so the operator's own mutation gets one the
	// moment the wedged writers let go — and its intent line is durable, which is
	// what would have failed if the forged requests had been holding them.
	releaseSlots()
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"the-operators-own"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the operator's mutation on the main listener = %d", resp.StatusCode)
	}

	// And the denials are all in the log: cheaper to record is not the same as
	// unrecorded.
	events := read()
	for _, source := range sources {
		var found bool
		for _, ev := range events {
			if ev.IP == source && ev.Op == "auth" && ev.Result == "denied" {
				found = true
				assertSessionlessShape(t, ev)
			}
		}
		if !found {
			t.Errorf("the denial from %s reached no audit line at all", source)
		}
	}
	// The forced-milestone flag is asserted on the CONSTRUCTED event, not on one
	// read back from the file (Astra r7 #5). It is `json:"-"`: every event that
	// comes back through Tail has it false, whatever was written, so the
	// assertion this test used to make against the file could not fail and proved
	// nothing at all.
	line := sessionlessRefusalEvent(httptest.NewRequest("POST", "/api/fs/mkdir", nil), "unauthorized", "no valid session on a mutation route")
	if line.ForceMilestone {
		t.Error("a sessionless denial is still constructed as a forced milestone")
	}
}

// --- Astra r6 #4: an abandoned window still reports what it counted ----------

// A source floods and stops. Nothing of its own ever comes back to collect the
// summary, and two windows later some unrelated source's refusal sweeps the
// entry away as dead weight — taking the count with it. The aggregate accounting
// is only complete if the sweep says what it is dropping.
func TestAPrunedWindowReportsTheBurstItWasHolding(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const flooder = "203.0.113.40"
	const unrelated = "203.0.113.41"

	// One line and four suppressed behind it, and then silence from this source.
	for i := 0; i < suppressed+1; i++ {
		bgSessionlessMutation(t, s, flooder)
	}
	// Two windows on: the age at which the sweep gives up on an entry nobody has
	// returned for.
	now = now.Add(2 * refusalWindow)
	bgSessionlessMutation(t, s, unrelated)

	if _, _, _, ok := bgTracked(s, flooder); ok {
		t.Error("the aged-out window was not pruned at all, so this test proves nothing about pruning")
	}
	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the window aged out", suppressed))
	assertSessionlessShape(t, ev)
	if !strings.Contains(ev.Detail, "ip="+flooder) {
		t.Errorf("the pruned summary does not name the source it counted: %q", ev.Detail)
	}
}

// The same sweep over a window of refusals at the DOOR reports them as the
// door's own event: a summary is written in the shape of what it counted, and
// pruning is not an exception to that.
func TestAPrunedLoginWindowKeepsTheDoorsShape(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const flooder = "203.0.113.42"
	const unrelated = "203.0.113.43"

	for i := 0; i < suppressed+1; i++ {
		bgRefusedLogin(t, s, flooder)
	}
	now = now.Add(2 * refusalWindow)
	bgRefusedLogin(t, s, unrelated)

	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the window aged out", suppressed))
	assertLoginShape(t, ev)
}

// A window pruned with nothing pending is still dropped in silence: the summary
// is about a burst, and there is no burst to report.
func TestAnEmptyPrunedWindowWritesNothing(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const quiet = "203.0.113.44"
	const unrelated = "203.0.113.45"

	bgSessionlessMutation(t, s, quiet) // one denial, nothing suppressed behind it
	now = now.Add(2 * refusalWindow)
	bgSessionlessMutation(t, s, unrelated)

	for _, ev := range read() {
		if strings.Contains(ev.Detail, "the window aged out") {
			t.Fatalf("an empty window was summarised anyway: %q", ev.Detail)
		}
	}
}
