package web

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
)

// bgOverTheLAN presents a real loopback socket as a peer on the LAN (Astra r7
// #6).
//
// The door refuses to issue a session to a loopback peer, and every test that
// drives it over a REAL listener dials 127.0.0.1, because that is what a test
// server is. The rule under test is about where the browser is, not about which
// interface the test harness happened to bind, so those tests present the LAN
// address they have always meant. The refusal itself is exercised directly, by
// the tests below, which is the only place it should be.
func bgOverTheLAN(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			port = "40000"
		}
		r.RemoteAddr = net.JoinHostPort(bgTestIP, port)
		h.ServeHTTP(w, r)
	})
}

// --- Astra r7 #2: one refusal is counted once -------------------------------

// A replayed cookie on a mutation route is refused twice over: resolve counts
// the peer mismatch through the bounded table, and the dispatch above it then
// counts the very same request again as a sessionless denial. Five replays
// pended nine suppressed refusals — a number an operator reads as "how hard am I
// being hit", inflated by a factor that depends on nothing but which routes the
// attacker chose.
func TestAReplayedMutationIsCountedOnce(t *testing.T) {
	const replays = 5
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const operator = "192.0.2.20"
	const elsewhere = "192.0.2.21"

	cookie := bgSignInFrom(t, s, operator)
	headers := bgWithCookie(cookie)
	headers["Content-Type"] = "application/json"
	for i := 0; i < replays; i++ {
		if w := bgRequestFrom(s, elsewhere, "POST", "/api/fs/mkdir", headers, `{"dir":"/","name":"replayed"}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("replayed mutation %d = %d %s, want 401", i+1, w.Code, w.Body)
		}
	}

	// The first replay opens the window and is written; the other four are
	// suppressed behind it. Once each, so four.
	_, suppressed, _, present := bgTracked(s, elsewhere)
	if !present {
		t.Fatal("the replaying source is not tracked at all")
	}
	if suppressed != replays-1 {
		t.Errorf("%d replays pended %d suppressed refusals, want %d — the same request is being counted twice",
			replays, suppressed, replays-1)
	}
	// And one line, in the mismatch's own vocabulary: the second count used to
	// bring a second line with it in the generic sessionless wording.
	var mismatch, generic int
	for _, ev := range read() {
		switch {
		case ev.Code == bgPeerMismatch:
			mismatch++
		case strings.Contains(ev.Detail, "no valid session on a mutation route"):
			generic++
		}
	}
	if mismatch != 1 {
		t.Errorf("%d peer-mismatch lines for %d replays, want the throttle's one", mismatch, replays)
	}
	if generic != 0 {
		t.Errorf("%d replays were also recorded as ordinary sessionless denials", generic)
	}
}

// --- Astra r7 #3: the logout route records the mismatch it refuses -----------

// Logging out is the one route that reaches a live session without going through
// resolve, and it folded the pin into the same condition as the CSRF check. A
// replay with a valid Origin was answered 403 and recorded nothing, so the event
// the pin exists to surface — a root session cookie presented from another
// address — was invisible on exactly the route that can close the operator's
// door.
func TestTheLogoutRouteRecordsAPeerMismatch(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	const operator = "192.0.2.22"
	const elsewhere = "192.0.2.23"

	cookie := bgSignInFrom(t, s, operator)
	_, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), ""))
	headers := bgWithCookie(cookie)
	headers["X-QFM-CSRF"] = csrf

	if w := bgRequestFrom(s, elsewhere, "POST", bgLogoutPath, headers, ""); w.Code != statusCode("permission") {
		t.Fatalf("a replayed logout from %s = %d %s, want %d", elsewhere, w.Code, w.Body, statusCode("permission"))
	}
	// The session survives: a refused replay must not cost the operator the door
	// they are standing in.
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Fatal("the replayed logout destroyed the operator's session")
	}

	ev := bgEventWith(t, read(), "presented from another address")
	assertSessionlessShape(t, ev)
	if ev.Code != bgPeerMismatch {
		t.Errorf("the logout mismatch carries code %q, want %q", ev.Code, bgPeerMismatch)
	}
	if ev.IP != elsewhere {
		t.Errorf("the logout mismatch names %q, want the address that sent it (%s)", ev.IP, elsewhere)
	}
}

// --- Astra r7 #4: a pruned summary is about the source it counted ------------

// The sweep runs on the goroutine of some unrelated request, and the summary it
// writes used to be built from THAT request: source A's burst was recorded with
// source B's address in the IP field and B's route in the path, with A named
// only inside the detail text. An operator filtering the trail by address is
// then told a count belongs to a host that never made it.
func TestAPrunedSummaryCarriesThePrunedSourcesIdentity(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	s.pinned = nil
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const flooder = "203.0.113.50"
	const unrelated = "203.0.113.51"

	for i := 0; i < suppressed+1; i++ {
		bgSessionlessMutation(t, s, flooder)
	}
	now = now.Add(2 * refusalWindow)
	// The triggering request aims at a route of its own, so a summary built from
	// it would carry that route rather than none.
	bgSessionlessMutation(t, s, unrelated)

	if _, _, _, ok := bgTracked(s, flooder); ok {
		t.Fatal("the aged-out window was not pruned, so this test proves nothing")
	}
	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the window aged out", suppressed))
	assertSessionlessShape(t, ev)
	if ev.IP != flooder {
		t.Errorf("the pruned summary is filed under %q, want the source it counted (%s)", ev.IP, flooder)
	}
	if ev.Path != "" {
		t.Errorf("the pruned summary names path %q; the window counted no single route, and certainly not the triggering request's", ev.Path)
	}
}

// The same, for a window of refusals at the DOOR. It keeps the door's own shape
// — that is round 6 #4 — and it is now also filed under the address that was
// refused rather than the one that happened to trigger the sweep.
func TestAPrunedLoginSummaryCarriesThePrunedSourcesAddress(t *testing.T) {
	const suppressed = 4
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	const flooder = "203.0.113.52"
	const unrelated = "203.0.113.53"

	for i := 0; i < suppressed+1; i++ {
		bgRefusedLogin(t, s, flooder)
	}
	now = now.Add(2 * refusalWindow)
	bgRefusedLogin(t, s, unrelated)

	ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the window aged out", suppressed))
	assertLoginShape(t, ev)
	if ev.IP != flooder {
		t.Errorf("the pruned login summary is filed under %q, want %s", ev.IP, flooder)
	}
}

// --- Astra r7 #1: a sessionless line is never mirrored to QuLog --------------

// The mirror is an exec of log_tool that qnap.Log allows ten seconds, and the
// automatic classification makes a milestone of every denial. So each of these
// lines — which anyone on the LAN can produce, without a password and without a
// session — used to buy one. The marking is what takes that lever away, and it
// is asserted on the constructed event because it is a decision flag and is
// never serialised.
func TestSessionlessRefusalLinesAreNeverMirroredToQuLog(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/fs/mkdir", nil)
	for _, tc := range []struct {
		name string
		ev   audit.Event
	}{
		{"a sessionless denial", sessionlessRefusalEvent(r, "unauthorized", "no valid session on a mutation route")},
		{"a pruned window's summary", sessionlessRefusalLine("203.0.113.60", audit.DoorLocal, "", "unauthorized", "the window aged out")},
	} {
		if !tc.ev.Quiet {
			t.Errorf("%s is still offered to the QuLog mirror", tc.name)
		}
		if tc.ev.ForceMilestone {
			t.Errorf("%s is still a forced milestone", tc.name)
		}
	}
	// The door's own events are unchanged: a use of the emergency door is exactly
	// what QuLog is for (contract §6.2).
	door := bgDoorEvent(r, "breakglass-login", "denied", "auth_failed", "door=local")
	if door.Quiet {
		t.Error("a refusal at the door itself is no longer mirrored to QuLog")
	}
	// And the peer mismatch is the exception r8 #6 carved out: it is a live root
	// session's cookie presented from somewhere else, which is exactly what an
	// operator scanning QuLog is scanning for. The throttle bounds it.
	mismatch := sessionlessRefusalEvent(r, bgPeerMismatch, "an emergency session cookie was presented from another address")
	if mismatch.Quiet {
		t.Error("a replayed root session cookie is hidden from QuLog")
	}
}

// --- Astra r7 #6: the emergency door is a LAN door ---------------------------

// The pin cannot see through a relay, and the relay that matters is a local one:
// any unprivileged process on the NAS can forward a high port to 127.0.0.1:8771,
// and an SSH tunnel does it with no code at all. The browser's login then arrives
// from loopback, the session is pinned to loopback — and every sibling HTTPS
// service on the NAS hostname, which receives the host-scoped cookie, can replay
// it from loopback and satisfy the pin. So no session is issued to loopback at
// all.
func TestTheDoorRefusesALoopbackLogin(t *testing.T) {
	for _, source := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		t.Run(source, func(t *testing.T) {
			s, _, _ := bgFixture(t)
			read := withAudit(t, s)

			w := bgRequestFrom(s, source, "POST", bgLoginPath,
				map[string]string{"Content-Type": "application/json"},
				fmt.Sprintf(`{"password":%q}`, bgTestPassword))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("a login from %s = %d %s, want the uniform 401", source, w.Code, w.Body)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == bgCookie && c.Value != "" {
					t.Fatalf("a login from %s was issued a session cookie", source)
				}
			}
			if n := s.bg.Sessions(); n != 0 {
				t.Fatalf("%d sessions exist after a refused loopback login", n)
			}
			// The ladder is untouched: nothing here was a verdict about a password,
			// and an operator who tunnels to their own door five times must not find
			// it locked when they finally reach it properly.
			if failures := s.BreakGlassGate().Failures(source); failures != 0 {
				t.Errorf("a loopback login advanced the lockout ladder to %d", failures)
			}
			ev := bgEventWith(t, read(), "peer is this machine")
			assertLoginShape(t, ev)
		})
	}
}

// And the door still opens for the machine it is for. This is the other half of
// the rule: refusing loopback is only acceptable because the operator is, by the
// nature of the emergency, at a different machine.
func TestALANPeerStillSignsIn(t *testing.T) {
	s, _, _ := bgFixture(t)
	const operator = "192.0.2.30"
	cookie := bgSignInFrom(t, s, operator)
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a LAN peer was refused its own session: authenticated %v, csrf %v", authenticated, csrf != "")
	}
}

// A session that somehow exists for a loopback peer is not honoured either: the
// rule is about the relay, not about which address the store happens to hold, so
// resolve and the logout route both treat loopback as a mismatch.
func TestALoopbackRequestNeverRedeemsASession(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	const operator = "192.0.2.31"

	cookie := bgSignInFrom(t, s, operator)
	// The session's own CSRF token is collected FIRST, from the address it belongs
	// to (Astra r8 #3). The logout below used to be sent without one, so the 403 it
	// asserted was the CSRF guard's and would have arrived with the peer rule
	// deleted — the test passed on a door that had no rule at all. With a valid
	// token, only the pin can refuse it.
	_, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), ""))
	if csrf == "" {
		t.Fatal("the operator's own session handed back no CSRF token")
	}
	// The session is re-pinned to loopback by hand — the state a relay used to
	// produce, and the one the door must refuse to act on however it arose.
	s.bg.mu.Lock()
	for _, sess := range s.bg.sessions {
		sess.peer = "127.0.0.1"
	}
	s.bg.mu.Unlock()

	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, "127.0.0.1", "GET", "/api/session", bgWithCookie(cookie), "")); authenticated || csrf != "" {
		t.Fatalf("a loopback request redeemed a loopback-pinned session: authenticated %v, csrf handed over %v", authenticated, csrf != "")
	}
	// resolve's refusal has already opened this source's window and written the one
	// line it is allowed, so the logout's own refusal is isolated by counting what
	// the throttle records across the call (Astra r8 #3). The old assertion read
	// the file at the end and was satisfied by the /api/session line above — it
	// said nothing whatever about this route.
	_, before, _, tracked := bgTracked(s, "127.0.0.1")
	if !tracked {
		t.Fatal("the refused loopback request was not tracked, so the count below proves nothing")
	}
	headers := bgWithCookie(cookie)
	headers["X-QFM-CSRF"] = csrf
	if w := bgRequestFrom(s, "127.0.0.1", "POST", bgLogoutPath, headers, ""); w.Code != statusCode("permission") {
		t.Fatalf("a loopback logout with a VALID token = %d %s, want %d", w.Code, w.Body, statusCode("permission"))
	}
	if _, after, _, _ := bgTracked(s, "127.0.0.1"); after != before+1 {
		t.Errorf("the loopback logout added %d refusals to the window, want exactly its own 1", after-before)
	}
	// And it destroyed nothing: a replayed logout is for signing the operator out.
	if n := s.bg.Sessions(); n != 1 {
		t.Errorf("%d sessions after a refused loopback logout, want the operator's 1", n)
	}
	ev := bgEventWith(t, read(), "presented from another address")
	if ev.Code != bgPeerMismatch {
		t.Errorf("the loopback refusal carries code %q, want %q", ev.Code, bgPeerMismatch)
	}
}
