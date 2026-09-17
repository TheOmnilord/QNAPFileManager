package web

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/qnap"
)

// --- Astra r8 #1: the peer is this machine ----------------------------------

// bgOwnAddresses makes the door believe this machine answers on exactly these
// addresses. They are plain canonical IPs, which is what bgInterfaceAddrs hands
// back: the prefix length and the zone are already off by then.
func bgOwnAddresses(s *Server, addrs ...string) {
	s.bg.local.setLookup(func() ([]string, error) { return addrs, nil })
}

// The relay round 7 missed, and the reason "loopback" was the wrong rule by one
// step. `socat TCP-LISTEN:9443,fork TCP:192.168.1.10:8771` run ON THE NAS makes
// the login peer 192.168.1.10 — the NAS's own LAN address, not loopback — so the
// session is pinned to an address every sibling service on the box presents from,
// and the host-scoped cookie reaches all of them. One command, and the pin is
// satisfied by exactly the replay it exists to stop.
func TestTheDoorRefusesARelayToItsOwnLANAddress(t *testing.T) {
	const own = "192.168.1.10"
	s, _, _ := bgFixture(t)
	bgOwnAddresses(s, own, "fe80::1")
	read := withAudit(t, s)

	w := bgRequestFrom(s, own, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login relayed through the NAS's own address = %d %s, want the uniform 401", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie && c.Value != "" {
			t.Fatal("a relay through the NAS's own address was issued a session cookie")
		}
	}
	if n := s.bg.Sessions(); n != 0 {
		t.Fatalf("%d sessions exist after a refused relay", n)
	}
	// The correct password was offered, and the ladder must still not move: this
	// is not a verdict about a password, and an operator who reaches their own
	// door the wrong way five times must not find it locked.
	if failures := s.BreakGlassGate().Failures(own); failures != 0 {
		t.Errorf("a relayed login advanced the lockout ladder to %d", failures)
	}
	ev := bgEventWith(t, read(), "peer is this machine")
	assertLoginShape(t, ev)
}

// The other half: an address this machine does NOT answer on is the operator,
// and the door opens. The rule has to stay a rule about relays, not a licence to
// refuse the LAN.
func TestAnAddressThisMachineDoesNotAnswerOnSignsIn(t *testing.T) {
	s, _, _ := bgFixture(t)
	bgOwnAddresses(s, "192.168.1.10", "fe80::1")
	const operator = "192.168.1.55"

	cookie := bgSignInFrom(t, s, operator)
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a LAN peer was refused its own session: authenticated %v, csrf %v", authenticated, csrf != "")
	}
}

// And a session that exists is not redeemable from one of the machine's own
// addresses either — resolve and the logout route both treat such a peer as a
// mismatch, whatever the session happens to be pinned to.
func TestTheMachinesOwnAddressNeverRedeemsASession(t *testing.T) {
	const own = "192.168.1.10"
	s, _, _ := bgFixture(t)
	bgOwnAddresses(s, own)
	read := withAudit(t, s)
	const operator = "192.168.1.55"

	cookie := bgSignInFrom(t, s, operator)
	_, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), ""))
	if csrf == "" {
		t.Fatal("the operator's own session handed back no CSRF token")
	}
	// The session is re-pinned by hand to the address the relay would have pinned
	// it to, which is the state this rule exists to make worthless.
	s.bg.mu.Lock()
	for _, sess := range s.bg.sessions {
		sess.peer = own
	}
	s.bg.mu.Unlock()

	if authenticated, handed := bgSessionAnswer(t, bgRequestFrom(s, own, "GET", "/api/session", bgWithCookie(cookie), "")); authenticated || handed != "" {
		t.Fatalf("a relayed request redeemed a relay-pinned session: authenticated %v, csrf handed over %v", authenticated, handed != "")
	}
	_, before, _, tracked := bgTracked(s, bgMismatchKey(own))
	if !tracked {
		t.Fatal("the refused request was not tracked, so the count below proves nothing")
	}
	headers := bgWithCookie(cookie)
	headers["X-QFM-CSRF"] = csrf
	if w := bgRequestFrom(s, own, "POST", bgLogoutPath, headers, ""); w.Code != statusCode("permission") {
		t.Fatalf("a relayed logout with a VALID token = %d %s, want %d", w.Code, w.Body, statusCode("permission"))
	}
	if _, after, _, _ := bgTracked(s, bgMismatchKey(own)); after != before+1 {
		t.Errorf("the relayed logout added %d refusals to the window, want exactly its own 1", after-before)
	}
	if n := s.bg.Sessions(); n != 1 {
		t.Errorf("%d sessions after a refused relayed logout, want the operator's 1", n)
	}
	ev := bgEventWith(t, read(), "presented from another address")
	if ev.Code != bgPeerMismatch {
		t.Errorf("the refusal carries code %q, want %q", ev.Code, bgPeerMismatch)
	}
}

// An address is added to a NAS without restarting anything — DHCP, an IPv6
// advertisement, an operator's own hand — so the set is re-read on a TTL. A door
// that read its interfaces once at start-up would hand a session to a relay built
// on an address that arrived afterwards.
//
// Round 9 #4 took the TTL off the login path entirely: the cached minute was
// itself the relay window, so a login from an address the cache does not know is
// answered from a fresh read. What the TTL still governs is REDEMPTION, and the
// second half of this test is where that shows.
func TestTheLocalAddressSetIsRefreshed(t *testing.T) {
	const arrives = "192.168.1.77"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	var mu sync.Mutex
	addrs := []string{"192.168.1.10"}
	s.bg.local.setLookup(func() ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), addrs...), nil
	})

	// Before it arrives, that address is somebody else and signs in.
	cookie := bgSignInFrom(t, s, arrives)
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, arrives, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Fatal("an address the machine does not answer on was refused its session")
	}

	mu.Lock()
	addrs = append(addrs, arrives)
	mu.Unlock()
	// Inside the TTL, and the login is refused all the same (Astra r9 #4): the
	// cached minute used to answer this, and a relay already listening on the
	// address that just arrived would have carried the login through it.
	now = now.Add(bgLocalFresh)
	w := bgRequestFrom(s, arrives, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from a newly local address = %d %s, want 401 from the fresh read", w.Code, w.Body)
	}
	// And the same answer once the TTL has gone by, which is the r8 rule the
	// fresh read now front-runs rather than replaces.
	now = now.Add(bgLocalPeerRefresh)
	if w := bgRequestFrom(s, arrives, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from a newly local address after the TTL = %d %s, want 401", w.Code, w.Body)
	}
	// And the session it held before the address became local is no longer
	// redeemable from it either.
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, arrives, "GET", "/api/session", bgWithCookie(cookie), "")); authenticated {
		t.Error("a session pinned to an address that has since become the machine's own is still redeemed")
	}
}

// Loopback is in the set whatever the interfaces say, and a lookup that fails
// keeps the previous answer rather than opening the door: the emergency door is
// used precisely when the machine is unwell, which is when an enumeration is
// likeliest to fail.
func TestAFailedLookupKeepsTheLastAnswer(t *testing.T) {
	const own = "192.168.1.10"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	var mu sync.Mutex
	fail := false
	s.bg.local.setLookup(func() ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, fmt.Errorf("the interfaces could not be read")
		}
		return []string{own}, nil
	})

	if w := bgRequestFrom(s, own, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from the machine's own address = %d, want 401", w.Code)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	now = now.Add(2 * bgLocalPeerRefresh)
	if w := bgRequestFrom(s, own, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from the machine's own address after a failed refresh = %d, want the previous answer's 401", w.Code)
	}
}

// --- Astra r8 #2: the refusal is not visible in the connection --------------

// bgRawLogin writes one login request on a connection the test owns and reads
// the answer, then puts a second request on the SAME connection: whether that
// second answer arrives is the keep-alive assertion, and no header is needed to
// make it.
func bgRawLogin(t *testing.T, srv *httptest.Server, password string) (first *http.Response, body string, reusable bool) {
	t.Helper()
	conn := bgDial(t, srv)
	br := bufio.NewReader(conn)
	send := func() {
		payload := fmt.Sprintf(`{"password":%q}`, password)
		req := "POST " + bgLoginPath + " HTTP/1.1\r\n" +
			"Host: " + strings.TrimPrefix(srv.URL, "https://") + "\r\n" +
			"Origin: " + srv.URL + "\r\n" +
			"Content-Type: application/json\r\n" +
			fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload)) +
			payload
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
	}
	read := func() (*http.Response, string, error) {
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, "", err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b), nil
	}
	send()
	resp, text, err := read()
	if err != nil {
		t.Fatalf("no answer to a login: %v", err)
	}
	send()
	second, _, err := read()
	return resp, text, err == nil && second != nil
}

// bgRefusalFixture is a door on a real socket whose own addresses are exactly
// `own`, so a test can make the SAME connection produce either refusal.
func bgRefusalFixture(t *testing.T, own ...string) *httptest.Server {
	t.Helper()
	s, _, _ := bgFixture(t)
	bgOwnAddresses(s, own...)
	srv := httptest.NewUnstartedServer(bgOverTheLAN(s.BreakGlassHandler()))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The two refusals must be the same event as far as the network can tell. They
// were not: the local-peer check returned before the body was read, so the
// outermost wrapper — which closes a connection whose declared body nobody
// consumed — added `Connection: close`, while a wrong password, whose body IS
// read, kept the connection. Identical bodies, identical floor, and a prober
// could still tell "you are being refused for where you are" from "that password
// is wrong" by watching the socket.
func TestALocalPeerRefusalLooksExactlyLikeAWrongPassword(t *testing.T) {
	// The presented peer is bgTestIP in both cases; only the door's idea of its
	// own addresses differs, so nothing but the rule under test changes.
	relay := bgRefusalFixture(t, bgTestIP)
	elsewhere := bgRefusalFixture(t, "192.168.1.10")

	local, localBody, localReusable := bgRawLogin(t, relay, bgTestPassword)
	wrong, wrongBody, wrongReusable := bgRawLogin(t, elsewhere, "the wrong one!!!!")

	if local.StatusCode != http.StatusUnauthorized || wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses differ: local peer %d, wrong password %d", local.StatusCode, wrong.StatusCode)
	}
	if localBody != wrongBody {
		t.Errorf("bodies differ:\n local peer:     %s\n wrong password: %s", localBody, wrongBody)
	}
	// net/http folds `Connection: close` into resp.Close rather than leaving it in
	// the header map, so that flag — not a header lookup — is where the difference
	// shows.
	if local.Close {
		t.Error("the local-peer refusal closed the connection; its body was consumed, so there is nothing to drain")
	}
	if local.Close != wrong.Close {
		t.Errorf("connection close: local peer %v, wrong password %v", local.Close, wrong.Close)
	}
	if !localReusable || !wrongReusable {
		t.Errorf("connection reuse: local peer %v, wrong password %v — the two refusals are distinguishable by the socket alone", localReusable, wrongReusable)
	}
	// Header for header, Date aside. A difference anywhere here is a difference a
	// prober can read.
	if a, b := bgHeaderShape(local.Header), bgHeaderShape(wrong.Header); a != b {
		t.Errorf("headers differ:\n local peer:     %s\n wrong password: %s", a, b)
	}
}

// bgHeaderShape renders the headers that are the server's own answer, leaving out
// the ones that cannot be the same twice.
func bgHeaderShape(h http.Header) string {
	var keys []string
	for k, v := range h {
		switch k {
		case "Date":
			continue
		}
		keys = append(keys, fmt.Sprintf("%s=%q", k, v))
	}
	// A stable order, so the comparison is about the headers and not about map
	// iteration.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return strings.Join(keys, " ")
}

// --- Astra r8 #4: the development door is still usable ----------------------

// `serve -dev` forces the break-glass listener to loopback
// (forceLoopbackBreakGlass), so the production rule refuses every login a
// developer can make: the door becomes untestable by hand on the one
// configuration that exists to be tested by hand. The relaxation is loopback's
// alone.
func TestADevelopmentDoorAcceptsLoopback(t *testing.T) {
	s, _, configPath := bgFixture(t)
	// Re-armed the way `serve -dev` arms it, so the flag travels the real path
	// rather than being poked into the door.
	s.Dev = true
	s.EnableBreakGlass(configPath)
	s.BreakGlassGate().Floor = -1
	bgOwnAddresses(s, "192.168.1.10")

	cookie := bgSignInFrom(t, s, "127.0.0.1")
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, "127.0.0.1", "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a development door refused its own loopback session: authenticated %v, csrf %v", authenticated, csrf != "")
	}
	// The relaxation is loopback's alone: a development daemon's own LAN address
	// is refused exactly as production refuses it, so the rule under test is still
	// the rule.
	if w := bgRequestFrom(s, "192.168.1.10", "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a development door accepted a relay to its own LAN address: %d %s", w.Code, w.Body)
	}
}

// And production is unchanged, which is the half that matters.
func TestAProductionDoorStillRefusesLoopback(t *testing.T) {
	s, _, _ := bgFixture(t)
	if w := bgRequestFrom(s, "127.0.0.1", "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a production door accepted a loopback login: %d %s", w.Code, w.Body)
	}
}

// --- Astra r8 #6: a replayed root cookie is a QuLog event -------------------

// bgWithMirroredAudit is withAudit with the QuLog mirror seamed, so a test can
// see what the door offers to QuLog Center without exec'ing /sbin/log_tool.
func bgWithMirroredAudit(t *testing.T, s *Server) (read func() []audit.Event, mirrored func() []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var msgs []string
	logger.SetQuLogMirror(func(_ qnap.Severity, msg string) error {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
		return nil
	})
	s.auditor = logger
	s.AuditPath = path
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = logger.Close()
			closed = true
		}
	})
	return func() []audit.Event {
			if !closed {
				// Close joins the mirror worker, so everything QuLog was going to be
				// offered has been offered by the time this returns.
				if err := logger.Close(); err != nil {
					t.Fatal(err)
				}
				closed = true
			}
			events, err := logger.Tail(200)
			if err != nil {
				t.Fatal(err)
			}
			return events
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), msgs...)
		}
}

// Round 7 marked every sessionless line Quiet, which took the peer mismatch with
// it — and that line is the one an operator scanning QuLog is scanning for: a live
// root session's cookie turning up at another address. It is throttled to one per
// source per window, so mirroring it is bounded; the ordinary sessionless denial,
// which anyone on the LAN can produce for free, stays out of QuLog entirely.
func TestAPeerMismatchIsMirroredOncePerWindow(t *testing.T) {
	const replays = 5
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read, mirrored := bgWithMirroredAudit(t, s)
	const operator = "192.0.2.40"
	const replayer = "192.0.2.41"
	const stranger = "192.0.2.42"

	cookie := bgSignInFrom(t, s, operator)
	headers := bgWithCookie(cookie)
	headers["Content-Type"] = "application/json"
	for i := 0; i < replays; i++ {
		if w := bgRequestFrom(s, replayer, "POST", "/api/fs/mkdir", headers, `{"dir":"/","name":"replayed"}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("replay %d = %d %s, want 401", i+1, w.Code, w.Body)
		}
	}
	for i := 0; i < replays; i++ {
		bgSessionlessMutation(t, s, stranger)
	}

	events := read()
	var mismatchLines, strangerLines int
	for _, ev := range events {
		if ev.Code == bgPeerMismatch {
			mismatchLines++
		}
		if ev.IP == stranger {
			strangerLines++
		}
	}
	if mismatchLines != 1 || strangerLines == 0 {
		t.Fatalf("the file holds %d mismatch lines and %d stranger lines; the throttle, not the mirror, is what this test needs to be measuring", mismatchLines, strangerLines)
	}
	var offered, strangerOffered int
	for _, msg := range mirrored() {
		if strings.Contains(msg, bgPeerMismatch) {
			offered++
		}
		if strings.Contains(msg, stranger) {
			strangerOffered++
		}
	}
	if offered != 1 {
		t.Errorf("%d of %d replays reached QuLog, want the throttle's 1", offered, replays)
	}
	if strangerOffered != 0 {
		t.Errorf("%d ordinary sessionless denials reached QuLog; anybody on the LAN can produce those for nothing", strangerOffered)
	}
}
