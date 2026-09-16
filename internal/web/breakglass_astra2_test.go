package web

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
)

// --- Astra r2 #6: every refusal summary is written in the shape it counts ----

// The throttle counts two different events. A refused LOGIN is an event of the
// door and carries the door's actor — break-glass, UID 0, admin, root. A
// SESSIONLESS mutation denial has no actor at all, and auditUnauthenticated is
// what records it. The per-source line already told them apart (Astra r1 #3);
// the two AGGREGATE lines did not, and wrote both through d.audit. These tests
// pin the aggregates to the shape of what they count.

// bgRequestFrom is bgRequest with a caller-chosen source address, because both
// halves of #6 are about WHICH source a refusal came from: the overflow branch
// needs more sources than the table holds, and the flush branch needs one source
// to come back to a window it opened itself.
func bgRequestFrom(s *Server, source, method, target string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = net.JoinHostPort(source, "40000")
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	for k, v := range headers {
		// An explicitly empty value means "do not send this header at all",
		// exactly as in bgRequest.
		if v == "" {
			r.Header.Del(k)
			continue
		}
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(w, r)
	return w
}

// bgSessionlessMutation is the denial Astra r1 #3 routed through the throttle: an
// unsafe request to a mutation route on 8771, with no cookie at all.
func bgSessionlessMutation(t *testing.T, s *Server, source string) {
	t.Helper()
	w := bgRequestFrom(s, source, "POST", "/api/fs/mkdir",
		map[string]string{"Content-Type": "application/json"}, `{"dir":"/","name":"x"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a sessionless mutation from %s = %d %s, want 401", source, w.Code, w.Body)
	}
}

// bgRefusedLogin is a refusal of the DOOR itself that costs no bcrypt: the
// Origin check runs after the source bucket is charged and before anything
// reaches the credential, so it reaches the throttle in the login shape for the
// price of a request.
func bgRefusedLogin(t *testing.T, s *Server, source string) {
	t.Helper()
	w := bgRequestFrom(s, source, "POST", bgLoginPath,
		map[string]string{"Origin": "https://elsewhere.invalid"}, `{"password":"whatever"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a cross-origin login from %s = %d %s, want 403", source, w.Code, w.Body)
	}
}

// bgEventWith returns the single audit event whose detail contains want.
func bgEventWith(t *testing.T, events []audit.Event, want string) audit.Event {
	t.Helper()
	var found []audit.Event
	for _, ev := range events {
		if strings.Contains(ev.Detail, want) {
			found = append(found, ev)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d audit lines contain %q, want exactly 1: %+v", len(found), want, found)
	}
	return found[0]
}

// assertSessionlessShape is the whole point of #6: nobody authenticated, so the
// line must not name the break-glass account as a root administrator actor, and
// must not be the door's own login event.
func assertSessionlessShape(t *testing.T, ev audit.Event) {
	t.Helper()
	if ev.Actor != "" || ev.Admin || ev.Root || ev.UID != 0 {
		t.Errorf("a sessionless summary names an authenticated actor: %+v", ev)
	}
	if ev.Op == "breakglass-login" {
		t.Errorf("a sessionless summary is recorded as a login refusal: %+v", ev)
	}
	if ev.Op != "auth" {
		t.Errorf("a sessionless summary has Op %q, want the unauthenticated %q", ev.Op, "auth")
	}
	if ev.Door != audit.DoorLocal {
		t.Errorf("a summary from the break-glass listener carries door %q", ev.Door)
	}
	if ev.Result != "denied" {
		t.Errorf("a refusal summary has Result %q", ev.Result)
	}
}

// assertLoginShape is the other half: a refusal at the door really is an event
// of the door, and must keep saying so.
func assertLoginShape(t *testing.T, ev audit.Event) {
	t.Helper()
	if ev.Op != "breakglass-login" {
		t.Errorf("a login summary has Op %q, want %q", ev.Op, "breakglass-login")
	}
	if ev.Actor != "break-glass" || !ev.Admin || !ev.Root {
		t.Errorf("a login summary lost the door's own shape: %+v", ev)
	}
	if ev.Door != audit.DoorLocal || ev.Result != "denied" {
		t.Errorf("a login summary: door %q result %q", ev.Door, ev.Result)
	}
}

// The full-table branch. 256 sources fill the tracking table; the 257th cannot
// be tracked at all, and the periodic line that reports those untracked refusals
// used to be written through d.audit whatever the refusal was — so a spray of
// cookie-less POSTs from a LAN full of hosts, which is precisely the flood that
// fills the table, was recorded as the root administrator account being refused.
func TestTheFullSourceTableReportsEachFloodInItsOwnShape(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.pinned = nil // no impersonation, so the requests really are sessionless
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)

	// Exactly MaxSources live windows, one per source, on a frozen clock so
	// nothing is pruned: the table is now full of sources that are still inside
	// their window.
	for i := 0; i < breakglass.MaxSources; i++ {
		bgSessionlessMutation(t, s, fmt.Sprintf("198.51.100.%d", i))
	}
	if n := len(s.bg.refusals); n != breakglass.MaxSources {
		t.Fatalf("%d tracked sources, want the table full at %d", n, breakglass.MaxSources)
	}
	// One more sessionless denial, and one more login refusal, each from a source
	// that cannot be tracked. Both overflow; the counters are keyed by shape, so
	// each reports once, in its own shape.
	bgSessionlessMutation(t, s, "203.0.113.9")
	bgRefusedLogin(t, s, "203.0.113.8")

	events := read()
	full := fmt.Sprintf("the %d-source table is full", breakglass.MaxSources)
	var sessionless, login []audit.Event
	for _, ev := range events {
		if !strings.Contains(ev.Detail, full) {
			continue
		}
		if ev.Op == "breakglass-login" {
			login = append(login, ev)
		} else {
			sessionless = append(sessionless, ev)
		}
	}
	if len(sessionless) != 1 || len(login) != 1 {
		t.Fatalf("%d sessionless and %d login overflow reports, want 1 of each: %+v %+v", len(sessionless), len(login), sessionless, login)
	}
	assertSessionlessShape(t, sessionless[0])
	assertLoginShape(t, login[0])
}

// The flush branch. Only a LOGIN reaches flushRefusals, so the summary it writes
// was always written in the login shape — including when the window it is
// flushing held nothing but sessionless denials from a host that never
// authenticated and never tried to.
func TestTheFlushSummaryKeepsTheShapeOfWhatItCounted(t *testing.T) {
	const suppressed = 4

	t.Run("a window of sessionless denials", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		s.pinned = nil
		now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
		s.BreakGlassGate().Now = func() time.Time { return now }
		read := withAudit(t, s)
		const source = "192.0.2.77"

		// One line, then suppressed denials behind it.
		for i := 0; i < suppressed+1; i++ {
			bgSessionlessMutation(t, s, source)
		}
		// The window elapses and the source comes back with a login, which is
		// what collects the summary.
		now = now.Add(2 * refusalWindow)
		if w := bgRequestFrom(s, source, "POST", bgLoginPath, nil, fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusNoContent {
			t.Fatalf("the returning login = %d %s", w.Code, w.Body)
		}

		ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
		assertSessionlessShape(t, ev)
	})

	t.Run("a window of login refusals", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
		s.BreakGlassGate().Now = func() time.Time { return now }
		read := withAudit(t, s)
		const source = "192.0.2.78"

		for i := 0; i < suppressed+1; i++ {
			bgRefusedLogin(t, s, source)
		}
		now = now.Add(2 * refusalWindow)
		if w := bgRequestFrom(s, source, "POST", bgLoginPath, nil, fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusNoContent {
			t.Fatalf("the returning login = %d %s", w.Code, w.Body)
		}

		ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
		assertLoginShape(t, ev)
	})

	t.Run("a window that began as a login refusal and filled with sessionless ones", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		s.pinned = nil
		now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
		s.BreakGlassGate().Now = func() time.Time { return now }
		read := withAudit(t, s)
		const source = "192.0.2.79"

		// The window is OPENED by a refusal at the door and then filled with
		// sessionless denials. The summary stands for both, so it takes the
		// shape that cannot overstate what happened: a count that includes
		// sessionless denials is never reported as the door refusing an
		// authenticated root administrator.
		bgRefusedLogin(t, s, source)
		for i := 0; i < suppressed; i++ {
			bgSessionlessMutation(t, s, source)
		}
		now = now.Add(2 * refusalWindow)
		if w := bgRequestFrom(s, source, "POST", bgLoginPath, nil, fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusNoContent {
			t.Fatalf("the returning login = %d %s", w.Code, w.Body)
		}

		ev := bgEventWith(t, read(), fmt.Sprintf("%d further refusals suppressed; the source is inside its budget again", suppressed))
		assertSessionlessShape(t, ev)
	})
}

// --- Astra r2 #7: the unfinished drain, on a real socket ---------------------

// What Astra r1 #8 fixed only exists on a connection. decodeBody's decode and
// drain now run under a read deadline, and a drain that did not finish closes
// the connection instead of counting as consumed — but httptest's recorder
// carries no read deadline at all, so the tests that drove the handler with a
// fake body proved none of it and passed against the code before the fix
// (Astra r2 #7). These two use a real listener and a raw TCP client that
// declares more body than it sends.

// bgShortenReadDeadlines clamps the listener's read deadlines for the duration
// of one test. The production bound on a small JSON body is fifteen seconds;
// waiting that out once per run is how a socket-level test becomes one nobody
// runs. Restored before anything else the test registers, because the cleanups
// run last-registered-first and the server must be shut down first.
func bgShortenReadDeadlines(t *testing.T, within time.Duration) {
	t.Helper()
	previous := bgReadDeadlineCap
	t.Cleanup(func() { bgReadDeadlineCap = previous })
	bgReadDeadlineCap = within
}

// bgSocketServer serves the REAL break-glass handler chain — the refusal
// wrapper, the security middleware, the door, the shared dispatch — over a real
// TLS listener.
func bgSocketServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(s.BreakGlassHandler())
	// HTTP/1 only: contract §13.5, and the Connection: close the wrapper relies
	// on has no meaning in HTTP/2.
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// bgSocketSignIn signs in over the real server and returns the cookie and the
// CSRF token, so the raw request below reaches a mutation route rather than
// being refused at the door.
func bgSocketSignIn(t *testing.T, srv *httptest.Server) (*http.Cookie, string) {
	t.Helper()
	client := srv.Client()
	req, err := http.NewRequest("POST", srv.URL+bgLoginPath, strings.NewReader(fmt.Sprintf(`{"password":%q}`, bgTestPassword)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login over the socket = %d", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == bgCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("login set no %s cookie", bgCookie)
	}
	sreq, err := http.NewRequest("GET", srv.URL+"/api/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	sreq.AddCookie(cookie)
	sresp, err := client.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var payload struct{ CSRF string }
	if err := json.NewDecoder(sresp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRF == "" {
		t.Fatal("the session response carried no CSRF token")
	}
	return cookie, payload.CSRF
}

// bgDial opens a raw TLS connection to the listener. InsecureSkipVerify because
// httptest's certificate is for the test only; what is under test is the
// server's behaviour on the connection, not the certificate.
func bgDial(t *testing.T, srv *httptest.Server) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// bgRawMkdir writes a mkdir request whose Content-Length is `declared` bytes
// while only the JSON object itself is sent. declared == len(body) is an
// ordinary, complete request.
func bgRawMkdir(t *testing.T, conn net.Conn, srv *httptest.Server, cookie *http.Cookie, csrf, name string, declared int) {
	t.Helper()
	body := fmt.Sprintf(`{"dir":"/","name":%q}`, name)
	if declared == 0 {
		declared = len(body)
	}
	req := "POST /api/fs/mkdir HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(srv.URL, "https://") + "\r\n" +
		"Origin: " + srv.URL + "\r\n" +
		"Content-Type: application/json\r\n" +
		"X-QFM-CSRF: " + csrf + "\r\n" +
		"Cookie: " + cookie.Name + "=" + cookie.Value + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", declared) +
		body
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
}

// A client that declares more body than it sends and then simply stops talking
// must be ANSWERED — the request parsed — and the connection must then be closed
// by the server. Before the fix the drain behind that response had no deadline
// at all, and this test would sit here until the whole test binary timed out.
func TestAWithheldBodyIsAnsweredAndClosed(t *testing.T) {
	bgShortenReadDeadlines(t, 300*time.Millisecond)
	s, _, _ := bgFixture(t)
	srv := bgSocketServer(t, s)
	cookie, csrf := bgSocketSignIn(t, srv)

	conn := bgDial(t, srv)
	body := `{"dir":"/","name":"withheld"}`
	start := time.Now()
	bgRawMkdir(t, conn, srv, cookie, csrf, "withheld", len(body)*100)

	// Bounded: the deadline inside the handler is what has to end this, not the
	// client giving up.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer to a request whose body was withheld: %v", err)
	}
	elapsed := time.Since(start)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mkdir = %d", resp.StatusCode)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the answer took %s: the read deadline is not bounding the drain", elapsed)
	}
	// And it did not come back instantly either: the handler blocked on the
	// remainder that never arrived and was released by the deadline. Without this
	// the test could go on passing while quietly exercising nothing, which is the
	// failure mode of the two tests it replaced.
	if elapsed < 200*time.Millisecond {
		t.Fatalf("the answer came back in %s, before the drain could block: this test is no longer exercising the deadline", elapsed)
	}
	// The body was never consumed, so net/http must not be left to drain the
	// remainder behind the response — the wrapper says so with Connection: close,
	// and the server closes.
	if !resp.Close {
		t.Fatalf("a withheld body left the connection reusable: %v", resp.Header)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_, err = br.Read(buf[:])
	if err == nil {
		t.Fatal("the server went on talking on a connection it said it would close")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the connection was still open %s after the answer: %v", 5*time.Second, err)
	}
}

// The other half, and the reason the close is keyed on the BODY rather than on
// the status: a request that sent everything it declared keeps its connection.
// Closing every successful mutation would be one TCP handshake per request
// through the emergency door.
func TestAConsumedBodyKeepsTheConnection(t *testing.T) {
	s, _, _ := bgFixture(t)
	srv := bgSocketServer(t, s)
	cookie, csrf := bgSocketSignIn(t, srv)

	conn := bgDial(t, srv)
	br := bufio.NewReader(conn)
	for i, name := range []string{"consumed-one", "consumed-two"} {
		bgRawMkdir(t, conn, srv, cookie, csrf, name, 0)
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			// The second request is the assertion: reaching it at all means the
			// first answer left the connection usable.
			t.Fatalf("request %d on the same connection: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mkdir %d = %d", i+1, resp.StatusCode)
		}
		if resp.Close {
			t.Fatalf("a fully sent body closed the connection: %v", resp.Header)
		}
	}
}
