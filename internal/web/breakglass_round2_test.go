package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
)

// --- round-2 P1-1: the drain lever -------------------------------------------

// bgTLSServer starts the real break-glass handler over TLS with production's
// timeout shape: ReadHeaderTimeout only, no ReadTimeout — because this listener
// serves uploads, and a server-wide read timeout would cut them.
func bgTLSServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	cert, err := breakglass.Ensure(tmpPath(t, "breakglass-cert.pem"), tmpPath(t, "breakglass-key.pem"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s.BreakGlassHandler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{*cert.TLS}}
	srv.Config.ReadHeaderTimeout = 10 * time.Second
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// A POST that promises a body and sends none makes net/http drain up to 256 KiB
// before writing the response — with no deadline on this listener, because it
// has no ReadTimeout. Any route that answers WITHOUT reading the body (a
// refused Origin, a 401 from s.fail on any API path) therefore used to park the
// connection indefinitely, on a root daemon, for any unauthenticated LAN host.
//
// The outermost wrapper now keys on whether a declared body was CONSUMED, not
// on the status (round-3 P1): it sets Connection: close — which is what makes
// net/http skip the drain — and arms a 5 s read deadline before the status is
// written, so a drain already under way cannot outlive it. Status was the wrong
// trigger: a 204 that ignored its body parks the connection exactly as a 403
// does, which is how the logout case below survived round 2.
func TestRefusalsDoNotParkConnections(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The assertion is about connections closing promptly under a real
		// server; Windows loopback teardown timing makes it flaky without
		// telling us anything the Linux run does not.
		t.Skip("connection-teardown timing is not assertable on Windows")
	}
	s, _, _ := bgFixture(t)
	srv := bgTLSServer(t, s)
	host := strings.TrimPrefix(srv.URL, "https://")

	// Every route an unauthenticated caller can reach that answers without
	// reading the body — INCLUDING the two that answer 2xx, which is what the
	// status-keyed round-2 fix missed (round-3 P1). A 204 that ignored its body
	// parks the connection exactly as a 403 does.
	for _, c := range []struct{ name, req string }{
		{"a refused origin on login", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://elsewhere.example\r\nContent-Length: 200000\r\n\r\n", bgLoginPath, host)},
		{"an unauthenticated API mutation", fmt.Sprintf("POST /api/fs/delete HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nContent-Length: 200000\r\n\r\n", host, host)},
		{"an unknown API route", fmt.Sprintf("POST /api/nope HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nContent-Length: 200000\r\n\r\n", host, host)},
		// The 204 that survived round 2: a logout with no cookie, which
		// answered a success without touching its declared body.
		{"a logout with no cookie", fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nContent-Length: 200000\r\n\r\n", bgLogoutPath, host, host)},
	} {
		t.Run(c.name, func(t *testing.T) {
			var conns []net.Conn
			defer func() {
				for _, conn := range conns {
					conn.Close()
				}
			}()
			for i := 0; i < 20; i++ {
				conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
				if err != nil {
					t.Fatal(err)
				}
				conns = append(conns, conn)
				if _, err := io.WriteString(conn, c.req); err != nil {
					t.Fatal(err)
				}
			}
			// Each one must be answered and then CLOSED by the server, without
			// ever receiving the body it was promised.
			for i, conn := range conns {
				// Generous: a route that READS its withheld body waits out its own
				// 10 s read deadline before answering, and that is the correct
				// behaviour — bounded, then closed.
				_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("connection %d got no response: %v", i, err)
				}
				head := string(buf[:n])
				if !strings.Contains(strings.ToLower(head), "connection: close") {
					t.Fatalf("connection %d: the refusal did not close the connection:\n%s", i, head)
				}
				// And the server really does hang up: the next read ends.
				for {
					if _, err := conn.Read(buf); err != nil {
						break
					}
				}
			}
			// With the connections released, the door still works.
			if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent && w.Code != http.StatusTooManyRequests {
				t.Fatalf("the door stopped working after the parked connections: %d %s", w.Code, w.Body)
			}
		})
	}
}

// A response whose request body WAS consumed keeps the connection alive —
// including a successful login, which is the request the emergency door most
// wants to be followed by more requests. Keep-alive is asserted on consumption,
// not on status: a 2xx that ignored its body is a parked connection too, and
// the logout case below is exactly the 204 that proved it (round-3 P1).
func TestConsumedBodiesKeepTheConnectionAlive(t *testing.T) {
	s, _, _ := bgFixture(t)
	for _, c := range []struct {
		name, method, path, body string
		wantCode                 int
	}{
		{"a successful login", "POST", bgLoginPath, fmt.Sprintf(`{"password":%q}`, bgTestPassword), http.StatusNoContent},
		{"a logout with no cookie", "POST", bgLogoutPath, `{}`, http.StatusNoContent},
		{"the session, with no body at all", "GET", "/api/session", "", http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			fresh, _, _ := bgFixture(t)
			w := bgRequest(fresh, c.method, c.path, nil, map[string]string{"Content-Type": "application/json"}, c.body)
			if w.Code != c.wantCode {
				t.Fatalf("%s = %d %s, want %d", c.name, w.Code, w.Body, c.wantCode)
			}
			if got := w.Header().Get("Connection"); got != "" {
				t.Fatalf("%s carried Connection: %q; its body was consumed, so there is nothing to drain", c.name, got)
			}
		})
	}
	_ = s
}

// The Origin check now runs AFTER the per-source bucket, so a caller sending a
// deliberately wrong Origin still pays for every attempt.
func TestARefusedOriginIsChargedToTheBucket(t *testing.T) {
	s, _, _ := bgFixture(t)
	body := fmt.Sprintf(`{"password":%q}`, bgTestPassword)
	bad := map[string]string{"Origin": "https://elsewhere.example", "Content-Type": "application/json"}
	var limited bool
	for i := 0; i < breakglass.BucketCapacity+3; i++ {
		w := bgRequest(s, "POST", bgLoginPath, nil, bad, body)
		if w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("attempt %d = %d %s", i+1, w.Code, w.Body)
		}
	}
	if !limited {
		t.Fatalf("a wrong Origin bought unlimited free refusals past the %d/minute budget", breakglass.BucketCapacity)
	}
}

// --- round-2 P2-2: a disabled password must not lock the door ----------------

// After `break-glass disable` the listener stays bound until the next restart.
// If "no password configured" walked the ladder, any LAN host could put the
// door into a 1800 s lockout — and the operator's fresh set-password would then
// be refused by a lockout they never caused, at exactly the moment they were
// trying to get back in.
func TestADisabledPasswordCannotBeLockedOut(t *testing.T) {
	s, _, configPath := bgFixture(t)
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = ""
		c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < breakglass.LockoutAfter+3; i++ {
		w := bgLogin(t, s, "anything at all!!!")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s, want the uniform 401", i+1, w.Code, w.Body)
		}
	}
	if locked, _, _ := s.BreakGlassGate().Locked(bgTestIP); locked {
		t.Fatal("attempts against a disabled password locked the door")
	}
	if n := s.BreakGlassGate().Failures(bgTestIP); n != 0 {
		t.Fatalf("%d consecutive failures recorded against a door with no password", n)
	}
	// And the operator's fresh password is accepted immediately.
	hash, err := breakglass.Hash(bgTestPassword, breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Updated = "2026-09-14T10:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(configPath, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent {
		t.Fatalf("the freshly set password was refused: %d %s", w.Code, w.Body)
	}
}

// --- round-2 P2-7: a queued correct password is not called wrong -------------

// The door's request deadline is sized to what its own verification queue can
// take on this machine, and a caller that ran out of time waiting gets a RATE
// answer — never "that password was not accepted", which would be a lie about a
// password nothing ever looked at.
func TestAQueuedLoginIsNotCalledWrong(t *testing.T) {
	s, _, _ := bgFixture(t)
	// A deadline that has already passed by the time Verify is reached.
	r := httptest.NewRequest("POST", bgLoginPath, strings.NewReader(fmt.Sprintf(`{"password":%q}`, bgTestPassword)))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://"+r.Host)
	r.Header.Set("Content-Type", "application/json")

	// Hold the single verification slot so the request under test must queue.
	holding := make(chan struct{})
	released := make(chan struct{})
	go func() {
		// A different source, so holding the slot does not itself touch the
		// ladder of the source the request under test comes from.
		_, _ = s.bg.gate.Verify(context.Background(), "10.0.0.250", func() breakglass.Outcome {
			close(holding)
			<-released
			return breakglass.OutcomeNeutral
		})
	}()
	<-holding
	defer close(released)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	w := httptest.NewRecorder()
	s.bg.login(w, r.WithContext(ctx))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("a queued login = %d %s, want 429", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"code":"rate_limited"`) {
		t.Fatalf("body = %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "not accepted") {
		t.Fatal("a password that was never verified must not be reported as wrong")
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a queue-wait refusal must say when to try again")
	}
	// And it did not walk the ladder.
	if n := s.BreakGlassGate().Failures(bgTestIP); n != 0 {
		t.Fatalf("%d failures charged for a verification that never ran", n)
	}
}

func TestDoorTimeoutIsSizedToTheVerificationQueue(t *testing.T) {
	s, _, _ := bgFixture(t)
	if got := s.bg.doorTimeout(); got < bgDoorTimeout {
		t.Fatalf("doorTimeout = %v, below the %v floor", got, bgDoorTimeout)
	}
	// A machine where one bcrypt takes a second must give the queue room for
	// InFlight of them; the floor alone would not.
	slow := &breakGlassDoor{bcryptTime: time.Second}
	want := bgDoorTimeout + time.Duration(breakglass.InFlight)*time.Second
	if got := slow.doorTimeout(); got != want {
		t.Fatalf("doorTimeout on a slow machine = %v, want %v", got, want)
	}
	// And the measurement really happened: EnableBreakGlass takes it.
	if s.bg.bcryptTime <= 0 {
		t.Fatal("the bcrypt cost was never measured")
	}
}

// --- round-2 P3-10: logout clears the cookie only after the CSRF check -------

func TestLogoutWithoutTheTokenChangesNothing(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	for _, c := range []struct {
		name    string
		headers map[string]string
	}{
		{"no token", map[string]string{}},
		{"a wrong token", map[string]string{"X-QFM-CSRF": "not-the-token"}},
		{"a cross-site fetch", map[string]string{"X-QFM-CSRF": csrf, "Sec-Fetch-Site": "cross-site"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := bgRequest(s, "POST", bgLogoutPath, []*http.Cookie{cookie}, c.headers, "{}")
			if w.Code != http.StatusForbidden {
				t.Fatalf("logout with %s = %d %s, want 403", c.name, w.Code, w.Body)
			}
			// No Set-Cookie at all: an unverifiable request must not be able to
			// sign the operator out from another origin.
			if len(w.Result().Cookies()) != 0 {
				t.Fatalf("logout with %s cleared the cookie: %v", c.name, w.Result().Cookies())
			}
			if sw := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); !strings.Contains(sw.Body.String(), `"authenticated":true`) {
				t.Fatalf("logout with %s destroyed the session", c.name)
			}
		})
	}
	// The real thing still works.
	w := bgRequest(s, "POST", bgLogoutPath, []*http.Cookie{cookie}, map[string]string{"X-QFM-CSRF": csrf}, "{}")
	if w.Code != http.StatusNoContent {
		t.Fatalf("a verified logout = %d %s", w.Code, w.Body)
	}
	var cleared bool
	for _, got := range w.Result().Cookies() {
		if got.Name == bgCookie && got.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("a verified logout must clear the cookie")
	}
}

// --- round-2 P3-11: a full refusal table still reports ----------------------

func TestAFullRefusalTableStillReports(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	// Fill the table with live windows, then keep going: the overflow is a
	// distributed attempt on the door, which is the most interesting thing that
	// can happen to it and must not be the quietest.
	for i := 0; i < breakglass.MaxSources*2; i++ {
		s.bg.noteRefusal(nil, fmt.Sprintf("10.8.%d.%d", i/256, i%256), "breakglass-login", "rate_limited", "door=local synthetic")
	}
	var overflow int
	for _, ev := range read() {
		if strings.Contains(ev.Detail, "table is full") {
			overflow++
		}
	}
	if overflow == 0 {
		t.Fatal("refusals from untracked sources were dropped silently")
	}
	if overflow > 2 {
		t.Fatalf("%d table-full lines; the report must be rate-bounded too", overflow)
	}
}

// --- round-2 P3-4 / P3-6: the settings toggle under -dev --------------------

// A daemon started with -dev may be running on a configuration whose auth.mode
// is "local", which strict validation refuses. Without the dev flag travelling
// to the settings route, the read-only toggle would fail forever on exactly the
// configuration the dev loop uses.
func TestReadOnlyToggleWorksOnADevConfiguration(t *testing.T) {
	s, _, configPath := bgFixture(t)
	withAudit(t, s)
	s.Dev = true
	if err := config.SaveDev(configPath, func() config.Config {
		c, err := config.LoadDev(configPath, true)
		if err != nil {
			t.Fatal(err)
		}
		c.Auth.Mode = config.AuthLocal
		return c
	}(), true); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := sessionCookie(t, s)
	s.sessions[cookie.Value].admin = true
	resp := post(s, "/api/settings", cookie, csrf, `{"readOnly":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the toggle failed on a -dev configuration: %d", resp.StatusCode)
	}
	got, err := config.LoadDev(configPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReadOnly || got.Auth.Mode != config.AuthLocal {
		t.Fatalf("the saved config = readOnly %v, mode %q", got.ReadOnly, got.Auth.Mode)
	}
	// A NON-dev server on the same file refuses rather than corrupting it.
	strict, _, _ := bgFixture(t)
	strict.ConfigPath = configPath
	withAudit(t, strict)
	sc, scsrf := sessionCookie(t, strict)
	strict.sessions[sc.Value].admin = true
	if resp := post(strict, "/api/settings", sc, scsrf, `{"readOnly":false}`); resp.StatusCode == http.StatusOK {
		t.Fatal("a strict daemon accepted a development configuration")
	}
	after, err := config.LoadDev(configPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if after.Auth.Mode != config.AuthLocal || !after.ReadOnly {
		t.Fatalf("the refused toggle changed the file: %+v", after.Auth)
	}
}

func TestSessionPayloadShapeIsUnchangedOnTheMainListener(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, _ := sessionCookie(t, s)
	var v map[string]any
	if err := json.Unmarshal(request(s, "GET", "/api/session", cookie, nil).Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"authenticated", "user", "admin", "rootMode", "uid", "gid", "groups", "readOnly", "canWrite", "version", "isQTS", "family", "csrf", "viaQTS", "door", "createsAs"} {
		if _, ok := v[want]; !ok {
			t.Errorf("the main listener's session payload lost %q", want)
		}
	}
	if _, ok := v["listener"]; ok {
		t.Error("the main listener grew a listener field")
	}
}

// The header half of the drain fix, asserted on every OS (the socket-level test
// above is Linux-only).
//
// The rule is NOT "non-2xx" — that was the round-2 shape, and it left the lever
// intact on a 204 (round-3 P1). The rule is "a declared body this handler never
// read", because that alone decides whether net/http is about to drain. Closing
// when the body WAS consumed would be wrong in the other direction: every
// response would cost a TCP handshake, and the read deadline would land on the
// next keep-alive header read.
func TestConnectionCloseFollowsTheUnreadBody(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	for _, c := range []struct {
		name, method, path string
		cookies            []*http.Cookie
		headers            map[string]string
		body               string
		wantClose          bool
	}{
		// Answered without reading the declared body: the drain is exactly what
		// must not happen.
		{"a refused origin on login", "POST", bgLoginPath, nil, map[string]string{"Origin": "https://elsewhere.example"}, `{"password":"whatever!!!!"}`, true},
		{"an unauthenticated mutation", "POST", "/api/fs/delete", nil, nil, `{"path":"/a.txt"}`, true},
		{"a mutation without a token", "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, nil, `{"dir":"/","name":"x"}`, true},
		{"an unknown route with a body", "POST", "/api/nope", nil, nil, `{"anything":true}`, true},
		{"a bad method with a body", "GET", bgLoginPath, nil, nil, `{"password":"whatever!!!!"}`, true},

		// The body was read to its end, so there is nothing to drain and the
		// connection is a normal keep-alive one — whatever the status.
		{"a wrong password", "POST", bgLoginPath, nil, nil, `{"password":"the wrong password!!"}`, false},
		{"a malformed login body", "POST", bgLoginPath, nil, nil, "not json", false},
		// Logout now reads its bounded body BEFORE it answers anything, so
		// every one of its outcomes — no cookie, a bad Origin, a missing token,
		// a real sign-out — leaves nothing to drain. That is stronger than
		// closing the connection, and it is what round-3 P1 asked for.
		{"a logout with no cookie", "POST", bgLogoutPath, nil, nil, `{}`, false},
		{"a logout without a token", "POST", bgLogoutPath, []*http.Cookie{cookie}, nil, "{}", false},
		{"a logout with a refused origin", "POST", bgLogoutPath, []*http.Cookie{cookie}, map[string]string{"Origin": "https://elsewhere.example"}, `{}`, false},

		// No body was ever declared.
		{"an unknown route", "GET", "/api/nope", nil, nil, "", false},
		{"a missing asset", "GET", "/nope.css", nil, nil, "", false},
		{"the shell", "GET", "/", nil, nil, "", false},
		{"the session", "GET", "/api/session", []*http.Cookie{cookie}, nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := bgRequest(s, c.method, c.path, c.cookies, c.headers, c.body)
			got := w.Header().Get("Connection") == "close"
			if got != c.wantClose {
				t.Fatalf("%s (%d): Connection close = %v, want %v (headers %v)", c.name, w.Code, got, c.wantClose, w.Header())
			}
		})
	}
	_ = csrf
}

// --- round-3 P3: the door measures the cost the HASH carries -----------------

// A daemon that started with no password and armed the door later used to
// measure the startup snapshot's cost — the default 11 — while serving whatever
// the operator had actually set. At cost 15 that sizes the request deadline to
// a queue sixteen times faster than the real one, and a correct password that
// waited its turn comes back "not accepted": the exact failure the deadline
// exists to prevent.
func TestTheDoorMeasuresTheCostTheHashCarries(t *testing.T) {
	s, _, configPath := bgFixture(t)
	// The config snapshot this Server holds says one cost; the hash on disk
	// carries another. The hash is the one in force.
	s.cfg.Auth.Local.Cost = breakglass.MaxCost
	hash, err := breakglass.Hash(bgTestPassword, breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MaxCost // deliberately a lie
		c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.EnableBreakGlass(configPath)
	if got := s.bg.bcryptCost; got != breakglass.MinCost {
		t.Fatalf("the door measured cost %d; the stored hash carries %d", got, breakglass.MinCost)
	}
	if s.bg.bcryptTime <= 0 {
		t.Fatal("the measurement did not run")
	}
	// With no hash at all there is nothing to read a cost from, so the
	// configured value stands.
	empty, _, emptyPath := bgFixture(t)
	if err := config.Update(emptyPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = ""
		c.Auth.Local.Cost = breakglass.MinCost
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	empty.EnableBreakGlass(emptyPath)
	if got := empty.bg.bcryptCost; got != breakglass.MinCost {
		t.Fatalf("with no hash the configured cost must stand, got %d", got)
	}
}

// --- round-3 P1, at the tracker ---------------------------------------------

// The tracker is what the whole close decision rests on, so it is asserted
// directly: an unread declared body stays flagged, a fully read one does not,
// and a body that was cut short by MaxBytesReader counts as unread — because
// from net/http's point of view there is still something to drain.
func TestBodyConsumptionTracking(t *testing.T) {
	for _, c := range []struct {
		name       string
		body       string
		read       func(r *http.Request)
		unconsumed bool
	}{
		{"never read", `{"a":1}`, func(*http.Request) {}, true},
		{"read to EOF", `{"a":1}`, func(r *http.Request) { io.ReadAll(r.Body) }, false},
		{"read short", `{"a":1}`, func(r *http.Request) { io.CopyN(io.Discard, r.Body, 2) }, true},
		{"cut off by the byte cap", strings.Repeat("x", 64), func(r *http.Request) {
			io.ReadAll(http.MaxBytesReader(httptest.NewRecorder(), r.Body, 8))
		}, true},
		{"no body declared", "", func(*http.Request) {}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var r *http.Request
			if c.body != "" {
				r = httptest.NewRequest("POST", "/api/session", strings.NewReader(c.body))
			} else {
				r = httptest.NewRequest("GET", "/api/session", nil)
			}
			st := &bodyState{unconsumed: r.ContentLength != 0 || len(r.TransferEncoding) > 0}
			if st.unconsumed {
				r.Body = trackedBody{ReadCloser: r.Body, st: st}
			}
			c.read(r)
			if st.unconsumed != c.unconsumed {
				t.Fatalf("%s: unconsumed = %v, want %v", c.name, st.unconsumed, c.unconsumed)
			}
			// And the wrapper turns that into the header, for any status.
			w := httptest.NewRecorder()
			bw := &bgRefusal{ResponseWriter: w, st: st}
			bw.WriteHeader(http.StatusNoContent)
			if got := w.Header().Get("Connection") == "close"; got != c.unconsumed {
				t.Fatalf("%s: a 204 set close = %v, want %v", c.name, got, c.unconsumed)
			}
		})
	}
}

// An implicit 200 — a handler that only writes a body — must still go through
// the check. Before Write was overridden it reached the embedded writer's own
// WriteHeader and skipped it entirely.
func TestAnImplicitStatusStillChecksTheBody(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/session", strings.NewReader(`{"a":1}`))
	st := &bodyState{unconsumed: true}
	r.Body = trackedBody{ReadCloser: r.Body, st: st}
	w := httptest.NewRecorder()
	bw := &bgRefusal{ResponseWriter: w, st: st}
	if _, err := bw.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("an implicit write produced %d", w.Code)
	}
	if w.Header().Get("Connection") != "close" {
		t.Fatalf("an implicit 200 over an unread body did not close: %v", w.Header())
	}
}

// --- round-4 P3 -------------------------------------------------------------

// Flush is what actually sends the status line, so a handler that flushed
// before writing anything would reach the embedded writer's implicit 200 and
// skip the unread-body check — the same hole Write had.
func TestFlushCommitsTheHeaderThroughTheCheck(t *testing.T) {
	for _, unconsumed := range []bool{true, false} {
		t.Run(fmt.Sprintf("unconsumed=%v", unconsumed), func(t *testing.T) {
			w := httptest.NewRecorder()
			bw := &bgRefusal{ResponseWriter: w, st: &bodyState{unconsumed: unconsumed}}
			bw.Flush()
			if w.Code != http.StatusOK {
				t.Fatalf("Flush produced %d, want an implicit 200", w.Code)
			}
			if got := w.Header().Get("Connection") == "close"; got != unconsumed {
				t.Fatalf("Flush set close = %v, want %v", got, unconsumed)
			}
			// A second Flush must not rewrite the header.
			bw.Flush()
			if w.Code != http.StatusOK {
				t.Fatalf("the second Flush changed the status to %d", w.Code)
			}
		})
	}
}

// json.Decoder stops at the closing brace and never reads to EOF, so every
// SUCCESSFUL shared-table POST on this listener was answered with
// Connection: close — one TCP handshake per mutation through the emergency
// door. decodeBody now drains the remainder under the cap the caller already
// applied.
func TestSuccessfulMutationsKeepTheConnectionAlive(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	headers := map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}
	for i, body := range []string{
		`{"dir":"/","name":"alive-one"}`,
		// Trailing whitespace is what a pretty-printer leaves behind, and it
		// must not cost a connection either.
		"{\"dir\":\"/\",\"name\":\"alive-two\"}\n\n  ",
	} {
		w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, headers, body)
		if w.Code != http.StatusOK {
			t.Fatalf("mkdir %d = %d %s", i, w.Code, w.Body)
		}
		if got := w.Header().Get("Connection"); got != "" {
			t.Fatalf("a successful mkdir carried Connection: %q; the body was parsed, so it must be drained too", got)
		}
	}
	// The main listener is unaffected either way: it has no such wrapper.
	mainCookie, mainCSRF := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", mainCookie, mainCSRF, `{"dir":"/","name":"alive-main"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the main listener's mkdir = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Connection"); got != "" {
		t.Fatalf("the main listener grew a Connection header: %q", got)
	}
	// A body that is genuinely too large is still refused, and still closes.
	big := `{"dir":"/","name":"x","pad":"` + strings.Repeat("y", 2<<20) + `"}`
	w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, headers, big)
	if w.Code == http.StatusOK {
		t.Fatal("an over-cap body was accepted")
	}
	if w.Header().Get("Connection") != "close" {
		t.Fatalf("an over-cap body did not close the connection: %v", w.Header())
	}
}

// Logout is the other route an unauthenticated caller can reach on this
// listener. Until now it was the only one that cost nothing: a caller could
// open its bounded-but-real body read as often as it liked while the login
// route beside it was capped at ten a minute.
func TestLogoutIsChargedToTheSourceBucket(t *testing.T) {
	s, _, _ := bgFixture(t)
	var limited bool
	for i := 0; i < breakglass.BucketCapacity+3; i++ {
		w := bgRequest(s, "POST", bgLogoutPath, nil, map[string]string{"Content-Type": "application/json"}, `{}`)
		if w.Code == http.StatusTooManyRequests {
			limited = true
			if !strings.Contains(w.Body.String(), `"code":"rate_limited"`) {
				t.Fatalf("body = %s", w.Body)
			}
			if w.Header().Get("Retry-After") == "" {
				t.Error("a rate-limited logout must say when to try again")
			}
			break
		}
		if w.Code != http.StatusNoContent {
			t.Fatalf("logout %d = %d %s", i+1, w.Code, w.Body)
		}
	}
	if !limited {
		t.Fatalf("logout bought unlimited free requests past the %d/minute budget", breakglass.BucketCapacity)
	}
	// The two routes share one budget, which is the point: a caller cannot
	// spend the login budget through the logout route or the other way round.
	if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("login after an exhausted logout budget = %d, want 429 from the shared bucket", w.Code)
	}
}
