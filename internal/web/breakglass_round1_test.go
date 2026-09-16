package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
)

// --- round-1 P1-1: the break-glass listener serves at "/" ---------------------

// In production the QPKG service script passes -proxy-prefix /qnapfilemanager,
// because that is where QTS's Apache mounts the app. The break-glass listener
// is reached DIRECTLY, precisely because Apache may be what is broken — so a
// shell served there with the proxy base would ask for /qnapfilemanager/app.css
// and /qnapfilemanager/api/session, neither of which that listener serves. The
// emergency door would 404 its own stylesheet.
func TestBreakGlassServesAtTheRootRegardlessOfTheProxyPrefix(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.cfg.Web.ProxyPrefix = "/qnapfilemanager"

	shell := bgRequest(s, "GET", "/", nil, nil, "")
	if shell.Code != http.StatusOK {
		t.Fatalf("GET / on the break-glass listener: %d", shell.Code)
	}
	body := shell.Body.String()
	for _, want := range []string{`href="/app.css"`, `src="/js/app.js"`, `content="/"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the break-glass shell does not carry %s:\n%s", want, firstLines(body, 12))
		}
	}
	if strings.Contains(body, "/qnapfilemanager/") {
		t.Errorf("the break-glass shell references the proxy prefix:\n%s", firstLines(body, 12))
	}
	// The URLs it names actually answer on that listener.
	for _, path := range []string{"/app.css", "/js/app.js", "/api/session"} {
		if w := bgRequest(s, "GET", path, nil, nil, ""); w.Code != http.StatusOK {
			t.Errorf("break-glass %s = %d %s", path, w.Code, w.Body)
		}
	}
	// And the prefixed spellings, which the old base would have produced, are
	// exactly the 404s this test exists to prevent — proving the assertion above
	// is load-bearing rather than cosmetic.
	if w := bgRequest(s, "GET", "/qnapfilemanager/app.css", nil, nil, ""); w.Code == http.StatusOK {
		t.Error("the break-glass listener unexpectedly serves the prefixed path; the base assertion above proves nothing")
	}
	// The MAIN listener is unchanged: it still serves the prefixed base.
	main := request(s, "GET", "/", nil, nil)
	if !strings.Contains(main.Body.String(), `href="/qnapfilemanager/app.css"`) {
		t.Errorf("the main listener lost its proxy base:\n%s", firstLines(main.Body.String(), 12))
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// --- round-1 P1-2: the sign-in flow ------------------------------------------

// The exact contract the UI agent builds against, asserted end to end.
func TestBreakGlassSignInFlow(t *testing.T) {
	s, _, _ := bgFixture(t)

	// 1. Unauthenticated GET /api/session names the door and the listener, and
	//    carries no token.
	w := bgRequest(s, "GET", "/api/session", nil, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("anonymous api/session: %d %s", w.Code, w.Body)
	}
	var before map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before["authenticated"] != false || before["listener"] != audit.DoorLocal {
		t.Fatalf("anonymous break-glass session = %v", before)
	}
	// TWO fields and nothing else (round-2 P3-4). This listener answers any host
	// on the LAN, so the version string, the firmware family, whether this is
	// QTS and whether the app is read-only are all free reconnaissance — enough
	// to match a unit against a vulnerability list without touching the
	// password. It must also never say whether a password is configured.
	if len(before) != 2 {
		t.Fatalf("the anonymous break-glass payload discloses %d fields: %v", len(before), before)
	}
	for _, leak := range []string{"version", "family", "isQTS", "readOnly", "csrf", "user", "uid", "hash", "passwordSet"} {
		if _, ok := before[leak]; ok {
			t.Errorf("the anonymous break-glass payload exposes %q", leak)
		}
	}
	// The MAIN listener keeps its own shape and does not grow a listener field.
	mw := request(s, "GET", "/api/session", nil, nil)
	var mainPayload map[string]any
	if err := json.Unmarshal(mw.Body.Bytes(), &mainPayload); err != nil {
		t.Fatal(err)
	}
	if _, ok := mainPayload["listener"]; ok {
		t.Error("the main listener's session shape changed")
	}

	// 2. POST the password with no X-QFM-CSRF header at all: the login route is
	//    exempt, because there is no session yet to bind a token to.
	lw := bgRequest(s, "POST", bgLoginPath, nil, map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if lw.Code != http.StatusNoContent {
		t.Fatalf("login: %d %s", lw.Code, lw.Body)
	}
	if lw.Body.Len() != 0 {
		t.Fatalf("login must answer 204 with no body, got %q", lw.Body)
	}
	var cookie *http.Cookie
	for _, c := range lw.Result().Cookies() {
		if c.Name == bgCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login set no session cookie")
	}

	// 3. GET /api/session again: now authenticated, now carrying the token.
	sw := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, "")
	var after map[string]any
	if err := json.Unmarshal(sw.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after["authenticated"] != true || after["listener"] != audit.DoorLocal || after["door"] != audit.DoorLocal {
		t.Fatalf("signed-in break-glass session = %v", after)
	}
	csrf, _ := after["csrf"].(string)
	if csrf == "" {
		t.Fatal("a signed-in session must carry a CSRF token")
	}

	// 4. That token is what every later mutating request uses.
	if mw := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie},
		map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"},
		`{"dir":"/","name":"flow"}`); mw.Code != http.StatusOK {
		t.Fatalf("mkdir with the issued token: %d %s", mw.Code, mw.Body)
	}

	// 5. /api/logout works on this listener and destroys the session.
	ow := bgRequest(s, "POST", "/api/logout", []*http.Cookie{cookie},
		map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}, "{}")
	if ow.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", ow.Code, ow.Body)
	}
	if fw := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); strings.Contains(fw.Body.String(), `"authenticated":true`) {
		t.Fatal("the session survived /api/logout")
	}
}

// --- round-1 P1-3: the read-only toggle must not clobber the credential ------

// postSettings used to persist s.cfg — the snapshot this process started with —
// so flipping read-only would rewrite auth.local from memory: reverting a
// password the operator had just set from the shell, or restoring one they had
// just disabled. The toggle now reads the file, changes ReadOnly, and writes
// that back.
func TestReadOnlyToggleDoesNotClobberTheCredential(t *testing.T) {
	for _, c := range []struct {
		name  string
		edit  func(*config.Config)
		check func(*testing.T, config.Local)
	}{
		{"a password set after the daemon started", func(cfg *config.Config) {
			cfg.Auth.Local = config.Local{Hash: "$2a$10$externally.written.hash.value.aaaaaaaaaaaaaaaaaaaaaaaa", Cost: 10, Updated: "2026-09-14T09:00:00Z"}
		}, func(t *testing.T, got config.Local) {
			if got.Hash == "" || got.Updated != "2026-09-14T09:00:00Z" {
				t.Fatalf("the externally written credential was lost: %+v", got)
			}
		}},
		{"a password disabled after the daemon started", func(cfg *config.Config) {
			cfg.Auth.Local = config.Local{Hash: "", Cost: 10, Updated: "2026-09-14T10:00:00Z"}
		}, func(t *testing.T, got config.Local) {
			if got.Hash != "" {
				t.Fatalf("a disabled password was re-enabled by a read-only toggle: %+v", got)
			}
			if got.Updated != "2026-09-14T10:00:00Z" {
				t.Fatalf("the eviction stamp was rolled back: %+v", got)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, configPath := bgFixture(t)
			withAudit(t, s)
			cookie, csrf := sessionCookie(t, s)
			s.sessions[cookie.Value].admin = true

			// The CLI's edit, made behind the running daemon's back.
			onDisk, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			c.edit(&onDisk)
			if err := config.Save(configPath, onDisk); err != nil {
				t.Fatal(err)
			}

			resp := post(s, "/api/settings", cookie, csrf, `{"readOnly":true}`)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("toggle: %d", resp.StatusCode)
			}
			got, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !got.ReadOnly {
				t.Fatal("the toggle did not take effect")
			}
			c.check(t, got.Auth.Local)
		})
	}
}

// --- round-1 P1-4: the slow-body lever ---------------------------------------

// Four connections that send login headers and then trickle nothing used to
// hold all four admission slots for as long as they liked, with no ReadTimeout
// and no request deadline anywhere on the path — the emergency door shut
// without a password ever being offered. The body is now read BEFORE any slot
// is taken, under its own read deadline.
func TestSlowLoginBodiesDoNotHoldAdmissionSlots(t *testing.T) {
	s, _, _ := bgFixture(t)
	// A short read deadline and a short floor: the point is the ORDERING, and a
	// test that waited ten real seconds four times over would not be run.
	s.BreakGlassGate().Floor = -1

	cert, err := breakglass.Ensure(
		tmpPath(t, "breakglass-cert.pem"), tmpPath(t, "breakglass-key.pem"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s.BreakGlassHandler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{*cert.TLS}}
	// ReadHeaderTimeout only, exactly as production configures it: if the body
	// read were unbounded and taken after admission, this test would hang until
	// its own deadline rather than fail.
	srv.Config.ReadHeaderTimeout = 10 * time.Second
	srv.StartTLS()
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	var stalled []net.Conn
	defer func() {
		for _, c := range stalled {
			c.Close()
		}
	}()
	// More stalled connections than there are admission slots.
	for i := 0; i < breakglass.InFlight+2; i++ {
		conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, conn)
		// Complete headers promising a body that never comes.
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n", bgLoginPath, host, host)
	}

	// With the slots held, this would time out. It must not.
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	client.Timeout = 20 * time.Second
	req, err := http.NewRequest("POST", srv.URL+bgLoginPath, strings.NewReader(fmt.Sprintf(`{"password":%q}`, bgTestPassword)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("a real login could not get through the stalled connections: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login while %d connections stalled = %d", len(stalled), resp.StatusCode)
	}
}

// --- round-1 P2-5: refusals are counted, not milestoned one by one -----------

func TestRefusalsAreAuditedOncePerWindow(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.BreakGlassGate().Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	// Exhaust the bucket, then keep hammering: every attempt past the budget is
	// refused, and the refusals must NOT each write a forced milestone.
	const attempts = 60
	for i := 0; i < attempts; i++ {
		bgLogin(t, s, "the wrong password!!")
	}
	// The window is per SOURCE, not per code: the first refusal of any kind
	// opens it and the rest are counted. Five real credential verdicts precede
	// them (those DO walk the ladder and are each worth a line), so the bound
	// below is on the refusals alone.
	var refusals, verdicts int
	for _, ev := range read() {
		switch {
		case ev.Op == "breakglass-login" && (ev.Code == "rate_limited" || ev.Code == "locked_out"),
			ev.Op == "breakglass-lockout" && ev.Code == "locked_out":
			refusals++
		case ev.Op == "breakglass-login" && ev.Code == "auth_failed":
			verdicts++
		}
	}
	if refusals == 0 {
		t.Fatal("a refused burst left no audit trace at all")
	}
	// One refusal line per source per window, plus the single lockout-entered
	// milestone. Anything proportional to `attempts` is the write amplifier.
	if refusals > 3 {
		t.Fatalf("%d refusal milestones for one source in one window of %d attempts; a flood must not be a write amplifier", refusals, attempts)
	}
	if verdicts > breakglass.LockoutAfter {
		t.Fatalf("%d credential-verdict lines; only the attempts that actually reached bcrypt should write one", verdicts)
	}
}

func TestRefusalSummaryIsWrittenWhenTheSourceRecovers(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	s.BreakGlassGate().Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	for i := 0; i < breakglass.BucketCapacity+8; i++ {
		bgLogin(t, s, "the wrong password!!")
	}
	// A full window later the source is inside its budget again, and the
	// suppressed count is reported once.
	advance(2 * breakglass.BucketWindow)
	bgLogin(t, s, "the wrong password!!")
	var summary bool
	for _, ev := range read() {
		if strings.Contains(ev.Detail, "further refusals suppressed") {
			summary = true
		}
	}
	if !summary {
		t.Fatal("the suppressed refusals were never summarised; a burst that stopped is simply absent from the log")
	}
}

func TestRefusalTrackingIsBounded(t *testing.T) {
	s, _, _ := bgFixture(t)
	withAudit(t, s)
	for i := 0; i < breakglass.MaxSources*2; i++ {
		s.bg.noteRefusal(nil, fmt.Sprintf("10.9.%d.%d", i/256, i%256), "breakglass-login", "rate_limited", "door=local synthetic")
	}
	s.bg.mu.Lock()
	n := len(s.bg.refusals)
	s.bg.mu.Unlock()
	if n > breakglass.MaxSources {
		t.Fatalf("the refusal table holds %d sources, want at most %d", n, breakglass.MaxSources)
	}
}

// --- round-1 P2-7: only a credential verdict walks the ladder -----------------

func TestOnlyAWrongPasswordAdvancesTheLockoutLadder(t *testing.T) {
	for _, c := range []struct {
		name     string
		send     func(t *testing.T, s *Server)
		advances bool
	}{
		{"malformed body", func(t *testing.T, s *Server) {
			bgRequest(s, "POST", bgLoginPath, nil, nil, "not json")
		}, false},
		{"empty password", func(t *testing.T, s *Server) {
			bgRequest(s, "POST", bgLoginPath, nil, nil, `{"password":""}`)
		}, false},
		{"oversized password", func(t *testing.T, s *Server) {
			bgRequest(s, "POST", bgLoginPath, nil, nil, fmt.Sprintf(`{"password":%q}`, strings.Repeat("z", breakglass.MaxPasswordBytes+1)))
		}, false},
		{"unreadable credential", func(t *testing.T, s *Server) {
			s.bg.cred = &localCred{path: tmpPath(t, "not-json.json")}
			if err := os.WriteFile(s.bg.cred.path, []byte("{{{ not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			bgLogin(t, s, bgTestPassword)
		}, false},
		{"wrong password", func(t *testing.T, s *Server) {
			bgLogin(t, s, "the wrong password!!")
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := bgFixture(t)
			// Enough attempts to reach the cap several times over if they counted.
			for i := 0; i < breakglass.LockoutAfter; i++ {
				c.send(t, s)
			}
			locked, _, _ := s.BreakGlassGate().Locked(bgTestIP)
			if locked != c.advances {
				t.Fatalf("%s: locked=%v after %d attempts, want %v", c.name, locked, breakglass.LockoutAfter, c.advances)
			}
			if got := s.BreakGlassGate().Failures(bgTestIP); (got > 0) != c.advances {
				t.Fatalf("%s: %d consecutive failures recorded, want advances=%v", c.name, got, c.advances)
			}
			// Whatever the cause, the answer the client sees is the same one.
			w := bgRequest(s, "POST", bgLoginPath, nil, nil, "not json")
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusTooManyRequests {
				t.Fatalf("%s: the uniform failure answer changed: %d %s", c.name, w.Code, w.Body)
			}
		})
	}
}

// --- round-1 P3-8: the peer address, everywhere, on this listener ------------

// The break-glass listener binds 0.0.0.0 and is not behind the QTS proxy, so an
// X-Forwarded-For there is a forgery — and the most convincing one comes from a
// loopback peer, which is exactly what the main listener's rule trusts. The
// pre-login and post-login events must name the same address, or the trail
// cannot be read.
func TestBreakGlassNeverTrustsForwardedHeaders(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	forged := map[string]string{"X-Forwarded-For": "198.51.100.7", "Content-Type": "application/json"}

	// Pre-login: a failed attempt.
	bgRequest(s, "POST", bgLoginPath, nil, forged, `{"password":"the wrong password!!"}`)
	// Post-login: a real mutation.
	cookie, csrf := bgSignIn(t, s)
	headers := map[string]string{"X-QFM-CSRF": csrf, "X-Forwarded-For": "198.51.100.7", "Content-Type": "application/json"}
	if w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, headers, `{"dir":"/","name":"forged"}`); w.Code != http.StatusOK {
		t.Fatalf("mkdir: %d %s", w.Code, w.Body)
	}

	events := read()
	if len(events) == 0 {
		t.Fatal("no audit events")
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.IP == "198.51.100.7" || strings.Contains(ev.Detail, "198.51.100.7") {
			t.Errorf("event %s/%s trusted a forwarded header: ip=%q detail=%q", ev.Op, ev.Result, ev.IP, ev.Detail)
		}
		seen[ev.IP] = true
	}
	// One address for every event on this listener, pre- and post-login alike.
	if len(seen) != 1 {
		t.Errorf("the break-glass trail names %d different addresses: %v", len(seen), seen)
	}
	// The MAIN listener's behaviour is unchanged: a loopback peer's forwarded
	// hop is still the client address there.
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := ClientIP(r); got != "198.51.100.7" {
		t.Errorf("the main listener stopped honouring the proxy hop: %q", got)
	}
}

// tmpPath names a file inside this test's own temporary directory.
func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}
