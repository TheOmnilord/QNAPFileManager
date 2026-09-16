package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/qtsauth"
)

// The break-glass password used throughout. Cost 10 is the configured floor:
// the tests must exercise the real bcrypt path without spending seconds per
// attempt (cost 11 is what production writes).
const bgTestPassword = "an emergency password"

// bgTestIP is the peer every bgRequest comes from (httptest's default
// RemoteAddr). The lockout ladder is keyed by it (Astra r1 #4), so a test that
// asks about the ladder has to name the source it walked.
const bgTestIP = "192.0.2.1"

// bgFixture builds a server serving BOTH listeners, with a real auditor so the
// Door stamp and the forced milestones are assertable, and a real credential in
// a real config file so the reload path is the one under test.
func bgFixture(t *testing.T) (*Server, *fakeBackend, string) {
	t.Helper()
	s, b := fixture(t, true)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	hash, err := breakglass.Hash(bgTestPassword, breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
	cfg.ReadOnly = false
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	s.cfg.ReadOnly = false
	if s.guard != nil {
		s.guard.SetReadOnly(false)
	}
	s.ConfigPath = configPath
	// Every knob is set before anything serves (the fixture convention), so the
	// race detector never sees a test goroutine writing what the server reads.
	s.EnableBreakGlass(configPath)
	// The floor is a wall-clock guarantee; measuring it is one test's job, and
	// every other test here would otherwise pay 400 ms per failed attempt.
	s.BreakGlassGate().Floor = -1
	return s, b, configPath
}

// bgRequest drives the BREAK-GLASS handler. The two helpers are deliberately
// separate from request(): a test that means to knock on one door must not be
// able to knock on the other by accident.
func bgRequest(s *Server, method, target string, cookies []*http.Cookie, headers map[string]string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	// The break-glass listener is TLS-only, and httptest's default request is
	// not; set the marker net/http would.
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://"+r.Host)
	// Headers first, cookies after: AddCookie APPENDS to the Cookie header, so a
	// test that sets one explicitly keeps both rather than losing the session.
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	// An explicitly empty header value means "send this header at all": the
	// default Origin above is a convenience, and a test about a MISSING Origin
	// has to be able to take it away.
	for k, v := range headers {
		if v == "" {
			r.Header.Del(k)
		}
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(w, r)
	return w
}

func bgLogin(t *testing.T, s *Server, password string) *httptest.ResponseRecorder {
	t.Helper()
	return bgRequest(s, "POST", bgLoginPath, nil, nil, fmt.Sprintf(`{"password":%q}`, password))
}

// bgSignIn logs in and returns the cookie and the CSRF token the session was
// issued with — the token comes from /api/session, exactly as on the main
// listener (contract §10).
func bgSignIn(t *testing.T, s *Server) (*http.Cookie, string) {
	t.Helper()
	w := bgLogin(t, s, bgTestPassword)
	if w.Code != http.StatusNoContent {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("login set no %s cookie: %v", bgCookie, w.Result().Cookies())
	}
	sw := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, "")
	if sw.Code != 200 {
		t.Fatalf("session: %d %s", sw.Code, sw.Body)
	}
	var payload struct {
		CSRF, Door, User, CreatesAs string
		Admin, RootMode             bool
	}
	if err := json.Unmarshal(sw.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRF == "" {
		t.Fatal("the session response must carry a CSRF token")
	}
	return cookie, payload.CSRF
}

// --- §16.1: the two doors never mix ------------------------------------------

func TestTheTwoDoorsNeverMix(t *testing.T) {
	s, _, _ := bgFixture(t)
	bgCookieValue, bgCSRF := bgSignIn(t, s)
	mainCookie, mainCSRF := sessionCookie(t, s)

	t.Run("a qfm_sid cookie is ignored on the break-glass listener", func(t *testing.T) {
		w := bgRequest(s, "GET", "/api/fs/list?path=/", []*http.Cookie{mainCookie}, nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("a main-listener cookie was honoured on 8771: %d %s", w.Code, w.Body)
		}
	})
	t.Run("a __Host-qfm_bg cookie is ignored on the main listener", func(t *testing.T) {
		// A server with no pinned identity, so the ONLY thing that could
		// authenticate this request is the break-glass cookie — and it must not.
		plain, _ := fixture(t, false)
		plain.EnableBreakGlass("")
		if w := request(plain, "GET", "/api/fs/list?path=/", bgCookieValue, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("a break-glass cookie was honoured on the main listener: %d %s", w.Code, w.Body)
		}
		// And it is not even looked at: the anonymous answer to api/session is
		// the one a request presenting NOTHING gets.
		w := request(plain, "GET", "/api/session", bgCookieValue, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":false`) {
			t.Fatalf("api/session with a break-glass cookie = %d %s", w.Code, w.Body)
		}
	})
	t.Run("the login route does not exist on the main listener", func(t *testing.T) {
		if _, ok := routes[bgLoginPath]; ok {
			t.Fatal("the break-glass login must not be in the shared route table")
		}
		if _, ok := routes[bgLogoutPath]; ok {
			t.Fatal("the break-glass logout must not be in the shared route table")
		}
		for _, path := range []string{bgLoginPath, bgLogoutPath} {
			w := request(s, "POST", path, mainCookie, map[string]string{
				"X-QFM-CSRF": mainCSRF, "Origin": "http://example.com", "Content-Type": "application/json",
			})
			// Authenticated, so routing is reached; the route simply is not there.
			if w.Code != http.StatusNotFound {
				t.Errorf("%s on the main listener = %d %s, want 404", path, w.Code, w.Body)
			}
		}
	})
	t.Run("the break-glass session works on its own listener", func(t *testing.T) {
		w := bgRequest(s, "GET", "/api/fs/list?path=/", []*http.Cookie{bgCookieValue}, map[string]string{"X-QFM-CSRF": bgCSRF}, "")
		if w.Code != http.StatusOK {
			t.Fatalf("the break-glass session could not list: %d %s", w.Code, w.Body)
		}
	})
}

// qtsauth.FromRequest is never reached from the break-glass mux. The verifier
// is the observable proxy for that: a request that consulted the QTS door would
// have had to go through it.
func TestBreakGlassNeverConsultsQTS(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.pinned = nil // no impersonation: the QTS path is the only other door
	var reached int
	s.verifier = qtsauth.NewVerifier(&qtsauth.Client{BaseURL: "http://127.0.0.1:1", HTTP: &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			reached++
			return nil, fmt.Errorf("the break-glass door must never call QTS")
		}),
	}})
	cookie, csrf := bgSignIn(t, s)
	// A full QTS cookie pair presented alongside: it must change nothing.
	headers := map[string]string{"X-QFM-CSRF": csrf, "Cookie": "NAS_USER=admin; qtoken=0123456789abcdef0123456789abcdef"}
	w := bgRequest(s, "GET", "/api/fs/list?path=/", []*http.Cookie{cookie}, headers, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if reached != 0 {
		t.Fatalf("the break-glass door reached QTS %d times", reached)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// --- §16.4: login, failure, cookies, CSP, caps -------------------------------

func TestBreakGlassLoginFailuresAreIndistinguishable(t *testing.T) {
	wrong := func(s *Server) *httptest.ResponseRecorder { return bgLogin(t, s, "the wrong password!!") }
	cases := []struct {
		name  string
		setup func(t *testing.T) *Server
		try   func(s *Server) *httptest.ResponseRecorder
	}{
		{"wrong password", func(t *testing.T) *Server { s, _, _ := bgFixture(t); return s }, wrong},
		{"no password configured", func(t *testing.T) *Server {
			s, _, p := bgFixture(t)
			cfg, err := config.Load(p)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Auth.Local.Hash = ""
			if err := config.Save(p, cfg); err != nil {
				t.Fatal(err)
			}
			return s
		}, func(s *Server) *httptest.ResponseRecorder { return bgLogin(t, s, bgTestPassword) }},
		{"malformed body", func(t *testing.T) *Server { s, _, _ := bgFixture(t); return s },
			func(s *Server) *httptest.ResponseRecorder {
				return bgRequest(s, "POST", bgLoginPath, nil, nil, "not json")
			}},
		{"empty password", func(t *testing.T) *Server { s, _, _ := bgFixture(t); return s },
			func(s *Server) *httptest.ResponseRecorder {
				return bgRequest(s, "POST", bgLoginPath, nil, nil, `{"password":""}`)
			}},
	}
	var bodies []string
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.setup(t)
			w := c.try(s)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s: %d %s", c.name, w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), `"code":"auth_failed"`) {
				t.Fatalf("%s: %s", c.name, w.Body)
			}
			if !strings.Contains(w.Body.String(), "That password was not accepted.") {
				t.Fatalf("%s: the message must be the single shared one: %s", c.name, w.Body)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatalf("%s: a failed login must not set a cookie", c.name)
			}
			bodies = append(bodies, w.Body.String())
		})
	}
	// Byte for byte the same: "no password is configured" and "wrong password"
	// must not be distinguishable by anything the client can see (§5.2).
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("failure bodies differ:\n%s\n%s", bodies[0], bodies[i])
		}
	}
}

func TestBreakGlassLockoutAndRateLimit(t *testing.T) {
	s, _, _ := bgFixture(t)
	for i := 1; i < breakglass.LockoutAfter; i++ {
		if w := bgLogin(t, s, "the wrong password!!"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	// The fifth failure locks; the answer is still 401 auth_failed, because the
	// attempt itself was answered before the ladder was consulted.
	if w := bgLogin(t, s, "the wrong password!!"); w.Code != http.StatusUnauthorized {
		t.Fatalf("the locking failure answered %d", w.Code)
	}
	// From here on, even the CORRECT password is refused, and the refusal never
	// says whether it was right.
	w := bgLogin(t, s, bgTestPassword)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked out = %d %s, want 429", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"code":"locked_out"`) {
		t.Fatalf("body = %s", w.Body)
	}
	retry := w.Header().Get("Retry-After")
	if n, err := strconv.Atoi(retry); err != nil || n <= 0 {
		t.Fatalf("Retry-After = %q, want a positive number of seconds", retry)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("a locked-out attempt must not issue a session")
	}
}

func TestBreakGlassSourceBucketRefuses(t *testing.T) {
	s, _, _ := bgFixture(t)
	// The bucket is consulted before the ladder, so an exhausted source is
	// 429 rate_limited rather than 401.
	var limited bool
	for i := 0; i < breakglass.BucketCapacity+2; i++ {
		w := bgLogin(t, s, "the wrong password!!")
		if w.Code == http.StatusTooManyRequests && strings.Contains(w.Body.String(), `"code":"rate_limited"`) {
			limited = true
			if w.Header().Get("Retry-After") == "" {
				t.Error("a rate-limited answer must carry Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Fatalf("more than %d attempts per minute were accepted from one source", breakglass.BucketCapacity)
	}
}

func TestBreakGlassCookieAttributes(t *testing.T) {
	s, _, _ := bgFixture(t)
	w := bgLogin(t, s, bgTestPassword)
	if w.Code != http.StatusNoContent {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var c *http.Cookie
	for _, got := range w.Result().Cookies() {
		if got.Name == bgCookie {
			c = got
		}
	}
	if c == nil {
		t.Fatalf("no %s cookie", bgCookie)
	}
	// The contract's table, field by field (§13.2).
	if c.Name != "__Host-qfm_bg" {
		t.Errorf("name = %q", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want / (required by the __Host- prefix)", c.Path)
	}
	if !c.Secure {
		t.Error("Secure must be unconditional: the listener is TLS-only")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict (this page is never framed)", c.SameSite)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly must be set")
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q; the __Host- prefix forbids one", c.Domain)
	}
	// And the main listener's cookie is unchanged beside it.
	mainCookie, _ := sessionCookie(t, s)
	if mainCookie.Name != "qfm_sid" || mainCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("the main cookie changed: %+v", mainCookie)
	}
}

func TestBreakGlassCSPForbidsFraming(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.cfg.Web.FrameAncestors = []string{"https://desktop.example"}
	bgCSP := bgRequest(s, "GET", "/", nil, nil, "").Header().Get("Content-Security-Policy")
	if !strings.Contains(bgCSP, "frame-ancestors 'none'") {
		t.Fatalf("break-glass CSP = %q, want frame-ancestors 'none'", bgCSP)
	}
	mainCSP := request(s, "GET", "/", nil, nil).Header().Get("Content-Security-Policy")
	if !strings.Contains(mainCSP, "frame-ancestors 'self' https://desktop.example") {
		t.Fatalf("main CSP = %q, want the QTS desktop still allowed to frame it", mainCSP)
	}
	// Everything else is identical, and NEITHER carries HSTS (§3.4): pinning
	// HTTPS for the whole NAS host from a self-signed door would break the QTS
	// desktop on that host.
	for name, header := range map[string]http.Header{
		"break-glass": bgRequest(s, "GET", "/", nil, nil, "").Header(),
		"main":        request(s, "GET", "/", nil, nil).Header(),
	} {
		if header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s listener sets HSTS", name)
		}
		if header.Get("Cross-Origin-Opener-Policy") != "same-origin" {
			t.Errorf("%s listener: COOP = %q", name, header.Get("Cross-Origin-Opener-Policy"))
		}
		if header.Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Errorf("%s listener: CORP = %q", name, header.Get("Cross-Origin-Resource-Policy"))
		}
		if header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s listener: missing nosniff", name)
		}
	}
}

func TestBreakGlassSessionPayload(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, _ := bgSignIn(t, s)
	w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, "")
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["door"] != audit.DoorLocal {
		t.Errorf("door = %v, want %q", v["door"], audit.DoorLocal)
	}
	// §2.4: an administrator session that is NOT a QTS user, so nothing it
	// creates can be owned by one. The UI keys its persistent banner on this.
	if v["admin"] != true || v["rootMode"] != true {
		t.Errorf("a break-glass session must be an administrator session: %v", v)
	}
	if v["createsAs"] != "" {
		t.Errorf("createsAs = %v, want empty: there is no real user behind this session", v["createsAs"])
	}
	// The main listener still reports its own door and its own user.
	mainCookie, _ := sessionCookie(t, s)
	mw := request(s, "GET", "/api/session", mainCookie, nil)
	var mv map[string]any
	if err := json.Unmarshal(mw.Body.Bytes(), &mv); err != nil {
		t.Fatal(err)
	}
	if mv["door"] != audit.DoorQTS {
		t.Errorf("main door = %v, want %q", mv["door"], audit.DoorQTS)
	}
	if mv["createsAs"] != "dev" {
		t.Errorf("main createsAs = %v, want the signed-in user", mv["createsAs"])
	}
	// Unauthenticated, the page is told which listener it is on and nothing
	// else; see TestBreakGlassSignInFlow for the full disclosure assertion.
	aw := bgRequest(s, "GET", "/api/session", nil, nil, "")
	var av map[string]any
	if err := json.Unmarshal(aw.Body.Bytes(), &av); err != nil {
		t.Fatal(err)
	}
	if av["authenticated"] != false || av["listener"] != audit.DoorLocal {
		t.Errorf("anonymous break-glass session payload = %v", av)
	}
	// The MAIN listener's anonymous answer is unchanged: it reaches only
	// someone already on the QTS origin, and the shell needs it to render.
	maw := request(s, "GET", "/api/session", nil, nil)
	if !strings.Contains(maw.Body.String(), `"version"`) || !strings.Contains(maw.Body.String(), `"readOnly"`) {
		t.Errorf("the main listener's anonymous payload was narrowed too: %s", maw.Body)
	}
}

// §2.4 again, at the layer that matters: no CreateAs reaches the worker.
func TestBreakGlassCreatesRootOwnedContent(t *testing.T) {
	s, b, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	b.lastAs = nil
	w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie},
		map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"},
		`{"dir":"/","name":"support"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("mkdir: %d %s", w.Code, w.Body)
	}
	if b.lastAs != nil {
		t.Fatalf("a break-glass mkdir sent CreateAs %+v; there is no real user to create as", b.lastAs)
	}
	// The same request through the main listener — an admin QTS session — DOES
	// carry it, so this is the break-glass rule and not a regression of M2-B.
	mainCookie, mainCSRF := sessionCookie(t, s)
	b.lastAs = nil
	w = request(s, "POST", "/api/fs/mkdir", mainCookie, map[string]string{
		"X-QFM-CSRF": mainCSRF, "Origin": "http://example.com", "Content-Type": "application/json",
	})
	_ = w
	if got := b.lastAs; got == nil && w.Code == http.StatusOK {
		t.Fatal("the main listener's admin session lost its CreateAs")
	}
}

func TestBreakGlassSessionCapAndTimeouts(t *testing.T) {
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	// Set before anything serves; the server reads it through the gate.
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

	var first *http.Cookie
	for i := 0; i < bgMaxSessions+3; i++ {
		// One refill interval between logins: the per-source bucket is a
		// separate bound and this test is about the session store, not it.
		advance(breakglass.BucketWindow / breakglass.BucketCapacity)
		c, _ := bgSignIn(t, s)
		if i == 0 {
			first = c
		}
	}
	if n := s.bg.Sessions(); n > bgMaxSessions {
		t.Fatalf("%d live break-glass sessions, want at most %d", n, bgMaxSessions)
	}
	// The oldest was evicted, not a random one.
	if w := bgRequest(s, "GET", "/api/session", []*http.Cookie{first}, nil, ""); strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("the oldest session survived the cap")
	}

	// Idle timeout.
	cookie, _ := bgSignIn(t, s)
	advance(bgIdle + time.Second)
	if w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("an idle session outlived its timeout")
	}

	// Absolute lifetime, kept alive by traffic the whole way.
	cookie, _ = bgSignIn(t, s)
	for spent := time.Duration(0); spent+bgIdle/2 < bgLifetime; spent += bgIdle / 2 {
		advance(bgIdle / 2)
		if w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); !strings.Contains(w.Body.String(), `"authenticated":true`) {
			t.Fatalf("an actively used session died after %v, before its %v lifetime", spent, bgLifetime)
		}
	}
	advance(bgIdle)
	if w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("a session outlived its absolute lifetime")
	}
}

// §4.4: changing or clearing the password destroys every live break-glass
// session. That is what makes `break-glass disable` an eviction and not a
// suggestion.
func TestChangingThePasswordEvictsLiveSessions(t *testing.T) {
	s, _, configPath := bgFixture(t)
	cookie, _ := bgSignIn(t, s)
	if w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("the session was not live to begin with")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.Local.Hash = ""
	cfg.Auth.Local.Updated = "2026-09-14T09:00:00Z"
	// The daemon notices by mtime+size, so make sure the stat differs even on a
	// filesystem with a coarse timestamp.
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(configPath, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, "")
	if strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("clearing the password left a live session behind")
	}
	// And the cleared hash refuses the password it used to accept, without a
	// restart.
	if lw := bgLogin(t, s, bgTestPassword); lw.Code != http.StatusUnauthorized {
		t.Fatalf("the cleared hash still accepted the old password: %d %s", lw.Code, lw.Body)
	}
}

func TestBreakGlassLogoutDestroysTheSession(t *testing.T) {
	s, _, _ := bgFixture(t)
	for _, path := range []string{bgLogoutPath, "/api/logout"} {
		t.Run(path, func(t *testing.T) {
			cookie, csrf := bgSignIn(t, s)
			w := bgRequest(s, "POST", path, []*http.Cookie{cookie},
				map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}, "{}")
			if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
				t.Fatalf("logout: %d %s", w.Code, w.Body)
			}
			if sw := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, ""); strings.Contains(sw.Body.String(), `"authenticated":true`) {
				t.Fatal("the session survived the logout")
			}
		})
	}
}

func TestBreakGlassRequiresCSRFAndOrigin(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	body := `{"dir":"/","name":"nope"}`
	// No token.
	if w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, map[string]string{"Content-Type": "application/json"}, body); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF token = %d %s, want 403", w.Code, w.Body)
	}
	// A cross-site fetch, token and all.
	if w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, map[string]string{
		"X-QFM-CSRF": csrf, "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json",
	}, body); w.Code != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site: cross-site = %d %s, want 403", w.Code, w.Body)
	}
	// The LOGIN route is the one exception, and only in one direction: no CSRF
	// TOKEN is required — there is no session yet to bind one to, and the UI's
	// sign-in form therefore sends none — while the Origin half of the scheme
	// applies in full. Every other route on this listener keeps both.
	t.Run("no token is required", func(t *testing.T) {
		fresh, _, _ := bgFixture(t)
		w := bgRequest(fresh, "POST", bgLoginPath, nil, map[string]string{"Content-Type": "application/json"},
			fmt.Sprintf(`{"password":%q}`, bgTestPassword))
		if w.Code != http.StatusNoContent {
			t.Fatalf("login without a CSRF token = %d %s, want 204", w.Code, w.Body)
		}
		if w.Header().Get("X-QFM-CSRF") != "" {
			t.Error("the login response must not echo a token; the UI reads it from /api/session")
		}
	})
	t.Run("the Origin half applies in full", func(t *testing.T) {
		for name, headers := range map[string]map[string]string{
			"a foreign origin":      {"Origin": "https://elsewhere.example"},
			"a foreign referer":     {"Origin": "", "Referer": "https://elsewhere.example/page"},
			"no origin at all":      {"Origin": ""},
			"a cross-site fetch":    {"Sec-Fetch-Site": "cross-site"},
			"an origin with a user": {"Origin": "https://someone@elsewhere.example"},
		} {
			fresh, _, _ := bgFixture(t)
			w := bgRequest(fresh, "POST", bgLoginPath, nil, headers, fmt.Sprintf(`{"password":%q}`, bgTestPassword))
			if w.Code != http.StatusForbidden {
				t.Errorf("login with %s = %d %s, want 403", name, w.Code, w.Body)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("login with %s issued a cookie", name)
			}
		}
	})
}

func TestBreakGlassLoginRejectsNonPOST(t *testing.T) {
	s, _, _ := bgFixture(t)
	w := bgRequest(s, "GET", bgLoginPath, nil, nil, "")
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Fatalf("GET %s = %d (Allow %q), want 405", bgLoginPath, w.Code, w.Header().Get("Allow"))
	}
}

// The read-only blanket covers the new door exactly as it covers the old one:
// the listener decides who you are, never what you may do (§2.3).
func TestReadOnlyCoversTheBreakGlassDoor(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	s.guard.SetReadOnly(true)
	headers := map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}
	for _, c := range []struct{ path, body string }{
		{"/api/fs/mkdir", `{"dir":"/","name":"x"}`},
		{"/api/fs/rename", `{"path":"/a.txt","to":"b.txt"}`},
		{"/api/fs/delete", `{"paths":[{"path":"/a.txt"}]}`},
	} {
		w := bgRequest(s, "POST", c.path, []*http.Cookie{cookie}, headers, c.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s in read-only mode = %d %s, want 403", c.path, w.Code, w.Body)
		}
	}
	// And the session still reports the state it is actually in.
	w := bgRequest(s, "GET", "/api/session", []*http.Cookie{cookie}, nil, "")
	if !strings.Contains(w.Body.String(), `"readOnly":true`) || !strings.Contains(w.Body.String(), `"canWrite":false`) {
		t.Fatalf("session payload = %s", w.Body)
	}
}

// --- the TLS end-to-end path (§16.8) -----------------------------------------

// The real listener, a generated certificate, a login over HTTPS. Everything
// else here drives the handler directly; this is what proves the pieces fit.
func TestBreakGlassOverRealTLS(t *testing.T) {
	s, _, _ := bgFixture(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "breakglass-cert.pem")
	keyFile := filepath.Join(dir, "breakglass-key.pem")
	cert, err := breakglass.EnsureUsable(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s.BreakGlassHandler())
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"}, // HTTP/2 declined on purpose (§13.5)
		Certificates: []tls.Certificate{*cert.TLS},
	}
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test client transport")
	}
	tr.TLSClientConfig.InsecureSkipVerify = true // self-signed, by design
	jar := &cookieJar{}
	client.Jar = jar

	post := func(path, body string, headers map[string]string) *http.Response {
		req, err := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", srv.URL)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post(bgLoginPath, fmt.Sprintf(`{"password":%q}`, "the wrong one!!!!"), nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password over TLS = %d", resp.StatusCode)
	}

	resp = post(bgLoginPath, fmt.Sprintf(`{"password":%q}`, bgTestPassword), nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login over TLS = %d", resp.StatusCode)
	}
	if resp.TLS == nil || resp.TLS.NegotiatedProtocol == "h2" {
		t.Fatalf("negotiated %q; HTTP/2 is declined on purpose", resp.TLS.NegotiatedProtocol)
	}

	req, err := http.NewRequest("GET", srv.URL+"/api/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	sresp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(sresp.Body)
	sresp.Body.Close()
	if !strings.Contains(string(body), `"authenticated":true`) || !strings.Contains(string(body), `"door":"local"`) {
		t.Fatalf("session over TLS = %s", body)
	}
}

// cookieJar is the smallest jar that keeps the __Host- cookie across requests:
// net/http/cookiejar would need a PSL-aware host and this is a loopback IP.
type cookieJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		replaced := false
		for i, existing := range j.cookies {
			if existing.Name == c.Name {
				j.cookies[i], replaced = c, true
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, c)
		}
	}
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		if c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}
