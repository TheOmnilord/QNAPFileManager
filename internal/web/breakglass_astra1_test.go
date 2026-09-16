package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
)

// --- Astra r1 #3: sessionless denials go through the refusal throttle --------

// A cookie-less POST to a mutation route on 8771 used to reach
// auditUnauthenticated directly: a synchronous durable write plus a QuLog
// milestone per packet, outside the source bucket and outside noteRefusal. That
// is the same unbounded write amplifier the login route's throttle was built to
// close, re-opened on every mutation route beside it — and on this listener it
// is reachable by any LAN host with no credential at all.
func TestSessionlessMutationDenialsAreThrottled(t *testing.T) {
	s, _, _ := bgFixture(t)
	s.pinned = nil // no impersonation, so the requests really are sessionless
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)

	const burst = 50
	for i := 0; i < burst; i++ {
		w := bgRequest(s, "POST", "/api/fs/mkdir", nil, map[string]string{"Content-Type": "application/json"}, `{"dir":"/","name":"x"}`)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s, want 401", i+1, w.Code, w.Body)
		}
	}
	// A new window: the next refusal carries the summary of what was suppressed.
	now = now.Add(2 * refusalWindow)
	bgRequest(s, "POST", "/api/fs/mkdir", nil, map[string]string{"Content-Type": "application/json"}, `{"dir":"/","name":"x"}`)

	var lines []audit.Event
	for _, ev := range read() {
		if ev.Op == "auth" && ev.Result == "denied" {
			lines = append(lines, ev)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("%d audit lines for %d refusals across two windows, want 2 (one per window)", len(lines), burst+1)
	}
	for _, ev := range lines {
		if ev.Door != audit.DoorLocal {
			t.Errorf("a sessionless denial on 8771 carries door %q", ev.Door)
		}
		// Still sessionless: the break-glass account must not be named as the
		// actor of a request that never authenticated.
		if ev.Actor != "" || ev.Admin || ev.Root {
			t.Errorf("a sessionless denial names an actor: %+v", ev)
		}
	}
	// The suppressed count is reported rather than lost, so a burst is legible.
	if !strings.Contains(lines[1].Detail, fmt.Sprintf("%d further refusals suppressed", burst-1)) {
		t.Fatalf("the second window did not report what was suppressed: %q", lines[1].Detail)
	}
}

// --- Astra r1 #4: the lockout is per source ----------------------------------

// With one emergency account and an account-wide ladder, any LAN peer could
// spend five wrong passwords and shut the sole door. Keyed by source, a peer
// can only lock itself out.
func TestTheDoorLocksTheSourceAndNotTheAccount(t *testing.T) {
	s, _, _ := bgFixture(t)
	const operator = "192.168.1.5:5555"

	for i := 0; i < breakglass.LockoutAfter; i++ {
		if w := bgLogin(t, s, "the wrong password!!"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s", i+1, w.Code, w.Body)
		}
	}
	// The attacker's own next attempt is refused as locked, with a Retry-After.
	w := bgLogin(t, s, "the wrong password!!")
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"locked_out"`) {
		t.Fatalf("the locked source = %d %s, want 429 locked_out", w.Code, w.Body)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a lockout must say when to try again")
	}

	// The operator, on another address, gets straight in with the right
	// password — which is the whole point of the change.
	r := httptest.NewRequest("POST", bgLoginPath, strings.NewReader(fmt.Sprintf(`{"password":%q}`, bgTestPassword)))
	r.RemoteAddr = operator
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	ow := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(ow, r)
	if ow.Code != http.StatusNoContent {
		t.Fatalf("the operator was refused from another address: %d %s", ow.Code, ow.Body)
	}
	// And the attacker is still locked: one peer's success does not clear
	// another peer's rung.
	if locked, _, _ := s.BreakGlassGate().Locked(bgTestIP); !locked {
		t.Fatal("the attacker's lockout was cleared by someone else's success")
	}
}

// --- Astra r1 #7: the verdict is decided inside the serialised turn ----------

// Four concurrent wrong attempts after four failures used to read the same
// "unlocked, 4 failures" before queueing and commit their failures after
// releasing, so they skipped straight past the first rung. Only one may enter a
// lockout, and it must be the first rung.
func TestConcurrentWrongPasswordsEnterOneRung(t *testing.T) {
	s, _, _ := bgFixture(t)
	for i := 0; i < breakglass.LockoutAfter-1; i++ {
		bgLogin(t, s, "the wrong password!!")
	}
	codes := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func() {
			w := bgRequest(s, "POST", bgLoginPath, nil, nil, `{"password":"the wrong password!!"}`)
			codes <- w.Code
		}()
	}
	var unauthorized, refused int
	for i := 0; i < 4; i++ {
		switch code := <-codes; code {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("a concurrent attempt = %d", code)
		}
	}
	if unauthorized != 1 {
		t.Fatalf("%d of four concurrent attempts reached the credential, want 1: the rest must be refused by the lockout the first one entered", unauthorized)
	}
	// The ladder advanced by exactly one rung, not four.
	if n := s.BreakGlassGate().Failures(bgTestIP); n != breakglass.LockoutAfter {
		t.Fatalf("Failures = %d, want %d", n, breakglass.LockoutAfter)
	}
}

// The other half: a CORRECT password queued behind the failure that enters a
// lockout is refused as locked, rather than let in during a lockout.
func TestACorrectPasswordQueuedBehindALockoutIsRefused(t *testing.T) {
	s, _, _ := bgFixture(t)
	for i := 0; i < breakglass.LockoutAfter-1; i++ {
		bgLogin(t, s, "the wrong password!!")
	}
	// The failing attempt holds the single verification slot until the correct
	// one is provably queued behind it.
	inside, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.bg.gate.Verify(t.Context(), bgTestIP, func() breakglass.Outcome {
			close(inside)
			<-release
			return breakglass.OutcomeFailed
		})
	}()
	<-inside

	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() { answered <- bgLogin(t, s, bgTestPassword) }()
	// Give the queued request time to reach the semaphore, then let the failure
	// commit its lockout. Whichever order the two end up in, the queued attempt
	// takes its turn after the commit and must see the lockout.
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done

	select {
	case w := <-answered:
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"locked_out"`) {
			t.Fatalf("a correct password was accepted during a lockout: %d %s", w.Code, w.Body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the queued login never returned")
	}
}

// --- Astra r1 #12: the credential's stamp changing is audited ----------------

// Contract §6.2 lists it and nothing produced it: the CLI writes nothing to the
// audit log by design, so a rotation under a live daemon left no record at all.
func TestAChangedCredentialStampIsAudited(t *testing.T) {
	s, _, configPath := bgFixture(t)
	read := withAudit(t, s)
	// The baseline is already cached (the fixture's EnableBreakGlass read it).
	bgLogin(t, s, "the wrong password!!")

	hash, err := breakglass.Hash("a different password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Updated = "2026-09-17T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Force the mtime+size guard to notice on a filesystem whose timestamps are
	// coarser than this test is fast.
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(configPath, future, future); err != nil {
		t.Fatal(err)
	}
	// Two attempts: the reload happens on the first, and the report must be
	// made exactly once however many follow.
	bgLogin(t, s, "a different password")
	bgLogin(t, s, "a different password")

	var lines []audit.Event
	for _, ev := range read() {
		if ev.Op == "breakglass-credential" {
			lines = append(lines, ev)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("%d credential-change milestones, want exactly 1", len(lines))
	}
	ev := lines[0]
	if ev.Door != audit.DoorLocal {
		t.Errorf("door = %q", ev.Door)
	}
	if ev.Path != "" || strings.Contains(ev.Detail, configPath) {
		t.Errorf("the detail names a path: %q / %q", ev.Path, ev.Detail)
	}
	if !strings.Contains(ev.Detail, "2026-09-13T12:00:00Z") || !strings.Contains(ev.Detail, "2026-09-17T09:00:00Z") {
		t.Errorf("the detail must carry both stamps: %q", ev.Detail)
	}
}

// --- Astra r1 #13: every session removal is audited with its reason ----------

func TestEveryBreakGlassSessionRemovalIsAudited(t *testing.T) {
	t.Run("logout through the shared route", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		read := withAudit(t, s)
		cookie, csrf := bgSignIn(t, s)
		// /api/logout, not /api/breakglass/logout: only the latter ever audited.
		w := bgRequest(s, "POST", "/api/logout", []*http.Cookie{cookie}, map[string]string{"X-QFM-CSRF": csrf}, "")
		if w.Code != http.StatusOK {
			t.Fatalf("logout = %d %s", w.Code, w.Body)
		}
		if !hasRemoval(read(), bgRemovalLogout) {
			t.Fatal("/api/logout destroyed a break-glass session silently")
		}
	})

	t.Run("capacity eviction", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		read := withAudit(t, s)
		for i := 0; i < bgMaxSessions+2; i++ {
			if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent {
				t.Fatalf("login %d = %d %s", i+1, w.Code, w.Body)
			}
		}
		if n := s.bg.Sessions(); n > bgMaxSessions {
			t.Fatalf("%d live sessions, cap is %d", n, bgMaxSessions)
		}
		if !hasRemoval(read(), bgRemovalEvicted) {
			t.Fatal("a session evicted to make room vanished silently")
		}
	})

	t.Run("expiry inside issue", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		read := withAudit(t, s)
		now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
		s.BreakGlassGate().Now = func() time.Time { return now }
		if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent {
			t.Fatalf("login = %d %s", w.Code, w.Body)
		}
		// Past the absolute lifetime, then a second login: the first session is
		// expired inside issue rather than on a request of its own.
		now = now.Add(bgLifetime + time.Minute)
		if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent {
			t.Fatalf("second login = %d %s", w.Code, w.Body)
		}
		if !hasRemoval(read(), bgRemovalExpired) {
			t.Fatal("a session expired inside issue vanished silently")
		}
	})
}

// hasRemoval looks for the one line a removal must leave. ForceMilestone is
// json:"-" and never round-trips through the log, so it cannot be asserted from
// a tail; every break-glass event goes through d.audit, which sets it, and
// TestBreakGlassEventsAreForcedMilestones covers that path.
func hasRemoval(events []audit.Event, reason string) bool {
	for _, ev := range events {
		if ev.Op == "breakglass-session" && strings.Contains(ev.Detail, "destroyed: "+reason) {
			return true
		}
	}
	return false
}

// --- Astra r1 #15: the reload carries the daemon's own validation mode -------

// localCred reloaded with production config.Load, so a daemon started with -dev
// on a config whose auth.mode is "local" could never read its own credential
// again: every login after the first reload failed closed on the very file the
// daemon started from.
func TestTheCredentialReloadsWithTheDaemonsValidationMode(t *testing.T) {
	s, _ := fixture(t, true)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Auth.Mode = config.AuthLocal // a development configuration
	cfg.ReadOnly = false
	hash, err := breakglass.Hash(bgTestPassword, breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-17T08:00:00Z"}
	if err := config.SaveDev(configPath, cfg, true); err != nil {
		t.Fatal(err)
	}
	s.cfg.ReadOnly = false
	if s.guard != nil {
		s.guard.SetReadOnly(false)
	}
	s.ConfigPath = configPath
	s.Dev = true
	s.EnableBreakGlass(configPath)
	s.BreakGlassGate().Floor = -1

	if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusNoContent {
		t.Fatalf("a -dev daemon could not read its own credential: %d %s", w.Code, w.Body)
	}
	// And a daemon that did NOT start with -dev fails closed on the same file,
	// which is the behaviour that must not change.
	s.Dev = false
	s.EnableBreakGlass(configPath)
	s.BreakGlassGate().Floor = -1
	if w := bgLogin(t, s, bgTestPassword); w.Code != http.StatusUnauthorized {
		t.Fatalf("a production daemon accepted a development configuration: %d %s", w.Code, w.Body)
	}
}

// --- Astra r1 #8: a declared-but-unsent body does not park the connection ----

// decodeBody's drain had no read deadline: a valid JSON prefix under a larger
// Content-Length, then silence, parked the handler goroutine — the 15 s handler
// context does not interrupt a socket read, and neither listener sets
// ReadTimeout. The deadline is what bounds it on a real connection; what a
// handler-level test can assert is the other half, that a drain which did not
// finish is not treated as a consumed body.
func TestAnUnfinishedDrainClosesTheConnection(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)

	body := `{"dir":"/","name":"support"}`
	r := httptest.NewRequest("POST", "/api/fs/mkdir", &haltingBody{data: []byte(body), err: os.ErrDeadlineExceeded})
	// Declared far larger than what is actually sent: the lever.
	r.ContentLength = int64(len(body) * 100)
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-QFM-CSRF", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(w, r)

	// The request itself is answered — it parsed — but the connection must not
	// be reused, because net/http would drain the remainder behind the response
	// with no deadline at all.
	if w.Header().Get("Connection") != "close" {
		t.Fatalf("a body that was never consumed left the connection open: %d %v", w.Code, w.Header())
	}

	// A body that WAS consumed keeps keep-alive: closing every successful
	// mutation would be one TCP handshake per request through the emergency
	// door, which is the opposite of what that door is for.
	ok := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie},
		map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}, `{"dir":"/","name":"support2"}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("mkdir = %d %s", ok.Code, ok.Body)
	}
	if got := ok.Header().Get("Connection"); got == "close" {
		t.Fatal("a fully consumed body closed the connection")
	}
}

// haltingBody yields its data and then fails, the way a socket read does when
// the read deadline expires under a Content-Length that will never arrive.
type haltingBody struct {
	data []byte
	err  error
	n    int
}

func (b *haltingBody) Read(p []byte) (int, error) {
	if b.n < len(b.data) {
		n := copy(p, b.data[b.n:])
		b.n += n
		return n, nil
	}
	return 0, b.err
}

func (b *haltingBody) Close() error { return nil }

// A drain that fails must not be mistaken for a decode that failed: the caller
// still gets its answer.
func TestAnUnfinishedDrainStillAnswersTheRequest(t *testing.T) {
	s, _, _ := bgFixture(t)
	cookie, csrf := bgSignIn(t, s)
	body := `{"dir":"/","name":"answered"}`
	r := httptest.NewRequest("POST", "/api/fs/mkdir", &haltingBody{data: []byte(body), err: io.ErrUnexpectedEOF})
	r.ContentLength = int64(len(body) * 10)
	r.TLS = bgTLS()
	r.Header.Set("Origin", "https://"+r.Host)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-QFM-CSRF", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.BreakGlassHandler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mkdir = %d %s", w.Code, w.Body)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("the answer is not JSON: %v (%s)", err, w.Body)
	}
}

// bgTLS is the marker net/http sets on a request that arrived over TLS. The
// break-glass listener is TLS-only, and validOrigin checks the scheme.
func bgTLS() *tls.ConnectionState { return &tls.ConnectionState{} }
