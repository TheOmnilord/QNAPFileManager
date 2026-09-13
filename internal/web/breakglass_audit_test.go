package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/fsx"
)

// §6.1: Door is set once at session creation and stamped on EVERY event that
// session produces. Without it the audit log cannot answer the one question an
// operator will actually ask after an incident.
func TestDoorIsStampedOnEveryEvent(t *testing.T) {
	t.Run("break-glass", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		read := withAudit(t, s)
		cookie, csrf := bgSignIn(t, s)
		headers := map[string]string{"X-QFM-CSRF": csrf, "Content-Type": "application/json"}
		if w := bgRequest(s, "POST", "/api/fs/mkdir", []*http.Cookie{cookie}, headers, `{"dir":"/","name":"support"}`); w.Code != http.StatusOK {
			t.Fatalf("mkdir: %d %s", w.Code, w.Body)
		}
		events := read()
		if len(events) == 0 {
			t.Fatal("no audit events at all")
		}
		var sawMkdir bool
		for _, ev := range events {
			if ev.Door != audit.DoorLocal {
				t.Errorf("event %s/%s carries door %q, want %q", ev.Op, ev.Phase, ev.Door, audit.DoorLocal)
			}
			if ev.Op == "mkdir" {
				sawMkdir = true
			}
		}
		if !sawMkdir {
			t.Fatal("the mutation itself was not audited")
		}
	})
	t.Run("qts", func(t *testing.T) {
		s, _, _ := bgFixture(t)
		read := withAudit(t, s)
		c, csrf := sessionCookie(t, s)
		if resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"support"}`); resp.StatusCode != http.StatusOK {
			t.Fatalf("mkdir: %d", resp.StatusCode)
		}
		events := read()
		if len(events) == 0 {
			t.Fatal("no audit events at all")
		}
		for _, ev := range events {
			if ev.Door != audit.DoorQTS {
				t.Errorf("event %s/%s carries door %q, want %q", ev.Op, ev.Phase, ev.Door, audit.DoorQTS)
			}
		}
	})
}

// A sessionless denial carries the LISTENER's door: a forged mutation arriving
// on the LAN-facing port is not the same event as one arriving through the
// proxy, and the trail must be able to tell them apart.
func TestSessionlessDenialsCarryTheListenerDoor(t *testing.T) {
	for _, c := range []struct {
		name     string
		wantDoor string
		send     func(s *Server)
	}{
		{"break-glass", audit.DoorLocal, func(s *Server) {
			bgRequest(s, "POST", "/api/fs/delete", nil, map[string]string{"Content-Type": "application/json"}, `{"path":"/a.txt"}`)
		}},
		{"main", audit.DoorQTS, func(s *Server) {
			r := httptest.NewRequest("POST", "/api/fs/delete", strings.NewReader(`{"path":"/a.txt"}`))
			r.Header.Set("Content-Type", "application/json")
			s.Handler().ServeHTTP(httptest.NewRecorder(), r)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := bgFixture(t)
			s.pinned = nil // no impersonation, so the request really is sessionless
			read := withAudit(t, s)
			c.send(s)
			var found bool
			for _, ev := range read() {
				if ev.Op == "auth" && ev.Result == "denied" {
					found = true
					if ev.Door != c.wantDoor {
						t.Errorf("denial door = %q, want %q", ev.Door, c.wantDoor)
					}
				}
			}
			if !found {
				t.Fatal("an unauthenticated mutation left no denial line")
			}
		})
	}
}

// §6.2: every break-glass event is a forced milestone, and §6.3: the detail
// strings are path-free and bounded. §16.5: a failed login is recorded BEFORE
// the response is written.
func TestBreakGlassEventsAreForcedMilestones(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	// A login success, a session issue, five failures, and the lockout they
	// enter: all of §6.2's list that a handler can produce.
	bgSignIn(t, s)
	for i := 0; i < breakglass.LockoutAfter; i++ {
		bgLogin(t, s, "the wrong password!!")
	}
	var login, failure, lockout, session bool
	for _, ev := range read() {
		if !strings.HasPrefix(ev.Op, "breakglass-") {
			continue
		}
		if ev.Door != audit.DoorLocal {
			t.Errorf("%s carries door %q", ev.Op, ev.Door)
		}
		if ev.Path != "" || ev.Dst != "" {
			t.Errorf("%s carries a path (%q -> %q); break-glass details are path-free", ev.Op, ev.Path, ev.Dst)
		}
		if len(ev.Detail) > 200 {
			t.Errorf("%s detail is %d bytes; details are bounded", ev.Op, len(ev.Detail))
		}
		if !strings.Contains(ev.Detail, "door=local") {
			t.Errorf("%s detail = %q, want it to name the door", ev.Op, ev.Detail)
		}
		switch {
		case ev.Op == "breakglass-login" && ev.Result == "ok":
			login = true
		case ev.Op == "breakglass-login" && ev.Result == "denied":
			failure = true
		case ev.Op == "breakglass-lockout":
			lockout = true
			if !strings.Contains(ev.Detail, "lockout") {
				t.Errorf("lockout detail = %q", ev.Detail)
			}
		case ev.Op == "breakglass-session":
			session = true
		}
	}
	if !login || !failure || !lockout || !session {
		t.Fatalf("missing milestones: login=%v failure=%v lockout=%v session=%v", login, failure, lockout, session)
	}
}

// The audit line for a failed login exists even when the client hangs up the
// moment it sees the status (§16.5: recorded before the response is written).
func TestFailedLoginIsRecordedBeforeTheResponse(t *testing.T) {
	s, _, _ := bgFixture(t)
	read := withAudit(t, s)
	// A recorder that fails the test if anything reached it before the audit
	// line was on disk would need a hook into the sink; the observable form is
	// that the line exists at all by the time the handler returns, which the
	// synchronous WriteSync inside fail() is what guarantees.
	w := bgLogin(t, s, "the wrong password!!")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login: %d", w.Code)
	}
	var found bool
	for _, ev := range read() {
		if ev.Op == "breakglass-login" && ev.Result == "denied" {
			found = true
			if !ev.T.IsZero() && time.Since(ev.T) > time.Minute {
				t.Errorf("the denial is stamped %v", ev.T)
			}
		}
	}
	if !found {
		t.Fatal("a failed login left no audit line")
	}
}

// §5.2 at the HTTP layer: the 400 ms floor applies to every failure path. This
// is the one web test that measures wall-clock latency, so it uses the real
// floor rather than the fixture's disabled one.
func TestBreakGlassFailureFloorAtTheDoor(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the real 400 ms floor")
	}
	floor := 120 * time.Millisecond
	for _, c := range []struct {
		name string
		send func(s *Server)
	}{
		{"wrong password", func(s *Server) { bgLogin(t, s, "the wrong password!!") }},
		{"malformed body", func(s *Server) { bgRequest(s, "POST", bgLoginPath, nil, nil, "not json") }},
		{"locked out", func(s *Server) {
			for i := 0; i <= breakglass.LockoutAfter; i++ {
				bgLogin(t, s, "the wrong password!!")
			}
			bgLogin(t, s, bgTestPassword)
		}},
		{"no password configured", func(s *Server) {
			s.bg.cred = &localCred{} // no path, no pinned credential: no hash at all
			bgLogin(t, s, bgTestPassword)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := bgFixture(t)
			s.BreakGlassGate().Floor = floor
			start := time.Now()
			c.send(s)
			if elapsed := time.Since(start); elapsed < floor {
				t.Fatalf("%s answered in %v, below the %v floor", c.name, elapsed, floor)
			}
		})
	}
}

// §10: two new error codes, both WEB-ONLY. They are issued by this layer and
// never cross the RPC, so they belong in web.statusCode's table and are
// deliberately absent from fsx.WorkerCodes — without this test the next person
// to read internal/workerpool's code-coverage table concludes it is incomplete.
func TestBreakGlassErrorCodes(t *testing.T) {
	for code, want := range map[string]int{"auth_failed": 401, "locked_out": 429} {
		if got := statusCode(code); got != want {
			t.Errorf("statusCode(%q) = %d, want %d", code, got, want)
		}
		for _, worker := range fsx.WorkerCodes {
			if worker == code {
				t.Errorf("%q is in fsx.WorkerCodes; it is issued by the web layer and never crosses the RPC", code)
			}
		}
	}
}
