package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/qtsauth"
)

func TestQuerySIDBootstrapWithoutCookies(t *testing.T) {
	s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sid") != "valid+token" {
			t.Errorf("unexpected SID: %q", r.URL.Query().Get("sid"))
		}
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
	})
	w := request(s, "GET", "/api/session?sid=valid%2Btoken", nil, nil)
	var body struct {
		Authenticated bool
		User, CSRF    string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !body.Authenticated || body.User != "dev" || body.CSRF == "" {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "qfm_sid" || cookies[0].Value == "" {
		t.Fatalf("session cookie: %v", cookies)
	}
	w = request(s, "GET", "/api/session", cookies[0], nil)
	if w.Code != 200 || len(s.sessions) != 1 {
		t.Fatalf("cookie-only follow-up: %d %s", w.Code, w.Body)
	}
}

func TestMalformedCredentialPresence(t *testing.T) {
	s, _ := fixture(t, false)
	for _, cookie := range []string{"NAS_USER=-bad; qtoken=expired", "qfm_sid=", "NAS_USER=", "qtoken=", "NAS_SID=", "qtoken=\"unterminated"} {
		t.Run(cookie, func(t *testing.T) {
			assertAuthError(t, request(s, "GET", "/api/session", nil, map[string]string{"Cookie": cookie}), 401, "unauthorized", "")
		})
	}
	assertAuthError(t, request(s, "GET", "/api/session?sid=", nil, nil), 401, "unauthorized", "")
	assertAuthError(t, request(s, "GET", "/api/session?sid=%zz", nil, nil), 401, "unauthorized", "")
	assertAuthError(t, request(s, "GET", "/api/session", nil, map[string]string{"X-QNAP-SID": ""}), 401, "unauthorized", "")
	w := request(s, "GET", "/api/session?user=dev", nil, map[string]string{"Cookie": "theme=dark"})
	if w.Code != 200 {
		t.Fatalf("no credential carriers: %d %s", w.Code, w.Body)
	}
}

func TestCSRFRejectedBeforeRevalidation(t *testing.T) {
	var calls atomic.Int32
	s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
	})
	w := request(s, "GET", "/api/session?sid=valid", nil, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	old := s.sessions[cookie.Value]
	old.checked = time.Now().Add(-time.Minute)
	for _, headers := range []map[string]string{
		{"Origin": "http://example.com"},
		{"X-QFM-CSRF": "wrong", "Origin": "http://example.com"},
		{"X-QFM-CSRF": old.csrf, "Origin": "https://evil.example"},
	} {
		assertAuthError(t, request(s, "POST", "/api/logout", cookie, headers), 403, "permission", "")
	}
	// Even a busy session cannot force an invalid-CSRF request to wait.
	old.mu.Lock()
	w = request(s, "POST", "/api/logout", cookie, nil)
	old.mu.Unlock()
	assertAuthError(t, w, 403, "permission", "")
	if calls.Load() != 1 || len(s.authAdmission.slots) != 0 || len(s.authAdmission.waiters) != 0 {
		t.Fatal("invalid CSRF consumed authentication work")
	}
	w = request(s, "POST", "/api/logout", cookie, map[string]string{"X-QFM-CSRF": old.csrf, "Origin": "http://example.com"})
	if w.Code != 200 || calls.Load() != 2 {
		t.Fatalf("valid CSRF must force revalidation: calls=%d status=%d body=%s", calls.Load(), w.Code, w.Body)
	}
}

func TestSymmetricAuthenticationReservations(t *testing.T) {
	for _, revalidation := range []bool{false, true} {
		t.Run(fmt.Sprintf("revalidation=%v", revalidation), func(t *testing.T) {
			s, _ := fixture(t, false)
			a := &s.authAdmission
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for i := 0; i < 6; i++ {
				if err := a.enter(ctx, revalidation); err != nil {
					t.Fatal(err)
				}
				defer a.leave(revalidation)
			}
			queued := make(chan error, 1)
			go func() {
				err := a.enter(ctx, revalidation)
				if err == nil {
					a.leave(revalidation)
				}
				queued <- err
			}()
			waitAuthWaiters(t, s, 1)
			if len(a.slots) != 6 {
				t.Fatalf("class occupied %d slots", len(a.slots))
			}
			otherCtx, otherCancel := context.WithTimeout(context.Background(), time.Second)
			defer otherCancel()
			for i := 0; i < 2; i++ {
				if err := a.enter(otherCtx, !revalidation); err != nil {
					t.Fatalf("other class starved: %v", err)
				}
				defer a.leave(!revalidation)
			}
			if len(a.slots) != 8 {
				t.Fatalf("total occupied slots=%d, want 8", len(a.slots))
			}
			cancel()
			if err := <-queued; err != context.Canceled {
				t.Fatalf("seventh request escaped class limit: %v", err)
			}
			if len(a.waiters) != 0 {
				t.Fatal("waiting admission leaked")
			}
		})
	}
}

func TestFirstLoginFollowerLeaderCancellation(t *testing.T) {
	for _, leaderErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(leaderErr.Error(), func(t *testing.T) {
			s, _ := fixture(t, false)
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			key := qtsauth.CacheKey(qtsauth.Cred{Kind: qtsauth.KindSID, Token: "valid"})
			go func() {
				defer close(done)
				_, _ = s.authAdmission.credential(context.Background(), key, func() (*session, error) {
					close(started)
					<-release
					return nil, fmt.Errorf("identity resolution: %w", leaderErr)
				})
			}()
			<-started
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- request(s, "GET", "/api/session?sid=valid", nil, nil) }()
			waitAuthWaiters(t, s, 1)
			unblock()
			assertAuthError(t, <-result, 503, "retry", "1")
			<-done
			if len(s.authAdmission.flights) != 0 || len(s.authAdmission.waiters) != 0 {
				t.Fatal("interrupted flight leaked admission")
			}
			// A subsequent attempt can become leader normally.
			called := false
			_, err := s.authAdmission.credential(context.Background(), key, func() (*session, error) {
				called = true
				return &session{}, nil
			})
			if err != nil || !called {
				t.Fatalf("retry did not become leader: %v", err)
			}
		})
	}
}
