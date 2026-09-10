package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/qtsauth"
)

func authTestServer(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	endpoint := httptest.NewServer(handler)
	t.Cleanup(endpoint.Close)
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	if err := os.WriteFile(passwd, []byte("dev:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	return s
}

func TestUnattributedFailureRecovery(t *testing.T) {
	for _, rotateUsers := range []bool{false, true} {
		t.Run(fmt.Sprintf("rotate-users=%v", rotateUsers), func(t *testing.T) {
			var calls atomic.Int32
			s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				token := r.URL.Query().Get("qtoken")
				if token == "valid" || token == "established" {
					fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
				} else {
					fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
				}
			})
			now := time.Now()
			s.Now = func() time.Time { return now }
			s.verifier.Now = s.Now
			attempt := func(user, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/api/session", nil)
				r.RemoteAddr = "127.0.0.1:1234"
				if cookie != nil {
					r.AddCookie(cookie)
				} else {
					r.AddCookie(&http.Cookie{Name: "NAS_USER", Value: user})
					r.AddCookie(&http.Cookie{Name: "qtoken", Value: token})
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				return w
			}
			w := attempt("dev", "established", nil)
			if w.Code != 200 {
				t.Fatalf("initial session: %d %s", w.Code, w.Body)
			}
			cookie := w.Result().Cookies()[0]
			old := s.sessions[cookie.Value]
			for i := 0; i < 500; i++ {
				user := "dev"
				if rotateUsers {
					user = fmt.Sprintf("bogus%d", i)
				}
				w := attempt(user, fmt.Sprintf("bad%d", i), nil)
				if w.Code != 401 && w.Code != 429 {
					t.Fatalf("bogus credential: %d %s", w.Code, w.Body)
				}
				if i == 300 {
					old.checked = s.now().Add(-time.Minute)
					s.verifier.Invalidate(old.cred)
					if w := attempt("", "", cookie); w.Code != 200 {
						t.Fatalf("revalidation during burst: %d %s", w.Code, w.Body)
					}
				}
			}
			limit := authFailureBurst
			if rotateUsers {
				limit = unattributedFailureBurst
			}
			if n := calls.Load(); n != int32(limit+2) {
				t.Fatalf("upstream calls=%d, want %d", n, limit+2)
			}
			// Refusal is transient and is not negative-cached by the verifier.
			assertAuthError(t, attempt("dev", "valid", nil), 429, "rate_limited", "1")
			now = now.Add(time.Second)
			if w := attempt("dev", "valid", nil); w.Code != 200 {
				t.Fatalf("valid recovery: %d %s", w.Code, w.Body)
			}
			assertAuthError(t, attempt("dev", "more-bogus", nil), 429, "rate_limited", "1")
			if rotateUsers {
				// Global pressure permits five uncached validations per second,
				// including when each attempt presents a previously unseen user.
				for i := 0; i < 5; i++ {
					now = now.Add(unattributedRecoveryInterval)
					user := fmt.Sprintf("recovery%d", i)
					assertAuthError(t, attempt(user, "bad", nil), 401, "unauthorized", "")
					assertAuthError(t, attempt(user+"x", "bad", nil), 429, "rate_limited", "1")
				}
			}
		})
	}
}

func TestFailureClientAttribution(t *testing.T) {
	for _, tc := range []struct{ peer, forwarded, user, want string }{
		{"127.0.0.1:1234", "198.51.100.1, 192.0.2.1", "dev", "ip:192.0.2.1"},
		{"[::1]:1234", "2001:db8::1", "dev", "ip:2001:db8::1"},
		{"127.0.0.1:1234", "", "dev", "user:dev"},
		{"127.0.0.1:1234", "192.0.2.1, invalid", "DEV", "user:dev"},
		{"192.0.2.2:1234", "192.0.2.1", "dev", "user:dev"},
		{"127.0.0.1:1234", "", "-invalid", "user:"},
		{"127.0.0.1:1234", "", "", "user:"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.forwarded)
		if got := authFailureClient(r, qtsauth.Cred{User: tc.user}); got != tc.want {
			t.Errorf("%+v: got %q", tc, got)
		}
	}
}

func waitAuthWaiters(t *testing.T, s *Server, count int) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for len(s.authAdmission.waiters) != count && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if n := len(s.authAdmission.waiters); n != count {
		t.Fatalf("waiting=%d, want %d", n, count)
	}
}

func TestFirstLoginFollowersLeaveExecutionCapacity(t *testing.T) {
	for _, followers := range []int{7, qtsauth.DefaultMaxValidationWaiters} {
		t.Run(fmt.Sprint(followers), func(t *testing.T) {
			release, started := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int32
			s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Query().Get("sid") == "slow" {
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
				fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
			})
			defer unblock()
			leader := make(chan *httptest.ResponseRecorder, 1)
			go func() { leader <- request(s, "GET", "/api/session?sid=slow", nil, nil) }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("leader did not start")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			results := make(chan *httptest.ResponseRecorder, followers)
			for i := 0; i < followers; i++ {
				go func() {
					r := httptest.NewRequest("GET", "/api/session?sid=slow", nil).WithContext(ctx)
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, r)
					results <- w
				}()
			}
			waitAuthWaiters(t, s, followers)
			if n := len(s.authAdmission.slots); n != 1 {
				t.Fatalf("followers hold execution slots: %d", n)
			}
			if followers == qtsauth.DefaultMaxValidationWaiters {
				assertAuthError(t, request(s, "GET", "/api/session?sid=slow", nil, nil), 503, "overloaded", "2")
				// Session followers consume the same waiting budget.
				old := s.insertSession(indexedTestSession("locked", "dev"))
				old.mu.Lock()
				w := request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: old.id}, nil)
				old.mu.Unlock()
				assertAuthError(t, w, 503, "overloaded", "2")
			}
			fast := make(chan *httptest.ResponseRecorder, 1)
			go func() { fast <- request(s, "GET", "/api/session?sid=fast", nil, nil) }()
			select {
			case w := <-fast:
				if w.Code != 200 {
					t.Fatalf("different credential: %d %s", w.Code, w.Body)
				}
			case <-time.After(time.Second):
				t.Fatal("different credential blocked behind first-login followers")
			}
			if followers == qtsauth.DefaultMaxValidationWaiters {
				cancel()
				for i := 0; i < followers; i++ {
					<-results
				}
				waitAuthWaiters(t, s, 0)
			}
			unblock()
			if w := <-leader; w.Code != 200 {
				t.Fatalf("leader: %d %s", w.Code, w.Body)
			}
			if followers == 7 {
				for i := 0; i < followers; i++ {
					if w := <-results; w.Code != 200 {
						t.Fatalf("follower: %d %s", w.Code, w.Body)
					}
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("upstream calls=%d, want 2", calls.Load())
			}
			if len(s.authAdmission.slots) != 0 || len(s.authAdmission.logins) != 0 || len(s.authAdmission.waiters) != 0 || len(s.authAdmission.flights) != 0 {
				t.Fatal("admission leaked")
			}
		})
	}
}

func TestRevalidationReservedCapacity(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 6)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sid") != "established" {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
	})
	defer unblock()
	results := make(chan *httptest.ResponseRecorder, 6)
	for i := 0; i < 6; i++ {
		go func() { results <- request(s, "GET", fmt.Sprintf("/api/session?sid=slow%d", i), nil, nil) }()
	}
	for i := 0; i < 6; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("new login did not start")
		}
	}
	// Fill the failure budget too: revalidation must ignore both kinds of pressure.
	for i := 0; i < authFailureBurst; i++ {
		_ = s.authFailures.failed("user:", fmt.Sprint(i), time.Now())
	}
	old := indexedTestSession("established", "dev")
	old.cred = qtsauth.Cred{Kind: qtsauth.KindSID, Token: "established"}
	old.binding = qtsauth.CacheKey(old.cred)
	old.checked = time.Now().Add(-time.Minute)
	s.insertSession(old)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var queued sync.WaitGroup
	for i := 0; i < qtsauth.DefaultMaxValidationWaiters; i++ {
		queued.Add(1)
		go func() {
			defer queued.Done()
			r := httptest.NewRequest("GET", fmt.Sprintf("/api/session?sid=queued%d", i), nil).WithContext(ctx)
			s.Handler().ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	waitAuthWaiters(t, s, qtsauth.DefaultMaxValidationWaiters)
	if n := len(s.authAdmission.slots); n != 6 {
		t.Fatalf("new logins occupy %d slots, want 6", n)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: old.id}, nil) }()
	select {
	case w := <-done:
		if w.Code != 200 {
			t.Fatalf("revalidation: %d %s", w.Code, w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("new login burst starved revalidation")
	}
	cancel()
	queued.Wait()
	unblock()
	for i := 0; i < 6; i++ {
		<-results
	}
	if len(s.authAdmission.slots) != 0 || len(s.authAdmission.logins) != 0 || len(s.authAdmission.waiters) != 0 || len(s.authAdmission.flights) != 0 {
		t.Fatal("admission leaked")
	}
}
