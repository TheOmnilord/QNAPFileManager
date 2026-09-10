package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestQTSUnavailable(t *testing.T) {
	for _, failure := range []string{"503", "closed", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			var down atomic.Bool
			s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if down.Load() {
					if failure == "timeout" {
						<-r.Context().Done()
						return
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
			})
			now := time.Now()
			s.Now = func() time.Time { return now }
			s.verifier.Now = s.Now
			s.AuthTimeout = 50 * time.Millisecond
			w := request(s, "GET", "/api/session?sid=established", nil, nil)
			if w.Code != 200 {
				t.Fatalf("bootstrap: %d %s", w.Code, w.Body)
			}
			cookie := w.Result().Cookies()[0]
			old := s.sessions[cookie.Value]
			down.Store(true)
			if failure == "closed" {
				closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				closed.Close()
				s.verifier.Client.BaseURL = closed.URL
			}
			// New login outages have the same transient response and no cookie.
			w = request(s, "GET", "/api/session?sid=new", nil, nil)
			assertAuthError(t, w, 503, "qts_unavailable", "2")
			if len(w.Result().Cookies()) != 0 || len(s.authFailures.clients) != 0 {
				t.Fatal("outage issued a cookie or counted as a bad credential")
			}
			now = now.Add(time.Minute)
			for _, elapsed := range []time.Duration{0, qtsUnavailableGrace - time.Second, time.Second} {
				now = now.Add(elapsed)
				w = request(s, "GET", "/api/session", cookie, nil)
				assertAuthError(t, w, 503, "qts_unavailable", "2")
				if now.Before(old.unavailableSince.Add(qtsUnavailableGrace)) {
					if old.dead.Load() || s.sessions[old.id] != old || len(w.Result().Cookies()) != 0 {
						t.Fatal("outage destroyed session within grace")
					}
				} else if !old.dead.Load() || s.sessions[old.id] != nil || s.byCredential[old.binding] != nil {
					t.Fatal("session survived expired outage grace")
				} else if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 {
					t.Fatal("expired outage did not clear cookie")
				}
			}
		})
	}
}

func TestQTSOutageRecoveryAndRejection(t *testing.T) {
	var mode atomic.Int32
	s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			w.WriteHeader(503)
		case 2:
			fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
		default:
			fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
		}
	})
	now := time.Now()
	s.Now = func() time.Time { return now }
	s.verifier.Now = s.Now
	w := request(s, "GET", "/api/session?sid=established", nil, nil)
	if w.Code != 200 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	old := s.sessions[cookie.Value]
	// A write forces validation even inside the normal 60-second read cache.
	// Once it fails, following reads must also validate instead of using it.
	mode.Store(1)
	assertAuthError(t, request(s, "POST", "/api/logout", cookie, map[string]string{
		"X-QFM-CSRF": old.csrf, "Origin": "http://example.com",
	}), 503, "qts_unavailable", "2")
	assertAuthError(t, request(s, "GET", "/api/session", cookie, nil), 503, "qts_unavailable", "2")
	mode.Store(0)
	if w := request(s, "GET", "/api/session", cookie, nil); w.Code != 200 {
		t.Fatalf("immediate recovery: %d %s", w.Code, w.Body)
	}
	for i := 0; i < 2; i++ {
		now = now.Add(time.Minute)
		mode.Store(1)
		assertAuthError(t, request(s, "GET", "/api/session", cookie, nil), 503, "qts_unavailable", "2")
		now = now.Add(qtsUnavailableGrace - time.Second)
		mode.Store(0)
		w = request(s, "GET", "/api/session", cookie, nil)
		if w.Code != 200 || s.sessions[old.id] != old || !old.unavailableSince.IsZero() {
			t.Fatalf("recovery did not preserve session/reset grace: %d %s", w.Code, w.Body)
		}
	}
	now = now.Add(time.Minute)
	mode.Store(1)
	assertAuthError(t, request(s, "GET", "/api/session", cookie, nil), 503, "qts_unavailable", "2")
	mode.Store(2)
	assertAuthError(t, request(s, "GET", "/api/session", cookie, nil), 401, "unauthorized", "")
	if !old.dead.Load() || s.sessions[old.id] != nil {
		t.Fatal("explicit rejection retained session during grace")
	}
}

func TestBootstrapReplacesOldCookie(t *testing.T) {
	for _, outcome := range []string{"valid", "invalid", "unavailable", "unsafe"} {
		t.Run(outcome, func(t *testing.T) {
			var calls atomic.Int32
			s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch r.URL.Query().Get("sid") {
				case "invalid":
					fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
				case "unavailable":
					w.WriteHeader(503)
				default:
					fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
				}
			})
			w := request(s, "GET", "/api/session?sid=old", nil, nil)
			if w.Code != 200 {
				t.Fatalf("bootstrap: %d %s", w.Code, w.Body)
			}
			cookie := w.Result().Cookies()[0]
			old := s.sessions[cookie.Value]
			method := "GET"
			if outcome == "unsafe" {
				method = "POST"
			}
			w = request(s, method, "/api/session?sid="+outcome, cookie, nil)
			if outcome == "valid" {
				cookies := w.Result().Cookies()
				if w.Code != 200 || len(cookies) != 1 || cookies[0].Value == cookie.Value || s.sessions[cookies[0].Value] == nil {
					t.Fatalf("replacement: %d %s cookies=%v", w.Code, w.Body, cookies)
				}
				if !old.dead.Load() || s.sessions[old.id] != nil || s.byCredential[old.binding] != nil {
					t.Fatal("old session retained after successful replacement")
				}
			} else {
				if outcome == "unavailable" {
					assertAuthError(t, w, 503, "qts_unavailable", "2")
				} else {
					assertAuthError(t, w, 401, "unauthorized", "")
				}
				if old.dead.Load() || s.sessions[old.id] != old || len(s.sessions) != 1 || len(w.Result().Cookies()) != 0 {
					t.Fatal("failed replacement changed old session")
				}
			}
			want := int32(2)
			if outcome == "unsafe" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatalf("QTS calls=%d, want %d", calls.Load(), want)
			}
		})
	}
}
