package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/qtsauth"
)

func TestCookielessSessionReuseAndUserLimit(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username><isAdmin>0</isAdmin></r>")
	}))
	defer endpoint.Close()
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	if err := os.WriteFile(passwd, []byte("dev:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	login := func(token string) string {
		t.Helper()
		w := request(s, "GET", "/api/session", nil, map[string]string{"Cookie": "NAS_USER=dev; qtoken=" + token})
		if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 {
			t.Errorf("login: %d %s", w.Code, w.Body)
			return ""
		}
		return w.Result().Cookies()[0].Value
	}
	// Concurrent first requests must converge on one id and CSRF secret too.
	ids := make(chan string, 64)
	var wg sync.WaitGroup
	for i := 0; i < cap(ids); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ids <- login("same") }()
	}
	wg.Wait()
	close(ids)
	want := login("same")
	for id := range ids {
		if id != want {
			t.Fatalf("concurrent login id %q, want %q", id, want)
		}
	}
	for i := 0; i < 1000; i++ {
		if got := login("same"); got != want {
			t.Fatalf("request %d changed session id: %q", i, got)
		}
	}
	if len(s.sessions) != 1 {
		t.Fatalf("identical credential retained %d sessions", len(s.sessions))
	}
	for i := 0; i < 1000; i++ {
		login(fmt.Sprintf("different-%d", i))
		if len(s.sessions) > DefaultMaxSessionsPerUser {
			t.Fatalf("user limit exceeded: %d", len(s.sessions))
		}
	}
	if s.sessions[want] != nil || len(s.byCredential) != DefaultMaxSessionsPerUser || s.byUser["dev"].Len() != DefaultMaxSessionsPerUser {
		t.Fatal("oldest session or credential index was retained")
	}
}

func indexedTestSession(id, user string) *session {
	now := time.Now()
	return &session{id: id, csrf: "csrf", binding: id, who: backend.Principal{User: user}, checked: now, expires: now.Add(sessionTTL)}
}

func TestSessionTotalLimitAndEviction(t *testing.T) {
	s, _ := fixture(t, true)
	first := s.insertSession(indexedTestSession("0", "0"))
	for i := 1; i <= DefaultMaxSessions; i++ {
		id := fmt.Sprint(i)
		s.insertSession(indexedTestSession(id, id))
	}
	if len(s.sessions) != DefaultMaxSessions || first.dead.Load() || s.sessions[first.id] != first || s.byCredential[first.binding] != first || s.byUser[first.user] == nil {
		t.Fatal("total bound invalidated another user's live session")
	}
	if s.sessionOrder.Len() != DefaultMaxSessions {
		t.Fatal("eviction queue was not bounded")
	}
	// Removal remains safe when a request that was already running is denied.
	s.destroy(first.id)
	s.destroy("1")
	if len(s.sessions) != DefaultMaxSessions-2 {
		t.Fatal("logout did not remove session")
	}

	s2, _ := fixture(t, true)
	s2.MaxSessions, s2.MaxSessionsPerUser = 3, 2
	a := s2.insertSession(indexedTestSession("a", "alice"))
	s2.insertSession(indexedTestSession("b", "alice"))
	s2.insertSession(indexedTestSession("c", "bob"))
	s2.insertSession(indexedTestSession("d", "alice"))
	if len(s2.sessions) != 3 || !a.dead.Load() || s2.byUser["alice"].Len() != 2 {
		t.Fatal("configured per-user limit did not evict oldest")
	}
	if got := s2.insertSession(indexedTestSession("e", "eve")); got != nil || len(s2.sessions) != 3 || s2.sessions["b"] == nil {
		t.Fatal("configured total limit did not refuse a new identity")
	}
}

func TestSessionExpiredReclaimedBeforeOwnEviction(t *testing.T) {
	s, _ := fixture(t, true)
	s.MaxSessions = 2
	a := s.insertSession(indexedTestSession("a", "alice"))
	expired := s.insertSession(indexedTestSession("expired", "bob"))
	expired.expires = time.Now().Add(-time.Second)
	// Even an expired session busy with validation can be reclaimed without
	// acquiring its network-held lock or blocking unrelated users.
	expired.mu.Lock()
	defer expired.mu.Unlock()
	if got := s.insertSession(indexedTestSession("b", "alice")); got == nil || a.dead.Load() || !expired.dead.Load() {
		t.Fatal("expired session was not reclaimed before own live session")
	}
	if s.byCredential["expired"] != nil || s.byUser["bob"] != nil || s.sessionOrder.Len() != 2 {
		t.Fatal("expired session indexes retained")
	}
	// Under total pressure, the requesting identity replaces only its own oldest.
	if got := s.insertSession(indexedTestSession("c", "alice")); got == nil || !a.dead.Load() || len(s.sessions) != 2 {
		t.Fatal("requester did not replace its own oldest session")
	}
	// A newcomer can use an expired entry belonging to another user.
	s.sessions["b"].expires = time.Now().Add(-time.Second)
	if got := s.insertSession(indexedTestSession("d", "dave")); got == nil || s.sessions["c"].dead.Load() {
		t.Fatal("new identity could not reclaim an expired entry")
	}
}

func TestSessionLookupConstantWork(t *testing.T) {
	for _, size := range []int{1, 20000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, _ := fixture(t, true)
			s.MaxSessions, s.MaxSessionsPerUser = size, size
			for i := 0; i < size; i++ {
				s.insertSession(indexedTestSession(fmt.Sprint(i), "dev"))
			}
			before := s.sessionLookups
			for i := 0; i < 100; i++ {
				w := request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: "0"}, nil)
				if w.Code != http.StatusOK {
					t.Fatal(w.Body.String())
				}
			}
			if got := s.sessionLookups - before; got != 100 {
				t.Fatalf("%d sessions: %d lookups for 100 requests", size, got)
			}
		})
	}
}

func BenchmarkAuthenticateIndexed(b *testing.B) {
	for _, size := range []int{1, 20000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := New(config.Default(), nil, nil, nil, nil, &backend.Principal{User: "dev"}, "test", nil)
			s.MaxSessions, s.MaxSessionsPerUser = size, size
			for i := 0; i < size; i++ {
				s.insertSession(indexedTestSession(fmt.Sprint(i), "dev"))
			}
			r := httptest.NewRequest("GET", "/api/session", nil)
			r.AddCookie(&http.Cookie{Name: "qfm_sid", Value: "0"})
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.authenticate(httptest.NewRecorder(), r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
