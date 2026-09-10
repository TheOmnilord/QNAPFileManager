package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/qtsauth"
)

func assertAuthError(t *testing.T, w *httptest.ResponseRecorder, status int, code, retry string) {
	t.Helper()
	if w.Code != status || !strings.Contains(w.Body.String(), `"code":"`+code+`"`) || w.Header().Get("Retry-After") != retry {
		t.Fatalf("response: status=%d retry=%q body=%s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}

func TestAuthenticationBurstBound(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var active, peak, calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
	}))
	defer endpoint.Close()
	defer unblock()
	s, _ := fixture(t, false)
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	results := make(chan *httptest.ResponseRecorder, 200)
	for i := 0; i < 200; i++ {
		go func(i int) {
			results <- request(s, "GET", "/api/session", nil, map[string]string{"Cookie": fmt.Sprintf("NAS_USER=dev; qtoken=bogus-%d", i)})
		}(i)
	}
	// All excess requests must finish while the six new-login CGI calls remain blocked.
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for i := 0; i < 130; i++ {
		select {
		case w := <-results:
			assertAuthError(t, w, 503, "overloaded", "2")
		case <-deadline.C:
			t.Fatalf("only %d excess requests rejected before releasing QTS", i)
		}
	}
	// 70 retained requests means at most six active plus 64 waiting.
	if calls.Load() > 6 || peak.Load() > 6 {
		t.Fatalf("calls=%d peak=%d", calls.Load(), peak.Load())
	}
	unblock()
	for i := 0; i < 70; i++ {
		select {
		case w := <-results:
			if w.Code == 429 {
				assertAuthError(t, w, 429, "rate_limited", "1")
			} else {
				assertAuthError(t, w, 401, "unauthorized", "")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("admitted request did not finish")
		}
	}
	// Calls already in flight when the last failure is recorded may finish.
	if calls.Load() < authFailureBurst || calls.Load() > authFailureBurst+7 || peak.Load() > 8 {
		t.Fatalf("calls=%d peak=%d", calls.Load(), peak.Load())
	}
}

func TestAuthenticationDeadline(t *testing.T) {
	for _, phase := range []string{"qts", "idmap", "session-lock", "revalidation"} {
		t.Run(phase, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "qts" || phase == "revalidation" {
					<-r.Context().Done()
					return
				}
				fmt.Fprint(w, "<r><authPassed>1</authPassed><username>domainuser</username></r>")
			}))
			defer endpoint.Close()
			s, b := fixture(t, false)
			s.AuthTimeout = 50 * time.Millisecond
			s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
			s.ids = idmap.Open(filepath.Join(b.dir, "absent-passwd"), filepath.Join(b.dir, "absent-group"))
			var helpers atomic.Int32
			s.ids.Exec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				helpers.Add(1)
				if _, ok := ctx.Deadline(); !ok {
					t.Error("identity helper has no deadline")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			var cookie *http.Cookie
			if phase == "revalidation" {
				old := indexedTestSession("existing", "domainuser")
				old.cred = qtsauth.Cred{Kind: qtsauth.KindSID, Token: "slow"}
				old.binding = qtsauth.CacheKey(old.cred)
				old.checked = time.Now().Add(-time.Minute)
				s.insertSession(old)
				cookie = &http.Cookie{Name: "qfm_sid", Value: old.id}
			}
			if phase == "session-lock" {
				old := s.insertSession(indexedTestSession("busy", "domainuser"))
				old.mu.Lock()
				defer old.mu.Unlock()
				cookie = &http.Cookie{Name: "qfm_sid", Value: old.id}
			}
			start := time.Now()
			w := request(s, "GET", "/api/session?sid=slow", cookie, nil)
			assertAuthError(t, w, 504, "auth_timeout", "")
			if time.Since(start) > time.Second {
				t.Fatal("authentication exceeded its deadline")
			}
			if phase == "idmap" && helpers.Load() == 0 {
				t.Fatal("identity resolution was not reached")
			}
			if (phase == "qts" || phase == "idmap") && len(s.sessions) != 0 {
				t.Fatal("timed-out authentication created a session")
			}
			if phase == "revalidation" && (s.sessions["existing"] == nil || s.sessions["existing"].dead.Load()) {
				t.Fatal("temporary authentication timeout destroyed a live session")
			}
		})
	}
}

func TestExistingSessionAuthenticationBurstBound(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sid") == "stuck" {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
	}))
	defer endpoint.Close()
	defer unblock()
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	if err := os.WriteFile(passwd, []byte("dev:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	old := indexedTestSession("stuck", "dev")
	old.cred = qtsauth.Cred{Kind: qtsauth.KindSID, Token: "stuck"}
	old.binding = qtsauth.CacheKey(old.cred)
	old.checked = time.Now().Add(-time.Minute)
	s.insertSession(old)
	cookie := &http.Cookie{Name: "qfm_sid", Value: old.id}
	results := make(chan *httptest.ResponseRecorder, 200)
	go func() { results <- request(s, "GET", "/api/session", cookie, nil) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("revalidation did not start")
	}
	for i := 1; i < 200; i++ {
		go func() { results <- request(s, "GET", "/api/session", cookie, nil) }()
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for i := 0; i < 191; i++ {
		select {
		case w := <-results:
			assertAuthError(t, w, 503, "overloaded", "2")
		case <-deadline.C:
			t.Fatalf("only %d requests rejected while session validation was stuck", i)
		}
	}
	if n := old.authRequests.Load(); n != 9 {
		t.Fatalf("retained %d requests; want one validator and eight followers", n)
	}
	// All eight followers must have reached the waiting gate before checking
	// fairness; merely launching goroutines would miss the original defect.
	until := time.Now().Add(time.Second)
	for len(s.authAdmission.waiters) != maxSessionAuthWaiters && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(s.authAdmission.waiters) != maxSessionAuthWaiters || len(s.authAdmission.slots) != 1 {
		t.Fatalf("followers hold execution slots: active=%d waiting=%d", len(s.authAdmission.slots), len(s.authAdmission.waiters))
	}
	for _, stale := range []bool{false, true} {
		fast := indexedTestSession(fmt.Sprintf("fast-%v", stale), "dev")
		fast.cred = qtsauth.Cred{Kind: qtsauth.KindSID, Token: fast.id}
		fast.binding = qtsauth.CacheKey(fast.cred)
		if stale {
			fast.checked = time.Now().Add(-time.Minute)
		}
		s.insertSession(fast)
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: fast.id}, nil) }()
		select {
		case w := <-done:
			if w.Code != 200 {
				t.Fatalf("other session (stale=%v): %d %s", stale, w.Code, w.Body)
			}
		case <-time.After(time.Second):
			t.Fatalf("other session (stale=%v) blocked behind followers", stale)
		}
	}
	unblock()
	for i := 0; i < 9; i++ {
		select {
		case w := <-results:
			if w.Code != 200 {
				t.Fatalf("admitted follower: %d %s", w.Code, w.Body)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("admitted follower did not finish")
		}
	}
	if old.authRequests.Load() != 0 || len(s.authAdmission.slots) != 0 || len(s.authAdmission.waiters) != 0 {
		t.Fatal("authentication admission leaked")
	}
}

func TestAuthenticationFailureLimiter(t *testing.T) {
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("sid") == "valid" {
			fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
			return
		}
		fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
	}))
	defer endpoint.Close()
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	if err := os.WriteFile(passwd, []byte("dev:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	now := time.Unix(1700000000, 0)
	s.Now = func() time.Time { return now }
	s.verifier.Now = s.Now
	// Prime only the verifier cache: no web session may bypass verification.
	if _, err := s.verifier.Verify(context.Background(), qtsauth.Cred{Kind: qtsauth.KindSID, Token: "valid"}); err != nil {
		t.Fatal(err)
	}
	attempt := func(ip, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/session?sid="+token, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-For", "198.51.100.200, "+ip)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 20; i++ {
		assertAuthError(t, attempt("192.0.2.1", fmt.Sprint(i)), 401, "unauthorized", "")
	}
	for i := 0; i < 30; i++ {
		assertAuthError(t, attempt("192.0.2.1", "0"), 401, "unauthorized", "")
	}
	if calls.Load() != 21 {
		t.Fatalf("repeated credential bypassed negative cache: %d", calls.Load())
	}
	for i := 0; i < 30; i++ {
		assertAuthError(t, attempt("192.0.2.1", fmt.Sprintf("blocked-%d", i)), 429, "rate_limited", "1")
	}
	if w := attempt("192.0.2.1", "valid"); w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"dev"`) {
		t.Fatalf("valid NAT peer blocked: %d %s", w.Code, w.Body)
	}
	old := indexedTestSession("revoked", "dev")
	old.cred = qtsauth.Cred{Kind: qtsauth.KindSID, Token: "revoked"}
	old.binding = qtsauth.CacheKey(old.cred)
	old.checked = time.Now().Add(-time.Minute)
	s.insertSession(old)
	// Established sessions bypass the failure budget and are actually revoked.
	assertAuthError(t, attempt("192.0.2.1", "revoked"), 401, "unauthorized", "")
	if !old.dead.Load() || s.sessions[old.id] != nil {
		t.Fatal("revoked session survived revalidation")
	}
	// A refusal must not poison the verifier's cache for another IP.
	assertAuthError(t, attempt("192.0.2.2", "blocked-0"), 401, "unauthorized", "")
	// Even an exhausted IP gets one uncached recovery attempt each second.
	s.destroy(s.byCredential[qtsauth.CacheKey(qtsauth.Cred{Kind: qtsauth.KindSID, Token: "valid"})].id)
	s.verifier.Invalidate(qtsauth.Cred{Kind: qtsauth.KindSID, Token: "valid"})
	assertAuthError(t, attempt("192.0.2.1", "valid"), 429, "rate_limited", "1")
	now = now.Add(time.Second)
	if w := attempt("192.0.2.1", "valid"); w.Code != 200 {
		t.Fatalf("recovery: %d %s", w.Code, w.Body)
	}
	assertAuthError(t, attempt("192.0.2.1", "still-blocked"), 429, "rate_limited", "1")
	if calls.Load() != 24 {
		t.Fatalf("unexpected upstream calls: %d", calls.Load())
	}

}

func TestSessionFollowersShareTotalWaitingBound(t *testing.T) {
	s, _ := fixture(t, false)
	s.AuthTimeout = 3 * time.Second
	// Occupy every execution slot, independently of session-lock followers.
	for i := 0; i < qtsauth.DefaultMaxConcurrentValidations; i++ {
		if err := s.authAdmission.enter(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		defer s.authAdmission.leave(true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var followers sync.WaitGroup
	defer func() { cancel(); followers.Wait() }()
	for i := 0; i < qtsauth.DefaultMaxValidationWaiters/maxSessionAuthWaiters; i++ {
		old := s.insertSession(indexedTestSession(fmt.Sprintf("locked-%d", i), "dev"))
		old.mu.Lock()
		defer old.mu.Unlock()
		for j := 0; j < maxSessionAuthWaiters; j++ {
			followers.Add(1)
			go func() {
				defer followers.Done()
				r := httptest.NewRequest("GET", "/api/session", nil).WithContext(ctx)
				r.AddCookie(&http.Cookie{Name: "qfm_sid", Value: old.id})
				s.Handler().ServeHTTP(httptest.NewRecorder(), r)
			}()
		}
	}
	until := time.Now().Add(2 * time.Second)
	for len(s.authAdmission.waiters) != qtsauth.DefaultMaxValidationWaiters && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if n := len(s.authAdmission.waiters); n != qtsauth.DefaultMaxValidationWaiters {
		t.Fatalf("followers retained %d waiting positions; want 64", n)
	}
	busy := s.insertSession(indexedTestSession("overflow", "dev"))
	busy.mu.Lock()
	defer busy.mu.Unlock()
	w := request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: busy.id}, nil)
	assertAuthError(t, w, 503, "overloaded", "2")
	// An already-validated session needs neither waiting nor execution capacity.
	s.insertSession(indexedTestSession("ready", "dev"))
	readyRequest := httptest.NewRequest("GET", "/api/session", nil)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer readyCancel()
	readyRequest = readyRequest.WithContext(readyCtx)
	readyRequest.AddCookie(&http.Cookie{Name: "qfm_sid", Value: "ready"})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, readyRequest)
	if w.Code != 200 {
		t.Fatalf("fresh session queued behind validation: %d %s", w.Code, w.Body)
	}
	cancel()
	followers.Wait()
	if len(s.authAdmission.waiters) != 0 {
		t.Fatal("cancelled followers leaked waiting capacity")
	}
}

func TestFailureBucketWindowAndBound(t *testing.T) {
	var l failureLimiter
	now := time.Unix(1700000000, 0)
	for i := 0; i < 30; i++ {
		if err := l.failed("slow", fmt.Sprint(i), now); err != nil {
			t.Fatal("steady rate below 20/minute was blocked", err)
		}
		now = now.Add(4 * time.Second)
	}
	l.clients = nil
	for i := 0; i < maxFailureClients+10; i++ {
		_ = l.failed(fmt.Sprint(i), "key", now)
	}
	if len(l.clients) != maxFailureClients || l.failed("new", "key", now) != errAuthRateLimited {
		t.Fatal("failure table is not bounded")
	}
	if err := l.allow("new", now); err != nil {
		t.Fatal("full table blocked recovery", err)
	}
	if err := l.allow("another", now); err != errAuthRateLimited {
		t.Fatal("full table failed to bound recovery", err)
	}
	if err := l.allow("another", now.Add(time.Second)); err != nil {
		t.Fatal("full table did not recover", err)
	}
	if err := l.failed("new", "key", now.Add(time.Minute)); err != nil {
		t.Fatal("inactive failure entries were not reclaimed", err)
	}
}

func TestDomainCookiesEndToEnd(t *testing.T) {
	for _, value := range []string{`DOMAIN\alice`, `DOMAIN%5Calice`, `"DOMAIN\alice"`, `"DOMAIN%5Calice"`} {
		t.Run(value, func(t *testing.T) {
			var calls atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Query().Get("user") != `DOMAIN\alice` || r.URL.Query().Get("qtoken") != "token+value" {
					t.Errorf("unexpected decoded credential: %v", r.URL.Query())
				}
				fmt.Fprint(w, "<r><authPassed>1</authPassed></r>")
			}))
			defer endpoint.Close()
			s, b := fixture(t, false)
			passwd := filepath.Join(b.dir, "passwd")
			if err := os.WriteFile(passwd, []byte("DOMAIN\\alice:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
				t.Fatal(err)
			}
			s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
			s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
			w := request(s, "GET", "/api/session", nil, map[string]string{"Cookie": "NAS_USER=" + value + `; qtoken="token%2Bvalue"`})
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"DOMAIN\\alice"`) || calls.Load() != 1 {
				t.Fatalf("domain cookie: %d %s calls=%d", w.Code, w.Body, calls.Load())
			}
		})
	}
}

func TestHostileCookiesNeverContactQTS(t *testing.T) {
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "<r><authPassed>1</authPassed></r>")
	}))
	defer endpoint.Close()
	s, _ := fixture(t, false)
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	for _, value := range []string{`-alice`, `%2Dalice`, `..%2Falice`, `alice%00`, `alice%0D%0A`, `alice%3Badmin`, `"alice bob"`, `alice%ZZ`, `"alice`, `alice%252Falice`, `alice%20`} {
		w := request(s, "GET", "/api/fs/roots", nil, map[string]string{"Cookie": "NAS_USER=" + value + "; qtoken=token; NAS_SID=sid"})
		assertAuthError(t, w, 401, "unauthorized", "")
	}
	if calls.Load() != 0 {
		t.Fatalf("hostile names contacted QTS %d times", calls.Load())
	}
}

func TestSessionStoreFullPreservesOtherUsersHTTP(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<r><authPassed>1</authPassed></r>")
	}))
	defer endpoint.Close()
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	if err := os.WriteFile(passwd, []byte("alice:x:1000:100::/:/bin/sh\nbob:x:1001:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, filepath.Join(b.dir, "group"))
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	s.MaxSessions = 2
	var cookies []*http.Cookie
	for _, token := range []string{"a1", "a2"} {
		w := request(s, "GET", "/api/session", nil, map[string]string{"Cookie": "NAS_USER=alice; qtoken=" + token})
		if w.Code != 200 || len(w.Result().Cookies()) != 1 {
			t.Fatalf("alice login: %d %s", w.Code, w.Body)
		}
		cookies = append(cookies, w.Result().Cookies()[0])
	}
	w := request(s, "GET", "/api/session", nil, map[string]string{"Cookie": "NAS_USER=bob; qtoken=b1"})
	assertAuthError(t, w, 503, "session_store_full", "")
	for _, cookie := range cookies {
		w := request(s, "GET", "/api/session", cookie, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"user":"alice"`) {
			t.Fatalf("alice's session lost: %d %s", w.Code, w.Body)
		}
	}
}
