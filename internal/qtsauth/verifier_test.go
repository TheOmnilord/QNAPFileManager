package qtsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer serves body and counts requests.
func countingServer(t *testing.T, body string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func newTestVerifier(srv *httptest.Server) *Verifier {
	return NewVerifier(testClient(srv, 2*time.Second))
}

func TestVerifyQToken(t *testing.T) {
	srv, _ := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)

	sess, err := v.Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "t"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.User != "admin" || !sess.IsAdmin() || sess.Kind != KindQToken {
		t.Fatalf("session = %+v", sess)
	}
	if sess.ValidatedAt.IsZero() {
		t.Error("ValidatedAt not set")
	}
}

func TestVerifyQTokenWithoutUsernameInResponse(t *testing.T) {
	// The qtoken call validates the (user, token) pair, so the cookie name is
	// authoritative even when the response omits username.
	srv, _ := countingServer(t, fixtureNoUsername)
	sess, err := newTestVerifier(srv).Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "t"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q, want admin", sess.User)
	}
}

func TestVerifySIDFailsClosedWithoutUsername(t *testing.T) {
	// identity-and-hero-plan.md §1.3: the sid call validates only the token, so
	// without a username in the response the session cannot be bound.
	srv, _ := countingServer(t, fixtureNoUsername)
	v := newTestVerifier(srv)

	_, err := v.Verify(context.Background(), Cred{Kind: KindSID, User: "admin", Token: "s"})
	if !errors.Is(err, ErrSIDUnbound) {
		t.Fatalf("error = %v, want ErrSIDUnbound", err)
	}

	// Opt-in escape hatch, for a deliberate NAS-side experiment only.
	v2 := newTestVerifier(srv)
	v2.AllowSIDWithoutUsername = true
	sess, err := v2.Verify(context.Background(), Cred{Kind: KindSID, User: "admin", Token: "s"})
	if err != nil {
		t.Fatalf("Verify with AllowSIDWithoutUsername: %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q", sess.User)
	}

	// Even then, a sid with no username anywhere is refused.
	if _, err := v2.Verify(context.Background(), Cred{Kind: KindSID, Token: "s2"}); !errors.Is(err, ErrSIDUnbound) {
		t.Fatalf("error = %v, want ErrSIDUnbound", err)
	}
}

func TestVerifySIDTakesUsernameFromResponse(t *testing.T) {
	srv, _ := countingServer(t, fixtureUser) // says "sveinung"
	sess, err := newTestVerifier(srv).Verify(context.Background(), Cred{Kind: KindSID, Token: "s"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.User != "sveinung" {
		t.Errorf("User = %q, want sveinung", sess.User)
	}
	if sess.IsAdmin() {
		t.Error("IsAdmin true for isAdmin=0")
	}
}

func TestVerifyUserMismatch(t *testing.T) {
	// The privilege-escalation case: a non-admin sets NAS_USER=admin and
	// presents their own NAS_SID. The response names the real user.
	srv, _ := countingServer(t, fixtureUser) // says "sveinung"
	v := newTestVerifier(srv)

	_, err := v.Verify(context.Background(), Cred{Kind: KindSID, User: "admin", Token: "s"})
	if !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("error = %v, want ErrUserMismatch", err)
	}
	// Same rule on the qtoken path.
	_, err = v.Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "t"})
	if !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("qtoken error = %v, want ErrUserMismatch", err)
	}
	// Case differences are not a mismatch.
	sess, err := v.Verify(context.Background(), Cred{Kind: KindQToken, User: "SVEINUNG", Token: "t"})
	if err != nil {
		t.Fatalf("case-insensitive compare: %v", err)
	}
	if sess.User != "sveinung" {
		t.Errorf("User = %q, want the response's spelling", sess.User)
	}
}

func TestVerifyNotAuthenticated(t *testing.T) {
	srv, _ := countingServer(t, fixtureDenied)
	_, err := newTestVerifier(srv).Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "t"})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("error = %v, want ErrNotAuthenticated", err)
	}
}

func TestVerifyRequireAdminSignal(t *testing.T) {
	srv, _ := countingServer(t, fixtureNoIsAdmin)

	// Default: a missing isAdmin element yields a session with Admin == nil.
	sess, err := newTestVerifier(srv).Verify(context.Background(), Cred{Kind: KindQToken, User: "bob", Token: "t"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.Admin != nil {
		t.Errorf("Admin = %v, want nil", *sess.Admin)
	}
	if sess.IsAdmin() {
		t.Error("IsAdmin() must be false when the signal is absent")
	}

	v := newTestVerifier(srv)
	v.RequireAdminSignal = true
	if _, err := v.Verify(context.Background(), Cred{Kind: KindQToken, User: "bob", Token: "t2"}); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse", err)
	}
}

func TestVerifyBadKindAndMalformedInput(t *testing.T) {
	srv, hits := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)

	for _, c := range []Cred{
		{Kind: "magic", User: "admin", Token: "t"},
		{Kind: KindQToken, Token: "t"},              // no user
		{Kind: KindQToken, User: "admin"},           // no token
		{Kind: KindQToken, User: "a b", Token: "t"}, // malformed user
	} {
		if _, err := v.Verify(context.Background(), c); !errors.Is(err, ErrNotAuthenticated) {
			t.Errorf("Verify(%+v) error = %v, want ErrNotAuthenticated", c, err)
		}
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("server hit %d times; malformed credentials must be rejected locally", n)
	}
}

func TestPositiveCacheAndInvalidate(t *testing.T) {
	srv, hits := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)
	cred := Cred{Kind: KindQToken, User: "admin", Token: "t"}

	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), cred); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("server hits = %d, want 1 (60 s positive cache)", n)
	}

	// A different credential is a different cache key.
	if _, err := v.Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "other"}); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 2 {
		t.Fatalf("server hits = %d, want 2", n)
	}

	// Invalidate forces revalidation (what every write path must do).
	v.Invalidate(cred)
	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 3 {
		t.Fatalf("server hits = %d after Invalidate, want 3", n)
	}

	v.InvalidateAll()
	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 4 {
		t.Fatalf("server hits = %d after InvalidateAll, want 4", n)
	}
}

func TestCacheExpiry(t *testing.T) {
	srv, hits := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)
	now := time.Unix(1_700_000_000, 0)
	v.Now = func() time.Time { return now }
	cred := Cred{Kind: KindQToken, User: "admin", Token: "t"}

	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	now = now.Add(59 * time.Second)
	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("hits = %d at t+59s, want 1", n)
	}
	now = now.Add(2 * time.Second) // past the 60 s TTL
	if _, err := v.Verify(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 2 {
		t.Fatalf("hits = %d at t+61s, want 2", n)
	}
}

func TestNegativeCache(t *testing.T) {
	srv, hits := countingServer(t, fixtureDenied)
	v := newTestVerifier(srv)
	now := time.Unix(1_700_000_000, 0)
	v.Now = func() time.Time { return now }
	cred := Cred{Kind: KindQToken, User: "admin", Token: "bad"}

	for i := 0; i < 4; i++ {
		if _, err := v.Verify(context.Background(), cred); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("error = %v, want ErrNotAuthenticated", err)
		}
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("hits = %d, want 1 (10 s negative cache)", n)
	}

	now = now.Add(9 * time.Second)
	if _, err := v.Verify(context.Background(), cred); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("hits = %d at t+9s, want 1", n)
	}

	// Negative entries expire sooner than positive ones.
	now = now.Add(2 * time.Second)
	if _, err := v.Verify(context.Background(), cred); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(hits); n != 2 {
		t.Fatalf("hits = %d at t+11s, want 2", n)
	}
}

func TestSingleFlight(t *testing.T) {
	const concurrency = 20

	var hits int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold every in-flight request open
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(fixtureAdmin))
	}))
	defer srv.Close()

	v := newTestVerifier(srv)
	cred := Cred{Kind: KindQToken, User: "admin", Token: "t"}

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]Session, concurrency)
	errs := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = v.Verify(context.Background(), cred)
		}(i)
	}
	close(start)

	// Let the goroutines pile up on the single in-flight call before releasing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&hits) == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("server hits = %d for %d concurrent Verify calls, want 1", n, concurrency)
	}
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if results[i].User != "admin" || !results[i].IsAdmin() {
			t.Fatalf("goroutine %d got %+v", i, results[i])
		}
	}
}

func TestVerifyUnreachable(t *testing.T) {
	srv, _ := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)
	srv.Close()

	if _, err := v.Verify(context.Background(), Cred{Kind: KindQToken, User: "admin", Token: "t"}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if _, err := (&Verifier{}).Verify(context.Background(), Cred{Kind: KindQToken, User: "a", Token: "t"}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("nil client error = %v, want ErrUnreachable", err)
	}
}

func TestCacheKeySeparatesFields(t *testing.T) {
	a := CacheKey(Cred{Kind: KindQToken, User: "ab", Token: "c"})
	b := CacheKey(Cred{Kind: KindQToken, User: "a", Token: "bc"})
	if a == b {
		t.Error("cache key collides across the user/token boundary")
	}
	if CacheKey(Cred{Kind: KindSID, User: "a", Token: "t"}) == CacheKey(Cred{Kind: KindQToken, User: "a", Token: "t"}) {
		t.Error("cache key ignores the credential kind")
	}
	if len(a) != 64 {
		t.Errorf("cache key length = %d, want 64 hex characters", len(a))
	}
}

func TestVerifyFromRequestEndToEnd(t *testing.T) {
	srv, hits := countingServer(t, fixtureAdmin)
	v := newTestVerifier(srv)

	r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	r.AddCookie(&http.Cookie{Name: CookieUser, Value: "admin"})
	r.AddCookie(&http.Cookie{Name: CookieQToken, Value: "qt"})

	cred, ok := FromRequest(r)
	if !ok {
		t.Fatal("FromRequest found no credential")
	}
	sess, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.User != "admin" || !sess.IsAdmin() {
		t.Fatalf("session = %+v", sess)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Fatalf("hits = %d", n)
	}
}
