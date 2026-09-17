package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/breakglass"
)

// --- Astra r10 #1: the interval is a wait, never a stale answer --------------

// bgClock is a fake clock a test may move WHILE the door is using it. The tests
// below drive concurrent logins, and a plain time.Time read from those goroutines
// while the test writes it is a data race whatever the timings happen to do.
type bgClock struct {
	mu sync.Mutex
	at time.Time
}

// bgFakeClock installs one on a fixture's gate, which is the clock d.now reads.
func bgFakeClock(s *Server, at time.Time) *bgClock {
	c := &bgClock{at: at}
	s.BreakGlassGate().Now = c.now
	return c
}

func (c *bgClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *bgClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// Round 9 made the login read the interfaces afresh and then rate-limited that
// read to one a second — and the rate limit was a window of exactly the same
// shape as the minute it replaced. A peer the cached set did not know, arriving
// inside that second, skipped the read and was authorised from the cached
// NEGATIVE: the NAS acquires an address, a relay already listening on it
// reconnects half a second later, and the door hands it a root session because it
// asked the interfaces half a second too early. A read this door may not make yet
// is a read it waits for.
func TestAnUnfamiliarAddressWaitsForTheNextReadRatherThanReuseAStaleNegative(t *testing.T) {
	const arrives = "192.168.1.77"
	s, _, _ := bgFixture(t)
	clock := bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	read := withAudit(t, s)
	seam := bgSeamAddresses(s, "192.168.1.10")

	// The read that fills the cache with the answer the relay would inherit.
	bgSignInFrom(t, s, arrives)
	seam.answer([]string{"192.168.1.10", arrives}, nil)

	// Half a second later: too soon for another read, and far too late to trust
	// the last one.
	clock.advance(bgLocalFresh / 2)
	before := seam.count()
	started := time.Now()
	w := bgRequestFrom(s, arrives, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	waited := time.Since(started)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from an address the NAS acquired inside the interval = %d %s, want 401", w.Code, w.Body)
	}
	if got := seam.count() - before; got != 1 {
		t.Errorf("the login made %d discoveries, want the one it waited for", got)
	}
	if waited < bgLocalFresh/4 {
		t.Errorf("the login answered in %v, which is too fast to have waited for a read it was not allowed to make", waited)
	}
	if n := s.bg.Sessions(); n != 1 {
		t.Errorf("%d sessions after the refusal, want only the one issued before the address arrived", n)
	}
	assertLoginShape(t, bgEventWith(t, read(), "peer is this machine"))
}

// And the wait does not turn into an enumeration per login: the caller that may
// not read yet waits for the read it is allowed to make, and every caller that
// arrives while that read is outstanding takes the same answer. One discovery a
// second, whatever the login rate, and not one of them a stale negative.
func TestAFloodOfUnfamiliarLoginsStillBuysOneDiscoveryPerSecond(t *testing.T) {
	const flooders = 5
	const warm = "192.0.2.60"
	const flooder = "192.0.2.61"
	s, _, _ := bgFixture(t)
	clock := bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	seam := bgSeamAddresses(s, "192.168.1.10")

	// One read, by a login that is not part of the flood.
	bgSignInFrom(t, s, warm)
	if got := seam.count(); got != 1 {
		t.Fatalf("the warming login made %d discoveries, want 1", got)
	}

	// Inside the interval, so every one of these needs a read it may not make.
	clock.advance(bgLocalFresh / 2)
	codes := make(chan int, flooders)
	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < flooders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// An empty password is refused after the placement and never touches
			// the ladder, so the flood is as long as the test likes.
			codes <- bgRequestFrom(s, flooder, "POST", bgLoginPath,
				map[string]string{"Content-Type": "application/json"}, `{"password":""}`).Code
		}()
	}
	wg.Wait()
	waited := time.Since(started)
	close(codes)
	for code := range codes {
		if code != http.StatusUnauthorized {
			t.Fatalf("a malformed login = %d, want 401", code)
		}
	}
	if got := seam.count(); got != 2 {
		t.Errorf("%d simultaneous logins made %d discoveries in all, want the warming one and the one they shared", flooders, got)
	}
	if waited < bgLocalFresh/4 {
		t.Errorf("the flood was answered in %v, too fast to have waited for the read it shared", waited)
	}
}

// The wait is only ever the price of an answer that predates the request. A peer
// the cached set already places, against a set read at this very moment, is
// answered from it — the door does not enumerate the machine once per login.
func TestAKnownRemotePeerIsAnsweredFromAFreshSetWithoutWaiting(t *testing.T) {
	const operator = "192.0.2.70"
	s, _, _ := bgFixture(t)
	bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	seam := bgSeamAddresses(s, "192.168.1.10")

	bgSignInFrom(t, s, operator)
	before := seam.count()
	started := time.Now()
	bgSignInFrom(t, s, operator)
	waited := time.Since(started)
	if got := seam.count() - before; got != 0 {
		t.Errorf("a second login against a set read this instant made %d further discoveries, want 0", got)
	}
	if waited > bgLocalFresh/2 {
		t.Errorf("a login that needed no read took %v; nothing here was rate-limited", waited)
	}
}

// The verification queue is the one part of this handler a caller can lengthen at
// will — four bcrypts deep on an ARM NAS is seconds — so a locality decided on the
// way IN is exactly what an attacker would age: acquire the address while the
// queue drains, and the door issues a session it placed before the relay existed.
// The placement is made again on the way out.
func TestTheVerificationQueueCannotAgeALocalityDecision(t *testing.T) {
	const arrives = "192.168.1.88"
	s, _, _ := bgFixture(t)
	clock := bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	read := withAudit(t, s)
	seam := bgSeamAddresses(s, "192.168.1.10")

	// Hold the single verification slot, from another source so the hold does not
	// touch the ladder of the login under test.
	holding := make(chan struct{})
	released := make(chan struct{})
	go func() {
		_, _ = s.bg.gate.Verify(context.Background(), "10.0.0.250", func() breakglass.Outcome {
			close(holding)
			<-released
			return breakglass.OutcomeNeutral
		})
	}()
	<-holding

	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- bgRequestFrom(s, arrives, "POST", bgLoginPath,
			map[string]string{"Content-Type": "application/json"},
			fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	}()
	// The login has made its placement — the peer is somebody else — and is now
	// queued behind the held slot.
	bgWaitFor(t, "the queued login's own placement", func() bool { return seam.count() >= 1 })

	// While it waits, the NAS acquires the address it came from.
	seam.answer([]string{"192.168.1.10", arrives}, nil)
	clock.advance(2 * bgLocalFresh)
	close(released)

	w := <-answered
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login placed before the relay existed = %d %s, want 401", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie && c.Value != "" {
			t.Fatal("a peer that became this machine while it queued was issued a session cookie")
		}
	}
	if n := s.bg.Sessions(); n != 0 {
		t.Fatalf("%d sessions exist after the re-placement refused the login", n)
	}
	assertLoginShape(t, bgEventWith(t, read(), "peer became this machine before issue"))
}

// --- Astra r10 #2: a zone is an interface, and an index is its only spelling --

// Go reports the zone of a link-local peer as whatever the socket gave it: a
// NUMERIC index where the kernel did not name the interface, the name where it
// did. Discovery stored the name. fe80::55%3 and fe80::55%eth0 are then two
// different keys for one address on one interface — the NAS's own — and the
// zoneless fallback is no help, because both sides named a zone. The NAS's own
// address read as somebody else's is a relay with a session.
func TestALinkLocalZoneIsComparedByInterfaceIndex(t *testing.T) {
	s, _, _ := bgFixture(t)
	bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	seam := bgSeamAddresses(s, "fe80::55%eth0", "192.168.1.10")
	seam.interfaces(map[string]int{"eth0": 3, "eth1": 4})

	refused := func(peer, why string) {
		t.Helper()
		if w := bgRequestFrom(s, peer, "POST", bgLoginPath,
			map[string]string{"Content-Type": "application/json"},
			fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
			t.Fatalf("a login from %s (%s) = %d %s, want 401", peer, why, w.Code, w.Body)
		}
	}
	// The same interface, under both of its spellings.
	refused("fe80::55%3", "the machine's own address, zone as an index")
	refused("fe80::55%eth0", "the machine's own address, zone as a name")
	// A zone that names nothing on this machine cannot be compared with the set at
	// all, and an answer this door cannot make is a refusal, not a session.
	refused("fe80::55%nosuch", "a zone this machine does not have")
	refused("fe80::55%0", "an index no interface can carry")

	// And the operator, on another interface entirely, is still the operator: the
	// zone is what tells the two apart and it still does.
	cookie := bgSignInFrom(t, s, "fe80::55%eth1")
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, "fe80::55%eth1", "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a link-local peer on another interface was refused: authenticated %v, csrf %v", authenticated, csrf != "")
	}
}

// --- Astra r10 #3: a warm cache is not a placement ---------------------------

// The login's fresh read failing is NOT the same as the cache being cold or
// stale: the set is warm, it was read successfully a second ago, and every other
// rule in this file would happily answer from it. It must not, because the one
// question the login asks — is this peer one of ours AS OF NOW — is exactly what
// a failed read leaves unanswered. Removing that rule leaves the cold and stale
// cases passing, which is why this test exists.
func TestAFailedFreshReadRefusesTheLoginThoughTheCacheIsWarm(t *testing.T) {
	const operator = "192.0.2.80"
	s, _, _ := bgFixture(t)
	clock := bgFakeClock(s, time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	read := withAudit(t, s)
	seam := bgSeamAddresses(s, "192.168.1.10")

	// A good discovery, and a session issued off it: this peer is known remote.
	bgSignInFrom(t, s, operator)

	// One second later the interfaces stop being readable. The set is warm — its
	// last SUCCESS is a second old, nowhere near bgLocalUnverifiable — and the
	// password offered is the right one.
	seam.answer(nil, fmt.Errorf("the interfaces could not be read"))
	clock.advance(bgLocalFresh)
	w := bgRequestFrom(s, operator, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a correct password placed by a failed read = %d %s, want the uniform 401", w.Code, w.Body)
	}
	if want := "That password was not accepted."; !strings.Contains(w.Body.String(), want) {
		t.Errorf("the refusal reads %s, want the same words a wrong password gets", w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie && c.Value != "" {
			t.Fatal("a login the door could not place afresh was issued a session cookie")
		}
	}
	if n := s.bg.Sessions(); n != 1 {
		t.Fatalf("%d sessions, want only the one issued while discovery still worked", n)
	}
	// Nothing here is a verdict about a password.
	if failures := s.BreakGlassGate().Failures(operator); failures != 0 {
		t.Errorf("a login the door could not place advanced the ladder to %d", failures)
	}
	assertLoginShape(t, bgEventWith(t, read(), "local addresses unknown"))
}
