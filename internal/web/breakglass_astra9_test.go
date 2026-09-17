package web

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
)

// --- Astra r9 #1 and #4: where the peer is, and when that is decided ---------

// bgAddressSeam is the discovery the door is given instead of the machine's real
// interfaces: it answers with whatever the test last set, and — the half round 9
// #4 needs — it counts how often it was asked.
type bgAddressSeam struct {
	mu    sync.Mutex
	addrs []string
	err   error
	calls int
}

// bgSeamAddresses installs that seam with an initial answer. Like
// bgOwnAddresses, the addresses are the canonical strings bgInterfaceAddrs hands
// back: the prefix length is already off, and a link-local address carries the
// interface it was found on as its zone.
func bgSeamAddresses(s *Server, addrs ...string) *bgAddressSeam {
	seam := &bgAddressSeam{addrs: addrs}
	s.bg.local.setLookup(seam.lookup)
	return seam
}

func (a *bgAddressSeam) lookup() ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	return append([]string(nil), a.addrs...), nil
}

// answer replaces what the machine is said to have. A nil error is a working
// enumeration; a non-nil one is the interfaces refusing to be read.
func (a *bgAddressSeam) answer(addrs []string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addrs, a.err = addrs, err
}

func (a *bgAddressSeam) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// A discovery that has NEVER succeeded used to fail open, and it failed open in
// the worst possible direction: the set was nil, so every address on the LAN —
// including the NAS's own, and therefore including a relay's — was somebody else
// and got a root session. A door that cannot say where a peer is refuses it.
func TestADoorThatCannotPlaceAPeerRefusesTheLogin(t *testing.T) {
	const operator = "192.168.1.55"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	seam := bgSeamAddresses(s)
	seam.answer(nil, fmt.Errorf("the interfaces could not be read"))

	w := bgRequestFrom(s, operator, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login the door cannot place = %d %s, want the uniform 401", w.Code, w.Body)
	}
	if want := "That password was not accepted."; !strings.Contains(w.Body.String(), want) {
		t.Errorf("the refusal reads %s, want the same words a wrong password gets", w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bgCookie && c.Value != "" {
			t.Fatal("a peer the door could not place was issued a session cookie")
		}
	}
	if n := s.bg.Sessions(); n != 0 {
		t.Fatalf("%d sessions exist after a refusal the door could not even reason about", n)
	}
	// Nothing here is a verdict about a password, so the ladder must not move: an
	// operator whose NAS cannot read its own interfaces would otherwise lock
	// themselves out of the emergency door in five attempts.
	if failures := s.BreakGlassGate().Failures(operator); failures != 0 {
		t.Errorf("an unplaceable login advanced the lockout ladder to %d", failures)
	}

	// And the moment the interfaces can be read, the same peer is the operator
	// again: this is a refusal to guess, not a new rule about the LAN.
	seam.answer([]string{"192.168.1.10"}, nil)
	now = now.Add(bgLocalFresh)
	cookie := bgSignInFrom(t, s, operator)
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("the operator was still refused after a successful discovery: authenticated %v, csrf %v", authenticated, csrf != "")
	}
	// The audit line says which refusal it was, because the answer on the wire
	// deliberately does not.
	assertLoginShape(t, bgEventWith(t, read(), "local addresses unknown"))
}

// A set that succeeded once and has been failing ever since is not an answer that
// happens to be old: it is an answer nobody has been able to check against a
// machine that may have been given addresses in the meantime. Five refreshes is
// where the door stops believing it.
func TestAnAddressSetNobodyCanCheckStopsBeingAnAnswer(t *testing.T) {
	const own = "192.168.1.10"
	const operator = "192.168.1.55"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read := withAudit(t, s)
	seam := bgSeamAddresses(s, own)

	cookie := bgSignInFrom(t, s, operator)
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Fatal("the operator was refused their own session while discovery was working")
	}
	seam.answer(nil, fmt.Errorf("the interfaces could not be read"))

	// Four refreshes of failure is a blip, and the last good answer stands: the
	// emergency door is used when the machine is unwell, and throwing the operator
	// out over one unlucky enumeration is the failure r8 refused to introduce.
	now = now.Add(bgLocalUnverifiable - bgLocalPeerRefresh)
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Fatal("a few failed refreshes threw the operator out of their own session")
	}
	// Past the fifth, the set is no longer evidence of anything. The peer is one
	// the cache holds as REMOTE, which is exactly the case a stale set gets wrong.
	now = now.Add(2 * bgLocalPeerRefresh)
	if w := bgRequestFrom(s, operator, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a login against an unverifiable set = %d %s, want 401", w.Code, w.Body)
	}
	// And the session issued before the set went stale stops resolving too: a
	// cookie is only as good as the door's ability to say who is presenting it.
	if authenticated, handed := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); authenticated || handed != "" {
		t.Fatalf("an unverifiable set still redeemed a session: authenticated %v, csrf handed over %v", authenticated, handed != "")
	}

	// Recovery is the login's own fresh read: one successful discovery and the
	// door is back to its ordinary rule, session and all.
	seam.answer([]string{own}, nil)
	now = now.Add(bgLocalFresh)
	bgSignInFrom(t, s, operator)
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Error("the operator's original session did not come back once the addresses could be read again")
	}
	assertLoginShape(t, bgEventWith(t, read(), "local addresses unknown"))
}

// The one peer a `serve -dev` door can ever have is loopback, because that door is
// bound to loopback and nothing else. Refusing it for want of an address set
// would make the development door unusable on precisely the machine where the
// enumeration is least likely to look like a NAS's.
func TestADevelopmentDoorOpensWithNoAddressesAtAll(t *testing.T) {
	s, _, configPath := bgFixture(t)
	s.Dev = true
	s.EnableBreakGlass(configPath)
	s.BreakGlassGate().Floor = -1
	seam := bgSeamAddresses(s)
	seam.answer(nil, fmt.Errorf("the interfaces could not be read"))

	cookie := bgSignInFrom(t, s, "127.0.0.1")
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, "127.0.0.1", "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a development door refused its own loopback session: authenticated %v, csrf %v", authenticated, csrf != "")
	}
	// The relaxation is loopback's alone, and an unreadable set does not widen it:
	// anything else is a peer the door cannot place, and is refused.
	if w := bgRequestFrom(s, "192.168.1.10", "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a development door with no address set accepted a LAN login: %d %s", w.Code, w.Body)
	}
}

// The cached minute was itself a relay window. DHCP, an IPv6 advertisement or an
// operator's own hand gives the NAS an address, a forwarder already listening on
// it is reached from the LAN within seconds, and for the rest of that minute the
// door treats the NAS's newest address as somebody else and hands it a root
// session. Locality is established when the session is issued.
func TestANewAddressIsRefusedWithoutWaitingForTheTTL(t *testing.T) {
	const arrives = "192.168.1.77"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	seam := bgSeamAddresses(s, "192.168.1.10")

	// Before it arrives, that address is somebody else and signs in; this is what
	// fills the cache with the answer the relay would otherwise inherit.
	bgSignInFrom(t, s, arrives)
	seam.answer([]string{"192.168.1.10", arrives}, nil)

	// A second later — far inside the TTL, which has not moved at all.
	now = now.Add(bgLocalFresh)
	before := seam.count()
	w := bgRequestFrom(s, arrives, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from an address the NAS acquired inside the TTL = %d %s, want 401", w.Code, w.Body)
	}
	if got := seam.count() - before; got != 1 {
		t.Errorf("the login made %d discoveries, want the one fresh read that is the whole rule", got)
	}
	if n := s.bg.Sessions(); n != 1 {
		t.Errorf("%d sessions after the refusal, want only the one issued before the address arrived", n)
	}
}

// And the fresh read is bounded by the CLOCK, not by the request rate: a login
// flood must not turn into an enumeration flood.
func TestALoginFloodBuysOneDiscoveryPerSecond(t *testing.T) {
	const attempts = 6
	const operator = "192.0.2.77"
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	seam := bgSeamAddresses(s, "192.168.1.10")

	// A malformed body is refused after the locality check has run and never
	// touches the lockout ladder, so the flood is as long as the test likes.
	flood := func() {
		if w := bgRequestFrom(s, operator, "POST", bgLoginPath,
			map[string]string{"Content-Type": "application/json"}, `{"password":""}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("a malformed login = %d %s, want 401", w.Code, w.Body)
		}
	}
	for i := 0; i < attempts; i++ {
		flood()
	}
	if got := seam.count(); got != 1 {
		t.Errorf("%d attempts in one instant made %d discoveries, want 1", attempts, got)
	}
	now = now.Add(bgLocalFresh)
	flood()
	if got := seam.count(); got != 2 {
		t.Errorf("%d discoveries after the second elapsed, want exactly one more", got)
	}
	// The flood changed nothing for the peer itself: it is still the operator.
	cookie := bgSignInFrom(t, s, operator)
	if authenticated, _ := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated {
		t.Error("a genuine peer was refused after its own flood of malformed bodies")
	}
}

// --- Astra r9 #5: a link-local address is only an address with its zone ------

// fe80::55 is not one host. It is one host per interface, and the zone is what
// says which — so cutting the zone off before the comparison matched an operator
// at fe80::55 on their own LAN against the NAS's fe80::55 on eth1 and refused
// them forever, with no way round it short of changing the address.
func TestALinkLocalPeerIsMatchedWithItsZone(t *testing.T) {
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	bgSeamAddresses(s, "fe80::55%eth1", "192.168.1.10")

	// The operator's machine, reached over eth0. Same address, different host.
	const operator = "fe80::55%eth0"
	cookie := bgSignInFrom(t, s, operator)
	if authenticated, csrf := bgSessionAnswer(t, bgRequestFrom(s, operator, "GET", "/api/session", bgWithCookie(cookie), "")); !authenticated || csrf == "" {
		t.Fatalf("a link-local peer on another interface was refused: authenticated %v, csrf %v", authenticated, csrf != "")
	}
	// The NAS's own copy, on the NAS's own interface, is still the relay.
	now = now.Add(bgLocalFresh)
	if w := bgRequestFrom(s, "fe80::55%eth1", "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"},
		fmt.Sprintf(`{"password":%q}`, bgTestPassword)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a login from the machine's own link-local address = %d %s, want 401", w.Code, w.Body)
	}
}

// --- Astra r9 #6: a generic refusal cannot hide a replay ---------------------

// Round 8 made the peer mismatch the one sessionless line QuLog hears. The shared
// per-source window could swallow it whole: one cookie-less POST — free, and
// anyone on the LAN can send it — opens the source's window, the replay that
// follows a moment later is suppressed into the generic count, and the summary
// that eventually reports the burst says "unauthorized" and is Quiet. Neither the
// file nor QuLog names the replay. The mismatch gets a window of its own.
func TestAGenericRefusalCannotHideAReplay(t *testing.T) {
	const replays = 6
	s, _, _ := bgFixture(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	s.BreakGlassGate().Now = func() time.Time { return now }
	read, mirrored := bgWithMirroredAudit(t, s)
	const operator = "192.0.2.50"
	const replayer = "192.0.2.51"

	cookie := bgSignInFrom(t, s, operator)
	// The free refusal first, which is what opens the source's ordinary window.
	bgSessionlessMutation(t, s, replayer)
	headers := bgWithCookie(cookie)
	headers["Content-Type"] = "application/json"
	for i := 0; i < replays; i++ {
		if w := bgRequestFrom(s, replayer, "POST", "/api/fs/mkdir", headers, `{"dir":"/","name":"replayed"}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("replay %d = %d %s, want 401", i+1, w.Code, w.Body)
		}
	}
	// The replays are counted in their own window, not in the one the cookie-less
	// POST opened.
	_, suppressed, _, present := bgTracked(s, bgMismatchKey(replayer))
	if !present {
		t.Fatal("the replays were not tracked as mismatches at all")
	}
	if suppressed != replays-1 {
		t.Errorf("%d replays pended %d suppressed mismatches, want %d", replays, suppressed, replays-1)
	}
	if _, generic, _, _ := bgTracked(s, replayer); generic != 0 {
		t.Errorf("%d replays were counted into the source's generic window as well", generic)
	}

	// The window closes and the source comes back, which is when a burst is
	// summarised. The summary must be the mismatch's own, not the generic one.
	now = now.Add(refusalWindow)
	if w := bgRequestFrom(s, replayer, "POST", bgLoginPath,
		map[string]string{"Content-Type": "application/json"}, `{"password":""}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("the returning source's login = %d %s, want 401", w.Code, w.Body)
	}

	events := read()
	var lines []audit.Event
	for _, ev := range events {
		if ev.Code == bgPeerMismatch {
			lines = append(lines, ev)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("%d lines name the replay, want the first one and its summary: %+v", len(lines), lines)
	}
	var summary *audit.Event
	for i, ev := range lines {
		if strings.Contains(ev.Detail, "further refusals suppressed") {
			summary = &lines[i]
		}
	}
	if summary == nil {
		t.Fatalf("no summary among the mismatch lines: %+v", lines)
	}
	if want := fmt.Sprintf("%d further refusals suppressed", replays-1); !strings.Contains(summary.Detail, want) {
		t.Errorf("the summary reads %q, want it to carry %q", summary.Detail, want)
	}
	assertSessionlessShape(t, *summary)
	// And both reach QuLog, because both are a root session's cookie turning up
	// somewhere else. The throttle is what bounds that, and it is unchanged: one
	// line per source per window, whatever else the source is doing.
	var offered int
	for _, msg := range mirrored() {
		if strings.Contains(msg, bgPeerMismatch) {
			offered++
		}
	}
	if offered != 2 {
		t.Errorf("%d mismatch lines reached QuLog, want the line and its summary", offered)
	}
}
