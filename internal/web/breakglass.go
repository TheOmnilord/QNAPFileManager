package web

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
)

// The break-glass door. One door per listener, and they never mix (M4 contract
// §2.1): the main listener serves the QTS session door, this one serves only
// the local bcrypt account. A qfm_sid cookie presented here is ignored; a
// __Host-qfm_bg cookie presented on the main listener is ignored;
// qtsauth.FromRequest is never called from this path and the local hash is
// never consulted from the other one.
const (
	// bgCookie carries the __Host- prefix deliberately. It is not cosmetic: the
	// browser refuses the cookie outright if anything ever tries to set it with
	// a Domain or a narrower Path, which is exactly the confusion a second
	// listener on the same host invites (contract §13.2).
	bgCookie = "__Host-qfm_bg"

	// Caps (contract §13.6 / §14). A separate store, so these are separate
	// numbers from the main listener's: this door is for one operator with one
	// broken NAS, not for a desktop full of users.
	bgMaxSessions = 8
	bgIdle        = 15 * time.Minute
	bgLifetime    = 4 * time.Hour

	// bgLoginBody bounds the login body; a password is at most 1 KiB and the
	// JSON around it is a handful of bytes.
	bgLoginBody = 4 << 10
	// bgLoginRead bounds how long that 4 KiB may take to arrive, and
	// bgDoorTimeout is the FLOOR of the whole login or logout request deadline.
	// The door routes never reach dispatch, which is where the main listener's
	// 15 s handler context is armed, so they arm their own — but a fixed 15 s is
	// too short when InFlight requests are queued behind a cost-15 bcrypt on a
	// slow ARM core, so the real deadline is the larger of this and the
	// measured queue (breakGlassDoor.doorTimeout).
	bgLoginRead   = 10 * time.Second
	bgDoorTimeout = 15 * time.Second

	bgLoginPath  = "/api/breakglass/login"
	bgLogoutPath = "/api/breakglass/logout"
)

// bgRoutes is this listener's OWN route table, kept separate from routes so
// /api/breakglass/login simply does not exist on the main listener (contract
// §16.1). Everything else below the door is the shared table: there is exactly
// one API surface, and the listener decides only who you are.
var bgRoutes = map[string][]string{
	bgLoginPath:  {"POST"},
	bgLogoutPath: {"POST"},
}

// breakGlassKey marks a request as having arrived on the break-glass listener.
// It is set by the outermost handler, before the security middleware, so the
// CSP and every door decision below see it.
type breakGlassKey struct{}

func breakGlassRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(breakGlassKey{}).(bool)
	return v
}

// doorOf names the door a request arrived through, for the audit stamp. It is
// the LISTENER's door, which is why an unauthenticated denial can carry it too.
func doorOf(r *http.Request) string {
	if breakGlassRequest(r) {
		return audit.DoorLocal
	}
	return audit.DoorQTS
}

// bgSession is one live break-glass session. It is a distinct type from
// session, held in a distinct map behind a distinct mutex, because a shared
// store with a door field would be one forgotten comparison away from a QTS
// cookie redeeming a break-glass session (contract §13.6).
type bgSession struct {
	id, csrf string
	who      backend.Principal
	issued   time.Time
	seen     time.Time
	// peer is the address the session was issued to, canonicalised (Astra r6
	// #1). A cookie presented from any other address is not this session's:
	// browser cookies are scoped to the HOST, not to the port, and the __Host-
	// prefix does not change that — it constrains what may SET the cookie, not
	// who it is sent to. So every browser-trusted HTTPS service on the NAS
	// hostname, QTS on 443 included, receives this root session's cookie and
	// could replay it against 8771. Pinning turns that replay into a 401,
	// because it arrives from the NAS's own address rather than the operator's.
	peer string
	// updated is the auth.local.updated stamp this session was issued under.
	// A mismatch on any later request destroys it, which is what makes
	// `break-glass disable` an eviction rather than a suggestion (§4.4).
	updated string
	order   *list.Element
}

// snapshot is the immutable per-request view handed to the shared dispatch. A
// break-glass session is an administrator session — that is what the account is
// for — so admin is true and who.Root is true, and it keys to the same root
// worker as any other admin session. It is NOT a QTS user, so nothing derived
// from it may name one: door is what the CreateAs decision reads.
func (b *bgSession) snapshot() *session {
	return &session{id: b.id, csrf: b.csrf, who: b.who, admin: true, door: audit.DoorLocal}
}

// breakGlassDoor is the listener's state: the credential source, the bounds,
// and the session store. Nil on a Server that does not serve the listener.
type breakGlassDoor struct {
	srv  *Server
	gate *breakglass.Gate
	cred *localCred
	// local is the set of addresses this machine answers on, which no session is
	// ever issued to (Astra r8 #1). Read at arm time and refreshed on a TTL.
	local *bgLocalAddrs

	mu       sync.Mutex
	sessions map[string]*bgSession
	order    list.List
	// refusals throttles the audit line a refused attempt writes, per source.
	// Guarded by mu; bounded by breakglass.MaxSources, exactly as the bucket is.
	refusals map[string]*refusalState
	// dropped counts refusals that could not even be tracked because the table
	// was full, and droppedAt rate-bounds the line that reports them. Both are
	// keyed BY EVENT SHAPE (Astra r2 #6): a refused login and a sessionless
	// mutation denial are different events, and one shared counter would have to
	// pick a single shape for a mixed flood — which for the sessionless half
	// means reporting it as an authenticated root administrator. Two counters is
	// the smaller change of the two on offer and it cannot misreport at all.
	// Guarded by mu.
	dropped   [refusalShapes]int
	droppedAt [refusalShapes]time.Time

	// bcryptTime is one verification's measured cost on this machine, taken
	// once in EnableBreakGlass and never written again — so doorTimeout reads
	// it from request goroutines without a lock. bcryptCost is the cost it was
	// measured at: the one the STORED HASH carries, not the config snapshot's.
	bcryptTime time.Duration
	bcryptCost int
	// dev carries `serve -dev` through to the settings route's config reload,
	// so a daemon started on a development configuration can still write it
	// back (round-2 P3-6).
	dev bool
}

// EnableBreakGlass arms this Server's break-glass door. configPath is where the
// credential is re-read from; an empty path pins the credential to the loaded
// config, which is the fixture and dev-loop case. It must be called before the
// server serves anything.
func (s *Server) EnableBreakGlass(configPath string) {
	// s.Dev is carried into the reload, not only into the settings route: a
	// daemon started with -dev must go on being able to read the very file it
	// started from (Astra r1 #15).
	cred := &localCred{path: configPath, pinned: s.cfg.Auth.Local, dev: s.Dev}
	// The cost is read from the hash that is actually IN FORCE, not from the
	// snapshot this process started with (round-3 P3). A daemon that started
	// with no password and armed the door later would otherwise measure the
	// default cost 11 while serving a cost-15 hash, and size its request
	// deadline to a queue four times faster than the real one — turning a
	// correct password that waited its turn into "not accepted", which is the
	// exact failure §5 exists to prevent.
	live, err := cred.get()
	if err != nil {
		// Not ignored (Astra r1 #15). The door still arms — the listener may be
		// the operator's only way back in, and the credential is re-read per
		// attempt, so a file that becomes readable again simply starts working —
		// but a credential store that could not be read at arm time is the sort
		// of thing an operator must find in the log rather than infer from every
		// password being refused.
		s.logger.Printf("break-glass: the credential could not be read at start-up (%v); the door treats it as absent until the file can be read", err)
		live = config.Local{}
	}
	cost := live.LocalCost()
	if c, err := breakglass.HashCost(live.Hash); err == nil {
		cost = c
	}
	local := &bgLocalAddrs{}
	// Read once before anything serves (Astra r8 #1). A door that armed with an
	// unreadable interface list would treat its own LAN address as somebody else's
	// until the first refresh, which is precisely the window a relay needs — and
	// now refuses every login it cannot place instead (Astra r9 #1), which an
	// operator must find in the log rather than infer from a door that will not
	// open.
	if note := local.prime(time.Now()); note != "" {
		s.logger.Printf("%s", note)
	}
	s.bg = &breakGlassDoor{
		srv:      s,
		gate:     &breakglass.Gate{},
		cred:     cred,
		local:    local,
		sessions: make(map[string]*bgSession),
		// One bcrypt, once, before anything serves: the door's request deadline
		// has to be longer than its own queue can legitimately take, and on the
		// ARM core of a two-bay NAS at cost 15 that is seconds, not
		// milliseconds (round-2 P2-7).
		bcryptTime: breakglass.MeasureCost(cost),
		bcryptCost: cost,
		dev:        s.Dev,
	}
	// The stamp moving under a live daemon is §6.2's last unaudited event: the
	// CLI writes nothing by design, so this is the only place a rotation can be
	// recorded at all (Astra r1 #12). Path-free and bounded, like every other
	// break-glass detail.
	cred.onChange = func(old, current string) {
		s.bg.audit(nil, "breakglass-credential", "ok", "",
			fmt.Sprintf("door=local the credential changed, stamp %s -> %s", shortStamp(old), shortStamp(current)))
	}
}

// shortStamp bounds an `updated` stamp for an audit detail. Validation already
// requires RFC3339, but the detail budget must not depend on validation having
// run on the file this process happens to be reading.
func shortStamp(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// BreakGlassGate exposes the door's bounds so a caller can inject a clock or
// shorten the failure floor before serving. It is nil until EnableBreakGlass.
func (s *Server) BreakGlassGate() *breakglass.Gate {
	if s.bg == nil {
		return nil
	}
	return s.bg.gate
}

// BreakGlassHandler is the handler the break-glass listener serves. It is the
// SAME mux, guard, readOnly, ladder, audit and worker pool as the main one; the
// only difference is the door. The marker is outermost so the security
// middleware sees it.
func (s *Server) BreakGlassHandler() http.Handler {
	h := s.security(collapseDoubleSlashes(http.HandlerFunc(s.serve)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), breakGlassKey{}, true))
		// A request that DECLARED a body starts out unconsumed. The tracker is
		// cleared the moment a handler reads that body to EOF; whatever is still
		// unconsumed when the response header is written is what net/http would
		// have to drain.
		st := &bodyState{unconsumed: r.ContentLength != 0 || len(r.TransferEncoding) > 0}
		if st.unconsumed {
			r.Body = trackedBody{ReadCloser: r.Body, st: st}
		}
		h.ServeHTTP(&bgRefusal{ResponseWriter: w, st: st}, r)
	})
}

// bgDrainDeadline bounds the body drain net/http performs behind a response
// written without reading it.
const bgDrainDeadline = 5 * time.Second

// bgReadDeadlineCap clamps every body-read deadline armed through the refusal
// wrapper, and is ZERO in production, which means no clamp at all: the handler's
// own bound — jsonBodyRead on the JSON routes, bgLoginRead at the door — is what
// applies, unchanged.
//
// It exists for one test (Astra r2 #7). The unfinished-drain behaviour is only
// real on a socket: httptest's recorder carries no read deadline, so a test
// driving the handler directly asserts nothing about it and passes against code
// that never armed one. A socket-level test has to hold a real connection open
// until the deadline fires, and the production bound for that is fifteen
// seconds — long enough that the test would be one nobody runs. The seam is a
// package-level var rather than a parameter because the deadline is armed in
// decodeBody, which this door does not own.
var bgReadDeadlineCap time.Duration

// bodyState says whether a declared request body is still unread. It is touched
// only from the request's own goroutine — the reader and the ResponseWriter are
// both used by the handler, never by anything else — so it needs no lock.
type bodyState struct{ unconsumed bool }

// trackedBody clears the flag when the body has been read to its end. Anything
// short of EOF leaves it set: a MaxBytesReader that refused an over-long body,
// a decoder that stopped after the closing brace, a handler that gave up.
type trackedBody struct {
	io.ReadCloser
	st *bodyState
}

func (b trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.st.unconsumed = false
	}
	return n, err
}

// bgRefusal is the OUTERMOST wrapper on the break-glass listener, and it exists
// because of one lever (round-2 P1-1, round-3 P1).
//
// net/http drains an unread request body — up to 256 KiB — before it writes the
// response, unless the response is already closeAfterReply. Nothing arms a read
// deadline for that drain: this listener has no ReadTimeout (it serves uploads),
// and the header deadline has been cleared by the time a handler runs. So any
// unauthenticated LAN host could send POST headers with "Content-Length: 200000"
// and then nothing at all, and the connection would sit there indefinitely,
// holding a goroutine and a socket on a root daemon.
//
// The trigger is NOT the status code. Keying on non-2xx was the round-2 fix and
// it left the lever intact on exactly one route: a logout with no cookie
// answered 204 — a success — without reading the body, unauthenticated and
// outside every budget. What matters is whether a declared body was consumed,
// because that alone decides whether net/http is about to drain; a 204 that
// ignored its body is as much a parked connection as a 403 that did.
//
// Two things close it, and both are needed. Connection: close makes net/http
// skip the drain entirely. The read deadline bounds a drain already under way,
// for the paths where the header is written after a read has begun. Neither is
// armed when the body WAS consumed: there is nothing to drain, the response is
// a normal keep-alive one, and a deadline set there would land on the next
// request's header read instead.
type bgRefusal struct {
	http.ResponseWriter
	st    *bodyState
	wrote bool
}

func (w *bgRefusal) WriteHeader(code int) {
	if w.wrote {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.wrote = true
	if w.st != nil && w.st.unconsumed {
		w.Header().Set("Connection", "close")
		// Armed BEFORE the status is written: once WriteHeader returns, the
		// drain may already be in progress, and a deadline set afterwards would
		// be a deadline on a read that is already blocked. Through this wrapper's
		// own method, so the one clamp below covers every deadline this listener
		// arms rather than most of them.
		_ = w.SetReadDeadline(time.Now().Add(bgDrainDeadline))
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write routes the IMPLICIT 200 through WriteHeader above. Without it a handler
// that only writes a body (writeJSON, the static assets) would reach the
// embedded writer's own WriteHeader and skip the check entirely.
func (w *bgRefusal) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush commits the header the same way Write does. A flush is what actually
// sends the status line, so a streaming handler that flushed before writing
// anything would otherwise reach the embedded writer's own implicit 200 and
// skip the unread-body check entirely — symmetric with Write above.
func (w *bgRefusal) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// markBodyUnconsumed tells the refusal wrapper that this request's declared
// body was NOT read to its end, whatever the status about to be written says
// (Astra r1 #8). A drain that timed out leaves exactly that state, and the
// tracker would normally have noticed on its own — the EOF that clears the flag
// never arrived — but a handler that knows it gave up should say so rather than
// depend on the absence of an EOF further down a wrapper chain. On the main
// listener there is no wrapper and this is a no-op.
func markBodyUnconsumed(w http.ResponseWriter) {
	for w != nil {
		if bg, ok := w.(*bgRefusal); ok {
			if bg.st != nil {
				bg.st.unconsumed = true
			}
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// Unwrap is how http.ResponseController reaches the real ResponseWriter, and so
// the connection underneath it. Without it every SetReadDeadline on this
// listener — the login body read included — answers ErrNotSupported and does
// nothing at all.
func (w *bgRefusal) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// SetReadDeadline is what http.ResponseController finds on this wrapper before
// it unwraps any further, so EVERY read deadline armed on this listener — the
// door's own body read, decodeBody's decode and drain, the drain bound above —
// passes through here. It forwards unchanged unless bgReadDeadlineCap has been
// shortened, which only a test does; see the note on that variable.
func (w *bgRefusal) SetReadDeadline(t time.Time) error {
	if limit := bgReadDeadlineCap; limit > 0 && !t.IsZero() {
		if capped := time.Now().Add(limit); capped.Before(t) {
			t = capped
		}
	}
	return http.NewResponseController(w.ResponseWriter).SetReadDeadline(t)
}

// --- the credential ----------------------------------------------------------

// localCred re-reads the break-glass credential from the config file rather
// than caching it, guarded by an mtime+size check, so a password change from
// the shell takes effect on the next attempt without a restart: the operator
// who is already repairing a broken NAS should not have to restart the app they
// are repairing it with (contract §4.3).
type localCred struct {
	path   string
	pinned config.Local // used when path is empty (fixtures, the dev loop)
	// dev carries `serve -dev` into the RELOAD (Astra r1 #15). Reloading with
	// production validation meant a daemon started on a development config —
	// auth.mode "local" or "both", which Validate refuses outside -dev — could
	// never read its own credential again: every login after the first reload
	// failed closed on a file the daemon itself had started from.
	dev bool
	// onChange is called once when a reload observes a different `updated`
	// stamp than the one previously cached. The door turns it into the
	// milestone contract §6.2 asks for: the CLI writes nothing by design, so
	// without this a rotation under a live daemon left no record at all
	// (Astra r1 #12).
	onChange func(old, current string)

	mu      sync.Mutex
	have    bool
	mod     time.Time
	size    int64
	current config.Local
}

// get returns the credential as it stands on disk. A stat or read failure is
// fail-closed for NEW logins — an empty hash refuses every password — but the
// last successfully read `updated` stamp is kept so a transient unreadable
// config cannot evict the live session of an operator who is mid-repair.
func (c *localCred) get() (config.Local, error) {
	local, changed, old, err := c.load()
	// Reported outside the lock: the callback writes an audit line, and a
	// durable write must not be held under the credential mutex.
	if changed && c.onChange != nil {
		c.onChange(old, local.Updated)
	}
	return local, err
}

func (c *localCred) load() (local config.Local, changed bool, old string, err error) {
	if c.path == "" {
		return c.pinned, false, "", nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, statErr := os.Stat(c.path)
	if statErr != nil {
		if os.IsNotExist(statErr) && !c.have {
			// No config file at all is the first-run state, not a failure: there
			// is simply no password, and the listener will not have bound.
			return config.Local{}, false, "", nil
		}
		return config.Local{Updated: c.current.Updated}, false, "", statErr
	}
	if c.have && fi.ModTime().Equal(c.mod) && fi.Size() == c.size {
		return c.current, false, "", nil
	}
	loaded, loadErr := config.LoadDev(c.path, c.dev)
	if loadErr != nil {
		return config.Local{Updated: c.current.Updated}, false, "", loadErr
	}
	// Only a STAMP that moved is a change worth reporting; a config rewritten
	// for some other key (the read-only toggle) touches mtime and size without
	// touching the credential.
	changed = c.have && c.current.Updated != loaded.Auth.Local.Updated
	old = c.current.Updated
	c.have, c.mod, c.size, c.current = true, fi.ModTime(), fi.Size(), loaded.Auth.Local
	return c.current, changed, old, nil
}

// --- the listener's own pre-dispatch ----------------------------------------

// breakGlassAuth is the break-glass listener's whole authentication. It answers
// the two door routes itself and otherwise resolves the __Host-qfm_bg cookie to
// a session for the shared dispatch. ok is false when it has already written
// the response.
func (s *Server) breakGlassAuth(w http.ResponseWriter, r *http.Request) (*session, bool) {
	if s.bg == nil {
		// The listener is served but the door was never armed: refuse everything
		// rather than fall through to the QTS door, which does not exist here.
		s.fail(w, r, "unauthorized", "Emergency access is not configured.", "", "")
		return nil, false
	}
	if methods, ok := bgRoutes[r.URL.Path]; ok {
		if !allowedMethod(methods, r.Method) {
			w.Header().Set("Allow", strings.Join(methods, ", "))
			writeError(w, 405, "bad_request", "Method not allowed.", "", r.URL.Path, "")
			return nil, false
		}
		// The door routes never reach dispatch, so they arm the handler deadline
		// dispatch would have armed (round-1 P1-4). Without it an admission slot
		// or a queued bcrypt could be held by a caller who has stopped talking.
		// The bound is sized to what the verification queue can legitimately
		// take on THIS machine, so a correct password that simply waited its
		// turn is never answered as if it were wrong (round-2 P2-7).
		ctx, cancel := context.WithTimeout(r.Context(), s.bg.doorTimeout())
		defer cancel()
		r = r.WithContext(ctx)
		switch r.URL.Path {
		case bgLoginPath:
			s.bg.login(w, r)
		case bgLogoutPath:
			s.bg.logout(w, r)
		}
		return nil, false
	}
	sess, accounted := s.bg.resolve(w, r)
	if sess == nil {
		// api/session is the one API answer an unauthenticated page may read, on
		// this listener exactly as on the other: it is what tells the sign-in
		// page which door it is standing at.
		if r.Method == http.MethodGet && r.URL.Path == "/api/session" {
			s.sessionInfo(w, r, nil)
			return nil, false
		}
		if !accounted && !safeMethod(r.Method) && isMutationRoute(r.URL.Path) {
			// Once, not twice (Astra r7 #2). resolve accounts for the refusals it
			// makes itself — a cookie presented from another address is counted and
			// audited there — and says so, because this line and that one are the
			// same refusal of the same request. Counting it again here made a
			// replayed POST cost two suppressed refusals apiece, so five of them
			// reported nine, which is a lie about a number whose whole purpose is to
			// tell an operator how hard they are being hit.
			//
			// Through the bounded refusal accounting, not straight to
			// auditUnauthenticated (Astra r1 #3). On the MAIN listener that call
			// is fine: it sits behind the QTS proxy and a caller must already be
			// on the NAS. Here it was reachable by any LAN host with a
			// cookie-less POST, and each one forced a synchronous durable write
			// plus a QuLog milestone — the same unbounded write amplifier the
			// login route's throttle was built to close, re-opened on every
			// mutation route beside it. One line per source per window, with the
			// suppressed count carried into the next one.
			s.bg.noteUnauthenticated(r)
		}
		s.fail(w, r, "unauthorized", "Sign in with the emergency password to continue.", "", "")
		return nil, false
	}
	if !safeMethod(r.Method) && !validCSRF(r, sess.csrf) {
		s.auditAuthDenied(r, sess, "csrf", "CSRF or Origin check failed")
		s.fail(w, r, "permission", "The request could not be verified. Refresh and try again.", "", "")
		return nil, false
	}
	return sess, true
}

// bgPeer is the source address a break-glass session is pinned to: the REAL
// peer, never a forwarded header (contract §6.3 — this listener is not behind a
// proxy, so a forwarded header on it is a forgery), reduced to one spelling.
//
// One address has many spellings and the pin has to see through all of them
// (Astra r6 #1): ::1 and 0:0:0:0:0:0:0:1 are the same host, and so are
// 192.0.2.10 and ::ffff:192.0.2.10, which is how a dual-stack listener reports
// an IPv4 peer. net.IP's own String is the canonical form of both — it prints an
// IPv4-mapped address as the dotted quad — so a comparison over it agrees where
// a string comparison over RemoteAddr would lock the operator out of their own
// session on nothing but notation.
//
// A zone ("fe80::1%eth0") is canonicalised on the address alone and keeps its
// zone, and anything that is not an address at all — a Unix socket, a test's
// literal — is compared as it was given.
func bgPeer(r *http.Request) string {
	if r == nil {
		return ""
	}
	return canonicalHost(peerHost(r))
}

func canonicalHost(host string) string {
	addr, zone, zoned := strings.Cut(host, "%")
	ip := net.ParseIP(addr)
	if ip == nil {
		return host
	}
	if zoned {
		return ip.String() + "%" + zone
	}
	return ip.String()
}

// bgPeerMismatch is the audit code for a cookie presented from an address the
// session was not issued to. It is the sessionless vocabulary: whoever sent it
// is, as far as this door is concerned, nobody.
const bgPeerMismatch = "session_peer_mismatch"

// bgLocalPeerRefresh is how long the set of this machine's own addresses is
// trusted by a request that is merely REDEEMING a session. An address is added
// to a NAS by DHCP, by an IPv6 advertisement or by an operator's own hand, and
// none of those restart the daemon; a minute is short enough that a new address
// is covered before anyone could have built a relay onto it, and long enough
// that the enumeration is not a per-request cost.
//
// A LOGIN does not use this window at all (Astra r9 #4): locality is established
// at the moment a session is issued, by a discovery made then. See bgLocalFresh.
const bgLocalPeerRefresh = time.Minute

// bgLocalFresh is the shortest interval between two enumerations on the login
// path (Astra r9 #4).
//
// The minute above was a relay window. An address that arrives after a refresh —
// DHCP, IPv6 autoconfiguration, an operator adding one — is treated as somebody
// else's for the rest of that minute, and a relay already listening on it carries
// the operator's login through: automation needs seconds, not a minute. So a
// login from a peer the cached set does not know is answered from a FRESH read,
// and the cost of that is bounded by this interval rather than by the request
// rate: a flood of logins from one address buys one enumeration a second, and a
// second is far less than the time it takes to notice an address and connect.
const bgLocalFresh = time.Second

// bgLocalUnverifiable is how long the set may go without a SUCCESSFUL discovery
// before the door stops believing it (Astra r9 #1).
//
// Keeping the last good answer through a failed refresh is right for a blip and
// wrong for an outage: the set was not merely old, it was never checked against a
// machine that has since been given addresses, and a relay built on one of those
// is exactly what the rule exists to refuse. Five refreshes is long enough that
// no ordinary hiccup reaches it and short enough that nobody can plan around it.
const bgLocalUnverifiable = 5 * bgLocalPeerRefresh

// bgLocalAddrs is the set of addresses THIS MACHINE answers on, cached behind a
// short TTL (Astra r8 #1), with the time of the last SUCCESSFUL read kept apart
// from the time of the last attempt (Astra r9 #1).
//
// lookup is the seam: production reads the interfaces, and a test says what the
// machine's addresses are without having any. It is held under the same mutex as
// the cache so a test may replace it without racing the request goroutines that
// read it.
type bgLocalAddrs struct {
	mu     sync.Mutex
	lookup func() ([]string, error)
	// set is keyed the way a peer is: a plain canonical IP, except for a
	// link-local address whose interface is known, which carries its zone
	// (Astra r9 #5).
	set map[string]struct{}
	// link is the zoneless form of every link-local address in the set, whatever
	// zone it was found on. It answers the one question set cannot: a peer whose
	// link-local address the socket reported WITHOUT a zone, which no single
	// zoned key can be compared against.
	link map[string]struct{}
	// tried is when a lookup was last attempted; ok is when one last succeeded.
	// They are different times and the difference is the whole of r9 #1: a set
	// that has only been ATTEMPTED since the last success is a set nobody has
	// checked against this machine.
	tried time.Time
	ok    time.Time
	have  bool
	// failing is the last attempt's error text, or "" when it succeeded; logged
	// is the last one written to the log, so a lookup that goes on failing the
	// same way costs one line rather than one a minute for as long as it lasts.
	failing string
	logged  string
}

// setLookup installs the seam and drops everything cached with it, including the
// timestamps: a test's clock is not the arm-time clock, and a stamp from one
// compared against the other is a comparison between two unrelated numbers.
func (a *bgLocalAddrs) setLookup(fn func() ([]string, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lookup, a.set, a.link, a.have = fn, nil, nil, false
	a.tried, a.ok = time.Time{}, time.Time{}
	a.failing, a.logged = "", ""
}

// check answers both questions the door has about a peer: whether this address is
// one of THIS MACHINE's, and whether the set that answer came from is believable
// at all (Astra r9 #1). note is a line for the log, written once per distinct
// reason, and empty when there is nothing new to say.
//
// atIssue marks the login path, which is held to the stricter rule (Astra r9 #4):
// a peer the cached set does not know is looked up again, at most once per
// bgLocalFresh, and an attempt that FAILS makes the answer unverifiable even
// though the cache is warm — locality has to be established when the session is
// issued, and "it was not one of ours a minute ago" is not that.
//
// The enumeration runs under this mutex, which is what makes the interval a real
// bound rather than a hope: a hundred simultaneous logins take it in turn and all
// but the first find the read already done. They are logins at an emergency door,
// bounded to ten a minute per source before they reach this point.
func (a *bgLocalAddrs) check(p bgPeerAddr, now time.Time, atIssue bool) (local, known bool, note string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// A clock that went backwards (a test's, or an NTP step) refreshes rather
	// than pinning the set until it catches up.
	if !a.have || now.Sub(a.tried) >= bgLocalPeerRefresh || now.Before(a.tried) {
		note = a.refreshLocked(now)
	}
	local = a.hasLocked(p)
	if atIssue && !local && (now.Sub(a.tried) >= bgLocalFresh || now.Before(a.tried)) {
		if fresh := a.refreshLocked(now); fresh != "" {
			note = fresh
		}
		local = a.hasLocked(p)
	}
	return local, a.knownLocked(now, atIssue), note
}

// hasLocked is the comparison itself, and the zone is the whole of it (Astra r9
// #5). fe80::55 on the NAS's eth1 and fe80::55 on an operator's laptop, reached
// over eth0, are two different hosts that share an address — the zone is what
// says which — so a link-local peer is compared zone and all.
//
// Either side may be missing its zone, and a missing zone is not a mismatch: it
// is an unknown, and an unknown here fails CLOSED. A link-local peer the socket
// reported without a zone matches any interface's copy of that address, and a set
// entry found without one matches a peer on any zone.
func (a *bgLocalAddrs) hasLocked(p bgPeerAddr) bool {
	if _, ok := a.set[p.key()]; ok {
		return true
	}
	if p.ip == nil || !bgZoned(p.ip) {
		return false
	}
	base := p.ip.String()
	if p.zone == "" {
		_, ok := a.link[base]
		return ok
	}
	_, ok := a.set[base]
	return ok
}

// knownLocked reports whether the cached answer may be acted on. A set that has
// never been read, one whose last success is older than bgLocalUnverifiable, and
// — on the login path only — one whose last attempt failed are all the same
// verdict: this door cannot say where the peer is, so it says nothing and refuses.
func (a *bgLocalAddrs) knownLocked(now time.Time, atIssue bool) bool {
	if !a.have {
		return false
	}
	if atIssue && a.failing != "" {
		return false
	}
	if now.Before(a.ok) {
		// A clock that stepped backwards is not an outage; the set is as good as
		// it was a moment ago and the next tick will re-read it anyway.
		return true
	}
	return now.Sub(a.ok) < bgLocalUnverifiable
}

// refreshLocked re-reads the interfaces. A failure KEEPS the previous answer —
// an empty set would open the relay this whole rule closes, at the exact moment
// the machine is unwell, which is when the emergency door is used at all — but it
// no longer keeps it FOREVER (Astra r9 #1): the success time is left where it
// was, so a set nobody has been able to check for five refreshes stops counting
// as an answer, and every tick and every login attempt tries again.
func (a *bgLocalAddrs) refreshLocked(now time.Time) string {
	lookup := a.lookup
	if lookup == nil {
		lookup = bgInterfaceAddrs
	}
	addrs, err := lookup()
	a.tried = now
	if err != nil {
		a.failing = err.Error()
		if a.logged == a.failing {
			return ""
		}
		a.logged = a.failing
		return fmt.Sprintf("break-glass: this machine's own addresses could not be read (%v); until they can be, the door refuses every login it cannot place", err)
	}
	set := make(map[string]struct{}, len(addrs)+2)
	link := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		key, base := bgLocalKey(addr)
		if key == "" {
			continue
		}
		set[key] = struct{}{}
		if base != "" {
			link[base] = struct{}{}
		}
	}
	// Loopback is always in the set, whatever the interfaces say: the rule's
	// oldest case must not depend on an enumeration that can fail.
	set["127.0.0.1"] = struct{}{}
	set["::1"] = struct{}{}
	a.set, a.link, a.have, a.ok = set, link, true, now
	if a.failing == "" {
		return ""
	}
	a.failing, a.logged = "", ""
	return "break-glass: this machine's own addresses can be read again; logins are judged on the real set once more"
}

// prime reads the set once, at arm time, so the door is never serving with an
// empty one. It returns the line the failure owes the log, if it failed.
func (a *bgLocalAddrs) prime(now time.Time) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refreshLocked(now)
}

// bgInterfaceAddrs is the production lookup: every address assigned to every
// interface, as a canonical IP string with the prefix length dropped — and, for a
// link-local address, with the INTERFACE'S NAME kept as the zone (Astra r9 #5),
// because that is the only thing that distinguishes the NAS's own fe80::55 from
// the operator's.
//
// It is read per interface rather than through net.InterfaceAddrs, which does not
// say which interface an address belongs to. An error anywhere is the whole
// lookup's error: a partial enumeration is a set with addresses missing from it,
// and a missing address is one this door would hand a session to.
func bgInterfaceAddrs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil {
				continue
			}
			if bgZoned(ip) && iface.Name != "" {
				out = append(out, ip.String()+"%"+iface.Name)
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// bgLocalKey puts one discovered address into the form the set is keyed in, and
// returns the zoneless form alongside it when the address is link-local. key is
// "" when the string is not an address at all.
func bgLocalKey(s string) (key, base string) {
	addr, zone, _ := strings.Cut(s, "%")
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", ""
	}
	if !bgZoned(ip) {
		return ip.String(), ""
	}
	base = ip.String()
	if zone == "" {
		return base, base
	}
	return base + "%" + zone, base
}

// bgZoned reports whether an address is one whose zone carries meaning: an IPv6
// link-local address is only an address together with the interface it is on.
// Everything else — including IPv4's own 169.254/16, which has no zones — is
// compared zonelessly, exactly as it always was.
func bgZoned(ip net.IP) bool {
	return ip.To4() == nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

// bgPeerAddr is one peer's address as the socket reported it: the IP, and the
// zone if it named one.
type bgPeerAddr struct {
	ip   net.IP
	zone string
}

// key is the form this peer would be found under in the set.
func (p bgPeerAddr) key() string {
	if p.ip == nil {
		return ""
	}
	if p.zone == "" || !bgZoned(p.ip) {
		return p.ip.String()
	}
	return p.ip.String() + "%" + p.zone
}

// bgParsePeer reads the peer's address off the request. net.SplitHostPort leaves
// the zone on the host — "[fe80::55%eth0]:40000" yields "fe80::55%eth0" — and the
// zone is kept, because for a link-local address it is half the address.
func bgParsePeer(r *http.Request) bgPeerAddr {
	addr, zone, _ := strings.Cut(peerHost(r), "%")
	return bgPeerAddr{ip: net.ParseIP(addr), zone: zone}
}

// localPeer reports whether the request came from this machine (Astra r7 #6,
// corrected by Astra r8 #1).
//
// The peer pin cannot see through a relay, and the relay that matters is a local
// one: any unprivileged process on the NAS may listen on a high port and forward
// to the door, and an SSH tunnel does the same thing with no code at all. The
// browser's login then arrives from an address the NAS itself answers on, the
// session is pinned to it — and every other HTTPS service on the NAS hostname,
// which receives the host-scoped cookie, presents from that same address. The pin
// would be satisfied by exactly the replay it exists to stop.
//
// Round 7 refused loopback, which was the wrong rule by one step: `socat
// TCP-LISTEN:9443,fork TCP:192.168.1.10:8771` on the NAS itself makes the login
// peer 192.168.1.10 — the NAS's OWN LAN address — and the relay is back with one
// command. The rule is not "loopback"; it is "the peer is this machine", and
// every address on every interface is this machine.
//
// So the emergency door is a LAN door: the operator is at another machine,
// because the reason they are using it is that the NAS is not well. Refusing the
// machine's own addresses costs that operator nothing and takes the relay away.
//
// The verdict has THREE values, not two (Astra r9 #1). "I do not know where this
// peer is" is a real answer and it used to be spelled "somewhere else": a
// discovery that had never succeeded left the set empty, and an empty set said
// every address on the LAN — including the NAS's own — belonged to somebody else.
// The door now refuses what it cannot place.
type bgLocality uint8

const (
	// bgPeerElsewhere: another machine. The operator, as far as this door knows.
	bgPeerElsewhere bgLocality = iota
	// bgPeerThisMachine: an address this NAS answers on, so a relay.
	bgPeerThisMachine
	// bgPeerUnverifiable: the set could not be read, or has not been read in long
	// enough that it no longer describes this machine.
	bgPeerUnverifiable
)

// peerLocality places the request's peer. atIssue marks the login path, which
// establishes locality with a fresh read rather than trusting the cached minute
// (Astra r9 #4); redemption keeps using the cache, because a replay needs a
// session that was issued through the relay and the fresh read at login is what
// stops one ever being.
func (d *breakGlassDoor) peerLocality(r *http.Request, atIssue bool) bgLocality {
	peer := bgParsePeer(r)
	if peer.ip == nil {
		// A peer whose address does not parse cannot be compared to the set at
		// all, so it is the unknown, not the operator.
		return bgPeerUnverifiable
	}
	if peer.ip.IsLoopback() {
		// Under `serve -dev` the listener is FORCED to loopback
		// (forceLoopbackBreakGlass), so the production rule would refuse every
		// login a developer can make — the door would be untestable by hand on the
		// one configuration that exists to be tested by hand (Astra r8 #4). The
		// relaxation is loopback's alone, and only there: a dev daemon's own LAN
		// addresses are refused exactly as production refuses them, so the rule
		// under test is still the rule.
		//
		// It is decided BEFORE the set is consulted, which is what keeps the dev
		// door usable when discovery is failing too (Astra r9 #1): the dev
		// listener is bound to loopback and nothing else, so there is no set to
		// consult for the only peer it can ever have.
		if d.dev {
			return bgPeerElsewhere
		}
		return bgPeerThisMachine
	}
	if d.local == nil {
		return bgPeerUnverifiable
	}
	local, known, note := d.local.check(peer, d.now(), atIssue)
	if note != "" {
		d.logf("%s", note)
	}
	switch {
	case local:
		return bgPeerThisMachine
	case !known:
		return bgPeerUnverifiable
	}
	return bgPeerElsewhere
}

// resolve maps the cookie to a live session, applying the peer pin, the idle
// timeout, the absolute lifetime and the credential-stamp eviction. It returns
// nil when the request is unauthenticated, having already destroyed anything
// stale.
//
// accounted is the second half of that answer (Astra r7 #2): true when resolve
// has already counted and audited this refusal through the bounded refusal
// table, so the caller must not count the same request a second time in its own
// shape. It is false for every nil that was simply not a session — no cookie, an
// unknown one, an expired one — because those are the caller's to account for.
func (d *breakGlassDoor) resolve(w http.ResponseWriter, r *http.Request) (*session, bool) {
	c, err := r.Cookie(bgCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	// The stamp is read before the lock so a wedged config read cannot be held
	// across the session map.
	live, credErr := d.cred.get()
	now := d.now()

	d.mu.Lock()
	sess := d.sessions[c.Value]
	if sess == nil {
		d.mu.Unlock()
		d.clearCookie(w)
		return nil, false
	}
	// The pin, before anything else this function does (Astra r6 #1). A request
	// from another address is not this session's and gets nothing from it: not
	// the snapshot, not the CSRF token /api/session would hand back, and not the
	// refreshed idle window either — a replay must not keep a session alive that
	// the operator has walked away from.
	//
	// And the session SURVIVES. It belongs to the peer that signed in, who is
	// still using it; destroying it here would let anything holding a copy of the
	// cookie sign the operator out mid-emergency. For the same reason no cookie
	// is cleared: the cookie is host-scoped, so a Set-Cookie written to whoever
	// replayed it would, in the browser case this is about, delete the operator's
	// own cookie from their own browser.
	//
	// A peer that is THIS MACHINE is a mismatch too, whatever the session says
	// (Astra r7 #6, r8 #1). No session is ever issued to one of the NAS's own
	// addresses any more, so this can only be a session pinned to another machine
	// being presented from the NAS itself — but it is written as its own condition
	// rather than left to the comparison, because the rule is about the relay, not
	// about which address happens to be stored.
	//
	// A peer this door cannot PLACE is a mismatch too (Astra r9 #1): with no
	// believable set of the machine's own addresses there is no way to tell the
	// operator's laptop from a forwarder running on the NAS, and the safe reading
	// of an unknown is the one that hands nothing over.
	if d.peerLocality(r, false) != bgPeerElsewhere || bgPeer(r) != sess.peer {
		d.mu.Unlock()
		d.notePeerMismatch(r)
		// Counted and audited HERE, so the caller does not do it again in the
		// sessionless shape (Astra r7 #2).
		return nil, true
	}
	reason := ""
	switch {
	case !now.Before(sess.issued.Add(bgLifetime)):
		reason = bgRemovalLifetime
	case !now.Before(sess.seen.Add(bgIdle)):
		reason = bgRemovalIdle
	case credErr == nil && sess.updated != live.Updated:
		reason = bgRemovalPassword
	}
	if reason != "" {
		note := d.removeLocked(sess, reason)
		d.mu.Unlock()
		d.clearCookie(w)
		d.auditRemoval(r, note)
		return nil, false
	}
	sess.seen = now
	snap := sess.snapshot()
	d.mu.Unlock()
	d.setCookie(w, sess.id, int(bgIdle.Seconds()))
	return snap, false
}

// logf writes to the app log, tolerating a door built without a server (the
// doorTimeout fixtures hold nothing else).
func (d *breakGlassDoor) logf(format string, args ...any) {
	if d.srv == nil || d.srv.logger == nil {
		return
	}
	d.srv.logger.Printf(format, args...)
}

func (d *breakGlassDoor) now() time.Time {
	if d.gate != nil && d.gate.Now != nil {
		return d.gate.Now()
	}
	return time.Now()
}

func (d *breakGlassDoor) setCookie(w http.ResponseWriter, value string, age int) {
	// Path "/" is required by the __Host- prefix; Secure is unconditional
	// because this listener is TLS-only; SameSite=Strict because this page is
	// never framed and never linked to from anywhere (contract §13.2).
	http.SetCookie(w, &http.Cookie{
		Name: bgCookie, Value: value, Path: "/", MaxAge: age,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (d *breakGlassDoor) clearCookie(w http.ResponseWriter) { d.setCookie(w, "", -1) }

// Why a session went away. The vocabulary is fixed and small so the audit
// detail stays bounded (contract §6.3).
const (
	bgRemovalLogout   = "logout"
	bgRemovalExpired  = "expired"
	bgRemovalEvicted  = "evicted"
	bgRemovalLifetime = "absolute lifetime reached"
	bgRemovalIdle     = "idle timeout"
	bgRemovalPassword = "the break-glass password changed"
)

// removeLocked deletes one session and returns the reason the caller must audit
// once it has released the lock. It returns "" when there was nothing to remove.
//
// EVERY removal is audited with its reason (Astra r1 #13). Three of them used to
// be silent — the shared /api/logout, and the expiry and capacity eviction
// inside issue — so an emergency session could simply stop existing with no
// trace of when or why, which is the one question the trail exists to answer.
// The write happens after the unlock because the auditor's WriteSync can block
// on a durable writer, and the session map must not be held across that.
func (d *breakGlassDoor) removeLocked(sess *bgSession, reason string) string {
	if sess == nil {
		return ""
	}
	delete(d.sessions, sess.id)
	if sess.order != nil {
		d.order.Remove(sess.order)
		sess.order = nil
	}
	return reason
}

// auditRemoval writes the one line a removal earns. The expiry reasons are
// denials — a request was refused because of them — while a logout or an
// eviction is ordinary lifecycle.
func (d *breakGlassDoor) auditRemoval(r *http.Request, reason string) {
	if reason == "" {
		return
	}
	result, code := "ok", ""
	switch reason {
	case bgRemovalLifetime, bgRemovalIdle, bgRemovalPassword, bgRemovalExpired:
		result, code = "denied", "session_expired"
	}
	ip := ""
	if r != nil {
		ip = peerHost(r)
	}
	d.audit(r, "breakglass-session", result, code, fmt.Sprintf("door=local ip=%s session destroyed: %s", ip, reason))
}

// --- login and logout --------------------------------------------------------

type bgLoginBodyJSON struct {
	Password string `json:"password"`
}

// login is the only route that consults the local hash, and it exists only on
// this listener. Every failure — wrong password, no password configured, locked
// out, malformed body, a refused rate — returns the SAME body after the SAME
// minimum latency (contract §5.2).
//
// The sign-in flow the UI follows, end to end:
//
//  1. GET /api/session with no cookie. It answers 200 with exactly
//     {"authenticated":false,"listener":"local"} — two fields, so the page
//     learns which listener it is standing at and renders the password form,
//     and a LAN scanner learns nothing else: not the version, not the firmware
//     family, not whether the app is read-only, and above all not whether a
//     password is configured. That last one is what the uniform login failure
//     below exists for, and disclosing it here would have undone it.
//  2. POST /api/breakglass/login {"password":"…"}. This route is exempt from
//     the X-QFM-CSRF header — there is no session yet to bind a token to — but
//     NOT from the other two locks: Origin/Referer must equal r.Host and a
//     Sec-Fetch-Site of cross-site is refused outright (validOrigin, the same
//     function every other unsafe request uses). A browser fetch from the page
//     itself satisfies both without doing anything special.
//  3. On success: 204 with the __Host-qfm_bg cookie. No body — the CSRF token
//     is NOT returned here.
//  4. GET /api/session again. Now authenticated, and it carries "csrf", exactly
//     as the main listener issues it. Every later mutating request sends that
//     value in X-QFM-CSRF, the same as on the main listener.
//  5. POST /api/logout (or /api/breakglass/logout) destroys the session; both
//     require the token, because destroying a session is a mutation.
func (d *breakGlassDoor) login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()
	// The peer is a real LAN address: this listener is not behind the QTS proxy,
	// so a forwarded header here is a forgery and is never read (contract §6.3).
	ip := peerHost(r)

	// The per-source bucket is charged FIRST, before anything else can refuse
	// (round-2 P1-1). An Origin check that ran first would be a free refusal:
	// a caller sending a deliberately wrong Origin would be answered without
	// ever touching the budget, so the only bound on how many such requests it
	// could open would be the listener's own accept rate.
	if err := d.gate.AllowSource(ip); err != nil {
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again shortly.", time.Minute, "source bucket exhausted")
		return
	}
	// Exempt from the CSRF header (no session exists yet to bind a token to) but
	// not from the other two locks.
	if !validOrigin(r) {
		d.reject(ctx, w, r, start, http.StatusForbidden, "permission", "The request could not be verified.", 0, "origin check failed")
		return
	}
	// A source that is inside its budget again gets its suppressed refusals
	// summarised once, so a burst is legible without one milestone per packet.
	d.flushRefusals(r, ip)

	// The body is read BEFORE any admission slot is taken, under its own read
	// deadline (round-1 P1-4). A connection that sends headers and then trickles
	// its body would otherwise hold one of the four in-flight slots for as long
	// as it liked — four of them, and the emergency door is shut with no
	// password ever offered. Read first, hold nothing; the deadline is what
	// bounds the read, and the per-IP bucket above is what bounds how many such
	// connections one source may open per minute.
	body, readErr := readWithDeadline(w, r, bgLoginBody, bgLoginRead)

	// No session is ever issued to the machine itself (Astra r7 #6, r8 #1). A
	// login that arrives from one of this NAS's own addresses came through a relay
	// — a forwarder some unprivileged process put in front of 8771, or an SSH
	// tunnel — and a session pinned to an address the NAS answers on is a session
	// every sibling service on it can replay, because the host-scoped cookie
	// reaches them and they present from that address too. The answer is the
	// uniform one: same body, same floor, same bucket charge, and no rung of the
	// lockout ladder, because nothing here is a verdict about a password and an
	// operator must not be able to lock their own door by tunnelling to it five
	// times.
	//
	// It is refused HERE, after the body has been read, and that placement is the
	// whole of Astra r8 #2. Refused before the read, the request left a declared
	// body unconsumed, so the outermost wrapper added `Connection: close` — and a
	// wrong password, whose body IS read, did not. The bodies matched, the floor
	// matched, and the connection header told a prober which of the two answers
	// they had just been given. Same path, same headers, same socket.
	//
	// The locality is established HERE, at issue time, from a discovery made now
	// rather than from the cached minute (Astra r9 #4) — and when that discovery
	// cannot be made the login is refused in exactly the same words (Astra r9 #1).
	// A door that cannot say whether the peer is one of its own addresses must not
	// issue a root session to it, and the operator is told which it was through the
	// audit line, which is the one place the two are distinguishable.
	switch d.peerLocality(r, true) {
	case bgPeerThisMachine:
		d.fail(ctx, w, r, start, ip, "peer is this machine", nil)
		return
	case bgPeerUnverifiable:
		d.fail(ctx, w, r, start, ip, "local addresses unknown", nil)
		return
	}
	var req bgLoginBodyJSON
	if readErr != nil || json.Unmarshal(body, &req) != nil || req.Password == "" {
		// Not a credential verdict, so it must not advance the lockout ladder
		// (round-1 P2-7): five malformed bodies would otherwise reach the
		// 1800 s cap and lock the operator out with no password ever tried.
		d.fail(ctx, w, r, start, ip, "malformed body", nil)
		return
	}
	if len(req.Password) > breakglass.MaxPasswordBytes {
		d.fail(ctx, w, r, start, ip, "oversized password", nil)
		return
	}

	release, err := d.gate.Admit()
	if err != nil {
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again shortly.", time.Second, "verification queue full")
		return
	}
	// Released on every return path, including the context ending under us.
	defer release()

	// The lockout verdict, the compare and the outcome are ONE serialised step
	// inside the gate (Astra r1 #7). Reading the verdict before queueing and
	// committing the outcome after releasing let four queued attempts act on the
	// same stale answer: they skipped rungs of the ladder, and a correct
	// password queued behind the failure that entered a lockout was accepted
	// during that lockout. The credential is read inside the turn too, so a
	// locked source costs this process no file I/O at all.
	var cred config.Local
	var credErr, verifyErr error
	verdict, err := d.gate.Verify(ctx, ip, func() breakglass.Outcome {
		cred, credErr = d.cred.get()
		if credErr != nil {
			// Our failure, not the caller's: fail closed, but never let an
			// unreadable config file walk anyone up the ladder.
			return breakglass.OutcomeNeutral
		}
		verifyErr = breakglass.Verify(cred.Hash, req.Password)
		switch {
		case verifyErr == nil:
			return breakglass.OutcomeSucceeded
		case errors.Is(verifyErr, breakglass.ErrNoPassword):
			// "No password configured" deliberately does not advance the ladder
			// (round-2 P2-2): after `break-glass disable` on a running daemon
			// the listener stays bound, so a peer could walk five attempts up to
			// the 1800 s cap and then be refused by a lockout at the exact
			// moment the operator was trying to get back in. The answer and the
			// latency are identical either way, so nothing is disclosed.
			return breakglass.OutcomeNeutral
		default:
			// A wrong password is the ONLY thing that advances the ladder.
			return breakglass.OutcomeFailed
		}
	})
	if err != nil {
		// Never verified: the caller waited behind other verifications until the
		// door's deadline, or went away. Answering "that password was not
		// accepted" would be a lie about a password nothing ever looked at — and
		// a cruel one, since the queue is longest exactly when an operator is
		// racing a brute-forcer for the door (round-2 P2-7). It is a rate
		// answer, and it says to try again.
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "rate_limited", "The emergency door is busy. Try again in a moment.", 2*time.Second, "queue wait expired before verification")
		return
	}
	if verdict.Left {
		// Exactly one "lockout left" milestone per lockout: the turn that
		// observes the expiry is the one that cleared it.
		d.audit(r, "breakglass-lockout", "ok", "", fmt.Sprintf("door=local ip=%s source lockout ended", ip))
	}
	if verdict.Locked {
		// The body never reveals whether the password offered was right.
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "locked_out", "Too many failed attempts. Try again later.", verdict.RetryAfter, fmt.Sprintf("source locked, %ds remaining", int(verdict.RetryAfter.Seconds())))
		return
	}
	if credErr != nil {
		d.logf("break-glass: the credential could not be read: %v", credErr)
		d.fail(ctx, w, r, start, ip, "credential unreadable", nil)
		return
	}
	if verifyErr != nil {
		// Only the wrong-password verdict carries the ladder report; "no
		// password configured" is a refusal like any other and is throttled.
		cause, reported := "wrong password", &verdict
		if errors.Is(verifyErr, breakglass.ErrNoPassword) {
			cause, reported = "no password configured", nil
		}
		d.fail(ctx, w, r, start, ip, cause, reported)
		return
	}

	sess, err := d.issue(r, cred)
	if err != nil {
		d.audit(r, "breakglass-login", "error", "internal", fmt.Sprintf("door=local ip=%s %v", ip, err))
		writeError(w, http.StatusServiceUnavailable, "session_store_full", "Emergency sessions are full. Try again shortly.", "", r.URL.Path, "")
		return
	}
	cost, _ := breakglass.HashCost(cred.Hash)
	d.audit(r, "breakglass-login", "ok", "", fmt.Sprintf("door=local ip=%s cost=%d", ip, cost))
	d.audit(r, "breakglass-session", "ok", "", fmt.Sprintf("door=local ip=%s session issued", ip))
	d.setCookie(w, sess.id, int(bgIdle.Seconds()))
	w.WriteHeader(http.StatusNoContent)
}

// readWithDeadline reads at most limit bytes of the request body under its own
// read deadline, so a client that sends headers and then stops cannot hold the
// handler open.
//
// The deadline is armed per REQUEST rather than as a server-wide ReadTimeout:
// this listener serves the same API as the main one, uploads included, and
// http.Server.ReadTimeout covers the whole body — a ten-second one would cut
// every multi-gigabyte upload made through the emergency door at ten seconds.
// See the note in cmd's listenBreakGlass.
func readWithDeadline(w http.ResponseWriter, r *http.Request, limit int64, within time.Duration) ([]byte, error) {
	rc := http.NewResponseController(w)
	// A ResponseWriter that cannot carry a deadline (httptest's recorder) yields
	// ErrNotSupported; the bounded read still applies, which is what every
	// handler-level test exercises.
	_ = rc.SetReadDeadline(time.Now().Add(within))
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

// logout destroys the session and clears the cookie — in that order, and only
// once the CSRF check has passed (round-2 P3-10).
//
// Clearing the cookie unconditionally was a cross-site logout: a page on any
// other origin could aim a form at this route and, whatever the server did with
// the session, the browser would obey the Set-Cookie and drop the operator's
// credential. Signing someone out is a smaller harm than signing them in, but
// it is exactly the harm an attacker wants while a NAS is being repaired, and
// the fix costs nothing.
func (d *breakGlassDoor) logout(w http.ResponseWriter, r *http.Request) {
	// Charged to the per-source bucket before anything else, exactly as login
	// is (round-4 P3). This is the other route an unauthenticated caller can
	// reach on this listener, and until now it was the only one that cost
	// nothing: a caller could open the bounded-but-real body read on it as
	// often as it liked, for free, while the login route beside it was capped
	// at ten a minute.
	ip := peerHost(r)
	if err := d.gate.AllowSource(ip); err != nil {
		start := time.Now()
		d.reject(r.Context(), w, r, start, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again shortly.", time.Minute, "source bucket exhausted on logout")
		return
	}
	// The body is read next, bounded and deadlined, before any answer
	// (round-3 P1). This route used to answer the no-cookie case 204 without
	// touching the body at all — unauthenticated, outside every budget, and a
	// success, so the status-keyed close never fired. A declared body that
	// nothing reads is a parked connection whatever the status says.
	if _, err := readWithDeadline(w, r, bgLoginBody, bgLoginRead); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "The request body could not be read.", "", r.URL.Path, "")
		return
	}
	// And the Origin check comes before the no-cookie shortcut, so a cross-site
	// page cannot use this route as a free, unauthenticated request either.
	if !validOrigin(r) {
		writeError(w, statusCode("permission"), "permission", "The request could not be verified. Refresh and try again.", "", r.URL.Path, "")
		return
	}
	c, err := r.Cookie(bgCookie)
	if err != nil || c.Value == "" {
		// Nothing presented, nothing to destroy, and nothing to clear: a
		// logout with no session is already in the state it asked for.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	d.mu.Lock()
	sess := d.sessions[c.Value]
	// The pin FIRST, and on its own (Astra r7 #3). Folding it into the condition
	// below answered a replay from another address with the same 403 as a missing
	// token and recorded nothing at all — so the one event the pin exists to make
	// visible, a root session cookie turning up somewhere else, was silent on the
	// single route that reaches a live session without going through resolve. It
	// goes through the same bounded mismatch path as every other replay, and the
	// session SURVIVES: signing the operator out is precisely what a replayed
	// logout is for.
	if sess != nil && (d.peerLocality(r, false) != bgPeerElsewhere || bgPeer(r) != sess.peer) {
		d.mu.Unlock()
		d.notePeerMismatch(r)
		writeError(w, statusCode("permission"), "permission", "The request could not be verified. Refresh and try again.", "", r.URL.Path, "")
		return
	}
	// Only a caller holding the session's own CSRF token may destroy it, the
	// same rule every other unsafe request follows.
	if sess == nil || !validCSRF(r, sess.csrf) {
		d.mu.Unlock()
		// No cookie is written on this path: an unverifiable request changes
		// nothing at all, including the browser's state.
		writeError(w, statusCode("permission"), "permission", "The request could not be verified. Refresh and try again.", "", r.URL.Path, "")
		return
	}
	note := d.removeLocked(sess, bgRemovalLogout)
	d.mu.Unlock()
	d.auditRemoval(r, note)
	d.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// issue creates a session, evicting the oldest when the cap is reached. Every
// session it removes on the way is audited with its reason, after the lock is
// released (Astra r1 #13).
func (d *breakGlassDoor) issue(r *http.Request, cred config.Local) (*bgSession, error) {
	now := d.now()
	sess := &bgSession{
		id: rand.Text(), csrf: rand.Text(), issued: now, seen: now, updated: cred.Updated,
		// The address this session belongs to, from here on (Astra r6 #1).
		peer: bgPeer(r),
		// Root, so it keys to the same root worker as any other admin session
		// (backend.Principal.Key). The name is not a QTS user and is not
		// resolvable by idmap: it exists to be legible in the audit trail.
		who: backend.Principal{User: "break-glass", UID: 0, GID: 0, Groups: []int{0}, Root: true},
	}
	// Collected under the lock, emitted after it: an audit write can block on a
	// durable writer, and the session map must not be held across one.
	var removed []string
	d.mu.Lock()
	if d.sessions == nil {
		d.sessions = make(map[string]*bgSession)
	}
	// Expire before evicting: a store full of idle sessions must not cost the
	// operator the one they are about to need.
	for _, old := range d.sessions {
		if !now.Before(old.issued.Add(bgLifetime)) || !now.Before(old.seen.Add(bgIdle)) {
			removed = append(removed, d.removeLocked(old, bgRemovalExpired))
		}
	}
	full := false
	for len(d.sessions) >= bgMaxSessions {
		front := d.order.Front()
		if front == nil {
			full = true
			break
		}
		removed = append(removed, d.removeLocked(front.Value.(*bgSession), bgRemovalEvicted))
	}
	if !full {
		sess.order = d.order.PushBack(sess)
		d.sessions[sess.id] = sess
	}
	d.mu.Unlock()
	for _, reason := range removed {
		d.auditRemoval(r, reason)
	}
	if full {
		return nil, errors.New("the break-glass session store is full")
	}
	return sess, nil
}

// destroy removes one session by id; it is what the shared /api/logout route
// calls for a break-glass session. It audits the removal, which that route did
// not (Astra r1 #13): only /api/breakglass/logout ever did, so an operator who
// signed out through the shared route left no record of it at all.
func (d *breakGlassDoor) destroy(r *http.Request, id string) {
	d.mu.Lock()
	note := d.removeLocked(d.sessions[id], bgRemovalLogout)
	d.mu.Unlock()
	d.auditRemoval(r, note)
}

// doorTimeout is how long a login or logout request may take: the floor, or the
// time InFlight queued verifications would need on this hardware, whichever is
// larger. bcryptCost is measured once (EnableBreakGlass) and only read here.
func (d *breakGlassDoor) doorTimeout() time.Duration {
	queue := time.Duration(breakglass.InFlight) * d.bcryptTime
	// Plus the floor's own slack for everything that is not bcrypt: the body
	// read, the failure floor, the audit write.
	if queue += bgDoorTimeout; queue > bgDoorTimeout {
		return queue
	}
	return bgDoorTimeout
}

// Sessions reports how many live break-glass sessions exist, for the tests and
// the diagnostic view.
func (d *breakGlassDoor) Sessions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

// --- failure paths -----------------------------------------------------------

// fail is EVERY attempt that reached the door and was refused: one body, one
// status, one minimum latency, whatever the cause. The cause is recorded (a
// forced milestone) and never disclosed.
//
// verdict is non-nil when this attempt took a verification turn — a password
// was offered and the turn reached a conclusion about it. The ladder has
// already been walked (or not) inside that turn (Astra r1 #7); what is left
// here is reporting it. A nil verdict is a refusal that never reached a
// credential at all: a malformed body, an oversized field, a config file we
// could not read. Those are our problem or a broken client's, and letting five
// of them reach the 1800 s cap would hand a peer a way to shut its own
// emergency door without ever guessing a password (round-1 P2-7). Every path
// keeps the uniform body, the uniform latency and the per-IP bucket charge it
// has already paid.
func (d *breakGlassDoor) fail(ctx context.Context, w http.ResponseWriter, r *http.Request, start time.Time, ip, cause string, verdict *breakglass.Verdict) {
	detail := fmt.Sprintf("door=local ip=%s %s", ip, cause)
	if verdict != nil {
		detail = fmt.Sprintf("%s, %d consecutive", detail, verdict.Failures)
		// The denial is recorded BEFORE the response is written (contract
		// §16.5): an attacker who disconnects on seeing the status must not be
		// able to discard the record of the attempt.
		d.audit(r, "breakglass-login", "denied", "auth_failed", detail)
		if verdict.Entered {
			d.audit(r, "breakglass-lockout", "denied", "locked_out", fmt.Sprintf("door=local ip=%s source lockout: %d failures, %ds", ip, verdict.Failures, int(verdict.RetryAfter.Seconds())))
		}
	} else {
		// Recorded, but throttled the same way a refusal is: a client looping on
		// a malformed body must not be able to drive the audit sink.
		d.noteRefusal(r, ip, "breakglass-login", "auth_failed", detail)
	}
	d.gate.Wait(ctx, start)
	writeError(w, http.StatusUnauthorized, "auth_failed", "That password was not accepted.", "", r.URL.Path, "")
}

// reject is a refusal that never reached the credential at all — a bad origin,
// an exhausted bucket, a full queue, a live lockout. It carries the same floor,
// because the latency of "locked out" must not be distinguishable from the
// latency of "wrong password".
//
// Its audit line is THROTTLED (round-1 P2-5). A forced milestone per refused
// packet is an unbounded write amplifier: the flood that exhausted the bucket
// would also fill the audit log, exec log_tool once per attempt, and saturate
// the auditor's four durable-writer slots — at which point real mutations on
// the MAIN listener start answering audit_unavailable. One line per source per
// window, plus one summary when the source comes back inside its budget, says
// everything an operator needs and cannot be turned into a lever.
func (d *breakGlassDoor) reject(ctx context.Context, w http.ResponseWriter, r *http.Request, start time.Time, status int, code, message string, retryAfter time.Duration, detail string) {
	ip := peerHost(r)
	d.noteRefusal(r, ip, "breakglass-login", code, fmt.Sprintf("door=local ip=%s %s", ip, detail))
	d.gate.Wait(ctx, start)
	if retryAfter > 0 {
		secs := int(retryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	writeError(w, status, code, message, "", r.URL.Path, "")
}

// refusalWindow is how long one audited refusal stands for a source before
// another is written. It matches the per-IP bucket's own window, so the line an
// operator sees lines up with the budget that produced it.
const refusalWindow = breakglass.BucketWindow

// refusalShape is WHAT a throttled refusal is, and therefore what shape every
// line about it has to be written in (Astra r2 #6).
//
// The throttle counts two quite different events. A refused LOGIN is an event of
// the door itself, and d.audit stamps it with the door's actor: break-glass, UID
// 0, admin, root. A SESSIONLESS mutation denial is the opposite — nobody
// authenticated, there is no actor at all, and auditUnauthenticated records the
// listener's door and the path instead. The per-source line already told them
// apart; the AGGREGATE lines did not, and wrote both through d.audit. So a spray
// of cookie-less POSTs from more sources than the table can hold was reported as
// a root administrator being refused, which is the one thing that had not
// happened.
type refusalShape uint8

const (
	// refusalLogin: an attempt at the door itself was refused.
	refusalLogin refusalShape = iota
	// refusalSessionless: an unsafe request to a mutation route arrived with no
	// session at all.
	refusalSessionless
	// refusalMismatch: a LIVE session's cookie was presented from an address the
	// session was not issued to (Astra r9 #6). It is written in the sessionless
	// shape — the sender proved nothing — but it is not the same event, and the
	// difference is the only one QuLog is shown: an ordinary sessionless denial is
	// Quiet, a replayed root cookie is not.
	refusalMismatch
	// refusalShapes is how many there are, so the overflow counters above can be
	// keyed by shape.
	refusalShapes
)

// refusalEvent is the line one refusal would write: its shape, and the audit
// vocabulary that goes with it. It is carried into the counters so every summary
// is written in the shape of what it counts.
type refusalEvent struct {
	shape refusalShape
	op    string // the audit Op — refusalLogin only; the other shape has its own
	code  string
}

// summary is the event an AGGREGATE line for this shape is written as. Both
// aggregates — the untracked-source count and the flush summary — are rate
// reports about a burst rather than a report of one particular refusal, so
// neither carries the individual refusal's code.
func (s refusalShape) summary() refusalEvent {
	switch s {
	case refusalSessionless:
		return refusalEvent{shape: refusalSessionless, code: "unauthorized"}
	case refusalMismatch:
		// The one aggregate that keeps its refusal's own code (Astra r9 #6): the
		// code is what makes the line audible in QuLog, and a summary of five
		// replays is at least as worth hearing as the first one.
		return refusalEvent{shape: refusalMismatch, code: bgPeerMismatch}
	}
	return refusalEvent{shape: refusalLogin, op: "breakglass-login", code: "rate_limited"}
}

// sessionless reports whether this shape is recorded in the actor-less line.
// Everything but a refused login at the door is: nobody authenticated for any of
// them, and naming the break-glass account would describe the operator as having
// done it.
func (s refusalShape) sessionless() bool { return s != refusalLogin }

// writeRefusal writes one line in its event's own shape — the single place that
// knows how each shape is recorded, so a new caller cannot reach for d.audit and
// silently give a sessionless event the door's root-administrator actor.
//
// It reports the durable write's verdict (Astra r3 #2). An aggregate line
// stands for refusals whose counters are cleared when it is written, so a
// caller that clears them without knowing whether the write landed has thrown
// the burst away; the two aggregates below ask.
//
// inFlight is the second half of that verdict (Astra r4 #2). An error alone
// does not say the line was lost: a cancelled context or a timeout can be
// returned by a call whose event is already with a durable writer that goes on
// to fsync it. Putting the counters back on THAT error reports the same burst
// twice — a flood that shrinks and a flood that doubles are both lies about the
// same number. So a caller restores only when inFlight is false, which is the
// one case where nothing was written and nothing will be.
func (d *breakGlassDoor) writeRefusal(r *http.Request, ev refusalEvent, detail string) (inFlight bool, err error) {
	if ev.shape.sessionless() {
		// The sessionless line names no actor: the listener's door and the path
		// are the whole of what is known, and the request is where both come
		// from — so a sessionless line with no request to read is dropped rather
		// than written in the other shape. Nothing reaches it that way today:
		// both callers of this shape are on a request goroutine.
		if d.srv == nil || r == nil {
			return false, nil
		}
		return d.srv.auditSessionlessRefusal(r, ev.code, detail)
	}
	return d.audit(r, ev.op, "denied", ev.code, detail)
}

// queuePrunedRefusal is writeRefusal for the one line that must not wait for
// anything and is not about the request that triggers it: the summary a swept
// window owes (Astra r6 #4, Astra r7 #4).
//
// The pruning sweep is its only caller, and the sweep is the reason it exists.
// It runs inside another source's refusal, it can find a whole table's worth of
// abandoned windows at once, and each one it drops owes a summary. Writing those
// durably would let one unlucky refusal spend every writer slot on news about
// sources that stopped talking minutes ago — the same amplifier #2 closed on the
// sessionless line itself, re-opened one level up. The verdict is a single bool
// because the async path has no in-flight state to tell apart.
//
// Every identifying field comes from the PRUNED WINDOW, and no http.Request is
// passed in at all (Astra r7 #4). That is not tidiness: with the request in
// hand, the two constructors read its address and its route, and the resulting
// line said that source B had made these refusals on the path B happened to be
// asking for — while the detail text, alone, named A. An operator filtering the
// trail by address gets a count attributed to the wrong host, which is worse
// than no line.
func (d *breakGlassDoor) queuePrunedRefusal(p prunedWindow, detail string) bool {
	if d.srv == nil || d.srv.auditor == nil {
		return false
	}
	if p.ev.shape.sessionless() {
		// No path. The window counted refusals across whatever routes the source
		// tried, so any single route would be a guess, and the one route this
		// summary certainly has nothing to do with is the one the triggering
		// request asked for.
		return d.srv.auditor.WriteQueued(sessionlessRefusalLine(p.ip, audit.DoorLocal, "", p.ev.code, detail))
	}
	// The door's own shape, minus the forced milestone: a summary of refusals is
	// a rate report about a source that has gone away, not a use of the door.
	// Result "denied" still puts it in front of QuLog on its own merits.
	ev := bgDoorEvent(nil, p.ev.op, "denied", p.ev.code, detail)
	ev.IP = p.ip
	return d.srv.auditor.WriteQueued(ev)
}

// bgAuditContext is the context every break-glass refusal line is written
// under: the request's values, none of its cancellation (Astra r3 #2).
//
// It is a variable, and the one thing that may replace it is a test (Astra r5
// #2). What this whole rule comes down to is a property of this context and of
// nothing else a test can see — a cancelled request must not cancel the write —
// and every attempt to demonstrate it from the outside races the admission
// select inside WriteSync, which reverting the detachment then wins often enough
// to keep the regression test green. Handing the test the context itself is
// decisive: it is cancelled, or it is not. Production never assigns to it, and
// the function it holds is the rule itself, so there is no second code path.
var bgAuditContext = func(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}

// errRefusalNotQueued is what a refused ASYNC write reports to a caller that
// cleared counters to make it. The async path has no in-flight state — the
// event is on the queue or it was turned away here and now — so this error, and
// an inFlight of false, is the whole verdict.
var errRefusalNotQueued = errors.New("the refusal line was not queued")

// sessionlessRefusalLine is the event a denial with nobody behind it is recorded
// as, built from the identity of WHOEVER IT IS ABOUT rather than from a request
// (Astra r7 #4).
//
// Taking the fields one at a time is the whole point. A per-source line is about
// the request that is being refused, so it is built from that request. A pruned
// window's summary is about a source that stopped talking minutes ago and is
// written on the goroutine of some unrelated request, so building it from that
// request put the wrong address in the IP field and the wrong route in the path,
// and left the truth in the detail text where no filter looks.
//
// The shape is the one routes_mutate.go's auditUnauthenticated writes, and
// assertSessionlessShape in breakglass_astra2_test.go pins both to it: no actor,
// the LISTENER's door, Op "auth".
func sessionlessRefusalLine(ip, door, path, code, detail string) audit.Event {
	return audit.Event{
		IP:     ip,
		Door:   door,
		Op:     "auth",
		Path:   path,
		Phase:  "result",
		Result: "denied",
		Code:   code,
		Detail: detail,
		// NOT a forced milestone (Astra r6 #2). §6.2's "a milestone on every use"
		// is about uses of the DOOR, and a forged mutation from a host that never
		// authenticated is not one.
		ForceMilestone: false,
		// And not mirrored to QuLog at all (Astra r7 #1). Leaving the automatic
		// classification to make a milestone of it — every denial is one — meant a
		// line anybody on the LAN can produce still bought an exec of log_tool, and
		// that exec was the thing standing between the audit file and the next
		// event. The line is written and kept; QuLog is for uses of the door.
		//
		// With ONE exception, and it is the most important line this door writes
		// (Astra r8 #6): a peer mismatch is a live root session's cookie turning up
		// at another address. That is not a stranger knocking, it is the emergency
		// session being replayed, and an operator scanning QuLog for what happened
		// to their NAS must find it there. The cost is bounded by the same throttle
		// as the line itself — one per source per window — so the lever r7 #1 closed
		// stays closed: a flood of cookie-less POSTs, which is what anybody on the
		// LAN can produce for free, buys no exec at all.
		Quiet: code != bgPeerMismatch,
	}
}

// sessionlessRefusalEvent is that line for the request in front of us: the peer
// that sent it, this listener's door, the route it aimed at.
func sessionlessRefusalEvent(r *http.Request, code, detail string) audit.Event {
	return sessionlessRefusalLine(ClientIP(r), doorOf(r), r.URL.Path, code, detail)
}

// auditSessionlessRefusal writes that event on the ASYNCHRONOUS path (Astra r6
// #2).
//
// It used to be a forced milestone written with WriteSync, on a context the peer
// could not cancel (Astra r3 #2) — and that made a denial nobody authenticated
// for as expensive as an operator's own mutation. Four sources refused at once
// took all four durable-writer slots, and if QuLog was slow to answer they held
// them for as long as it took: the operator's real mkdir, on the other listener,
// then failed its intent line on the admission timeout. A forged request must
// not be able to spend the slots a genuine one needs, so this shape queues
// instead, which cannot block and cannot wait.
//
// The cost is where the line lands in the FILE. A queued line is appended by the
// drain while a durable one appends itself, so a denial can turn up below a
// mutation recorded after it. Each line carries the time it was made at, which
// is what orders the record; the file's order was only ever an approximation of
// that, since every ordinary result line has taken this path all along.
//
// The context goes with it: there is nothing left for a cancellation to reach.
// A queued event belongs to the drain, and the peer hanging up cannot take it
// back — which is the property bgAuditContext was protecting, now held by
// construction rather than by care.
func (s *Server) auditSessionlessRefusal(r *http.Request, code, detail string) (bool, error) {
	if s.auditor == nil {
		return false, nil
	}
	// inFlight is always false here, and that is the point: the answer is
	// definite either way, so a caller that has to put its counters back knows
	// immediately whether to.
	if !s.auditor.WriteQueued(sessionlessRefusalEvent(r, code, detail)) {
		return false, errRefusalNotQueued
	}
	return false, nil
}

type refusalState struct {
	// ip is the address this window is ABOUT, which is not always the key it is
	// filed under (Astra r9 #6): a mismatch is tracked separately from the same
	// source's ordinary refusals, and every line the window writes has to name the
	// address rather than the key.
	ip         string
	opened     time.Time
	suppressed int
	// claimed is how many suppressed refusals have been taken out of the count
	// above by a flush that is writing their summary right now, and whose write
	// has not yet come back (Astra r4 #1).
	//
	// The count has to leave suppressed — that is what stops a second returning
	// request from writing the same summary again — but for as long as the write
	// is in flight this entry is the ONLY place the burst still exists. An entry
	// with a claim on it is therefore never deleted, by any path: not by the next
	// login from this source finding suppressed at zero, not by another source's
	// pruning sweep. If the write is then refused there is somewhere to put the
	// burst back; without the claim the rollback found nothing and a flood went
	// unreported.
	//
	// It is a count, not a flag, because a second flush may legitimately claim a
	// second burst before the first resolves: each resolution takes back only
	// what it claimed.
	claimed int
	// shape is what the SUMMARY for this window will be written as (Astra r2 #6).
	// It starts as the shape that opened the window and only ever moves towards
	// refusalSessionless: a window that counted even one sessionless denial must
	// not be summarised as an authenticated root administrator being refused,
	// whereas the reverse — a login refusal summarised in the actor-less shape —
	// is merely less specific, and true either way, because nobody has
	// authenticated at this door on either path.
	shape refusalShape
}

// noteRefusal writes at most one audit line per source per refusalWindow and
// counts the rest, in the door's own event shape.
func (d *breakGlassDoor) noteRefusal(r *http.Request, ip, op, code, detail string) {
	d.noteRefusalEvent(r, ip, ip, detail, refusalEvent{shape: refusalLogin, op: op, code: code})
}

// bgMismatchKey is the throttle key a peer mismatch from this source is counted
// under (Astra r9 #6). The NUL is what makes it a key no peerHost can spell, so
// the two windows can never collide however the address is written.
func bgMismatchKey(ip string) string { return ip + "\x00mismatch" }

// noteUnauthenticated is the same throttle over a SESSIONLESS denial (Astra r1
// #3). It cannot reuse d.audit: that event names the break-glass account as a
// root administrator actor, and a request that never authenticated has no
// actor at all. The listener's door is what is known, and that is exactly what
// auditUnauthenticated already records.
func (d *breakGlassDoor) noteUnauthenticated(r *http.Request) {
	if d == nil || d.srv == nil {
		return
	}
	ip := peerHost(r)
	d.noteRefusalEvent(r, ip, ip, "no valid session on a mutation route", refusalEvent{shape: refusalSessionless, code: "unauthorized"})
}

// notePeerMismatch records a live session cookie presented from an address the
// session was not issued to (Astra r6 #1).
//
// It is the SESSIONLESS shape, and for the same reason the others are: the
// sender proved nothing, so naming the break-glass account as a root
// administrator actor would describe the operator as having done this. It goes
// through the same throttle as every other refusal, because the thing it is most
// likely to be — a browser that has been to the door and then visits QTS on 443,
// or a page on another port fetching in a loop — repeats.
//
// The detail names no path and no cookie value: what it stands for is one
// sentence, "this cookie turned up somewhere else", and the address it turned up
// at is the throttle's own key.
// The throttle is keyed on peerHost, the raw source, exactly as the rate bucket
// and every other refusal are: the canonical form is what the PIN compares, and
// a second keying convention in the same table would be one more thing to get
// wrong for a distinction no real peer can make (one connection, one spelling).
//
// But it is keyed on that source's OWN window, not on the one its other refusals
// share (Astra r9 #6). Round 8 made this the one sessionless line QuLog hears,
// and the shared window could swallow it whole: a cookie-less POST from B opens
// B's window, the replay that follows a moment later is suppressed into the
// generic count, and the summary that eventually reports the burst says
// "unauthorized" and is Quiet — so neither the file nor QuLog names the replay,
// and producing that cookie-less POST first is free for anyone on the LAN. A
// separate key gives the mismatch its own window, its own line and its own
// summary, and the mirror stays bounded at one per source per window because the
// window is still one per source.
func (d *breakGlassDoor) notePeerMismatch(r *http.Request) {
	if d == nil || d.srv == nil {
		return
	}
	ip := peerHost(r)
	d.noteRefusalEvent(r, bgMismatchKey(ip), ip, "an emergency session cookie was presented from another address",
		refusalEvent{shape: refusalMismatch, code: bgPeerMismatch})
}

// noteRefusalEvent is the throttle itself: at most one line per source per
// refusalWindow, the rest counted and carried into the next one. The tracking
// table is bounded exactly as the source bucket is, so a spray from many
// sources can neither grow memory nor buy extra lines. ev carries the event's
// SHAPE as well as its vocabulary — a login refusal and a sessionless mutation
// denial are different events and must not be made to look alike, on the
// per-source line or on either of the aggregates (Astra r2 #6).
// key is the window this refusal is counted in and ip is the address it is
// about; they are the same string for everything except a peer mismatch, which
// has a window of its own so that a generic refusal can never hide one (Astra r9
// #6). The table's bound is unchanged — it is a bound on ENTRIES, and a source
// that produces both kinds holds two.
func (d *breakGlassDoor) noteRefusalEvent(r *http.Request, key, ip, detail string, ev refusalEvent) {
	now := d.now()
	d.mu.Lock()
	if d.refusals == nil {
		d.refusals = make(map[string]*refusalState, breakglass.MaxSources)
	}
	state := d.refusals[key]
	if state != nil && now.Sub(state.opened) < refusalWindow {
		state.suppressed++
		// One sessionless denial anywhere in the window fixes the summary's
		// shape, as refusalState.shape explains: the summary is written once for
		// everything the window counted, and it must not describe a sessionless
		// flood as the door refusing an authenticated root administrator.
		if ev.shape == refusalSessionless {
			state.shape = refusalSessionless
		}
		d.mu.Unlock()
		return
	}
	// A new window. Prune what has aged out before deciding whether there is
	// room, so a long-running daemon does not accumulate dead entries. What the
	// sweep drops with a count still on it is summarised first (Astra r6 #4), and
	// those lines are written after the lock is released, like every other one.
	var pruned []prunedWindow
	for other, old := range d.refusals {
		if other == key {
			continue
		}
		age := now.Sub(old.opened)
		// A closed window with nothing pending is dead weight. One with a
		// pending summary is kept for a second window so the source can come
		// back and collect it — but no longer: a summary nobody returned for is
		// stale news, and holding it would let abandoned entries fill the table
		// and silence the reporting for every NEW source.
		//
		// A CLAIMED entry is not dead weight at either age (Astra r4 #1): a flush
		// is holding that burst outside the count while its write is in flight,
		// and pruning the entry from under it would leave the rollback with
		// nowhere to put the burst back. The claim resolves in bounded time —
		// WriteSync's own timeout — and the resolution deletes the entry itself
		// when nothing is left on it.
		if old.claimed != 0 || age < refusalWindow {
			continue
		}
		if old.suppressed == 0 {
			delete(d.refusals, other)
			continue
		}
		if age >= 2*refusalWindow {
			// The count goes out with a line of its own before the entry does
			// (Astra r6 #4). This is the one path on which a burst was simply
			// discarded: a source that floods and then stops is never seen again,
			// so nothing of its own ever collects the summary, and two windows
			// later some unrelated source's refusal swept the count away. The
			// aggregate accounting is only complete if every counted refusal is
			// reported by someone, and for an abandoned window this is the last
			// moment anyone can.
			pruned = append(pruned, prunedWindow{ip: old.ip, count: old.suppressed, ev: old.shape.summary()})
			delete(d.refusals, other)
		}
	}
	if state == nil && len(d.refusals) >= breakglass.MaxSources {
		// The table is full of live windows — a spray across many source
		// addresses, which is a distributed attempt on the door and the most
		// interesting thing that can happen to it. Tracking each one would be
		// unbounded, so they are COUNTED and reported periodically instead
		// (round-2 P3-11). Dropping them silently would make the loudest
		// possible event the one the log says least about.
		//
		// Counted PER SHAPE, and reported in that shape (Astra r2 #6). This is
		// the branch a distributed flood actually lands in — 257 sources is all
		// it takes — so it is the branch where getting the shape wrong matters
		// most: a spray of cookie-less POSTs is exactly the sessionless case, and
		// one shared counter reported the whole of it as a break-glass login
		// refusal by the root administrator account.
		d.dropped[ev.shape]++
		dropped := d.dropped[ev.shape]
		was := d.droppedAt[ev.shape]
		report := was.IsZero() || now.Sub(was) >= refusalWindow
		if report {
			d.droppedAt[ev.shape], d.dropped[ev.shape] = now, 0
		}
		d.mu.Unlock()
		d.emitPruned(pruned)
		if report {
			inFlight, err := d.writeRefusal(r, ev.shape.summary(),
				fmt.Sprintf("door=local %d refusals from untracked sources; the %d-source table is full", dropped, breakglass.MaxSources))
			if err != nil && !inFlight {
				// The count was cleared for a line that never landed, so it goes
				// back (Astra r3 #2): the next refusal from an untracked source
				// reports the whole burst instead of restarting from one, and the
				// rate stamp is put back as it was so that next refusal may report
				// at all. Whatever arrived in the meantime is added to, not
				// overwritten.
				//
				// Only when the write is definitely lost (Astra r4 #2). A line
				// still with a durable writer will land, and restoring behind it
				// would report the same burst in the next line as well.
				d.mu.Lock()
				d.dropped[ev.shape] += dropped
				d.droppedAt[ev.shape] = was
				d.mu.Unlock()
			}
		}
		return
	}
	carried, previous := 0, ev.shape
	if state == nil {
		state = &refusalState{ip: ip}
		d.refusals[key] = state
	} else {
		carried, previous = state.suppressed, state.shape
	}
	state.opened, state.suppressed, state.shape = now, 0, ev.shape
	d.mu.Unlock()
	d.emitPruned(pruned)
	line := ev
	if carried > 0 {
		detail = fmt.Sprintf("%s (%d further refusals suppressed in the previous window)", detail, carried)
		// The carried count belongs to the window that just closed, not to this
		// refusal, so the line that reports it obeys the same rule as every other
		// summary (Astra r2 #6): a count of sessionless denials is never written
		// in the door's authenticated shape. When the two agree — which is the
		// ordinary case, a source doing one thing repeatedly — nothing changes.
		if previous == refusalSessionless && ev.shape != refusalSessionless {
			line = refusalSessionless.summary()
		}
	}
	inFlight, err := d.writeRefusal(r, line, detail)
	if err != nil && !inFlight && carried > 0 {
		// The same rule as the two aggregates (Astra r3 #2): this line carried a
		// closed window's count, and the count was zeroed to write it. A write
		// that was not admitted puts it back on the window that is now open, so
		// the next line for this source reports it rather than losing it. A write
		// still in flight is not put back (Astra r4 #2) — it is going to land.
		// The shape only ever moves towards sessionless, exactly as it does when
		// a refusal is suppressed.
		d.mu.Lock()
		if current := d.refusals[key]; current != nil && current.opened.Equal(now) {
			current.suppressed += carried
			if previous == refusalSessionless {
				current.shape = refusalSessionless
			}
		}
		d.mu.Unlock()
	}
}

// prunedWindow is one abandoned window's last words: the source it belonged to,
// what it had counted, and the shape that count has to be reported in (Astra r6
// #4). It is collected under the door's lock and written outside it.
type prunedWindow struct {
	ip    string
	count int
	ev    refusalEvent
}

// emitPruned writes the summary each swept window owed. Queued, never durable:
// the sweep can produce a table's worth of these at once, on the goroutine of a
// request that has nothing to do with any of them.
//
// A line the queue refuses is simply gone, and there is deliberately nothing to
// put it back on: the entry it belonged to has been deleted, the source stopped
// talking long ago, and re-inserting a window nobody will return to would spend
// a slot in a bounded table on news that would only be swept again. The
// auditor's own drop counter is what reports that the log lost lines.
func (d *breakGlassDoor) emitPruned(pruned []prunedWindow) {
	for _, p := range pruned {
		d.queuePrunedRefusal(p, fmt.Sprintf(
			"door=local ip=%s %d further refusals suppressed; the window aged out before the source came back", p.ip, p.count))
	}
}

// flushRefusals writes the summary lines a source earns when it comes back
// inside its budget, so a burst that stopped is visibly over rather than simply
// absent from the log.
//
// Both of the source's windows are collected (Astra r9 #6): its ordinary
// refusals, and the mismatches it is tracked separately for. A mismatch burst
// that was never flushed would be reported only by the pruning sweep two windows
// later, which is a long time to wait for news that a root cookie is being
// replayed.
func (d *breakGlassDoor) flushRefusals(r *http.Request, ip string) {
	d.flushRefusalWindow(r, ip, ip)
	d.flushRefusalWindow(r, bgMismatchKey(ip), ip)
}

// flushRefusalWindow is that flush for one window: key is where it is filed, ip
// is the address every line it writes has to name.
func (d *breakGlassDoor) flushRefusalWindow(r *http.Request, key, ip string) {
	now := d.now()
	d.mu.Lock()
	state := d.refusals[key]
	// Only once the WINDOW has elapsed. Passing the per-IP bucket is not by
	// itself recovery: an attempt can be inside the bucket and still be refused
	// by the lockout a moment later, and flushing on every such attempt would
	// re-open the window each time — turning the throttle back into one line per
	// attempt, which is the amplifier it exists to prevent.
	if state == nil || now.Sub(state.opened) < refusalWindow {
		d.mu.Unlock()
		return
	}
	suppressed, shape, opened := state.suppressed, state.shape, state.opened
	if suppressed == 0 {
		// Nothing to report, so the closed window is simply forgotten — unless
		// another flush is holding a claim on it (Astra r4 #1). This is the path
		// that used to delete the entry out from under an in-flight summary: the
		// claim had already taken the count out of suppressed, so a second login
		// from the same source arrived, saw nothing pending, and threw away the
		// one record of a burst that was still being written.
		if state.claimed == 0 {
			delete(d.refusals, key)
		}
		d.mu.Unlock()
		return
	}
	// The count is CLAIMED here and the entry kept until the write resolves
	// (Astra r3 #2, Astra r4 #1). Claiming it under the lock is what stops two
	// returning requests from writing the same summary twice; recording the claim
	// ON the entry is what keeps the entry alive while the write is in flight,
	// because the state is the only place the burst still exists.
	state.suppressed, state.claimed = 0, state.claimed+suppressed
	d.mu.Unlock()
	// In the shape of what the window COUNTED, not of the login that happens to
	// be collecting it (Astra r2 #6). Only a login reaches this function, so
	// writing the summary through d.audit gave every flush the door's
	// root-administrator actor — including the flush of a window that held
	// nothing but sessionless mutation denials from a host that had not
	// authenticated and was not trying to.
	inFlight, err := d.writeRefusal(r, shape.summary(),
		fmt.Sprintf("door=local ip=%s %d further refusals suppressed; the source is inside its budget again", ip, suppressed))
	d.mu.Lock()
	defer d.mu.Unlock()
	current := d.refusals[key]
	if current == nil {
		// Nothing holds a claimed entry open except a bug: every deletion path
		// checks the claim (Astra r4 #1). If one somehow got past, the burst is
		// gone either way and there is nothing useful to re-insert — a fresh
		// entry here would spend a slot in a table this source no longer holds
		// one in, on news nobody will come back for.
		return
	}
	// The claim is resolved either way: it is no longer in flight.
	current.claimed -= suppressed
	if current.claimed < 0 {
		current.claimed = 0
	}
	if err != nil && !inFlight {
		// Definitely not written (Astra r4 #2). Put the burst back and let the
		// next return collect it. Whatever the source did in the meantime is
		// added to, never overwritten, and the shape moves only towards
		// sessionless, exactly as it does when a refusal is suppressed.
		//
		// A write that FAILED but is still in flight is left alone: that line is
		// with a durable writer and will land, and putting the count back would
		// have the next summary report the same burst a second time.
		current.suppressed += suppressed
		if shape == refusalSessionless {
			current.shape = refusalSessionless
		}
		return
	}
	// Written, or on its way. The entry goes only if it is still the window that
	// was flushed, nothing has been counted against it since, and no other flush
	// is holding a claim: a refusal that arrived while the summary was being
	// written has a window of its own to be reported in, and deleting it here
	// would hand the source a fresh unthrottled line.
	if current.suppressed == 0 && current.claimed == 0 && current.opened.Equal(opened) {
		delete(d.refusals, key)
	}
}

// audit writes one break-glass event. Every one of them is a forced milestone
// and therefore mirrored to QuLog (contract §6.2): this door is rare by
// construction, so the QuLog volume is bounded by how often it is used, and an
// operator asking "who got in when Apache was down" must not have to
// reconstruct it from the JSON lines.
//
// It returns the durable write's verdict, and whether a failed one is still in
// flight (Astra r4 #2). Almost every caller ignores both — the line is a record,
// not a gate — but the aggregate refusal lines do not, because they clear the
// counters they stand for (Astra r3 #2) and must neither lose a burst nor
// report it twice.
func (d *breakGlassDoor) audit(r *http.Request, op, result, code, detail string) (bool, error) {
	if d.srv == nil || d.srv.auditor == nil {
		return false, nil
	}
	ctx := context.Background()
	if r != nil {
		ctx = bgAuditContext(r)
	}
	ev := bgDoorEvent(r, op, result, code, detail)
	ev.ForceMilestone = true
	return d.srv.auditor.WriteSyncInFlight(ctx, ev)
}

// bgDoorEvent is the event shape of the door itself: the break-glass account as
// the actor, this listener's door, the real peer. Shared by the durable path
// above and the queued one (Astra r6 #4), which differ in how the line is
// written and in nothing about what it says — except the forced milestone, which
// the caller sets, because it is a statement about the EVENT rather than about
// the shape.
func bgDoorEvent(r *http.Request, op, result, code, detail string) audit.Event {
	ip := ""
	if r != nil {
		ip = peerHost(r)
	}
	return audit.Event{
		Actor: "break-glass", UID: 0, Admin: true, Root: true,
		IP: ip, Door: audit.DoorLocal, Op: op, Phase: "result",
		Result: result, Code: code, Detail: detail,
	}
}

// AuditBreakGlass records a break-glass event that happens outside a request —
// the listener binding at start-up, a certificate generated or regenerated —
// as a forced milestone. Exported because cmd owns the listener's lifetime.
func (s *Server) AuditBreakGlass(op, result, detail string) {
	if s.auditor == nil {
		return
	}
	_ = s.auditor.WriteSync(context.Background(), audit.Event{
		Actor: "break-glass", UID: 0, Admin: true, Root: true, Door: audit.DoorLocal,
		Op: op, Phase: "result", Result: result, Detail: detail, ForceMilestone: true,
	})
}
