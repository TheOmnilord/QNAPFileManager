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
	s.bg = &breakGlassDoor{
		srv:      s,
		gate:     &breakglass.Gate{},
		cred:     cred,
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
	sess := s.bg.resolve(w, r)
	if sess == nil {
		// api/session is the one API answer an unauthenticated page may read, on
		// this listener exactly as on the other: it is what tells the sign-in
		// page which door it is standing at.
		if r.Method == http.MethodGet && r.URL.Path == "/api/session" {
			s.sessionInfo(w, r, nil)
			return nil, false
		}
		if !safeMethod(r.Method) && isMutationRoute(r.URL.Path) {
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

// resolve maps the cookie to a live session, applying the peer pin, the idle
// timeout, the absolute lifetime and the credential-stamp eviction. It returns
// nil when the request is unauthenticated, having already destroyed anything
// stale.
func (d *breakGlassDoor) resolve(w http.ResponseWriter, r *http.Request) *session {
	c, err := r.Cookie(bgCookie)
	if err != nil || c.Value == "" {
		return nil
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
		return nil
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
	if bgPeer(r) != sess.peer {
		d.mu.Unlock()
		d.notePeerMismatch(r)
		return nil
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
		return nil
	}
	sess.seen = now
	snap := sess.snapshot()
	d.mu.Unlock()
	d.setCookie(w, sess.id, int(bgIdle.Seconds()))
	return snap
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
	// Only a caller holding the session's own CSRF token may destroy it, the
	// same rule every other unsafe request follows — and only from the address
	// the session belongs to (Astra r6 #1). Destroying a session is a mutation
	// like any other, so this route obeys the pin too rather than being the one
	// place a replayed cookie can still reach a live session.
	if sess == nil || !validCSRF(r, sess.csrf) || bgPeer(r) != sess.peer {
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
	if s == refusalSessionless {
		return refusalEvent{shape: refusalSessionless, code: "unauthorized"}
	}
	return refusalEvent{shape: refusalLogin, op: "breakglass-login", code: "rate_limited"}
}

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
	if ev.shape == refusalSessionless {
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

// queueRefusal is writeRefusal for a line that must not wait for anything: the
// same two shapes, both on the async path (Astra r6 #4).
//
// The pruning sweep is its only caller, and the sweep is the reason it exists.
// It runs inside another source's refusal, it can find a whole table's worth of
// abandoned windows at once, and each one it drops owes a summary. Writing those
// durably would let one unlucky refusal spend every writer slot on news about
// sources that stopped talking minutes ago — the same amplifier #2 closed on the
// sessionless line itself, re-opened one level up. The verdict is a single bool
// because the async path has no in-flight state to tell apart.
func (d *breakGlassDoor) queueRefusal(r *http.Request, ev refusalEvent, detail string) bool {
	if d.srv == nil || d.srv.auditor == nil {
		return false
	}
	if ev.shape == refusalSessionless {
		if r == nil {
			return false
		}
		return d.srv.auditor.WriteQueued(sessionlessRefusalEvent(r, ev.code, detail))
	}
	// The door's own shape, minus the forced milestone: a summary of refusals is
	// a rate report about a source that has gone away, not a use of the door.
	// Result "denied" still puts it in front of QuLog on its own merits.
	return d.srv.auditor.WriteQueued(bgDoorEvent(r, ev.op, "denied", ev.code, detail))
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

// sessionlessRefusalEvent is the event a denial with nobody behind it is
// recorded as. The shape is the one routes_mutate.go's auditUnauthenticated
// writes, and assertSessionlessShape in breakglass_astra2_test.go pins both to
// it: no actor, the LISTENER's door, the path, Op "auth".
func sessionlessRefusalEvent(r *http.Request, code, detail string) audit.Event {
	return audit.Event{
		IP:     ClientIP(r),
		Door:   doorOf(r),
		Op:     "auth",
		Path:   r.URL.Path,
		Phase:  "result",
		Result: "denied",
		Code:   code,
		Detail: detail,
		// NOT a forced milestone (Astra r6 #2). §6.2's "a milestone on every use"
		// is about uses of the DOOR, and a forged mutation from a host that never
		// authenticated is not one. The line is still classified on its own merits
		// — every denial is — so QuLog still hears about it; what it no longer does
		// is demand a durable writer and a synchronous QuLog call per line.
		ForceMilestone: false,
	}
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
	d.noteRefusalEvent(r, ip, detail, refusalEvent{shape: refusalLogin, op: op, code: code})
}

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
	d.noteRefusalEvent(r, ip, "no valid session on a mutation route", refusalEvent{shape: refusalSessionless, code: "unauthorized"})
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
func (d *breakGlassDoor) notePeerMismatch(r *http.Request) {
	if d == nil || d.srv == nil {
		return
	}
	d.noteRefusalEvent(r, peerHost(r), "an emergency session cookie was presented from another address",
		refusalEvent{shape: refusalSessionless, code: bgPeerMismatch})
}

// noteRefusalEvent is the throttle itself: at most one line per source per
// refusalWindow, the rest counted and carried into the next one. The tracking
// table is bounded exactly as the source bucket is, so a spray from many
// sources can neither grow memory nor buy extra lines. ev carries the event's
// SHAPE as well as its vocabulary — a login refusal and a sessionless mutation
// denial are different events and must not be made to look alike, on the
// per-source line or on either of the aggregates (Astra r2 #6).
func (d *breakGlassDoor) noteRefusalEvent(r *http.Request, ip, detail string, ev refusalEvent) {
	now := d.now()
	d.mu.Lock()
	if d.refusals == nil {
		d.refusals = make(map[string]*refusalState, breakglass.MaxSources)
	}
	state := d.refusals[ip]
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
	for key, old := range d.refusals {
		if key == ip {
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
			delete(d.refusals, key)
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
			pruned = append(pruned, prunedWindow{ip: key, count: old.suppressed, ev: old.shape.summary()})
			delete(d.refusals, key)
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
		d.emitPruned(r, pruned)
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
		state = &refusalState{}
		d.refusals[ip] = state
	} else {
		carried, previous = state.suppressed, state.shape
	}
	state.opened, state.suppressed, state.shape = now, 0, ev.shape
	d.mu.Unlock()
	d.emitPruned(r, pruned)
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
		if current := d.refusals[ip]; current != nil && current.opened.Equal(now) {
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
func (d *breakGlassDoor) emitPruned(r *http.Request, pruned []prunedWindow) {
	for _, p := range pruned {
		d.queueRefusal(r, p.ev, fmt.Sprintf(
			"door=local ip=%s %d further refusals suppressed; the window aged out before the source came back", p.ip, p.count))
	}
}

// flushRefusals writes the one summary line a source earns when it comes back
// inside its budget, so a burst that stopped is visibly over rather than simply
// absent from the log.
func (d *breakGlassDoor) flushRefusals(r *http.Request, ip string) {
	now := d.now()
	d.mu.Lock()
	state := d.refusals[ip]
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
			delete(d.refusals, ip)
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
	current := d.refusals[ip]
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
		delete(d.refusals, ip)
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
