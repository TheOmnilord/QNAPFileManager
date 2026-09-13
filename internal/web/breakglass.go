package web

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// was full, and droppedAt rate-bounds the line that reports them. Guarded
	// by mu.
	dropped   int
	droppedAt time.Time

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
	cred := &localCred{path: configPath, pinned: s.cfg.Auth.Local}
	// The cost is read from the hash that is actually IN FORCE, not from the
	// snapshot this process started with (round-3 P3). A daemon that started
	// with no password and armed the door later would otherwise measure the
	// default cost 11 while serving a cost-15 hash, and size its request
	// deadline to a queue four times faster than the real one — turning a
	// correct password that waited its turn into "not accepted", which is the
	// exact failure §5 exists to prevent.
	live, _ := cred.get()
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
		// be a deadline on a read that is already blocked.
		_ = http.NewResponseController(w.ResponseWriter).SetReadDeadline(time.Now().Add(bgDrainDeadline))
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

// Unwrap is how http.ResponseController reaches the real ResponseWriter, and so
// the connection underneath it. Without it every SetReadDeadline on this
// listener — the login body read included — answers ErrNotSupported and does
// nothing at all.
func (w *bgRefusal) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// --- the credential ----------------------------------------------------------

// localCred re-reads the break-glass credential from the config file rather
// than caching it, guarded by an mtime+size check, so a password change from
// the shell takes effect on the next attempt without a restart: the operator
// who is already repairing a broken NAS should not have to restart the app they
// are repairing it with (contract §4.3).
type localCred struct {
	path   string
	pinned config.Local // used when path is empty (fixtures, the dev loop)

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
	if c.path == "" {
		return c.pinned, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(c.path)
	if err != nil {
		if os.IsNotExist(err) && !c.have {
			// No config file at all is the first-run state, not a failure: there
			// is simply no password, and the listener will not have bound.
			return config.Local{}, nil
		}
		return config.Local{Updated: c.current.Updated}, err
	}
	if c.have && fi.ModTime().Equal(c.mod) && fi.Size() == c.size {
		return c.current, nil
	}
	loaded, err := config.Load(c.path)
	if err != nil {
		return config.Local{Updated: c.current.Updated}, err
	}
	c.have, c.mod, c.size, c.current = true, fi.ModTime(), fi.Size(), loaded.Auth.Local
	return c.current, nil
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
			s.auditUnauthenticated(r, "unauthorized", "no valid session on a mutation route")
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

// resolve maps the cookie to a live session, applying the idle timeout, the
// absolute lifetime and the credential-stamp eviction. It returns nil when the
// request is unauthenticated, having already destroyed anything stale.
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
	reason := ""
	switch {
	case !now.Before(sess.issued.Add(bgLifetime)):
		reason = "absolute lifetime reached"
	case !now.Before(sess.seen.Add(bgIdle)):
		reason = "idle timeout"
	case credErr == nil && sess.updated != live.Updated:
		reason = "the break-glass password changed"
	}
	if reason != "" {
		d.removeLocked(sess)
		d.mu.Unlock()
		d.clearCookie(w)
		d.audit(r, "breakglass-session", "denied", "session_expired", fmt.Sprintf("door=local ip=%s destroyed: %s", peerHost(r), reason))
		return nil
	}
	sess.seen = now
	snap := sess.snapshot()
	d.mu.Unlock()
	d.setCookie(w, sess.id, int(bgIdle.Seconds()))
	return snap
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

func (d *breakGlassDoor) removeLocked(sess *bgSession) {
	if sess == nil {
		return
	}
	delete(d.sessions, sess.id)
	if sess.order != nil {
		d.order.Remove(sess.order)
		sess.order = nil
	}
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
		d.fail(ctx, w, r, start, ip, "malformed body", false)
		return
	}
	if len(req.Password) > breakglass.MaxPasswordBytes {
		d.fail(ctx, w, r, start, ip, "oversized password", false)
		return
	}

	release, err := d.gate.Admit()
	if err != nil {
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again shortly.", time.Second, "verification queue full")
		return
	}
	// Released on every return path, including the context ending under us.
	defer release()

	locked, retry, left := d.gate.Locked()
	if left {
		// Exactly one "lockout left" milestone per lockout: the call that
		// observes the expiry is the one that clears it.
		d.audit(r, "breakglass-lockout", "ok", "", fmt.Sprintf("door=local ip=%s lockout ended", ip))
	}
	if locked {
		// The body never reveals whether the password offered was right.
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "locked_out", "Too many failed attempts. Try again later.", retry, fmt.Sprintf("locked, %ds remaining", int(retry.Seconds())))
		return
	}

	cred, credErr := d.cred.get()
	if credErr != nil {
		d.srv.logger.Printf("break-glass: the credential could not be read: %v", credErr)
	}
	var verifyErr error
	if err := d.gate.Verify(ctx, func() error {
		verifyErr = breakglass.Verify(cred.Hash, req.Password)
		return nil
	}); err != nil {
		// Never verified: the caller waited behind other verifications until the
		// door's deadline, or went away. Answering "that password was not
		// accepted" would be a lie about a password nothing ever looked at — and
		// a cruel one, since the queue is longest exactly when an operator is
		// racing a brute-forcer for the door (round-2 P2-7). It is a rate
		// answer, and it says to try again.
		d.reject(ctx, w, r, start, http.StatusTooManyRequests, "rate_limited", "The emergency door is busy. Try again in a moment.", 2*time.Second, "queue wait expired before verification")
		return
	}
	if credErr != nil {
		// Our failure, not the caller's: fail closed, but do not let an
		// unreadable config file walk the operator up the lockout ladder.
		d.fail(ctx, w, r, start, ip, "credential unreadable", false)
		return
	}
	if verifyErr != nil {
		// A wrong password is the ONLY thing that advances the ladder.
		//
		// "No password configured" deliberately does not (round-2 P2-2): after
		// `break-glass disable` on a running daemon the listener stays bound,
		// so any LAN host could walk five attempts up to the 1800 s cap — and
		// the operator's fresh set-password would then be refused by a lockout
		// they never caused, at the exact moment they were trying to get back
		// in. The answer and the latency are identical either way, so nothing
		// is disclosed by the distinction.
		cause, advance := "wrong password", true
		if errors.Is(verifyErr, breakglass.ErrNoPassword) {
			cause, advance = "no password configured", false
		}
		d.fail(ctx, w, r, start, ip, cause, advance)
		return
	}

	d.gate.Succeeded()
	sess, err := d.issue(cred)
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
	// same rule every other unsafe request follows.
	if sess == nil || !validCSRF(r, sess.csrf) {
		d.mu.Unlock()
		// No cookie is written on this path: an unverifiable request changes
		// nothing at all, including the browser's state.
		writeError(w, statusCode("permission"), "permission", "The request could not be verified. Refresh and try again.", "", r.URL.Path, "")
		return
	}
	d.removeLocked(sess)
	d.mu.Unlock()
	d.audit(r, "breakglass-session", "ok", "", fmt.Sprintf("door=local ip=%s session destroyed", peerHost(r)))
	d.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// issue creates a session, evicting the oldest when the cap is reached.
func (d *breakGlassDoor) issue(cred config.Local) (*bgSession, error) {
	now := d.now()
	sess := &bgSession{
		id: rand.Text(), csrf: rand.Text(), issued: now, seen: now, updated: cred.Updated,
		// Root, so it keys to the same root worker as any other admin session
		// (backend.Principal.Key). The name is not a QTS user and is not
		// resolvable by idmap: it exists to be legible in the audit trail.
		who: backend.Principal{User: "break-glass", UID: 0, GID: 0, Groups: []int{0}, Root: true},
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = make(map[string]*bgSession)
	}
	// Expire before evicting: a store full of idle sessions must not cost the
	// operator the one they are about to need.
	for _, old := range d.sessions {
		if !now.Before(old.issued.Add(bgLifetime)) || !now.Before(old.seen.Add(bgIdle)) {
			d.removeLocked(old)
		}
	}
	for len(d.sessions) >= bgMaxSessions {
		front := d.order.Front()
		if front == nil {
			return nil, errors.New("the break-glass session store is full")
		}
		d.removeLocked(front.Value.(*bgSession))
	}
	sess.order = d.order.PushBack(sess)
	d.sessions[sess.id] = sess
	return sess, nil
}

// destroy removes one session by id; it is what the shared /api/logout route
// calls for a break-glass session.
func (d *breakGlassDoor) destroy(id string) {
	d.mu.Lock()
	d.removeLocked(d.sessions[id])
	d.mu.Unlock()
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
// advance says whether this was a CREDENTIAL VERDICT — a password was offered
// and the stored hash rejected it. Only those walk the lockout ladder. A
// malformed body, an oversized field, a request abandoned while queued or a
// config file we could not read are our problem or a broken client's, and
// letting five of them reach the 1800 s cap would hand any LAN host a way to
// shut the emergency door without ever guessing a password (round-1 P2-7).
// Every path keeps the uniform body, the uniform latency and the per-IP bucket
// charge it has already paid.
func (d *breakGlassDoor) fail(ctx context.Context, w http.ResponseWriter, r *http.Request, start time.Time, ip, cause string, advance bool) {
	detail := fmt.Sprintf("door=local ip=%s %s", ip, cause)
	if advance {
		_, retry, entered := d.gate.Failed()
		detail = fmt.Sprintf("%s, %d consecutive", detail, d.gate.Failures())
		// The denial is recorded BEFORE the response is written (contract
		// §16.5): an attacker who disconnects on seeing the status must not be
		// able to discard the record of the attempt.
		d.audit(r, "breakglass-login", "denied", "auth_failed", detail)
		if entered {
			d.audit(r, "breakglass-lockout", "denied", "locked_out", fmt.Sprintf("door=local ip=%s lockout %d failures, %ds", ip, d.gate.Failures(), int(retry.Seconds())))
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

type refusalState struct {
	opened     time.Time
	suppressed int
}

// noteRefusal writes at most one audit line per source per refusalWindow and
// counts the rest. The tracking table is bounded exactly as the source bucket
// is: a spray from forged sources can neither grow memory nor buy extra lines.
func (d *breakGlassDoor) noteRefusal(r *http.Request, ip, op, code, detail string) {
	now := d.now()
	d.mu.Lock()
	if d.refusals == nil {
		d.refusals = make(map[string]*refusalState, breakglass.MaxSources)
	}
	state := d.refusals[ip]
	if state != nil && now.Sub(state.opened) < refusalWindow {
		state.suppressed++
		d.mu.Unlock()
		return
	}
	// A new window. Prune what has aged out before deciding whether there is
	// room, so a long-running daemon does not accumulate dead entries.
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
		if age >= refusalWindow && (old.suppressed == 0 || age >= 2*refusalWindow) {
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
		d.dropped++
		dropped := d.dropped
		report := d.droppedAt.IsZero() || now.Sub(d.droppedAt) >= refusalWindow
		if report {
			d.droppedAt, d.dropped = now, 0
		}
		d.mu.Unlock()
		if report {
			d.audit(r, "breakglass-login", "denied", "rate_limited",
				fmt.Sprintf("door=local %d refusals from untracked sources; the %d-source table is full", dropped, breakglass.MaxSources))
		}
		return
	}
	carried := 0
	if state == nil {
		state = &refusalState{}
		d.refusals[ip] = state
	} else {
		carried = state.suppressed
	}
	state.opened, state.suppressed = now, 0
	d.mu.Unlock()
	if carried > 0 {
		detail = fmt.Sprintf("%s (%d further refusals suppressed in the previous window)", detail, carried)
	}
	d.audit(r, op, "denied", code, detail)
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
	suppressed := state.suppressed
	delete(d.refusals, ip)
	d.mu.Unlock()
	if suppressed > 0 {
		d.audit(r, "breakglass-login", "denied", "rate_limited",
			fmt.Sprintf("door=local ip=%s %d further refusals suppressed; the source is inside its budget again", ip, suppressed))
	}
}

// audit writes one break-glass event. Every one of them is a forced milestone
// and therefore mirrored to QuLog (contract §6.2): this door is rare by
// construction, so the QuLog volume is bounded by how often it is used, and an
// operator asking "who got in when Apache was down" must not have to
// reconstruct it from the JSON lines.
func (d *breakGlassDoor) audit(r *http.Request, op, result, code, detail string) {
	if d.srv == nil || d.srv.auditor == nil {
		return
	}
	ctx, ip := context.Background(), ""
	if r != nil {
		ctx, ip = context.WithoutCancel(r.Context()), peerHost(r)
	}
	_ = d.srv.auditor.WriteSync(ctx, audit.Event{
		Actor: "break-glass", UID: 0, Admin: true, Root: true,
		IP: ip, Door: audit.DoorLocal, Op: op, Phase: "result",
		Result: result, Code: code, Detail: detail, ForceMilestone: true,
	})
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
