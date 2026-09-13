// Package web is the root HTTP front-end. All user filesystem access crosses
// backend.Backend; it must never import internal/fsops (PLAN.md INV-1).
package web

import (
	"container/list"
	"context"
	"embed"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/qtsauth"
	"qnapfilemanager/internal/trashroot"
)

//go:embed static
var assets embed.FS

type Server struct {
	cfg      config.Config
	backend  backend.Backend
	verifier *qtsauth.Verifier
	ids      *idmap.Map
	platform *platform.Platform
	pinned   *backend.Principal
	version  string
	logger   *log.Logger

	// M1 mutation spine. All three are nil-tolerant so read-only fixtures and
	// the placeholder server in cmd keep working; the mutation routes refuse
	// service when guard or mutator is absent.
	guard   *guard.Guard
	auditor *audit.Logger
	mutator backend.Mutator

	// M2-A job spine. Both are nil-tolerant, like the M1 trio above: a fixture
	// without them answers a clear 500 on the job routes instead of panicking.
	// jobRunner is the worker-side long-lived RPC (the pool); jobMgr is the
	// front-end's own bookkeeping (queue, progress, cancellation, retention).
	jobRunner backend.Jobs
	jobMgr    *jobs.Manager
	// searchRetained budgets the bytes every FINISHED search job's hits still
	// hold, which is the one part of a retained job that is unbounded; see
	// routes_search.go. It has its own mutex and is usable zero.
	searchRetained searchRetention
	// bulkReads bounds how many large single-job results may be in flight at
	// once, which is what the retention ledger cannot see; see routes_search.go.
	// Its limits are settable before serving, for tests; usable zero.
	bulkReads bulkReadLimiter
	// archiveReads bounds concurrent archive downloads and how long one chunk
	// write may stall; see routes_archive.go. Same type, separate pool: an
	// archive and a search result bound different resources, and sharing one
	// would let either starve the other. Usable zero (New sets its wording).
	archiveReads bulkReadLimiter
	// uploads bounds how many upload requests may be in flight (per session and
	// process-wide) and how long one may go silent before it is dropped; see
	// routes_upload.go. Its limits are settable before serving, for tests; it
	// has its own mutex and is usable zero.
	uploads uploadLimiter
	// ensureTrash is trashroot.Ensure, indirected so a test can drive the
	// trash-root creation path (and its audit milestone) on a host whose mount
	// table has no storage mounts. Never nil after New.
	ensureTrash func(*platform.Platform, string) (string, bool, error)
	// ConfigPath is where a read-only toggle is persisted (config.Save); empty
	// means the change is applied in memory only. AuditPath is the JSON-lines
	// file /api/audit/export streams. Both are set by the caller after New.
	ConfigPath string
	AuditPath  string
	// Root is the -jail API↔OS mapping the guard uses to resolve parent
	// symlinks before a mutation (resolveForGuard). The zero value is the
	// identity mapping production uses; a jailed dev loop or a test sets it so
	// EvalSymlinks lands inside the jail. INV-1 permits this front-end symlink
	// resolution (PLAN.md: Lstat/EvalSymlinks/statfs/mountinfo are guard work).
	Root  fsx.Root
	cfgMu sync.Mutex // serialises read-only toggles and their persistence

	mu                sync.Mutex
	archiveSelections map[string]map[string]archiveSelection // session ID -> token; guarded by mu
	sessions          map[string]*session
	byCredential      map[string]*session
	byUser            map[string]*list.List
	sessionOrder      list.List
	// Set before serving; nonpositive limits select the defaults.
	MaxSessions, MaxSessionsPerUser int
	sessionLookups                  uint64 // indexed lookups, guarded by mu
	// AuthTimeout defaults to 10 seconds; config currently has no auth deadline.
	// Set these before serving. Now is injectable for failure-limiter tests.
	AuthTimeout       time.Duration
	Now               func() time.Time
	authFailures      failureLimiter
	authAdmission     authAdmission
	authTransportOnce sync.Once
}

func New(cfg config.Config, b backend.Backend, v *qtsauth.Verifier, ids *idmap.Map, p *platform.Platform, pinned *backend.Principal, version string, logger *log.Logger, g *guard.Guard, auditor *audit.Logger, mutator backend.Mutator) *Server {
	cfg.Normalize()
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if ids == nil {
		ids = idmap.Open("", "")
	}
	if p == nil {
		p, _ = platform.FromMountinfo(strings.NewReader(""))
	}
	if pinned != nil {
		cp := *pinned
		cp.Root = false
		cp.Groups = append([]int{}, pinned.Groups...)
		pinned = &cp
	}
	s := &Server{cfg: cfg, backend: b, verifier: v, ids: ids, platform: p, pinned: pinned, version: version, logger: logger, sessions: make(map[string]*session), guard: g, auditor: auditor}
	// The mutator may be supplied explicitly or, as the production pool does,
	// implemented by the backend itself; type-assert it so cmd can pass nil.
	if mutator == nil {
		if m, ok := b.(backend.Mutator); ok {
			mutator = m
		}
	}
	s.mutator = mutator
	s.ensureTrash = trashroot.Ensure
	s.archiveReads.what = "archive downloads"
	s.archiveReads.perSessionLimit = maxArchiveDownloadsPerSession
	s.archiveReads.totalLimit = maxArchiveDownloadsTotal
	// The same pool that implements Backend and Mutator implements Jobs; type-
	// assert it so cmd can wire the job manager alone (SetJobs).
	if j, ok := b.(backend.Jobs); ok {
		s.jobRunner = j
	}
	// The admission channels are created here, before any goroutine can see
	// the server, rather than lazily on the first request: the race detector
	// caught a test reading them while the first request's once.Do was still
	// assigning them. The lazy path stays as a guard for zero-value fixtures.
	s.authAdmission.init()
	return s
}

// SetJobs wires the M2-A job spine: runner is the worker-side long-lived RPC
// (the pool) and mgr the front-end manager whose Reap ticker and Close the
// caller owns. Either may be nil, which leaves the job routes answering 500
// "this build cannot run jobs" — the same shape mutationsReady uses.
func (s *Server) SetJobs(runner backend.Jobs, mgr *jobs.Manager) {
	if runner != nil {
		s.jobRunner = runner
	}
	s.jobMgr = mgr
}

// routes is also the source of truth for the static JS endpoint contract test.
// The value is the set of methods a path answers; a request for anything else
// gets 405 with an Allow header. The two job-id forms (/api/jobs/<id> and
// /api/jobs/<id>/cancel) are not literal paths and are matched by routeFor.
var routes = map[string][]string{
	"/api/session": {"GET"}, "/api/status": {"GET"}, "/api/fs/list": {"GET"},
	"/api/fs/stat": {"GET"}, "/api/fs/roots": {"GET"}, "/api/fs/download": {"GET"},
	"/api/fs/text": {"GET"}, "/api/ids": {"GET"}, "/api/diag": {"GET"}, "/api/logout": {"POST"},
	"/api/fs/mkdir": {"POST"}, "/api/fs/rename": {"POST"}, "/api/fs/delete": {"POST"},
	"/api/settings": {"GET", "POST"}, "/api/audit": {"GET"}, "/api/audit/export": {"GET"},
	"/api/jobs": {"GET"}, "/api/jobs/delete": {"POST"}, "/api/jobs/size": {"POST"},
	"/api/jobs/copy": {"POST"}, "/api/jobs/move": {"POST"},
	"/api/fs/upload": {"POST"}, "/api/fs/archive": {"GET"}, "/api/jobs/search": {"POST"},
	"/api/fs/archive/select": {"POST"},
	"/api/trash":             {"GET"}, "/api/trash/restore": {"POST"}, "/api/trash/empty": {"POST"},
}

// routeFor resolves a request path to the methods it answers. Literal routes
// win, so /api/jobs/delete is the delete route and never a job whose id is
// "delete" — job ids are 16 hex characters (jobs.newID) and jobPath insists on
// exactly that shape, so the two vocabularies cannot collide.
func routeFor(p string) ([]string, bool) {
	if methods, ok := routes[p]; ok {
		return methods, true
	}
	if _, action, ok := jobPath(p); ok {
		if action == "cancel" {
			return []string{"POST"}, true
		}
		return []string{"GET"}, true
	}
	return nil, false
}

// allowedMethod reports whether method is served by one of methods; a HEAD is
// answered wherever GET is.
func allowedMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method || (method == "HEAD" && m == "GET") {
			return true
		}
	}
	return false
}

func (s *Server) Handler() http.Handler {
	inner := http.HandlerFunc(s.serve)
	var h http.Handler = inner
	if p := s.cfg.Web.ProxyPrefix; p != "" {
		mux := http.NewServeMux()
		mux.Handle(p+"/", http.StripPrefix(p, inner))
		mux.Handle(p, http.RedirectHandler(p+"/", http.StatusMovedPermanently))
		mux.Handle("/", inner)
		h = mux
	}
	return s.security(collapseDoubleSlashes(h))
}

// collapseDoubleSlashes rewrites "/qnapfilemanager//app.css" to
// "/qnapfilemanager/app.css" before routing.
//
// QTS's reverse proxy joins its target "http://127.0.0.1:8770/qnapfilemanager/"
// with the remainder of the request path, so "/qnapfilemanager/app.css" reaches
// this daemon as "/qnapfilemanager//app.css" (and the bare "/qnapfilemanager"
// as "/qnapfilemanager/", which is why the shell alone loaded). Left alone,
// http.ServeMux cleans the doubled slash and answers a 307 to the cleaned path,
// which is the very URL the browser asked for, so it loops forever — observed
// on QTS 5.2.9 and QuTS hero alike as a shell with no stylesheet and no
// script. The doubled slash is an artefact of the join, not something the
// client asked for, so it is normalised here instead of redirected. Every
// run of slashes anywhere in the path collapses; no filename can contain one.
func collapseDoubleSlashes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "//") {
			r2 := r.Clone(r.Context())
			u := *r.URL
			u.Path = squeezeSlashes(u.Path)
			if u.RawPath != "" {
				u.RawPath = squeezeSlashes(u.RawPath)
			}
			r2.URL = &u
			r = r2
		}
		next.ServeHTTP(w, r)
	})
}

func squeezeSlashes(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// bodiedRead reports a GET or HEAD that claims to carry a request body.
//
// Such a request is not merely odd, it is a lever. net/http drains an unread
// request body — up to 256 KiB — before it writes the response headers, unless
// the response is already closeAfterReply, and nothing arms a read deadline for
// that drain. So a GET with "Content-Length: 1" and no body blocks the handler
// at its FIRST WRITE, holding whatever that handler is holding: an archive's
// admission slot, its worker hold and its pipe with the audit pair unfinished,
// or a bulk-result slot. A handful of them empties the global pools while the
// attacker sends nothing at all (round-13 P1).
//
// No legitimate client sends one: a body on a GET has no defined meaning, and
// this app's own UI never does it. Refusing early costs nothing and the refusal
// carries Connection: close, which is also what lets net/http skip the drain.
func bodiedRead(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return r.ContentLength != 0 || len(r.TransferEncoding) > 0
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	api := r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
	if api || r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	// Before routing, before authentication, before any handler can take a slot
	// or a worker hold: a read that claims a body never reaches one.
	if bodiedRead(r) {
		w.Header().Set("Connection", "close")
		s.logger.Printf("request ip=%q method=%s op=%q code=bad_request path=\"\" (read with a body)", ClientIP(r), r.Method, r.URL.Path)
		writeError(w, http.StatusBadRequest, "bad_request", "A GET or HEAD request must not carry a body.", "", r.URL.Path, "")
		return
	}
	if !api {
		// Embedded assets contain no user data. Let the shell load even with
		// stale QTS credentials; api/session drives the sign-in notice.
		s.static(w, r)
		return
	}
	// For upload POST, wrap the ResponseWriter early so any error (auth, method, etc)
	// gets Connection: close before being sent. This prevents large unauthenticated
	// uploads from sending the entire body before getting a 401 response.
	if r.URL.Path == "/api/fs/upload" && r.Method == http.MethodPost {
		w = uploadRefusal{w}
	}
	timeout := s.AuthTimeout
	if timeout <= 0 {
		timeout = defaultAuthTimeout
	}
	authCtx, authCancel := context.WithTimeout(r.Context(), timeout)
	sess, err := s.authenticate(w, r.WithContext(authCtx))
	if authCtx.Err() != nil {
		err = authCtx.Err()
	}
	authCancel()
	if err != nil {
		switch {
		case errors.Is(err, errCSRF):
			s.fail(w, r, "permission", "The request could not be verified. Refresh and try again.", "", "")
		case errors.Is(err, errAuthRetry):
			w.Header().Set("Retry-After", "1")
			writeError(w, 503, "retry", "Authentication was interrupted. Try again.", "", r.URL.Path, "")
		case qtsUnavailable(err):
			w.Header().Set("Retry-After", "2")
			writeError(w, 503, "qts_unavailable", "QTS authentication is temporarily unavailable. Try again shortly.", "", r.URL.Path, "")
		case errors.Is(err, qtsauth.ErrOverloaded):
			w.Header().Set("Retry-After", "2")
			writeError(w, 503, "overloaded", "Authentication is busy. Try again shortly.", "", r.URL.Path, "")
		case errors.Is(err, errAuthRateLimited):
			w.Header().Set("Retry-After", "1")
			writeError(w, 429, "rate_limited", "Too many failed authentication attempts. Try again in a second.", "", r.URL.Path, "")
		case errors.Is(err, errSessionStoreFull):
			writeError(w, 503, "session_store_full", "The session store is full. Try again later.", "", r.URL.Path, "")
		default:
			// api/session is the one API answer an unauthenticated page may
			// read: it carries no user data and tells the shell whether to
			// show the sign-in notice. The packaging smoke test reads
			// readOnly from it before any QTS session exists.
			if r.Method == http.MethodGet && r.URL.Path == "/api/session" && anonymous(r) {
				s.sessionInfo(w, r, nil)
				return
			}
			// An unsafe request to a mutation route that never reached a valid
			// session is a denial worth recording (adv 10).
			if !safeMethod(r.Method) && isMutationRoute(r.URL.Path) {
				s.auditUnauthenticated(r, "unauthorized", "no valid session on a mutation route")
			}
			s.fail(w, r, "unauthorized", "Sign in to QTS again to continue.", "", "")
		}
		return
	}
	if sess == nil {
		// A first visit with nothing presented: api/session answers publicly
		// (see the anonymous rule above) so the shell can render its sign-in
		// notice and the smoke test can read readOnly.
		if r.Method == http.MethodGet && r.URL.Path == "/api/session" && anonymous(r) {
			s.sessionInfo(w, r, nil)
			return
		}
		s.fail(w, r, "unauthorized", "Sign in to QTS to continue.", "", "")
		return
	}
	if r.URL.Path != "/api/fs/upload" && r.URL.Path != "/api/fs/archive" {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	methods, ok := routeFor(r.URL.Path)
	if !ok {
		s.fail(w, r, "not_found", "No such endpoint.", "", "")
		return
	}
	if !allowedMethod(methods, r.Method) {
		w.Header().Set("Allow", strings.Join(methods, ", "))
		writeError(w, 405, "bad_request", "Method not allowed.", "", r.URL.Path, "")
		return
	}
	if r.URL.Path != "/api/fs/download" && r.URL.Path != "/api/fs/upload" && r.URL.Path != "/api/fs/archive" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}
	switch r.URL.Path {
	case "/api/session":
		s.sessionInfo(w, r, sess)
	case "/api/status":
		s.status(w, r, sess)
	case "/api/fs/list":
		s.list(w, r, sess)
	case "/api/fs/stat":
		s.stat(w, r, sess)
	case "/api/fs/roots":
		s.roots(w, r, sess)
	case "/api/fs/download":
		s.download(w, r, sess)
	case "/api/fs/upload":
		s.upload(w, r, sess)
	case "/api/fs/archive":
		s.archive(w, r, sess)
	case "/api/fs/archive/select":
		s.archiveSelect(w, r, sess)
	case "/api/jobs/search":
		s.jobSearch(w, r, sess)
	case "/api/fs/text":
		s.text(w, r, sess)
	case "/api/ids":
		s.identities(w, r)
	case "/api/diag":
		s.diag(w, r, sess)
	case "/api/fs/mkdir":
		s.mkdir(w, r, sess)
	case "/api/fs/rename":
		s.rename(w, r, sess)
	case "/api/fs/delete":
		s.delete(w, r, sess)
	case "/api/settings":
		// GET and HEAD are reads; only POST mutates. A HEAD must never reach
		// postSettings — Go's decoder would apply a HEAD body without CSRF or an
		// Origin check (adv 5).
		if r.Method == http.MethodPost {
			s.postSettings(w, r, sess)
		} else {
			s.getSettings(w, r, sess)
		}
	case "/api/audit":
		s.auditTail(w, r, sess)
	case "/api/audit/export":
		s.auditExport(w, r, sess)
	case "/api/jobs":
		s.jobList(w, r, sess)
	case "/api/jobs/delete":
		s.jobDelete(w, r, sess)
	case "/api/jobs/copy":
		s.jobTransfer(w, r, sess, "copy")
	case "/api/jobs/move":
		s.jobTransfer(w, r, sess, "move")
	case "/api/jobs/size":
		s.jobSize(w, r, sess)
	case "/api/trash":
		s.trashList(w, r, sess)
	case "/api/trash/restore":
		s.trashRestore(w, r, sess)
	case "/api/trash/empty":
		s.trashEmpty(w, r, sess)
	case "/api/logout":
		s.destroy(sess.id)
		s.cookie(w, r, "", -1)
		writeJSON(w, map[string]bool{"authenticated": false})
	default:
		// The two job-id forms; routeFor has already vetted the shape and the
		// method, so anything reaching here is /api/jobs/<id>[/cancel].
		if id, action, ok := jobPath(r.URL.Path); ok {
			if action == "cancel" {
				s.jobCancel(w, r, sess, id)
			} else {
				s.jobGet(w, r, sess, id)
			}
		}
	}
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if !safeMethod(r.Method) {
		writeError(w, 405, "bad_request", "Use GET.", "", r.URL.Path, "")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	ct := ""
	switch {
	case name == "index.html":
		ct = "text/html; charset=utf-8"
	case name == "app.css":
		ct = "text/css; charset=utf-8"
	case strings.HasPrefix(name, "js/") && strings.HasSuffix(name, ".js"):
		ct = "text/javascript; charset=utf-8"
	}
	if ct == "" || !fs.ValidPath(name) {
		s.fail(w, r, "not_found", "No such asset.", "", "")
		return
	}
	data, err := assets.ReadFile("static/" + name)
	if err != nil {
		s.fail(w, r, "not_found", "No such asset.", "", "")
		return
	}
	if name == "index.html" {
		data = s.shellWithBase(data)
	}
	w.Header().Set("Content-Type", ct)
	if r.Method != "HEAD" {
		_, _ = w.Write(data)
	}
}

// readOnly reports the live read-only state: the guard is authoritative once
// wired (its flag is atomic and the settings toggle drives it), otherwise the
// loaded config value stands.
func (s *Server) readOnly() bool {
	if s.guard != nil {
		return s.guard.ReadOnly()
	}
	return s.cfg.ReadOnly
}

// basePath is the absolute path every asset and API URL is built under:
// QPKG_PROXY_PATH plus a slash behind the QTS proxy, "/" otherwise.
func (s *Server) basePath() string {
	return strings.TrimSuffix(s.cfg.Web.ProxyPrefix, "/") + "/"
}

// shellWithBase rewrites the shell's two asset references to absolute URLs
// under basePath and injects that base for the scripts.
//
// The QTS desktop opens the app at the bare proxy path, "/qnapfilemanager"
// with no trailing slash (seen in the browser's network tab on the first
// hardware test): a relative "app.css" then resolves to "/app.css" on the QTS
// origin, outside the proxy, and QTS answers its own 404. Absolute URLs under
// the configured prefix hold whatever the document URL looks like, and they
// still work on the loopback port, where the mux serves the prefix too. The
// base travels as a meta element rather than <base>, which the CSP forbids.
func (s *Server) shellWithBase(shell []byte) []byte {
	base := s.basePath()
	out := string(shell)
	out = strings.Replace(out, `href="app.css"`, `href="`+base+`app.css"`, 1)
	out = strings.Replace(out, `src="js/app.js"`, `src="`+base+`js/app.js"`, 1)
	out = strings.Replace(out, `<meta charset="utf-8">`, `<meta charset="utf-8"><meta name="qfm-base" content="`+base+`">`, 1)
	return []byte(out)
}
