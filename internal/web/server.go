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

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/qtsauth"
)

//go:embed static
var assets embed.FS

type Server struct {
	cfg          config.Config
	backend      backend.Backend
	verifier     *qtsauth.Verifier
	ids          *idmap.Map
	platform     *platform.Platform
	pinned       *backend.Principal
	version      string
	logger       *log.Logger
	mu           sync.Mutex
	sessions     map[string]*session
	byCredential map[string]*session
	byUser       map[string]*list.List
	sessionOrder list.List
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

func New(cfg config.Config, b backend.Backend, v *qtsauth.Verifier, ids *idmap.Map, p *platform.Platform, pinned *backend.Principal, version string, logger *log.Logger) *Server {
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
	s := &Server{cfg: cfg, backend: b, verifier: v, ids: ids, platform: p, pinned: pinned, version: version, logger: logger, sessions: make(map[string]*session)}
	// The admission channels are created here, before any goroutine can see
	// the server, rather than lazily on the first request: the race detector
	// caught a test reading them while the first request's once.Do was still
	// assigning them. The lazy path stays as a guard for zero-value fixtures.
	s.authAdmission.init()
	return s
}

// routes is also the source of truth for the static JS endpoint contract test.
var routes = map[string]string{
	"/api/session": "GET", "/api/status": "GET", "/api/fs/list": "GET",
	"/api/fs/stat": "GET", "/api/fs/roots": "GET", "/api/fs/download": "GET",
	"/api/fs/text": "GET", "/api/ids": "GET", "/api/diag": "GET", "/api/logout": "POST",
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
	return s.security(collapseLeadingSlashes(h))
}

// collapseLeadingSlashes rewrites "//app.css" to "/app.css" before routing.
//
// QTS's reverse proxy strips QPKG_PROXY_PATH and joins its target
// "http://127.0.0.1:8770/" with what is left of the request path, so
// "/qnapfilemanager/app.css" reaches this daemon as "//app.css". Left alone,
// http.ServeMux cleans that path and answers a 307 to "/app.css"; the proxy
// rewrites the Location back to "/qnapfilemanager/app.css", the browser
// follows it, and the loop repeats — observed on QTS 5.2.9 and QuTS hero alike
// as a shell with no stylesheet, no script and every API call looping. Only
// the bare "/qnapfilemanager" survived, because it forwards as "/". The doubled
// slash is an artefact of the join, not a path the client asked for, so it is
// normalised here instead of redirected.
func collapseLeadingSlashes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "//") {
			r2 := r.Clone(r.Context())
			u := *r.URL
			u.Path = "/" + strings.TrimLeft(u.Path, "/")
			if u.RawPath != "" {
				u.RawPath = "/" + strings.TrimLeft(u.RawPath, "/")
			}
			r2.URL = &u
			r = r2
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	api := r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")
	if api || r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	if !api {
		// Embedded assets contain no user data. Let the shell load even with
		// stale QTS credentials; api/session drives the sign-in notice.
		s.static(w, r)
		return
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	method, ok := routes[r.URL.Path]
	if !ok {
		s.fail(w, r, "not_found", "No such endpoint.", "", "")
		return
	}
	if r.Method != method && !(r.Method == "HEAD" && method == "GET") {
		w.Header().Set("Allow", method)
		writeError(w, 405, "bad_request", "Method not allowed.", "", r.URL.Path, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if r.URL.Path != "/api/fs/download" {
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
	case "/api/fs/text":
		s.text(w, r, sess)
	case "/api/ids":
		s.identities(w, r)
	case "/api/diag":
		s.diag(w, r, sess)
	case "/api/logout":
		s.destroy(sess.id)
		s.cookie(w, r, "", -1)
		writeJSON(w, map[string]bool{"authenticated": false})
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
	w.Header().Set("Content-Type", ct)
	if r.Method != "HEAD" {
		_, _ = w.Write(data)
	}
}
