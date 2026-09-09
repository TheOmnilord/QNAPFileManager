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
	AuthTimeout  time.Duration
	Now          func() time.Time
	authFailures failureLimiter
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
	return &Server{cfg: cfg, backend: b, verifier: v, ids: ids, platform: p, pinned: pinned, version: version, logger: logger, sessions: make(map[string]*session)}
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
	return s.security(h)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	if api || r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Cache-Control", "no-store")
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
		case errors.Is(err, context.DeadlineExceeded):
			writeError(w, 504, "auth_timeout", "Authentication timed out. Try again.", "", r.URL.Path, "")
		case errors.Is(err, qtsauth.ErrOverloaded):
			w.Header().Set("Retry-After", "2")
			writeError(w, 503, "overloaded", "Authentication is busy. Try again shortly.", "", r.URL.Path, "")
		case errors.Is(err, errAuthRateLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "rate_limited", "Too many failed authentication attempts. Try again in a minute.", "", r.URL.Path, "")
		case errors.Is(err, errSessionStoreFull):
			writeError(w, 503, "session_store_full", "The session store is full. Try again later.", "", r.URL.Path, "")
		default:
			s.fail(w, r, "unauthorized", "Sign in to QTS again to continue.", "", "")
		}
		return
	}
	if !safeMethod(r.Method) {
		if sess == nil {
			s.fail(w, r, "unauthorized", "Sign in to QTS to continue.", "", "")
			return
		}
		if !validCSRF(r, sess.csrf) {
			s.fail(w, r, "permission", "The request could not be verified. Refresh and try again.", "", "")
			return
		}
	}
	if !api {
		s.static(w, r)
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
	if sess == nil && r.URL.Path != "/api/session" {
		s.fail(w, r, "unauthorized", "Sign in to QTS to continue.", "", "")
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
