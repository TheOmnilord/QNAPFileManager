package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/qtsauth"
)

// fakeBackend intentionally uses os only in the test package. No fsops import:
// production web code must have no route around the Backend identity boundary.
type fakeBackend struct {
	dir  string
	last backend.Principal
	opts fsx.ListOptions
}

func (b *fakeBackend) osPath(p string) string {
	return filepath.Join(b.dir, filepath.FromSlash(strings.TrimPrefix(p, "/")))
}
func (b *fakeBackend) Ping(_ context.Context, p backend.Principal) error { b.last = p; return nil }
func (b *fakeBackend) Stats() any                                        { return map[string]int{"workers": 1} }
func (b *fakeBackend) Stat(_ context.Context, p backend.Principal, name string) (fsx.Entry, error) {
	b.last = p
	fi, err := os.Lstat(b.osPath(name))
	if err != nil {
		return fsx.Entry{}, err
	}
	e := fsx.Entry{Type: fsx.TypeString(fi.Mode()), Size: fi.Size(), MTime: fi.ModTime(), Mode: fsx.ModeOctal(fi.Mode()), ModeStr: fsx.ModeString(fi.Mode())}
	e.SetName([]byte(fsx.Base(name)))
	e.SetPath([]byte(name))
	return e, nil
}
func (b *fakeBackend) Readlink(_ context.Context, p backend.Principal, name string) (string, error) {
	b.last = p
	return os.Readlink(b.osPath(name))
}
func (b *fakeBackend) OpenRead(ctx context.Context, p backend.Principal, name string) (*os.File, fsx.Entry, error) {
	e, err := b.Stat(ctx, p, name)
	if err != nil {
		return nil, e, err
	}
	if e.Type != "file" {
		return nil, e, fsx.ErrUnsupported
	}
	f, err := os.Open(b.osPath(name))
	return f, e, err
}
func (b *fakeBackend) List(ctx context.Context, p backend.Principal, name string, o fsx.ListOptions) (fsx.Listing, error) {
	b.last = p
	b.opts = o
	files, err := os.ReadDir(b.osPath(name))
	if err != nil {
		return fsx.Listing{}, err
	}
	entries := []fsx.Entry{}
	for _, f := range files {
		if !o.ShowHidden && strings.HasPrefix(f.Name(), ".") {
			continue
		}
		e, err := b.Stat(ctx, p, fsx.Join(name, f.Name()))
		if err != nil {
			return fsx.Listing{}, err
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		a, z := entries[i], entries[j]
		cmp := strings.Compare(a.Name, z.Name)
		switch o.Sort {
		case "size":
			if a.Size < z.Size {
				cmp = -1
			} else if a.Size > z.Size {
				cmp = 1
			}
		case "mtime":
			if a.MTime.Before(z.MTime) {
				cmp = -1
			} else if a.MTime.After(z.MTime) {
				cmp = 1
			}
		case "type":
			if a.Type != z.Type {
				cmp = strings.Compare(a.Type, z.Type)
			}
		}
		if o.Desc {
			return cmp > 0
		}
		return cmp < 0
	})
	total := len(entries)
	start := min(o.Offset, total)
	end := min(start+o.Limit, total)
	return fsx.Listing{Path: name, Parent: fsx.Parent(name), Entries: entries[start:end], Total: total, Truncated: end < total}, nil
}

func fixture(t *testing.T, pinned bool) (*Server, *fakeBackend) {
	t.Helper()
	b := &fakeBackend{dir: t.TempDir()}
	for name, data := range map[string]string{"a.txt": "0123456789", "b #.txt": "hello", "binary": "hi\x00there", ".hidden": "secret"} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var p *backend.Principal
	if pinned {
		p = &backend.Principal{User: "dev", UID: 1000, GID: 100, Groups: []int{100, 200}, Root: true}
	}
	return New(config.Default(), b, nil, nil, nil, p, "test", nil), b
}
func request(s *Server, method, target string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func sessionCookie(t *testing.T, s *Server) (*http.Cookie, string) {
	t.Helper()
	w := request(s, "GET", "/api/session", nil, nil)
	if w.Code != 200 {
		t.Fatalf("session: %d %s", w.Code, w.Body)
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie")
	}
	return cookies[0], body.CSRF
}

func TestStaticAndHeaders(t *testing.T) {
	s, _ := fixture(t, false)
	s.cfg.Web.ProxyPrefix = "/qnapfilemanager"
	s.cfg.Web.FrameAncestors = []string{"https://desktop.example"}
	for _, prefix := range []string{"", "/qnapfilemanager"} {
		for _, asset := range []struct{ path, ct string }{{"/", "text/html"}, {"/index.html", "text/html"}, {"/app.css", "text/css"}, {"/js/app.js", "text/javascript"}} {
			w := request(s, "GET", prefix+asset.path, nil, nil)
			if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), asset.ct) {
				t.Errorf("%s: %d %v", asset.path, w.Code, w.Header())
			}
			// QTS desktop opens this same-origin application in an iframe. Even
			// SAMEORIGIN must not creep in: CSP alone owns the framing policy.
			if _, exists := w.Header()["X-Frame-Options"]; exists {
				t.Fatal("X-Frame-Options must be absent")
			}
			if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'self' https://desktop.example") {
				t.Errorf("CSP: %s", csp)
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing nosniff")
			}
			if strings.HasPrefix(asset.ct, "text/html") && (!strings.Contains(w.Body.String(), `id="app"`) || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("shell contract")
			}
		}
	}
	w := request(s, "GET", "/api/fs/list?path=/", nil, nil)
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !strings.Contains(w.Body.String(), `"code":"unauthorized"`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Location") != "" {
		t.Fatal("authentication must never redirect")
	}
}

func TestStaticShellWithInvalidSession(t *testing.T) {
	for _, switched := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "QTS user switch"}[switched], func(t *testing.T) {
			s, _ := fixture(t, false)
			s.cfg.Web.ProxyPrefix = "/qnapfilemanager"
			old := &session{id: "old-session", csrf: "private-csrf", who: backend.Principal{User: "private-user"}, expires: time.Now().Add(-time.Second)}
			headers := map[string]string{}
			if switched {
				old.expires = time.Now().Add(time.Hour)
				old.binding = qtsauth.CacheKey(qtsauth.Cred{Kind: "qtoken", User: "private-user", Token: "old-token"})
				headers["Cookie"] = "qfm_sid=old-session; NAS_USER=new-user; qtoken=new-token"
			}
			s.sessions[old.id] = old
			cookie := &http.Cookie{Name: "qfm_sid", Value: old.id}
			for _, prefix := range []string{"", "/qnapfilemanager"} {
				for _, asset := range []struct{ path, name, ct string }{
					{"/", "index.html", "text/html"},
					{"/index.html", "index.html", "text/html"},
					{"/app.css", "app.css", "text/css"},
					{"/js/app.js", "js/app.js", "text/javascript"},
				} {
					w := request(s, "GET", prefix+asset.path, cookie, headers)
					raw, err := assets.ReadFile("static/" + asset.name)
					if err != nil {
						t.Fatal(err)
					}
					want := raw
					if asset.name == "index.html" {
						// The shell is the one asset served with the base injected;
						// it must still carry no session data (checked below).
						want = s.shellWithBase(raw)
					}
					if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), asset.ct) || w.Body.String() != string(want) {
						t.Fatalf("public asset %s: %d %s", prefix+asset.path, w.Code, w.Body)
					}
					if len(w.Result().Cookies()) != 0 || s.sessionLookups != 0 {
						t.Fatal("static assets must not authenticate or personalize the response")
					}
				}
			}
			for _, endpoint := range []string{"/api/session", "/api/fs/list?path=/"} {
				w := request(s, "GET", endpoint, cookie, headers)
				if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
					t.Fatalf("invalid session %s: %d %s", endpoint, w.Code, w.Body)
				}
			}
		})
	}
}

func TestEveryAPIRequiresAuthentication(t *testing.T) {
	s, _ := fixture(t, false)
	for endpoint, method := range routes {
		w := request(s, method, endpoint, nil, nil)
		if endpoint == "/api/session" && method == "GET" {
			// The one public answer: a first visit with nothing presented
			// learns only that it is not signed in, never a csrf token.
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":false`) || !strings.Contains(w.Body.String(), `"csrf":""`) {
				t.Errorf("anonymous %s: %d %s", endpoint, w.Code, w.Body)
			}
			continue
		}
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("unauthenticated %s: %d %s", endpoint, w.Code, w.Body)
		}
	}
	for _, endpoint := range []string{"/api", "/api/unknown"} {
		if w := request(s, "GET", endpoint, nil, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s: %d", endpoint, w.Code)
		}
	}
}

func TestPinnedSessionCookieAndIdentity(t *testing.T) {
	s, b := fixture(t, true)
	s.cfg.Web.ProxyPrefix = "/qnapfilemanager"
	for _, secure := range []bool{false, true} {
		headers := map[string]string{}
		if secure {
			headers["X-Forwarded-Proto"] = "https"
		}
		w := request(s, "GET", "/qnapfilemanager/api/session", nil, headers)
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("expected session cookie")
		}
		c := cookies[0]
		if c.Name != "qfm_sid" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != secure || c.Path != "/qnapfilemanager/" || c.MaxAge != 43200 {
			t.Fatalf("cookie: %+v", c)
		}
		if !strings.Contains(w.Body.String(), `"rootMode":false`) || !strings.Contains(w.Body.String(), `"user":"dev"`) {
			t.Fatal(w.Body.String())
		}
		listed := request(s, "GET", "/api/fs/list?path=/", c, nil)
		if listed.Code != 200 {
			t.Fatal(listed.Body.String())
		}
		if b.last.User != "dev" || b.last.Root || b.last.UID != 1000 || len(b.last.Groups) != 2 {
			t.Fatalf("principal %+v", b.last)
		}
	}
	w := request(s, "GET", "https://example.com/api/session", nil, nil)
	if !w.Result().Cookies()[0].Secure {
		t.Fatal("TLS cookie must be secure")
	}
}

func TestListPagingAndPaths(t *testing.T) {
	s, b := fixture(t, true)
	c, _ := sessionCookie(t, s)
	var names []string
	for offset := 0; offset < 3; offset++ {
		w := request(s, "GET", fmt.Sprintf("/api/fs/list?pathB64=%s&offset=%d&limit=1&sort=name", base64.RawURLEncoding.EncodeToString([]byte("/")), offset), c, nil)
		var page fsx.Listing
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || page.Total != 3 || len(page.Entries) != 1 {
			t.Fatalf("page: %d %+v", w.Code, page)
		}
		names = append(names, page.Entries[0].Name)
	}
	if strings.Join(names, ",") != "a.txt,b #.txt,binary" {
		t.Fatal(names)
	}
	w := request(s, "GET", "/api/fs/list?path=/&hidden=true&sort=size&desc=true&volumes=true&limit=500", c, nil)
	if w.Code != 200 || !b.opts.ShowHidden || !b.opts.Desc || !b.opts.ShowVolumeRoots || !b.opts.ResolveLinks || b.opts.Sort != "size" {
		t.Fatalf("options: %+v %s", b.opts, w.Body)
	}
	for _, target := range []string{"/api/fs/list?pathB64=!!!", "/api/fs/list?path=relative", "/api/fs/list?path=/&offset=-1", "/api/fs/list?path=/&sort=invalid", "/api/fs/list?path=/&hidden=maybe"} {
		if w := request(s, "GET", target, c, nil); w.Code != 400 {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	for _, endpoint := range []string{"/api/fs/stat", "/api/fs/text", "/api/fs/download"} {
		target := endpoint + "?pathB64=" + base64.RawURLEncoding.EncodeToString([]byte("/b #.txt"))
		if w := request(s, "GET", target, c, nil); w.Code != 200 {
			t.Errorf("%s: %d %s", target, w.Code, w.Body)
		}
	}
}

func TestDownloadRangeAndText(t *testing.T) {
	s, _ := fixture(t, true)
	c, _ := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/download?path=/a.txt", c, map[string]string{"Range": "bytes=2-5"})
	if w.Code != 206 || w.Body.String() != "2345" || w.Header().Get("Content-Range") != "bytes 2-5/10" {
		t.Fatalf("Range: %d %s %v", w.Code, w.Body, w.Header())
	}
	disposition := w.Header().Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment;") || !strings.Contains(disposition, `filename="a.txt"`) || !strings.Contains(disposition, "filename*=UTF-8''a.txt") {
		t.Fatal(disposition)
	}
	for _, test := range []struct {
		path              string
		binary, truncated bool
		size              int
	}{{"/binary&max=1", true, true, 1}, {"/a.txt&max=4", false, true, 4}, {"/a.txt", false, false, 10}} {
		w := request(s, "GET", "/api/fs/text?path="+test.path, c, nil)
		var body struct {
			Binary, Truncated bool
			Bytes             int
			ETag              string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Binary != test.binary || body.Truncated != test.truncated || body.Bytes != test.size || body.ETag == "" {
			t.Fatalf("text: %+v", body)
		}
	}
}

func TestCSRFAndLogout(t *testing.T) {
	s, _ := fixture(t, true)
	c, csrf := sessionCookie(t, s)
	for _, h := range []map[string]string{
		{"Origin": "http://example.com"},
		{"X-QFM-CSRF": csrf, "Origin": "https://evil.example"},
		{"X-QFM-CSRF": csrf},
		{"X-QFM-CSRF": csrf, "Origin": "http://example.com", "Sec-Fetch-Site": "cross-site"},
	} {
		w := request(s, "POST", "/api/logout", c, h)
		if w.Code != 403 {
			t.Errorf("CSRF %v: %d", h, w.Code)
		}
	}
	w := request(s, "POST", "/api/logout", c, map[string]string{"X-QFM-CSRF": csrf, "Referer": "http://example.com/qnapfilemanager/"})
	if w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body)
	}
	if cookies := w.Result().Cookies(); cookies[len(cookies)-1].MaxAge != -1 {
		t.Fatal("cookie not expired")
	}
	s.mu.Lock()
	_, exists := s.sessions[c.Value]
	s.mu.Unlock()
	if exists {
		t.Fatal("session retained")
	}
}

func TestQTSRevalidationAndBinding(t *testing.T) {
	var reject atomic.Bool
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
			return
		}
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username><isAdmin>1</isAdmin></r>")
	}))
	defer endpoint.Close()
	s, b := fixture(t, false)
	passwd := filepath.Join(b.dir, "passwd")
	groups := filepath.Join(b.dir, "group")
	if err := os.WriteFile(passwd, []byte("dev:x:1000:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groups, []byte("administrators:x:200:dev\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ids = idmap.Open(passwd, groups)
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	login := func() *http.Cookie {
		w := request(s, "GET", "/api/session", nil, map[string]string{"Cookie": "NAS_USER=dev; qtoken=valid"})
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"admin":true`) {
			t.Fatalf("login %d %s", w.Code, w.Body)
		}
		return w.Result().Cookies()[0]
	}
	c := login()
	old := s.sessions[c.Value]
	if old.binding != qtsauth.CacheKey(qtsauth.Cred{Kind: "qtoken", User: "dev", Token: "valid"}) || old.kind != "qtoken" {
		t.Fatal("missing binding")
	}
	// An administrator's session operates as root (owner decision, like File
	// Station), which api/session reports as rootMode.
	if !old.who.Root || !old.admin {
		t.Fatalf("admin session is not root: root=%v admin=%v", old.who.Root, old.admin)
	}
	if w := request(s, "GET", "/api/session", c, nil); !strings.Contains(w.Body.String(), `"rootMode":true`) {
		t.Fatalf("api/session should report rootMode for an admin: %s", w.Body)
	}
	// An app cookie alone works until the periodic verification denies its
	// retained QTS credential. QTS's credential is never returned to the UI.
	if w := request(s, "GET", "/api/fs/list?path=/", c, nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	reject.Store(true)
	s.verifier.InvalidateAll()
	old.checked = time.Now().Add(-61 * time.Second)
	w := request(s, "GET", "/api/fs/list?path=/", c, nil)
	if w.Code != 401 || w.Header().Get("Location") != "" {
		t.Fatalf("revalidation %d %s", w.Code, w.Body)
	}
	if _, exists := s.sessions[c.Value]; exists {
		t.Fatal("failed session was not destroyed")
	}
	reject.Store(false)
	s.verifier.InvalidateAll()
	c = login()
	w = request(s, "GET", "/api/fs/list?path=/", nil, map[string]string{"Cookie": "qfm_sid=" + c.Value + "; NAS_USER=dev; qtoken=rotated"})
	if w.Code != 401 {
		t.Fatalf("changed binding: %d", w.Code)
	}
}

func TestStatusRootsDiagAndErrors(t *testing.T) {
	s, _ := fixture(t, true)
	c, _ := sessionCookie(t, s)
	for _, endpoint := range []string{"/api/status", "/api/fs/roots", "/api/ids?kind=users", "/api/ids?kind=groups"} {
		if w := request(s, "GET", endpoint, c, nil); w.Code != 200 {
			t.Errorf("%s: %d %s", endpoint, w.Code, w.Body)
		}
	}
	if w := request(s, "GET", "/api/diag", c, nil); w.Code != 403 {
		t.Fatal("diag should require admin")
	}
	s.sessions[c.Value].admin = true
	if w := request(s, "GET", "/api/diag", c, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"workers":1`) {
		t.Fatal(w.Body.String())
	}
	if w := request(s, "GET", "/api/fs/stat?path=/missing", c, nil); w.Code != 404 {
		t.Fatal(w.Body.String())
	}
	for code, want := range map[string]int{"bad_request": 400, "unauthorized": 401, "permission": 403, "protected": 403, "readonly": 403, "not_found": 404, "exists": 409, "not_empty": 409, "cross_device": 409, "conflict": 409, "too_large": 413, "unsupported": 415, "queue_full": 429, "worker_gone": 503, "internal": 500} {
		if got := statusCode(code); got != want {
			t.Errorf("%s = %d", code, got)
		}
	}
	p, _ := platform.FromMountinfo(strings.NewReader("1 0 0:1 / /share rw - tmpfs tmpfs rw\n"))
	s.platform = p
	if !s.ramShare() || s.class("/share") != "warn" || s.class("/etc/config") != "protected" || s.class("/etcetera") != "normal" {
		t.Fatal("class hint boundaries")
	}
}

func TestClientIP(t *testing.T) {
	for _, tc := range []struct{ remote, xff, want string }{{"127.0.0.1:12", "198.51.100.1, 192.0.2.3", "192.0.2.3"}, {"192.0.2.5:12", "198.51.100.1", "192.0.2.5"}, {"[::1]:12", "bad", "::1"}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.xff)
		if got := ClientIP(r); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}

func TestEmbeddedIDContract(t *testing.T) {
	html, err := assets.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(string(html), -1) {
		if ids[m[1]] {
			t.Errorf("duplicate id %s", m[1])
		}
		ids[m[1]] = true
	}
	patterns := []*regexp.Regexp{regexp.MustCompile(`\$\(['"]#([A-Za-z][\w-]*)['"]\)`), regexp.MustCompile(`getElementById\(['"]([A-Za-z][\w-]*)['"]\)`), regexp.MustCompile(`querySelector\(['"]#([A-Za-z][\w-]*)['"]\)`)}
	files, _ := assets.ReadDir("static/js")
	for _, file := range files {
		data, _ := assets.ReadFile("static/js/" + file.Name())
		for _, pattern := range patterns {
			for _, m := range pattern.FindAllStringSubmatch(string(data), -1) {
				if !ids[m[1]] {
					t.Errorf("%s references missing #%s", file.Name(), m[1])
				}
			}
		}
	}
	if regexp.MustCompile(`(?i)<script[^>]*>\s*[^<\s]|\sstyle=`).Match(html) {
		t.Fatal("inline script or style in shell")
	}
}

func TestEmbeddedRouteContract(t *testing.T) {
	used := map[string]bool{}
	files, _ := assets.ReadDir("static/js")
	re := regexp.MustCompile(`['"](api/[a-zA-Z0-9/_-]+)(?:[?'"#])`)
	for _, file := range files {
		data, _ := assets.ReadFile("static/js/" + file.Name())
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			route := "/" + m[1]
			if _, ok := routes[route]; !ok {
				t.Errorf("%s calls unregistered %s", file.Name(), route)
			}
			used[route] = true
		}
	}
	for route := range routes {
		if !used[route] {
			t.Logf("registered route not called by UI: %s", route)
		}
	}
}

func TestWebDoesNotImportFSOps(t *testing.T) {
	// Check all production Go files, not the fake backend above.
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"qnapfilemanager/internal/fsops"`) {
			t.Errorf("INV-1: %s imports fsops", file.Name())
		}
	}
}
