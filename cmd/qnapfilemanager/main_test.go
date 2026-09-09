package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
)

// The -worker switch has to be recognised before anything else runs: a worker
// is re-executed with the kernel already holding it to another uid, and it
// must not fall through into the front-end's startup.
func TestIsWorkerInvocation(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-worker", "-uid", "1000"}, true},
		{[]string{"--worker", "-uid", "1000"}, true},
		{[]string{"-uid", "1000", "-worker"}, true},
		{[]string{"-worker=true"}, true},
		{nil, false},
		{[]string{"serve"}, false},
		{[]string{"serve", "-config", "c.json"}, false},
		{[]string{"version"}, false},
		// A path that merely contains the word must not trigger it.
		{[]string{"serve", "-config", "/tmp/-worker.json"}, false},
		{[]string{"serve", "-jail", "worker"}, false},
	}
	for _, c := range cases {
		if got := isWorkerInvocation(c.args); got != c.want {
			t.Errorf("isWorkerInvocation(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestRunWorkerRejectsInvalidUID(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWorker([]string{"-worker", "-uid", "-1"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("uid -1")) {
		t.Fatalf("the rejected uid must be reported, got %q", errOut.String())
	}
}

func TestSessionEndpoint(t *testing.T) {
	cfg := config.Default()
	s := newServer(cfg, fsx.Root{}, log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", ct)
	}
	var got sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Authenticated {
		t.Error("nothing is authenticated yet")
	}
	if got.Version != version {
		t.Errorf("version = %q, want %q", got.Version, version)
	}
	// The CI smoke test greps for exactly this, so it is part of the contract.
	if !got.ReadOnly {
		t.Error("readOnly must be reported as the config has it")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"readOnly":true`)) {
		t.Errorf("the smoke test greps for \"readOnly\":true, body was %s", rec.Body)
	}
}

func TestSessionReflectsReadOnlyOff(t *testing.T) {
	cfg := config.Default()
	cfg.ReadOnly = false
	s := newServer(cfg, fsx.Root{}, log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	var got sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ReadOnly {
		t.Fatal("readOnly = true, want false")
	}
}

func TestUnknownRouteIs404JSON(t *testing.T) {
	s := newServer(config.Default(), fsx.Root{}, log.New(io.Discard, "", 0))
	for _, p := range []string{"/missing", "/api/missing"} {
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", p, rec.Code)
		}
		var e apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
			t.Errorf("%s: body is not the error envelope: %v", p, err)
		} else if e.Error.Code != "not_found" {
			t.Errorf("%s: code = %q", p, e.Error.Code)
		}
	}
}

func TestSessionRejectsWrongMethod(t *testing.T) {
	s := newServer(config.Default(), fsx.Root{}, log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/session", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 before method dispatch", rec.Code)
	}
}

// QTS's Apache rule may or may not strip QPKG_PROXY_PATH before proxying
// (identity plan §5.2), so both shapes have to reach the same handler.
func TestProxyPrefixServedBothWays(t *testing.T) {
	cfg := config.Default()
	cfg.Web.ProxyPrefix = "/qnapfilemanager"
	s := newServer(cfg, fsx.Root{}, log.New(io.Discard, "", 0))
	for _, p := range []string{"/api/session", "/qnapfilemanager/api/session"} {
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", p, rec.Code)
		}
	}
}

func TestParseServeFlags(t *testing.T) {
	o, err := parseServeFlags([]string{
		"-config", "dev-config.json", "-jail", "testdata/fakeroot",
		"-addr", "127.0.0.1:8899", "-proxy-prefix", "/qnapfilemanager",
		"-readonly=false", "-impersonate", "sveinung", "-log", "qfm.log",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.configPath != "dev-config.json" || o.jail != "testdata/fakeroot" ||
		o.addr != "127.0.0.1:8899" || o.proxyPrefix != "/qnapfilemanager" ||
		o.impersonate != "sveinung" || o.logPath != "qfm.log" || o.readOnly {
		t.Fatalf("options = %+v", o)
	}
	c := o.apply(config.Default())
	if c.ReadOnly {
		t.Error("-readonly=false must turn it off")
	}
	if c.Web.Listen != "127.0.0.1:8899" || c.Web.ProxyPrefix != "/qnapfilemanager" || c.Logging.File != "qfm.log" {
		t.Errorf("config = %+v", c.Web)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the result must still validate: %v", err)
	}

	// An unmentioned -readonly must leave the config alone rather than
	// overwrite it with the flag's default — the whole reason apply consults
	// which flags were actually given.
	o2, err := parseServeFlags([]string{"-addr", "127.0.0.1:1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	off := config.Default()
	off.ReadOnly = false
	if got := o2.apply(off); got.ReadOnly {
		t.Fatal("an absent -readonly flag must not re-enable read-only mode")
	}

	if _, err := parseServeFlags([]string{"-nonsense"}, io.Discard); err == nil {
		t.Error("an unknown flag must be an error")
	}
	if _, err := parseServeFlags([]string{"extra"}, io.Discard); err == nil {
		t.Error("a positional argument must be an error")
	}
}

// TestIdentityFilesAreHostOnlyOutsideDevMode is the round-one finding: the
// daemon read /etc/passwd and /etc/group from inside -jail even when it was
// about to fork real workers with the credentials it found there. A writable
// jail could then map an authenticated QTS name to uid 0.
func TestIdentityFilesAreHostOnlyOutsideDevMode(t *testing.T) {
	jail, err := fsx.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jail.Close() })
	var none fsx.Root

	cases := []struct {
		name      string
		root      fsx.Root
		inProcess bool
		wantHost  bool
	}{
		{"jailed process mode", jail, false, true},
		{"jailed in-process mode", jail, true, false},
		{"unjailed process mode", none, false, true},
		{"unjailed in-process mode", none, true, true},
	}
	for _, c := range cases {
		passwd, group, err := identityFiles(c.root, c.inProcess)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		host := passwd == idmap.DefaultPasswdPath && group == idmap.DefaultGroupPath
		if host != c.wantHost {
			t.Errorf("%s: passwd=%q group=%q; host-only = %v, want %v", c.name, passwd, group, host, c.wantHost)
		}
		if !c.wantHost && !strings.HasPrefix(passwd, jail.Base()) {
			t.Errorf("%s: the fixture files must come from inside the jail, got %q", c.name, passwd)
		}
	}
}

// Real worker processes and jailed identities are mutually exclusive, and -dev
// is the only thing that turns the process ones off on Linux.
func TestInProcessWorkersFollowsDev(t *testing.T) {
	if !inProcessWorkers(true) {
		t.Error("-dev must run the workers in this process")
	}
	if got, want := inProcessWorkers(false), runtime.GOOS != "linux"; got != want {
		t.Errorf("without -dev, inProcess = %v on %s, want %v", got, runtime.GOOS, want)
	}
}

func TestImpersonateRequiresDev(t *testing.T) {
	err := runServe([]string{"-impersonate", "alice", "-addr", "127.0.0.1:0"}, io.Discard)
	if err == nil {
		t.Fatal("-impersonate without -dev must be refused")
	}
	for _, want := range []string{"-impersonate", "-dev"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %s: %v", want, err)
		}
	}
	// And the flag itself parses, so -dev is what changes the outcome.
	o, err := parseServeFlags([]string{"-dev", "-impersonate", "alice"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !o.dev || o.impersonate != "alice" {
		t.Fatalf("options = %+v", o)
	}
	if o2, err := parseServeFlags([]string{"-impersonate", "alice"}, io.Discard); err != nil {
		t.Fatal(err)
	} else if o2.dev {
		t.Fatal("-dev must default to off")
	}
}

func TestRunServeRejectsABadJail(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Port 0 would be legal but the jail check has to fail first; use an
	// address that cannot bind either way to prove nothing was started.
	err := runServe([]string{"-jail", file, "-addr", "127.0.0.1:0"}, io.Discard)
	if err == nil {
		t.Fatal("a -jail that is not a directory must be refused")
	}
	err = runServe([]string{"-jail", filepath.Join(dir, "absent"), "-addr", "127.0.0.1:0"}, io.Discard)
	if err == nil {
		t.Fatal("a -jail that does not exist must be refused")
	}
}

func TestRunServeRejectsABadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(`{"worker":{"max":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runServe([]string{"-config", p}, io.Discard); err == nil {
		t.Fatal("an invalid config must stop the daemon starting")
	}
}
