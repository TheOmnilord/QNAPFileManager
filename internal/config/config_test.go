package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("the defaults must validate: %v", err)
	}
	if c.Web.Listen != "127.0.0.1:8770" {
		t.Errorf("web.listen = %q, want 127.0.0.1:8770 (loopback behind the QTS proxy)", c.Web.Listen)
	}
	if !c.Web.BreakGlass.Enabled || c.Web.BreakGlass.Addr != "0.0.0.0:8771" {
		t.Errorf("breakGlass = %+v, want enabled on 0.0.0.0:8771", c.Web.BreakGlass)
	}
	if c.Auth.Mode != AuthQTS || !c.Auth.AdminRequiresBoth || c.Auth.QTSPort != 0 {
		t.Errorf("auth = %+v, want qts / adminRequiresBoth / auto port", c.Auth)
	}
	// The one default that must never quietly flip.
	if !c.ReadOnly {
		t.Error("readOnly must default to true")
	}
	if !c.Trash.Enabled || c.Trash.Days != 30 {
		t.Errorf("trash = %+v, want enabled for 30 days", c.Trash)
	}
	if c.Worker.Max != 8 || c.Worker.IdleTimeout != "10m" || c.Worker.Umask != "0022" {
		t.Errorf("worker = %+v", c.Worker)
	}
	if c.Limits.ListMax != 5000 || c.Limits.MaxTextBytes != 2<<20 {
		t.Errorf("limits = %+v, want 5000 / 2 MiB", c.Limits)
	}
}

func TestLoadMissingFileIsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing config is the first-run state, not an error: %v", err)
	}
	if c != Default() {
		t.Fatalf("Load = %+v, want the defaults", c)
	}
}

func TestLoadUnreadableFileIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not deny the owner on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(`{"readOnly":false}`), 0o000); err != nil {
		t.Fatal(err)
	}
	// Starting with defaults on top of a config that exists but could not be
	// read would silently re-enable read-only — or, worse, silently discard
	// it. It must fail instead.
	if _, err := Load(p); err == nil {
		t.Fatal("an unreadable config must be an error")
	}
}

func TestLoadPartialOverlaysDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	body := `{"readOnly":false,"web":{"listen":"0.0.0.0:9000","proxyPrefix":"/qnapfilemanager/"},"worker":{"max":2}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReadOnly {
		t.Error("an explicit false must turn readOnly off")
	}
	if c.Web.Listen != "0.0.0.0:9000" {
		t.Errorf("listen = %q", c.Web.Listen)
	}
	// Normalize strips the trailing slash: the mux mounts at the prefix and
	// "/qnapfilemanager//" would not match anything.
	if c.Web.ProxyPrefix != "/qnapfilemanager" {
		t.Errorf("proxyPrefix = %q, want /qnapfilemanager", c.Web.ProxyPrefix)
	}
	if c.Worker.Max != 2 {
		t.Errorf("worker.max = %d", c.Worker.Max)
	}
	// Everything not mentioned keeps its default, including the nested
	// fields of a struct that was partially specified.
	if c.Worker.IdleTimeout != "10m" || c.Worker.Umask != "0022" {
		t.Errorf("worker = %+v, want the untouched fields defaulted", c.Worker)
	}
	if !c.Trash.Enabled || c.Limits.ListMax != 5000 {
		t.Errorf("unmentioned sections lost their defaults: %+v %+v", c.Trash, c.Limits)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"readOnly":`},
		// A typo in a hand-edited config must not be silently ignored
		// (Go matches field names case-insensitively, so "readonly" is
		// still accepted — a wrong key name is what this catches).
		{"unknown field", `{"web":{"port":8770}}`},
		{"unknown top-level field", `{"readOnlyMode":false}`},
		{"bad listen", `{"web":{"listen":"8770"}}`},
		{"listen without port", `{"web":{"listen":"127.0.0.1"}}`},
		{"hostname listen", `{"web":{"listen":"nas.local:8770"}}`},
		{"bad auth mode", `{"auth":{"mode":"ldap"}}`},
		{"zero workers", `{"worker":{"max":0}}`},
		{"bad duration", `{"worker":{"idleTimeout":"ten minutes"}}`},
		{"non-octal umask", `{"worker":{"umask":"0o22"}}`},
		{"umask out of range", `{"worker":{"umask":"7777"}}`},
		{"listMax over the cap", `{"limits":{"listMax":50001}}`},
		{"negative trash days", `{"trash":{"days":-1}}`},
		{"break-glass on the same port", `{"web":{"listen":"127.0.0.1:8770","breakGlass":{"enabled":true,"addr":"127.0.0.1:8770"}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatalf("Load(%s) = nil, want an error", c.body)
			}
		})
	}
}

func TestValidateNamesEveryProblem(t *testing.T) {
	c := Default()
	c.Web.Listen = "nope"
	c.Auth.Mode = "kerberos"
	c.Limits.ListMax = 0
	err := c.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate = %v, want ErrInvalid", err)
	}
	// One run should report all three, not just the first: an operator
	// fixing a config by trial and error restarts a root daemon each time.
	for _, want := range []string{"web.listen", "auth.mode", "limits.listMax"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c := Default()
	c.ReadOnly = false
	c.Web.ProxyPrefix = "qnapfilemanager/"
	c.Trash.Days = 7
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReadOnly || got.Trash.Days != 7 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	// Save normalizes before writing, so what lands on disk is what Load
	// would produce — no drift between the two paths.
	if got.Web.ProxyPrefix != "/qnapfilemanager" {
		t.Fatalf("proxyPrefix = %q", got.Web.ProxyPrefix)
	}
	// The file holds the break-glass password hash.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	// It must also be a file a human can read and edit.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\n  \"web\"") {
		t.Fatalf("the saved config is not indented:\n%s", raw)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["readOnly"]; !ok {
		t.Fatal("readOnly must always be written out, even when false")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.Worker.Max = 0
	if err := Save(p, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an invalid config must not be written at all")
	}
}

func TestWorkerParsing(t *testing.T) {
	cases := []struct {
		umask string
		want  uint32
		bad   bool
	}{
		{"0022", 0o022, false},
		{"022", 0o022, false},
		{"077", 0o077, false},
		{"0", 0, false},
		{"", 0o022, false}, // empty means the QTS default
		{"8", 0, true},
		{"0o22", 0, true},
		{"-1", 0, true},
		{"1000", 0, true},
	}
	for _, c := range cases {
		got, err := Worker{Umask: c.umask}.UmaskValue()
		if c.bad {
			if err == nil {
				t.Errorf("UmaskValue(%q) = %o, want an error", c.umask, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("UmaskValue(%q): %v", c.umask, err)
		} else if got != c.want {
			t.Errorf("UmaskValue(%q) = %o, want %o", c.umask, got, c.want)
		}
	}
	d, err := Worker{IdleTimeout: "10m"}.IdleTimeoutDuration()
	if err != nil || d != 10*time.Minute {
		t.Fatalf("IdleTimeoutDuration = %v, %v", d, err)
	}
	if _, err := (Worker{IdleTimeout: "soon"}).IdleTimeoutDuration(); err == nil {
		t.Fatal("want an error for an unparsable duration")
	}
}

func TestNormalizeProxyPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"//", ""},
		{"qnapfilemanager", "/qnapfilemanager"},
		{"/qnapfilemanager", "/qnapfilemanager"},
		{"/qnapfilemanager/", "/qnapfilemanager"},
		{"  /qnapfilemanager//  ", "/qnapfilemanager"},
	}
	for _, c := range cases {
		got := Config{Web: Web{ProxyPrefix: c.in}}
		got.Normalize()
		if got.Web.ProxyPrefix != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got.Web.ProxyPrefix, c.want)
		}
	}
}

// config.example.json ships in the QPKG and is the file an operator copies
// into place, so it has to be a config this build actually accepts.
func TestExampleConfigLoads(t *testing.T) {
	p := filepath.Join("..", "..", "config.example.json")
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		t.Skip("no config.example.json in this tree")
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("config.example.json does not load: %v", err)
	}
	if !c.ReadOnly {
		t.Error("the shipped example must start read-only")
	}
}
