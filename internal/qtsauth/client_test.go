package qtsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testClient points a Client at srv with a short timeout.
func testClient(srv *httptest.Server, timeout time.Duration) *Client {
	return &Client{
		BaseURL: srv.URL,
		HTTP:    NewHTTPClient(srv.URL, timeout),
		MaxBody: DefaultMaxBody,
	}
}

func xmlServer(t *testing.T, body string) (*httptest.Server, *[]url.Values) {
	t.Helper()
	var seen []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query())
		if r.URL.Path != AuthPath {
			t.Errorf("path = %q, want %q", r.URL.Path, AuthPath)
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestValidateQTokenRequestShape(t *testing.T) {
	srv, seen := xmlServer(t, fixtureAdmin)
	c := testClient(srv, time.Second)

	res, err := c.ValidateQToken(context.Background(), "ad min&x", "tok=en/+ ")
	if err != nil {
		t.Fatalf("ValidateQToken: %v", err)
	}
	if !res.AuthPassed || !res.Admin() || res.Username != "admin" {
		t.Fatalf("unexpected result %+v", res)
	}
	q := (*seen)[0]
	if got := q.Get("qtoken"); got != "tok=en/+ " {
		t.Errorf("qtoken = %q, want the escaped-then-decoded original", got)
	}
	if got := q.Get("user"); got != "ad min&x" {
		t.Errorf("user = %q, want the escaped-then-decoded original", got)
	}
}

func TestValidateSIDAndLoginRequestShape(t *testing.T) {
	srv, seen := xmlServer(t, fixtureUser)
	c := testClient(srv, time.Second)

	if _, err := c.ValidateSID(context.Background(), "s id&1"); err != nil {
		t.Fatalf("ValidateSID: %v", err)
	}
	if got := (*seen)[0].Get("sid"); got != "s id&1" {
		t.Errorf("sid = %q", got)
	}
	if _, ok := (*seen)[0]["user"]; ok {
		t.Error("ValidateSID must not send a user parameter")
	}

	if _, err := c.Login(context.Background(), "bob", "p&ss word"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	q := (*seen)[1]
	if q.Get("user") != "bob" {
		t.Errorf("user = %q", q.Get("user"))
	}
	// VERIFY ON NAS: ezEncode is believed to be base64.
	if want := EncodePassword("p&ss word"); q.Get("pwd") != want {
		t.Errorf("pwd = %q, want %q", q.Get("pwd"), want)
	}
	if q.Get("pwd") == "p&ss word" {
		t.Error("password was sent in the clear")
	}
}

func TestServerErrorIsBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := testClient(srv, time.Second).ValidateSID(context.Background(), "x")
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse", err)
	}
	if strings.Contains(err.Error(), "boom") {
		t.Error("body leaked into the error")
	}
}

func TestGarbageBodyIsBadResponse(t *testing.T) {
	srv, _ := xmlServer(t, "<html><body>not the CGI you are looking for</body></html>")
	_, err := testClient(srv, time.Second).ValidateSID(context.Background(), "x")
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse", err)
	}
}

func TestSlowServerHitsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(release); srv.Close() }()

	start := time.Now()
	_, err := testClient(srv, 100*time.Millisecond).ValidateSID(context.Background(), "x")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("call took %v, timeout not enforced", elapsed)
	}
}

// TestRedirectHostIsNeverContacted is the security guarantee behind the
// Force-HTTPS fallback: a redirect is retried only on loopback, never at the
// host the Location names. The redirect here points at another server; that
// server must not be touched, and because the retry goes to a closed loopback
// SSL port the call ends ErrUnreachable rather than chasing the redirect.
func TestRedirectHostIsNeverContacted(t *testing.T) {
	var elsewhere int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&elsewhere, 1)
		_, _ = w.Write([]byte(fixtureAdmin))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+AuthPath, http.StatusFound)
	}))
	defer srv.Close()

	c := testClient(srv, time.Second)
	c.SSLPort = 1 // a closed loopback port, so the HTTPS fallback fails deterministically
	_, err := c.ValidateQToken(context.Background(), "admin", "t")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if n := atomic.LoadInt32(&elsewhere); n != 0 {
		t.Fatalf("redirect target was contacted %d times; the redirect host must never be followed", n)
	}
}

func TestUnreachableEndpoint(t *testing.T) {
	srv, _ := xmlServer(t, fixtureAdmin)
	c := testClient(srv, time.Second)
	srv.Close() // now refuses connections

	_, err := c.ValidateSID(context.Background(), "secret-token")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("token leaked into error: %v", err)
	}
}

func TestMaxBodyCap(t *testing.T) {
	// A body whose recognisable elements sit past the cap must not be seen.
	head := "<QDocRoot>" + strings.Repeat("<pad>x</pad>", 4096)
	srv, _ := xmlServer(t, head+"<authPassed>1</authPassed></QDocRoot>")
	c := testClient(srv, time.Second)
	c.MaxBody = 128

	if _, err := c.ValidateSID(context.Background(), "x"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("error = %v, want ErrBadResponse (body should be truncated at MaxBody)", err)
	}
}

func TestDetectPortFromULinuxConf(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	full := write("uLinux.conf", strings.Join([]string{
		"# comment",
		"[Misc]",
		"Web Access Port = 9999",
		"",
		"[System]",
		"Model = TS-431P",
		"Web Access Port = 8081",
		"Web Access Port Enable = 1",
		"[Network]",
		"Web Access Port = 7777",
	}, "\r\n"))
	if got := DetectPort(full); got != 8081 {
		t.Errorf("DetectPort = %d, want 8081 (only the [System] section counts)", got)
	}

	quoted := write("quoted.conf", "[System]\nWeb Access Port = \"8443\"\n")
	if got := DetectPort(quoted); got != 8443 {
		t.Errorf("DetectPort(quoted) = %d, want 8443", got)
	}

	// Fallback: the primary key is unusable, so the secondary is tried.
	secondary := write("secondary.conf", "[System]\nWeb Access Port = \nWeb Access Port Enable = 8082\n")
	if got := DetectPort(secondary); got != 8082 {
		t.Errorf("DetectPort(secondary) = %d, want 8082", got)
	}

	// Fallbacks to DefaultPort.
	for name, content := range map[string]string{
		"nosection.conf":  "[Network]\nWeb Access Port = 1234\n",
		"nokey.conf":      "[System]\nModel = TS-431P\n",
		"bad.conf":        "[System]\nWeb Access Port = not-a-number\n",
		"outofrange.conf": "[System]\nWeb Access Port = 70000\n",
	} {
		if got := DetectPort(write(name, content)); got != DefaultPort {
			t.Errorf("DetectPort(%s) = %d, want %d", name, got, DefaultPort)
		}
	}
	if got := DetectPort(filepath.Join(dir, "does-not-exist.conf")); got != DefaultPort {
		t.Errorf("DetectPort(missing) = %d, want %d", got, DefaultPort)
	}
}

func TestDetectAlwaysLoopback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "uLinux.conf")
	if err := os.WriteFile(p, []byte("[System]\nWeb Access Port = 8081\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Detect(p)
	if c == nil {
		t.Fatal("Detect returned nil")
	}
	if c.BaseURL != "http://127.0.0.1:8081" {
		t.Errorf("BaseURL = %q, want http://127.0.0.1:8081", c.BaseURL)
	}
	if c.MaxBody != DefaultMaxBody {
		t.Errorf("MaxBody = %d, want %d", c.MaxBody, DefaultMaxBody)
	}
	if c.HTTP == nil || c.HTTP.Timeout != DefaultTimeout {
		t.Errorf("HTTP client timeout not %v", DefaultTimeout)
	}
	if c.HTTP.CheckRedirect == nil {
		t.Error("HTTP client would follow redirects")
	}
	// Detect never trusts the request host, so a missing file is still loopback.
	if got := Detect(filepath.Join(dir, "nope")).BaseURL; got != "http://127.0.0.1:8080" {
		t.Errorf("Detect(missing).BaseURL = %q", got)
	}
}

func TestNewHTTPClientTLSOnlyForHTTPS(t *testing.T) {
	plain := NewHTTPClient("http://127.0.0.1:8080", time.Second)
	if tr := plain.Transport.(*http.Transport); tr.TLSClientConfig != nil {
		t.Error("plain http client must not set a TLS config")
	}
	secure := NewHTTPClient("https://127.0.0.1:443", time.Second)
	tr := secure.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("https client must set InsecureSkipVerify (QTS self-signed certificate)")
	}
}

func TestNilHTTPUsesDefault(t *testing.T) {
	srv, _ := xmlServer(t, fixtureAdmin)
	c := &Client{BaseURL: srv.URL}
	if _, err := c.ValidateQToken(context.Background(), "admin", "t"); err != nil {
		t.Fatalf("ValidateQToken with nil HTTP: %v", err)
	}
}

func TestEmptyBaseURL(t *testing.T) {
	c := &Client{}
	if _, err := c.ValidateSID(context.Background(), "x"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
}
