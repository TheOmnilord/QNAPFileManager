package qtsauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

const validXML = `<?xml version="1.0"?><QDocRoot><authPassed>1</authPassed><isAdmin>1</isAdmin><username>svea</username><authSid>abc</authSid></QDocRoot>`

// TestForceHTTPSRedirectIsFollowedToLoopback pins the second hardware finding
// (QTS unit 192.168.1.95, Force HTTPS on): the plain HTTP validation call is
// answered with a 302 to the HTTPS port, and the daemon must retry over HTTPS
// on loopback with the self-signed certificate accepted, not report the
// redirect as qts_unavailable.
func TestForceHTTPSRedirectIsFollowedToLoopback(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != AuthPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(validXML))
	}))
	defer tls.Close()
	sslPort := mustPort(t, tls.URL)

	var httpHits, tlsHits int
	tls.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsHits++
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(validXML))
	})

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpHits++
		// QTS "Force HTTPS": redirect to the external host on the SSL port.
		http.Redirect(w, r, "https://192.168.1.95:"+strconv.Itoa(sslPort)+r.URL.RequestURI(), http.StatusFound)
	}))
	defer httpSrv.Close()

	// The client is built against the HTTP server (its port stands in for the
	// loopback HTTP port); the SSL fallback is pinned to the test TLS port. The
	// retry forces host 127.0.0.1, which is where httptest's TLS server listens.
	c := New(httpSrv.URL)
	c.SSLPort = sslPort

	res, err := c.ValidateSID(context.Background(), "token")
	if err != nil {
		t.Fatalf("ValidateSID after Force-HTTPS redirect: %v", err)
	}
	if !res.AuthPassed || res.Username != "svea" {
		t.Fatalf("result = %+v", res)
	}
	if httpHits != 1 || tlsHits != 1 {
		t.Fatalf("hits: http=%d tls=%d, want 1 and 1", httpHits, tlsHits)
	}
}

// TestHTTPUnreachableFallsBackToConfiguredSSLPort covers a unit that closed the
// HTTP port entirely: the transport error must trigger the HTTPS loopback
// fallback on the configured SSL port.
func TestHTTPUnreachableFallsBackToConfiguredSSLPort(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(validXML))
	}))
	defer tls.Close()
	sslPort := mustPort(t, tls.URL)

	// Point the HTTP base at a closed port on loopback.
	c := New("http://127.0.0.1:1")
	c.SSLPort = sslPort

	res, err := c.ValidateSID(context.Background(), "token")
	if err != nil {
		t.Fatalf("ValidateSID with HTTP closed: %v", err)
	}
	if !res.AuthPassed {
		t.Fatalf("result = %+v", res)
	}
}

// TestHTTPSBaseHasNoFallbackLoop ensures a client already on https never
// produces a fallback (which would loop): an unreachable https base is a plain
// ErrUnreachable.
func TestHTTPSBaseHasNoFallbackLoop(t *testing.T) {
	c := New("https://127.0.0.1:1")
	if fb := c.httpsFallback("https://127.0.0.1:1", 0); fb != "" {
		t.Fatalf("https base offered a fallback %q", fb)
	}
	if _, err := c.ValidateSID(context.Background(), "token"); err == nil {
		t.Fatal("expected an error from an unreachable https base")
	}
}

func TestHTTPSPortFromLocation(t *testing.T) {
	for loc, want := range map[string]int{
		"https://192.168.1.95:8181/cgi-bin/authLogin.cgi": 8181,
		"https://nas/cgi-bin/authLogin.cgi":               443,
		"http://192.168.1.95:8080/x":                      0, // not https
		"":                                                0,
		"://bad":                                          0,
	} {
		if got := httpsPort(loc); got != want {
			t.Errorf("httpsPort(%q) = %d, want %d", loc, got, want)
		}
	}
}

func mustPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectSSLPortReadsStunnel(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/uLinux.conf"
	if err := os.WriteFile(path, []byte("[System]\nWeb Access Port = 8080\n[Stunnel]\nEnable = TRUE\nPort = 8181\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DetectSSLPort(path); got != 8181 {
		t.Fatalf("DetectSSLPort = %d, want 8181", got)
	}
	if got := DetectSSLPort(dir + "/missing"); got != DefaultSSLPort {
		t.Fatalf("DetectSSLPort(missing) = %d, want %d", got, DefaultSSLPort)
	}
	if !strings.HasPrefix(Detect(path).BaseURL, "http://127.0.0.1:8080") {
		t.Fatalf("Detect base = %q", Detect(path).BaseURL)
	}
	if Detect(path).SSLPort != 8181 {
		t.Fatalf("Detect SSLPort = %d", Detect(path).SSLPort)
	}
}
