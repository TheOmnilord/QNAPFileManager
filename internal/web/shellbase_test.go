package web

import (
	"net/http"
	"strings"
	"testing"

	"qnapfilemanager/internal/config"
)

// TestShellUsesAbsoluteURLsUnderTheProxyPrefix pins the second hardware
// finding: the QTS desktop opens the app at the bare "/qnapfilemanager", so
// the shell's relative "app.css" resolved to "/app.css" on the QTS origin and
// QTS answered 404. The shell must reference its assets absolutely under the
// configured prefix and hand that base to the scripts.
func TestShellUsesAbsoluteURLsUnderTheProxyPrefix(t *testing.T) {
	for prefix, base := range map[string]string{"": "/", "/qnapfilemanager": "/qnapfilemanager/"} {
		cfg := config.Default()
		cfg.Web.ProxyPrefix = prefix
		s := New(cfg, nil, nil, nil, nil, nil, "test", nil)
		w := request(s, "GET", "/", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("prefix %q: status %d", prefix, w.Code)
		}
		body := w.Body.String()
		for _, want := range []string{
			`href="` + base + `app.css"`,
			`src="` + base + `js/app.js"`,
			`<meta name="qfm-base" content="` + base + `">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("prefix %q: shell lacks %s", prefix, want)
			}
		}
		if strings.Contains(body, `href="app.css"`) || strings.Contains(body, `src="js/app.js"`) {
			t.Errorf("prefix %q: a relative asset reference survived", prefix)
		}
		// The same shell must be reachable through the prefixed mount too,
		// because the daemon also listens on the loopback port without QTS.
		if prefix != "" {
			if w := request(s, "GET", prefix+"/", nil, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `href="`+base+`app.css"`) {
				t.Errorf("prefixed mount: status %d", w.Code)
			}
		}
	}
}
