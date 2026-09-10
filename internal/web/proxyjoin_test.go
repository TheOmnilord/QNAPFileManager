package web

import (
	"net/http"
	"strings"
	"testing"
)

// TestProxyJoinedPathsAreNotRedirected pins the first hardware finding: the QTS
// proxy forwards "/qnapfilemanager/app.css" as "//app.css". Before the fix the
// mux answered 307 to "/app.css", which the proxy mapped back to the original
// URL, so the QTS desktop window showed unstyled HTML and a script that never
// ran. The doubled slash must be served as the single-slash path, with no
// redirect, for assets and API routes alike.
func TestProxyJoinedPathsAreNotRedirected(t *testing.T) {
	s, _ := fixture(t, false)
	for path, want := range map[string]struct {
		status int
		ctype  string
		body   string
	}{
		"//":            {http.StatusOK, "text/html", "QNAPFileManager"},
		"//app.css":     {http.StatusOK, "text/css", ""},
		"//js/app.js":   {http.StatusOK, "text/javascript", ""},
		"//api/session": {http.StatusOK, "application/json", `"authenticated":false`},
		"///app.css":    {http.StatusOK, "text/css", ""},
	} {
		w := request(s, "GET", path, nil, nil)
		if w.Code != want.status {
			t.Errorf("%s: status = %d (Location %q), want %d", path, w.Code, w.Header().Get("Location"), want.status)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, want.ctype) {
			t.Errorf("%s: content type = %q, want %s", path, ct, want.ctype)
		}
		if want.body != "" && !strings.Contains(w.Body.String(), want.body) {
			t.Errorf("%s: body lacks %q", path, want.body)
		}
	}
}
