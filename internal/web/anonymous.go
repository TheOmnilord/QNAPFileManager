package web

import (
	"net/http"
	"net/url"
	"strings"
)

// anonymous reports whether a request presented no credential at all: no app
// session cookie and no QTS cookie, sid or header. Only such a request may read
// api/session unauthenticated; a credential that was presented and failed is
// answered 401 so the shell knows to ask for a fresh QTS sign-in rather than
// mistake an expired session for a first visit.
func anonymous(r *http.Request) bool {
	// Inspect names before cookie parsing can discard malformed values.
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch strings.TrimSpace(name) {
			case "qfm_sid", "NAS_USER", "qtoken", "NAS_SID":
				return false
			}
		}
	}
	for name := range r.Header {
		if strings.EqualFold(name, "X-QNAP-SID") {
			return false
		}
	}
	for part := range strings.SplitSeq(r.URL.RawQuery, "&") {
		name, _, _ := strings.Cut(part, "=")
		if decoded, err := url.QueryUnescape(name); err == nil && decoded == "sid" {
			return false
		}
	}
	return true
}
