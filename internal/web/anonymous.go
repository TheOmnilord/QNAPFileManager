package web

import (
	"net/http"

	"qnapfilemanager/internal/qtsauth"
)

// anonymous reports whether a request presented no credential at all: no app
// session cookie and no QTS cookie, sid or header. Only such a request may read
// api/session unauthenticated; a credential that was presented and failed is
// answered 401 so the shell knows to ask for a fresh QTS sign-in rather than
// mistake an expired session for a first visit.
func anonymous(r *http.Request) bool {
	if _, err := r.Cookie("qfm_sid"); err == nil {
		return false
	}
	if _, ok := qtsauth.FromRequest(r); ok {
		return false
	}
	return true
}
