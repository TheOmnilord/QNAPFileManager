package web

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func safeMethod(method string) bool { return method == "GET" || method == "HEAD" }

func validCSRF(r *http.Request, token string) bool {
	if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-QFM-CSRF")), []byte(token)) != 1 {
		return false
	}
	return validOrigin(r)
}

// validOrigin is the non-token half of the three locks (contract §13.3): the
// outright rejection of Sec-Fetch-Site: cross-site, and Origin/Referer host
// equal to r.Host. It is factored out unchanged so the break-glass login route —
// which is exempt from the header token, there being no session yet to bind one
// to — applies exactly the same check as every other unsafe request rather than
// a second, subtly different copy of it.
func validOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.User == nil && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The break-glass page is never framed — it is a top-level tab reached
		// by IP when the QTS desktop is what is broken — and the one place a
		// clickjacking frame would be most valuable is its password field
		// (contract §13.4).
		ancestors := "'none'"
		if !breakGlassRequest(r) {
			ancestors = "'self'"
			for _, a := range s.cfg.Web.FrameAncestors {
				// Only explicit origins; never permit directive injection or wildcards.
				u, err := url.Parse(a)
				if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && !strings.ContainsAny(a, "*; \t\r\n") {
					ancestors += " " + strings.TrimSuffix(a, "/")
				}
			}
		}
		w.Header().Del("X-Frame-Options") // QTS embeds the app in its desktop iframe.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors "+ancestors)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Isolate the document from anything it opens or that opens it, and stop
		// another origin embedding our responses as a subresource (contract
		// §13.4). Deliberately NO HSTS on either listener: pinning HTTPS for the
		// whole NAS host from a self-signed door would break the QTS desktop on
		// that host, which is the opposite of repair (§3.4).
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// forwardedClientIP trusts the final proxy hop only from a loopback peer, and
// never at all on the break-glass listener.
//
// That listener binds 0.0.0.0 and is NOT behind the QTS proxy (M4 contract
// §6.3), so an X-Forwarded-For there is a forgery — and one arriving from a
// loopback peer is the most convincing forgery of all, since a process on the
// NAS itself can send it. The check lives here rather than in each caller so
// that every audit line, every log line and the login bucket agree on one
// address for a given request: a door where the pre-login and post-login events
// name different IPs is a door whose trail cannot be read.
func forwardedClientIP(r *http.Request) string {
	if breakGlassRequest(r) {
		return ""
	}
	host := peerHost(r)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if last := net.ParseIP(strings.TrimSpace(hops[len(hops)-1])); last != nil {
			return last.String()
		}
	}
	return ""
}

func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ClientIP trusts the final proxy hop only when the immediate peer is loopback.
func ClientIP(r *http.Request) string {
	if ip := forwardedClientIP(r); ip != "" {
		return ip
	}
	return peerHost(r)
}
