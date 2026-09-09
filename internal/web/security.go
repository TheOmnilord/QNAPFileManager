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
		ancestors := "'self'"
		for _, a := range s.cfg.Web.FrameAncestors {
			// Only explicit origins; never permit directive injection or wildcards.
			u, err := url.Parse(a)
			if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && !strings.ContainsAny(a, "*; \t\r\n") {
				ancestors += " " + strings.TrimSuffix(a, "/")
			}
		}
		w.Header().Del("X-Frame-Options") // QTS embeds the app in its desktop iframe.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors "+ancestors)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ClientIP trusts the final proxy hop only when the immediate peer is loopback.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if last := net.ParseIP(strings.TrimSpace(hops[len(hops)-1])); last != nil {
			return last.String()
		}
	}
	return host
}
