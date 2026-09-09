package qtsauth

import (
	"net/http"
	"net/url"
	"strings"

	"qnapfilemanager/internal/idmap"
)

// Credential kinds.
const (
	// KindQToken is the QTS 5 form: the (user, token) pair is validated
	// together, so the user name may be taken from the cookie.
	KindQToken = "qtoken"
	// KindSID is the older form: only the token is validated, so the user name
	// must come from the response body.
	KindSID = "sid"
)

// Cookie, query and header names QTS uses (VERIFY ON NAS: exact cookie names
// and attributes, identity-and-hero-plan.md §5.4 item 5).
const (
	CookieUser   = "NAS_USER"
	CookieQToken = "qtoken"
	CookieSID    = "NAS_SID"
	QuerySID     = "sid"
	HeaderSID    = "X-QNAP-SID"
)

// maxTokenLen bounds a credential we are willing to forward to the CGI.
const maxTokenLen = 512

// ValidUserName reports whether name is acceptable as a QTS user name.
// Share NSS's grammar, including domain names and rejection of leading '-'.
func ValidUserName(name string) bool { return idmap.ValidName(name) }

// Cred is a QTS credential taken from a request.
type Cred struct {
	// Kind is KindQToken or KindSID.
	Kind string
	// User is the claimed user name. Authoritative only for KindQToken, where
	// the pair was validated together. For KindSID it is a hint at best and may
	// be empty; Verifier requires the real name from the response.
	User string
	// Token is the qtoken or NAS_SID value.
	Token string
}

// FromRequest extracts a QTS credential from an incoming request.
//
// Sources, highest priority first:
//
//  1. NAS_USER + qtoken cookies (QTS 5, the pair is validated together)
//  2. NAS_USER + NAS_SID cookies (older firmware)
//  3. ?sid= query parameter        (lower priority)
//  4. X-QNAP-SID header            (lower priority)
//
// Sources 3 and 4 exist for clients that cannot send cookies (the break-glass
// listener, a bookmark to the wrong origin). They yield KindSID with whatever
// NAS_USER cookie happens to be present, which Verifier will not trust.
//
// A NAS_USER cookie that is present but syntactically invalid makes the whole
// extraction fail: that is a hostile or corrupt cookie, not a missing one.
func FromRequest(r *http.Request) (Cred, bool) {
	if r == nil {
		return Cred{}, false
	}

	cookies := qtsCookies(r)
	user := ""
	if value, ok := cookies[CookieUser]; ok {
		user = value
		if user != "" && !ValidUserName(user) {
			return Cred{}, false
		}
	}

	if value, ok := cookies[CookieQToken]; ok && user != "" {
		if tok := value; validToken(tok) {
			return Cred{Kind: KindQToken, User: user, Token: tok}, true
		}
	}
	if value, ok := cookies[CookieSID]; ok {
		if tok := value; validToken(tok) {
			return Cred{Kind: KindSID, User: user, Token: tok}, true
		}
	}
	if r.URL != nil {
		if tok := strings.TrimSpace(r.URL.Query().Get(QuerySID)); validToken(tok) {
			return Cred{Kind: KindSID, User: user, Token: tok}, true
		}
	}
	if tok := strings.TrimSpace(r.Header.Get(HeaderSID)); validToken(tok) {
		return Cred{Kind: KindSID, User: user, Token: tok}, true
	}
	return Cred{}, false
}

// qtsCookies accepts literal domain backslashes rejected by net/http.Cookie.
// VERIFY ON NAS: exact QTS cookie encoding (raw versus percent-encoded).
// Decode once, preserving literal '+'; validate the decoded bytes at extraction.
// Only the three QTS names use this parser; application cookies stay strict.
func qtsCookies(r *http.Request) map[string]string {
	out := make(map[string]string, 3)
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			name, value, ok := strings.Cut(strings.TrimLeft(pair, " \t"), "=")
			if !ok || (name != CookieUser && name != CookieQToken && name != CookieSID) {
				continue
			}
			if _, seen := out[name]; seen {
				continue // Match net/http's first-cookie precedence.
			}
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			if decoded, err := url.PathUnescape(value); err == nil {
				value = decoded
			}
			out[name] = value
		}
	}
	return out
}

// validToken rejects empty, over-long and control-character-bearing tokens
// before they are put into a URL.
func validToken(tok string) bool {
	if tok == "" || len(tok) > maxTokenLen {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 0x21 || tok[i] > 0x7e {
			return false
		}
	}
	return true
}
