package qtsauth

import (
	"net/http"
	"regexp"
	"strings"
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

// userNameRe is the accepted syntax for a QTS user name. The name reaches an
// argv (idmap's `id -G <user>` fallback) and a query string, so it is filtered
// before either. Same expression as identity-and-hero-plan.md §1.1.
var userNameRe = regexp.MustCompile(`^[A-Za-z0-9._@\-]{1,64}$`)

// ValidUserName reports whether name is acceptable as a QTS user name.
func ValidUserName(name string) bool { return userNameRe.MatchString(name) }

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

	user := ""
	if c, err := r.Cookie(CookieUser); err == nil {
		user = strings.TrimSpace(c.Value)
		if user != "" && !ValidUserName(user) {
			return Cred{}, false
		}
	}

	if c, err := r.Cookie(CookieQToken); err == nil && user != "" {
		if tok := strings.TrimSpace(c.Value); validToken(tok) {
			return Cred{Kind: KindQToken, User: user, Token: tok}, true
		}
	}
	if c, err := r.Cookie(CookieSID); err == nil {
		if tok := strings.TrimSpace(c.Value); validToken(tok) {
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
