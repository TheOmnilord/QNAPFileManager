package qtsauth

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Result is what one authLogin.cgi call told us.
//
// The response shape is firmware-dependent, so every field is optional and the
// parser is deliberately lenient (see parseResponse).
type Result struct {
	// AuthPassed is true when the authPassed element was present and non-zero.
	AuthPassed bool
	// IsAdmin is nil when the isAdmin element was absent from the response.
	//
	// VERIFY ON NAS: whether isAdmin is returned on *validation* or only on
	// *login* (identity-and-hero-plan.md §1.3 and §5.4 item 7). If it is absent
	// on validation, cookie SSO must issue a normal-user session for everyone
	// and an administrator re-enters their password once to obtain root mode.
	// That is why this is a *bool and not a bool: "absent" and "0" are
	// different answers and must not be conflated.
	IsAdmin *bool
	// Username is the user name reported by QTS, from the username element or,
	// failing that, the user element. Empty when the response carried neither.
	//
	// VERIFY ON NAS: whether the validation response carries a username at all
	// (identity-and-hero-plan.md §5.4 item 6). If it does not, the sid path
	// stays disabled and only the qtoken path is accepted.
	Username string
	// AuthSID is the authSid element, QTS's own session id for this user.
	AuthSID string
	// ErrorValue is the errorValue element, 0 when absent or unparsable.
	ErrorValue int
	// Raw holds the raw (whitespace-trimmed) text of every recognised element,
	// keyed by the LOWER-CASED element name: "authpassed", "isadmin",
	// "username", "user", "authsid", "errorvalue". First occurrence wins.
	// Kept so /api/diag can show what the firmware actually returned.
	Raw map[string]string
}

// Admin reports whether the response positively said "administrator". An absent
// isAdmin element is not an administrator.
func (r Result) Admin() bool { return r.IsAdmin != nil && *r.IsAdmin }

// recognised element names, lower-cased.
var wantedElements = map[string]bool{
	"authpassed": true,
	"isadmin":    true,
	"username":   true,
	"user":       true,
	"authsid":    true,
	"errorvalue": true,
}

type xmlFrame struct {
	name string
	text []byte
}

// parseResponse walks the XML response and collects the text of the elements we
// care about wherever they appear, at any depth and under any wrapper.
//
// The QTS response is documented as <QDocRoot version="1.0">...</QDocRoot>, but
// the wrapper, element order, attributes, casing and surrounding whitespace all
// vary by firmware, and some builds nest the fields inside additional elements.
// Matching a fixed struct would silently produce a zero Result on any of those,
// which for an auth decision fails *open* in the isAdmin case. So this is a
// token walk instead: unknown wrappers and unknown siblings are ignored, a
// truncated document still yields whatever was already collected, and only a
// body with no recognised element at all is an error.
func parseResponse(body []byte) (Result, error) {
	res := Result{Raw: map[string]string{}}

	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	var stack []xmlFrame
	commit := func(f xmlFrame) {
		if !wantedElements[f.name] {
			return
		}
		if _, seen := res.Raw[f.name]; seen {
			return // first occurrence wins
		}
		res.Raw[f.name] = strings.TrimSpace(string(f.text))
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Tolerate a truncated or slightly malformed document: keep
			// whatever was collected before the fault. If nothing was
			// collected, the emptiness check below turns this into an error.
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, xmlFrame{name: strings.ToLower(t.Name.Local)})
		case xml.EndElement:
			if n := len(stack); n > 0 {
				commit(stack[n-1])
				stack = stack[:n-1]
			}
		case xml.CharData:
			if n := len(stack); n > 0 && wantedElements[stack[n-1].name] {
				stack[n-1].text = append(stack[n-1].text, t...)
			}
		}
	}
	// Anything still open at EOF (truncated document) still counts.
	for i := len(stack) - 1; i >= 0; i-- {
		commit(stack[i])
	}

	if len(res.Raw) == 0 {
		return Result{}, fmt.Errorf("qtsauth: no recognised element in %d-byte body: %w", len(body), ErrBadResponse)
	}

	if v, ok := res.Raw["authpassed"]; ok {
		res.AuthPassed = truthy(v)
	}
	if v, ok := res.Raw["isadmin"]; ok {
		b := truthy(v)
		res.IsAdmin = &b
	}
	res.Username = res.Raw["username"]
	if res.Username == "" {
		res.Username = res.Raw["user"]
	}
	res.AuthSID = res.Raw["authsid"]
	if v, ok := res.Raw["errorvalue"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			res.ErrorValue = n
		}
	}
	return res, nil
}

// truthy reads QTS's int-as-flag values leniently: "1", any non-zero integer,
// or "true"/"yes" count as true; everything else, including "", is false.
func truthy(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n != 0
	}
	switch strings.ToLower(s) {
	case "true", "yes", "y":
		return true
	}
	return false
}
