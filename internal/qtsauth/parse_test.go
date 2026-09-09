package qtsauth

import (
	"errors"
	"testing"
)

// Plausible captured-style fixtures. VERIFY ON NAS: replace these with bodies
// actually captured from QTS and QuTS hero before M1 sign-off.
const (
	fixtureAdmin = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<QDocRoot version="1.0"><authPassed>1</authPassed><isAdmin>1</isAdmin>` +
		`<username>admin</username><authSid>abc</authSid><errorValue>0</errorValue></QDocRoot>`

	fixtureUser = `<?xml version="1.0" encoding="UTF-8"?>` +
		"<QDocRoot version=\"1.0\">\n  <authPassed>1</authPassed>\n  <isAdmin>0</isAdmin>\n" +
		"  <username>  sveinung  </username>\n  <authSid>s-123</authSid>\n</QDocRoot>"

	// No <username>: gates the sid path (identity-and-hero-plan.md §1.3).
	fixtureNoUsername = `<QDocRoot version="1.0"><authPassed>1</authPassed><isAdmin>1</isAdmin><authSid>abc</authSid></QDocRoot>`

	// No <isAdmin>: everyone gets a normal-user session.
	fixtureNoIsAdmin = `<QDocRoot version="1.0"><authPassed>1</authPassed><username>bob</username><authSid>abc</authSid></QDocRoot>`

	fixtureDenied = `<QDocRoot version="1.0"><authPassed>0</authPassed><errorValue>3</errorValue></QDocRoot>`

	// Unknown wrappers, extra siblings, mixed case, attributes: must still parse.
	fixtureWrapped = `<QDocRoot version="1.0"><QNAP><result><status ok="1"/>` +
		`<AuthPassed>1</AuthPassed><IsAdmin>0</IsAdmin><User>carol</User>` +
		`<somethingNew>ignore me</somethingNew><authSid>zz</authSid></result></QNAP></QDocRoot>`

	// Truncated document: whatever was collected before the fault survives.
	fixtureTruncated = `<QDocRoot version="1.0"><authPassed>1</authPassed><username>dora</username>`
)

func TestParseResponseFixtures(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		passed   bool
		admin    *bool // expected IsAdmin
		user     string
		sid      string
		errValue int
	}{
		{"admin", fixtureAdmin, true, boolp(true), "admin", "abc", 0},
		{"user with whitespace", fixtureUser, true, boolp(false), "sveinung", "s-123", 0},
		{"no username", fixtureNoUsername, true, boolp(true), "", "abc", 0},
		{"no isAdmin", fixtureNoIsAdmin, true, nil, "bob", "abc", 0},
		{"denied", fixtureDenied, false, nil, "", "", 3},
		{"unknown wrappers and <user> fallback", fixtureWrapped, true, boolp(false), "carol", "zz", 0},
		{"truncated", fixtureTruncated, true, nil, "dora", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResponse([]byte(tc.body))
			if err != nil {
				t.Fatalf("parseResponse: %v", err)
			}
			if got.AuthPassed != tc.passed {
				t.Errorf("AuthPassed = %v, want %v", got.AuthPassed, tc.passed)
			}
			switch {
			case tc.admin == nil && got.IsAdmin != nil:
				t.Errorf("IsAdmin = %v, want nil (absent element)", *got.IsAdmin)
			case tc.admin != nil && got.IsAdmin == nil:
				t.Errorf("IsAdmin = nil, want %v", *tc.admin)
			case tc.admin != nil && *got.IsAdmin != *tc.admin:
				t.Errorf("IsAdmin = %v, want %v", *got.IsAdmin, *tc.admin)
			}
			if got.Username != tc.user {
				t.Errorf("Username = %q, want %q", got.Username, tc.user)
			}
			if got.AuthSID != tc.sid {
				t.Errorf("AuthSID = %q, want %q", got.AuthSID, tc.sid)
			}
			if got.ErrorValue != tc.errValue {
				t.Errorf("ErrorValue = %d, want %d", got.ErrorValue, tc.errValue)
			}
			if got.Raw == nil {
				t.Error("Raw is nil")
			}
		})
	}
}

func TestParseResponseRejectsNonXML(t *testing.T) {
	for _, body := range []string{
		"",
		"not xml at all",
		"\x00\x01\x02garbage\xff",
		"<html><body>QTS login page</body></html>",
		"{\"json\": true}",
	} {
		if _, err := parseResponse([]byte(body)); !errors.Is(err, ErrBadResponse) {
			t.Errorf("parseResponse(%q) error = %v, want ErrBadResponse", body, err)
		}
	}
}

func TestResultAdminHelper(t *testing.T) {
	r, err := parseResponse([]byte(fixtureNoIsAdmin))
	if err != nil {
		t.Fatal(err)
	}
	if r.Admin() {
		t.Error("Admin() = true for a response with no isAdmin element")
	}
}

func boolp(b bool) *bool { return &b }
