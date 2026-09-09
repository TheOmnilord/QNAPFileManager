package qtsauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"qnapfilemanager/internal/idmap"
)

func req(cookies map[string]string, target string, headers map[string]string) *http.Request {
	if target == "" {
		target = "/api/session"
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestFromRequestPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		cookies map[string]string
		target  string
		headers map[string]string
		want    Cred
		ok      bool
	}{
		{
			name:    "qtoken wins over sid cookie, query and header",
			cookies: map[string]string{CookieUser: "admin", CookieQToken: "qt", CookieSID: "ns"},
			target:  "/api/session?sid=qs",
			headers: map[string]string{HeaderSID: "hs"},
			want:    Cred{Kind: KindQToken, User: "admin", Token: "qt"},
			ok:      true,
		},
		{
			name:    "NAS_SID cookie wins over query and header",
			cookies: map[string]string{CookieUser: "bob", CookieSID: "ns"},
			target:  "/api/session?sid=qs",
			headers: map[string]string{HeaderSID: "hs"},
			want:    Cred{Kind: KindSID, User: "bob", Token: "ns"},
			ok:      true,
		},
		{
			name:    "query sid wins over header",
			target:  "/api/session?sid=qs",
			headers: map[string]string{HeaderSID: "hs"},
			want:    Cred{Kind: KindSID, User: "", Token: "qs"},
			ok:      true,
		},
		{
			name:    "header sid is the last resort",
			headers: map[string]string{HeaderSID: "hs"},
			want:    Cred{Kind: KindSID, User: "", Token: "hs"},
			ok:      true,
		},
		{
			name:    "qtoken without NAS_USER falls through to the sid cookie",
			cookies: map[string]string{CookieQToken: "qt", CookieSID: "ns"},
			want:    Cred{Kind: KindSID, User: "", Token: "ns"},
			ok:      true,
		},
		{
			name:    "qtoken without NAS_USER and without sid is unusable",
			cookies: map[string]string{CookieQToken: "qt"},
			ok:      false,
		},
		{
			name: "no credential at all",
			ok:   false,
		},
		{
			name:    "empty token values are ignored",
			cookies: map[string]string{CookieUser: "admin", CookieQToken: "", CookieSID: ""},
			ok:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FromRequest(req(tc.cookies, tc.target, tc.headers))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("Cred = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFromRequestRejectsHostileUserCookie(t *testing.T) {
	// A NAS_USER that is present but malformed is a hostile or corrupt cookie:
	// fail closed rather than silently dropping it and continuing as anonymous.
	// Only bytes that survive net/http's cookie serialisation are listed;
	// ValidUserName itself is exercised directly in TestValidUserName.
	for _, bad := range []string{
		"root rm -rf /",
		"../../etc/passwd",
		"user name",
		strings.Repeat("a", 65),
		"admin$(id)",
	} {
		if got, ok := FromRequest(req(map[string]string{CookieUser: bad, CookieQToken: "qt"}, "", nil)); ok {
			t.Errorf("FromRequest accepted NAS_USER %q as %+v", bad, got)
		}
	}
}

func TestFromRequestRejectsHostileToken(t *testing.T) {
	for _, bad := range []string{
		"tok en",
		strings.Repeat("t", maxTokenLen+1),
	} {
		if _, ok := FromRequest(req(map[string]string{CookieUser: "admin", CookieQToken: bad}, "", nil)); ok {
			t.Errorf("FromRequest accepted token %q", bad)
		}
	}
}

func TestValidUserName(t *testing.T) {
	good := []string{"alice", `DOMAIN\alice`, "alice@example.com", "a.b-c_d", "admin", "sveinung", "user.name", "user_x", "a-b", "DOMAIN@corp", "a", strings.Repeat("a", 64)}
	bad := []string{"", "-x", "bob;rm", "a b", "a/b", "a;b", "a\tb", "a\nb", strings.Repeat("a", 65), "üser", "a\x00"}
	for _, s := range good {
		if !ValidUserName(s) || ValidUserName(s) != idmap.ValidName(s) {
			t.Errorf("ValidUserName(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidUserName(s) || ValidUserName(s) != idmap.ValidName(s) {
			t.Errorf("ValidUserName(%q) = true, want false", s)
		}
	}
}

func TestDomainResponseBinding(t *testing.T) {
	for _, name := range []string{`DOMAIN\alice`, "alice@example.com"} {
		for _, kind := range []string{KindSID, KindQToken} {
			got, err := bindUser(Cred{Kind: kind, User: name, Token: "token"}, Result{Username: name}, false)
			if err != nil || got != name {
				t.Errorf("bindUser(%q, %q) = %q, %v", kind, name, got, err)
			}
		}
	}
}

func TestFromRequestNil(t *testing.T) {
	if _, ok := FromRequest(nil); ok {
		t.Error("FromRequest(nil) = ok")
	}
}
