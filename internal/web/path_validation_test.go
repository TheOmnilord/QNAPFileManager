package web

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"

	"qnapfilemanager/internal/backend"
)

func TestRequestPathsRejectDotComponents(t *testing.T) {
	s, b := fixture(t, true)
	cookie, _ := sessionCookie(t, s)
	for _, path := range []string{"/dangling/../report", "/locked/../report", "/link/../report", "/./a.txt", "/a.txt/.", "/..", "/.", "/a//../b", "/\xff/../report"} {
		for _, query := range []string{
			"path=" + url.QueryEscape(path),
			"path=/a.txt&pathB64=" + base64.RawURLEncoding.EncodeToString([]byte(path)),
			"pathB64=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(path))),
		} {
			for _, endpoint := range []string{"list", "stat", "text", "download"} {
				t.Run(endpoint+"/"+query, func(t *testing.T) {
					b.last = backend.Principal{}
					w := request(s, "GET", "/api/fs/"+endpoint+"?"+query, cookie, nil)
					assertAuthError(t, w, 400, "bad_request", "")
					if b.last.User != "" {
						t.Fatal("noncanonical path reached backend")
					}
				})
			}
		}
	}
}

func TestRequestPathPreservesSlashAndDotNameRules(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"/a//b/", "/a/b"}, {"/.hidden/.../file..", "/.hidden/.../file.."},
		{"/", "/"}, {"/%2e%2e/report", "/%2e%2e/report"},
	} {
		r := httptest.NewRequest("GET", "/?path="+url.QueryEscape(test.raw), nil)
		got, err := requestPath(r)
		if err != nil || got != test.want {
			t.Errorf("requestPath(%q) = %q, %v; want %q", test.raw, got, err, test.want)
		}
	}
}
