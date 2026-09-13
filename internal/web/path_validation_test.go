package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// TestRequestPathsRejectOverlongComponents is the round-7 sweep. Every job
// title, audit line and confirmation token the front end builds is made out of
// path components, and nothing bounded one: /api/jobs/size built a title from
// fsx.Base(paths[0]) without ever resolving it, so a component the size of the
// body limit became a job title retained for the whole window and re-serialised
// on every poll. NAME_MAX is the kernel's own rule, so refusing one here
// refuses nothing the worker would have accepted (INV-2 still holds: this
// predicts ENAMETOOLONG, it does not replace the kernel's decision).
func TestRequestPathsRejectOverlongComponents(t *testing.T) {
	long, atCap := strings.Repeat("n", maxComponentBytes+1), strings.Repeat("n", maxComponentBytes)
	b64 := func(p string) string { return base64.RawURLEncoding.EncodeToString([]byte(p)) }

	for _, tc := range []struct{ route, body string }{
		{"/api/jobs/size", `{"paths":[%s]}`},
		{"/api/jobs/search", `{"roots":[%s],"query":"a"}`},
	} {
		t.Run(tc.route, func(t *testing.T) {
			// Both spellings of the same oversized component: pathB64 decodes
			// first, so the cap must be applied to the decoded bytes.
			for _, ref := range []string{
				`{"path":"/src/` + long + `"}`,
				`{"pathB64":"` + b64("/src/"+long) + `"}`,
			} {
				s, fj := transferFixture(t)
				c, csrf := sessionCookie(t, s)
				resp := post(s, tc.route, c, csrf, fmt.Sprintf(tc.body, ref))
				got := readBody(resp)
				resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest || !strings.Contains(got, `"code":"bad_request"`) {
					t.Fatalf("oversized component: %d %s", resp.StatusCode, got)
				}
				if !strings.Contains(got, "longer than 255 bytes") {
					t.Fatalf("the refusal does not say why: %s", got)
				}
				if len(fj.requests()) != 0 || len(s.jobMgr.List()) != 0 {
					t.Fatalf("an oversized component reached the worker: %v", fj.requests())
				}
			}
			// A component AT the cap is ordinary and still works, and the title
			// built from it is a row label rather than the whole name.
			s, _ := transferFixture(t)
			// Search resolves its roots through the worker; the stub answers for
			// a root it knows, so the fixture names this one. (Size never
			// resolves, which is why its title needed the clip.)
			s.mutator.(*resolveStub).aliases["/src/"+atCap] = "/real/" + atCap
			c, csrf := sessionCookie(t, s)
			j := acceptedJob(t, post(s, tc.route, c, csrf, fmt.Sprintf(tc.body, `{"path":"/src/`+atCap+`"}`)))
			awaitTerminal(t, s, j.ID)
			if len(j.Title) > 64+maxJobTitleBytes {
				t.Fatalf("title is %d bytes: %q", len(j.Title), j.Title)
			}
		})
	}

	// mkdir takes a path AND a name it invents outright; both are components.
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	for _, body := range []string{
		`{"dir":"/` + long + `","name":"ok"}`,
		`{"dirB64":"` + b64("/"+long) + `","name":"ok"}`,
		`{"dir":"/","name":"` + long + `"}`,
	} {
		resp := post(s, "/api/fs/mkdir", c, csrf, body)
		got := readBody(resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(got, "longer than 255 bytes") {
			t.Fatalf("mkdir: %d %s", resp.StatusCode, got)
		}
	}
	// A name at the cap is not refused by THIS rule. What the host then makes of
	// the full pathname is the kernel's business, not ours — a jailed test root
	// on a short-path host may still refuse it — so only the rule is asserted.
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"`+atCap+`"}`)
	got := readBody(resp)
	resp.Body.Close()
	if strings.Contains(got, "longer than 255 bytes") {
		t.Fatalf("a name at NAME_MAX was refused: %d %s", resp.StatusCode, got)
	}
	// rename's bare new name is the same invented component.
	resp = post(s, "/api/fs/rename", c, csrf, `{"path":"/a.txt","to":"`+long+`"}`)
	got = readBody(resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(got, "longer than 255 bytes") {
		t.Fatalf("rename: %d %s", resp.StatusCode, got)
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
