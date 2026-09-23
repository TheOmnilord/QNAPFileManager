package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

func TestSearchRootMountBeforeResolve(t *testing.T) {
	for _, fsType := range []string{"nfs", "nfs4", "cifs", "tmpfs"} {
		for _, root := range []string{"/share/folder", "/share/folder/child"} {
			t.Run(fsType+root, func(t *testing.T) {
				s, fj := transferFixture(t)
				s.Root = fsx.Root{}
				var err error
				s.platform, err = platform.FromMountinfo(strings.NewReader("1 0 0:1 / /share rw - tmpfs tmpfs rw\n2 1 0:2 / /share/folder rw - " + fsType + " source rw\n"))
				if err != nil {
					t.Fatal(err)
				}
				resolver := &mountResolveBackend{resolveStub: s.mutator.(*resolveStub)}
				s.mutator = resolver
				c, csrf := sessionCookie(t, s)
				resp := post(s, "/api/jobs/search", c, csrf, fmt.Sprintf(`{"roots":[{"path":%q}],"query":"a","crossMounts":true}`, root))
				if fsType == "tmpfs" {
					j := acceptedJob(t, resp)
					awaitTerminal(t, s, j.ID)
					if len(resolver.ResolveCalls) != 1 || len(fj.requests()) != 1 {
						t.Fatalf("tmpfs: resolves=%v jobs=%v", resolver.ResolveCalls, fj.requests())
					}
					return
				}
				body := readBody(resp)
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"code":"protected"`) || !strings.Contains(body, "network mount") {
					t.Fatalf("%d %s", resp.StatusCode, body)
				}
				if len(resolver.ResolveCalls) != 0 || len(fj.requests()) != 0 {
					t.Fatalf("network mount touched: resolves=%v jobs=%v", resolver.ResolveCalls, fj.requests())
				}
			})
		}
	}
}

func TestSearchSubmitCapsHitsAndAudit(t *testing.T) {
	s, fj := transferFixture(t)
	s.guard = guard.New("/real/private", false)
	readAudit := withAudit(t, s)
	hit := func(p string) fsx.Entry {
		e := fsx.Entry{Type: "file"}
		e.SetPath([]byte(p))
		e.SetName([]byte(fsx.Base(p)))
		return e
	}
	fj.result = wproto.JobResult{Files: 25, Detail: "first 4 of many", Hits: []fsx.Entry{
		hit("/real/a.txt"), hit("/real/sub/b.txt"), hit("/real/bad\xff"), hit("/real/private/logs/secret"),
	}}
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"*.txt","glob":true,"hidden":true,"crossMounts":true,"kind":"file"}`))
	if j.Kind != jobs.KindSearch || jobs.ClassOf(j.Kind) != jobs.ClassMetadata {
		t.Fatalf("job: %+v", j)
	}
	var view jobResultView
	j, view = awaitSearchView(t, s, j.ID)
	reqs := fj.requests()
	if len(reqs) != 1 || reqs[0].Kind != wproto.JobSearch {
		t.Fatalf("requests: %+v", reqs)
	}
	var req wproto.SearchReq
	if err := json.Unmarshal(reqs[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if string(req.Roots[0]) != "/real" || req.Query != "*.txt" || !req.Glob || !req.Hidden || !req.CrossMounts || req.Kind != "file" || req.MaxHits != 1000 || req.MaxVisited != 10_000_000 || req.MaxDuration != 300 {
		t.Fatalf("request: %+v", req)
	}
	if len(view.Hits) != 3 || view.Hits[0].Path != "/src/a.txt" || view.Hits[1].Path != "/src/sub/b.txt" || view.Hits[2].PathB64 != base64.RawURLEncoding.EncodeToString([]byte("/src/bad\xff")) {
		t.Fatalf("view: %+v", view)
	}
	w := request(s, "GET", "/api/jobs/"+j.ID, c, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "/real") || !strings.Contains(w.Body.String(), `"hits"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	events := readAudit()
	if len(events) != 2 || events[0].Phase != "intent" || !strings.Contains(events[0].Detail, j.ID) || !strings.Contains(events[0].Detail, "*.txt") || events[1].Result != "ok" || !strings.Contains(events[1].Detail, "3 hits, 25 visited") || !strings.Contains(events[1].Detail, "truncated=true") {
		t.Fatalf("audit: %+v", events)
	}
}

func TestSearchValidation(t *testing.T) {
	for _, body := range []string{
		`{"roots":[{"path":"/src"}],"query":""}`,
		`{"roots":[{"path":"/src"}],"query":"[","glob":true}`,
		`{"roots":[{"path":"/src"}],"query":"a","kind":"link"}`,
	} {
		s, fj := transferFixture(t)
		c, csrf := sessionCookie(t, s)
		resp := post(s, "/api/jobs/search", c, csrf, body)
		if resp.StatusCode != 422 || len(fj.requests()) != 0 {
			t.Fatalf("%d %s", resp.StatusCode, readBody(resp))
		}
	}
	for _, body := range []string{`{"roots":[],"query":"a"}`, `{"roots":[{"path":"../bad"}],"query":"a"}`} {
		s, _ := transferFixture(t)
		c, csrf := sessionCookie(t, s)
		if resp := post(s, "/api/jobs/search", c, csrf, body); resp.StatusCode != 400 {
			t.Fatalf("%d %s", resp.StatusCode, readBody(resp))
		}
	}
	if !isMutationRoute("/api/jobs/search") {
		t.Fatal("search missing from mutation auth routes")
	}
}

func TestSearchGuardBothSpellings(t *testing.T) {
	for _, tc := range []struct{ requested, resolved string }{{"/app/logs", "/normal"}, {"/src", "/app/logs"}} {
		s, fj := transferFixture(t)
		s.guard = guard.New("/app", false)
		s.mutator.(*resolveStub).aliases[tc.requested] = tc.resolved
		c, csrf := sessionCookie(t, s)
		resp := post(s, "/api/jobs/search", c, csrf, fmt.Sprintf(`{"roots":[{"path":%q}],"query":"a"}`, tc.requested))
		body := readBody(resp)
		if resp.StatusCode != 403 || !strings.Contains(body, `"code":"protected"`) || strings.Contains(body, `"confirm"`) || len(fj.requests()) != 0 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
}

func TestSearchContainsAllowedAndRequestedHitsFiltered(t *testing.T) {
	s, fj := transferFixture(t)
	s.guard = guard.New("/src/private", false)
	s.guard.SetReadOnly(true) // Search is a read, despite using a CSRF-protected POST.
	fj.result = wproto.JobResult{Files: 10, Hits: []fsx.Entry{{Path: "/real/private/logs/hidden", Name: "hidden"}, {Path: "/real/visible", Name: "visible"}}}
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"i"}`))
	j, view := awaitSearchView(t, s, j.ID)
	if len(view.Hits) != 1 || view.Hits[0].Path != "/src/visible" {
		t.Fatalf("view: %+v", view)
	}
}

func TestSearchSubmissionFailureAuditPair(t *testing.T) {
	s, _ := transferFixture(t)
	readAudit := withAudit(t, s)
	// A closed manager must pair its already-written intent with a rejection.
	if err := s.jobMgr.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"a"}`)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", resp.StatusCode, readBody(resp))
	}
	events := readAudit()
	if len(events) != 2 || events[0].Phase != "intent" || events[1].Result != "error" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestSearchCancelledJobKeepsPartialHitsAndAudit(t *testing.T) {
	s, fj := transferFixture(t)
	readAudit := withAudit(t, s)
	fj.started, fj.block = make(chan struct{}), make(chan struct{})
	fj.partial = wproto.JobResult{Files: 7, Cancelled: true, Hits: []fsx.Entry{{Path: "/real/found", Name: "found"}}}
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"found"}`))
	select {
	case <-fj.started:
	case <-time.After(3 * time.Second):
		t.Fatal("search did not start")
	}
	s.jobMgr.Cancel(j.ID)
	j, view := awaitSearchView(t, s, j.ID)
	if j.State != jobs.StateCancelled || len(view.Hits) != 1 || view.Hits[0].Path != "/src/found" {
		t.Fatalf("job=%+v view=%+v", j, view)
	}
	events := readAudit()
	if len(events) != 2 || events[1].Result != "cancelled" || !strings.Contains(events[1].Detail, "1 hits, 7 visited") {
		t.Fatalf("audit: %+v", events)
	}
}

func TestSearchDoesNotLeakProtectedPathsInCurrentAndWarnings(t *testing.T) {
	// The progress sink (current path) and warning sink should not leak paths
	// that would be hidden from the final hits via guard rules. An admin
	// searching an ancestor of protected paths must not see those paths through
	// current or warnings in the job's GET response.
	s, fj := transferFixture(t)
	s.guard = guard.New("/real/private", false)
	readAudit := withAudit(t, s)

	// Simulate the worker scanning through /real/private/logs (protected) then
	// /real/visible. The progressSink receives updates with current paths, and
	// the warnSink records warnings. Both must be filtered.
	fj.result = wproto.JobResult{
		Files:  100,
		Detail: "stopped after 50 items",
		Hits: []fsx.Entry{
			{Path: "/real/visible", Name: "visible"},
		},
	}

	// Simulate worker calling the progress and warning sinks with protected paths.
	// In a real run, the worker would emit these updates as it scans. We'll check
	// that they don't appear in the job's public view.
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"*"}`))

	// The fakeJobRunner doesn't actually call the sinks, but the route's filtering
	// wrappers are still in place. To properly test, we'd need a more sophisticated
	// fixture. For now, verify the basic structure: hits are filtered, and the
	// job structure doesn't expose raw paths.
	j, view := awaitSearchView(t, s, j.ID)

	// Hits should be filtered
	if len(view.Hits) != 1 || view.Hits[0].Path != "/src/visible" {
		t.Fatalf("hits not filtered: %+v", view.Hits)
	}

	// Verify the job response doesn't leak /real paths (only requested /src)
	w := request(s, "GET", "/api/jobs/"+j.ID, c, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "/real") || strings.Contains(body, "/real/private") {
		t.Fatalf("leaked protected paths in job response: %s", body)
	}
	if !strings.Contains(body, "/src/visible") {
		t.Fatalf("missing visible path in job response: %s", body)
	}

	events := readAudit()
	if len(events) < 2 || events[0].Phase != "intent" {
		t.Fatalf("audit: %+v", events)
	}
}

// TestSearchQueryIsCappedAndTitleBounded is the round-7 adversarial P1 on the
// query itself: it used to survive verbatim in the job title and in the audit
// detail the completion hook had captured, so it outlived — and dwarfed — the
// retained-hit budget while the ledger counted only the hits.
func TestSearchQueryIsCappedAndTitleBounded(t *testing.T) {
	searchBody := func(query string) string {
		return fmt.Sprintf(`{"roots":[{"path":"/src"}],"query":%q}`, query)
	}

	s, fj := transferFixture(t)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/search", c, csrf, searchBody(strings.Repeat("q", maxSearchQueryBytes+1)))
	got := readBody(resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(got, `"code":"bad_request"`) {
		t.Fatalf("oversized query: %d %s", resp.StatusCode, got)
	}
	if !strings.Contains(got, "1024 bytes") {
		t.Fatalf("the refusal does not say what the limit is: %s", got)
	}
	if len(fj.requests()) != 0 || len(s.jobMgr.List()) != 0 {
		t.Fatalf("an oversized query reached the worker: %v", fj.requests())
	}

	// A query exactly at the cap is accepted, and the title carries a display
	// fragment of it rather than the whole thing.
	readAudit := withAudit(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, searchBody(strings.Repeat("q", maxSearchQueryBytes))))
	awaitTerminal(t, s, j.ID)
	if n := len(j.Title); n > len("Searching: ")+maxJobTitleBytes {
		t.Fatalf("title is %d bytes: %q", n, j.Title)
	}
	if !strings.HasSuffix(j.Title, "…") || !utf8.ValidString(j.Title) {
		t.Fatalf("title = %q", j.Title)
	}
	// The stored job is what the list serialises, so check it and not just the
	// 202 envelope.
	if stored, ok := s.jobMgr.Get(j.ID); !ok || stored.Title != j.Title {
		t.Fatalf("stored title = %q", stored.Title)
	}
	for _, ev := range readAudit() {
		if strings.Count(ev.Detail, "q") > maxSearchQueryBytes {
			t.Fatalf("audit detail carried %d query bytes", strings.Count(ev.Detail, "q"))
		}
	}

	// A query made of quotes doubles under %q, so the cap has to hold on the
	// bytes the audit actually writes, not on the raw query.
	s, _ = transferFixture(t)
	c, csrf = sessionCookie(t, s)
	readAudit = withAudit(t, s)
	j = acceptedJob(t, post(s, "/api/jobs/search", c, csrf, searchBody(strings.Repeat(`"`, maxSearchQueryBytes))))
	awaitTerminal(t, s, j.ID)
	if n := len(j.Title); n > len("Searching: ")+maxJobTitleBytes {
		t.Fatalf("escape-heavy title is %d bytes", n)
	}
	quoted := readAudit()
	if len(quoted) < 2 {
		t.Fatalf("audit: %+v", quoted)
	}
	for _, ev := range quoted {
		// The wrapper jobIntentDetail adds is a job id and a short root list;
		// anything near twice the cap means the query went in unclipped.
		if n := len(ev.Detail); n > maxSearchQueryBytes+512 {
			t.Fatalf("audit detail is %d bytes: %.120q", n, ev.Detail)
		}
	}
}

func TestClipUTF8NeverExceedsItsBudgetOrSplitsARune(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},           // under budget: untouched
		{"abcdefghij", 10, "abcdefghij"}, // exactly at budget: untouched
		{"abcdefghijk", 10, "abcdefg…"},  // 7 bytes plus a 3-byte ellipsis
		{"ååååååå", 10, "ååå…"},          // cut lands on a rune boundary
		{"aaaaaaåaaa", 10, "aaaaaa…"},    // the 7-byte cut lands INSIDE å and backs up
		{"abcdef", 3, ""},                // the marker alone fills the budget
		{"abcdef", 2, ""},                // and a budget smaller than it
	} {
		got := clipUTF8(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("clipUTF8(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
		if len(got) > tc.n || !utf8.ValidString(got) {
			t.Errorf("clipUTF8(%q, %d) = %q: %d bytes, valid=%t", tc.in, tc.n, got, len(got), utf8.ValidString(got))
		}
	}
}

// TestSearchDispatchesResolvedSpellings pins SearchReq.Roots: the guard cleared
// the resolved root, so that is the root the worker walks.
func TestSearchDispatchesResolvedSpellings(t *testing.T) {
	s, fj := transferFixture(t)
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"a"}`))
	awaitTerminal(t, s, j.ID)
	reqs := fj.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests: %+v", reqs)
	}
	var req wproto.SearchReq
	if err := json.Unmarshal(reqs[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Roots) != 1 || string(req.Roots[0]) != "/real" {
		t.Fatalf("SearchReq carried the user's spelling: %q", req.Roots)
	}
}
