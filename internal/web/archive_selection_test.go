package web

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/platform"
)

func selectArchive(t *testing.T, s *Server, c *http.Cookie, body string) string {
	t.Helper()
	resp := post(s, "/api/fs/archive/select", c, s.sessions[c.Value].csrf, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("select: %d %s", resp.StatusCode, readBody(resp))
	}
	var result struct{ Sel string }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(result.Sel)
	if err != nil || len(raw) != 16 {
		t.Fatalf("invalid 128-bit token: %q", result.Sel)
	}
	return result.Sel
}

func TestArchiveSelectionRoundTrip(t *testing.T) {
	for _, format := range []string{"zip", "tgz"} {
		t.Run(format, func(t *testing.T) {
			s, b, resolver, c := archiveFixture(t, []byte("archive data"))
			s.guard.SetReadOnly(true)
			readAudit := withAudit(t, s)
			encoded := base64.RawURLEncoding.EncodeToString([]byte("/src/other\xff"))
			sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/file"},{"pathB64":"`+encoded+`"}],"format":"`+format+`","name":"chosen.`+format+`","crossMounts":true}`)
			if len(b.reqs) != 0 || isMutationRoute("/api/fs/archive/select") {
				t.Fatal("selection streamed an archive or is a disk mutation route")
			}
			// The ticket keeps the REQUESTED spellings only, so consumption
			// resolves them again: a parent swapped between select and download
			// is seen — and re-guarded — now, not trusted from the POST.
			resolver.aliases["/src"] = "/changed"
			w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
			if w.Code != http.StatusOK || w.Body.String() != "archive data" || !strings.Contains(w.Header().Get("Content-Disposition"), `filename="chosen.`+format+`"`) {
				t.Fatalf("GET: %d %v %s", w.Code, w.Header(), w.Body)
			}
			if len(b.reqs) != 1 || len(b.reqs[0].Paths) != 2 || string(b.reqs[0].Paths[0]) != "/changed/file" || string(b.reqs[0].Paths[1]) != "/changed/other\xff" || b.reqs[0].Format != format || !b.reqs[0].CrossMounts {
				t.Fatalf("request: %+v", b.reqs)
			}
			events := readAudit()
			if len(events) != 2 || events[0].Phase != "intent" || events[1].Phase != "result" || events[1].Result != "ok" {
				t.Fatalf("audit: %+v", events)
			}
			for _, event := range events {
				if !strings.Contains(event.Detail, "sel") || strings.Contains(event.Detail, sel) {
					t.Fatalf("audit must mention sel without exposing token: %+v", event)
				}
			}
		})
	}
}

func TestArchiveSelectionExpiryAndSingleUse(t *testing.T) {
	for _, age := range []time.Duration{59 * time.Second, 60 * time.Second, 61 * time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			s, b, _, c := archiveFixture(t, []byte("archive"))
			now := time.Now()
			s.Now = func() time.Time { return now }
			sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
			now = now.Add(age)
			w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
			if age < archiveSelectionTTL {
				if w.Code != http.StatusOK || len(b.reqs) != 1 || b.reqs[0].Format != "zip" {
					t.Fatalf("unexpired: %d %s requests=%v", w.Code, w.Body, b.reqs)
				}
			} else if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) || len(b.reqs) != 0 {
				t.Fatalf("expired: %d %s requests=%v", w.Code, w.Body, b.reqs)
			}
			w = request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
			if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) {
				t.Fatalf("reused: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestArchiveSelectionSessionIsolationAndCleanup(t *testing.T) {
	s, b, _, owner := archiveFixture(t, []byte("archive"))
	other, _ := sessionCookie(t, s) // Same user, different session.
	if other.Value == owner.Value {
		t.Fatal("fixture did not create another session")
	}
	sel := selectArchive(t, s, owner, `{"paths":[{"path":"/src/file"}]}`)
	w := request(s, "GET", "/api/fs/archive?sel="+sel, other, nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) || len(b.reqs) != 0 {
		t.Fatalf("other session: %d %s", w.Code, w.Body)
	}
	w = request(s, "GET", "/api/fs/archive?sel="+sel, owner, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("owner's ticket was consumed by other session: %d %s", w.Code, w.Body)
	}
	selectArchive(t, s, owner, `{"paths":[{"path":"/src/file"}]}`)
	s.destroy(owner.Value)
	if len(s.archiveSelections) != 0 {
		t.Fatal("session destruction retained selections")
	}
}

func TestArchiveSelectionBoundAndAtomicConsume(t *testing.T) {
	s, _, _, c := archiveFixture(t, nil)
	now := time.Now()
	s.Now = func() time.Time { return now }
	var tokens []string
	for range maxArchiveSelections {
		tokens = append(tokens, selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`))
	}
	resp := post(s, "/api/fs/archive/select", c, s.sessions[c.Value].csrf, `{"paths":[{"path":"/src/file"}]}`)
	if resp.StatusCode != http.StatusTooManyRequests || len(s.archiveSelections[c.Value]) != maxArchiveSelections {
		t.Fatalf("bound: %d %s", resp.StatusCode, readBody(resp))
	}
	resp.Body.Close()
	other, _ := sessionCookie(t, s)
	selectArchive(t, s, other, `{"paths":[{"path":"/src/file"}]}`)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, ok := s.consumeArchiveSelection(c.Value, tokens[0]); ok {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent consumers: %d", winners.Load())
	}
	selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
	now = now.Add(archiveSelectionTTL)
	selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
	if len(s.archiveSelections[c.Value]) != 1 {
		t.Fatal("expired entries were not reclaimed")
	}
}

func TestArchiveSelectionValidation(t *testing.T) {
	for _, body := range []string{`{}`, `{"paths":[{"path":"relative"}]}`, `{"paths":[{"pathB64":"%%%"}]}`, `{"paths":[{"path":"/src/file"}],"format":"tar"}`, `{"paths":[{"path":"/src/file"}],"name":"../bad"}`, `{"paths":[{"path":"/src/file"}],"crossMounts":"nope"}`, `{"paths":[]}`, `{"unknown":true}`} {
		s, b, _, c := archiveFixture(t, nil)
		resp := post(s, "/api/fs/archive/select", c, s.sessions[c.Value].csrf, body)
		if resp.StatusCode != http.StatusBadRequest || len(s.archiveSelections) != 0 || len(b.reqs) != 0 {
			t.Fatalf("%s: %d %s", body, resp.StatusCode, readBody(resp))
		}
		resp.Body.Close()
	}
	s, _, _, c := archiveFixture(t, nil)
	sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
	for _, suffix := range []string{"&path=/src/file", "&format=zip", "&name=a", "&crossMounts=false", "&unknown=", "&sel=" + sel, "&bad=%zz", "&bad;x=1"} {
		w := request(s, "GET", "/api/fs/archive?sel="+sel+suffix, c, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("mixed parameters %s: %d %s", suffix, w.Code, w.Body)
		}
	}
	for _, token := range []string{"", "invalid", strings.Repeat("0", 32)} {
		w := request(s, "GET", "/api/fs/archive?sel="+token, c, nil)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) {
			t.Fatalf("invalid token %q: %d %s", token, w.Code, w.Body)
		}
	}
	w := request(s, "GET", "/api/fs/archive?path=/src/file&sel=%zz", c, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed sel was ignored: %d %s", w.Code, w.Body)
	}
	if _, ok := s.consumeArchiveSelection(c.Value, sel); !ok {
		t.Fatal("mixed parameters consumed the ticket")
	}
}

func TestArchiveSelectionGuards(t *testing.T) {
	for _, tc := range []struct{ path, parent, resolved string }{
		{"/app/logs/file", "/app/logs", "/normal"},
		{"/src/logs", "/src", "/app"},
		{"/app", "/", "/"},
		{"/src/app", "/src", "/"},
		{"/etc", "/", "/normal"},
		{"/src/etc", "/src", "/"},
	} {
		t.Run(tc.path+tc.resolved, func(t *testing.T) {
			s, b, rs, c := archiveFixture(t, nil)
			s.guard = guard.New("/app", false)
			rs.aliases[tc.parent] = tc.resolved
			resp := post(s, "/api/fs/archive/select", c, s.sessions[c.Value].csrf, `{"paths":[{"path":"`+tc.path+`"}]}`)
			defer resp.Body.Close()
			body := readBody(resp)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"code":"protected"`) || len(s.archiveSelections) != 0 || len(b.reqs) != 0 {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
		})
	}
	for _, fsType := range []string{"nfs", "nfs4", "cifs"} {
		t.Run(fsType, func(t *testing.T) {
			s, b, rs, c := archiveFixture(t, nil)
			s.Root = fsx.Root{}
			var err error
			s.platform, err = platform.FromMountinfo(strings.NewReader("1 0 0:1 / /share rw - tmpfs tmpfs rw\n2 1 0:2 / /share/folder rw - " + fsType + " source rw\n"))
			if err != nil {
				t.Fatal(err)
			}
			resolver := &mountResolveBackend{resolveStub: rs}
			s.mutator = resolver
			resp := post(s, "/api/fs/archive/select", c, s.sessions[c.Value].csrf, `{"paths":[{"path":"/share/folder/child"}]}`)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || len(resolver.ResolveCalls) != 0 || len(b.reqs) != 0 || len(s.archiveSelections) != 0 {
				t.Fatalf("network mount touched: %d %s", resp.StatusCode, readBody(resp))
			}
		})
	}
}

func TestArchiveSelectionOversizedURL(t *testing.T) {
	s, b, _, c := archiveFixture(t, []byte("archive"))
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.MaxHeaderBytes = 64 << 10
	ts.Start()
	defer ts.Close()
	refs := make([]pathRef, 600)
	query := url.Values{}
	for i := range refs {
		refs[i].Path = fmt.Sprintf("/src/%04d-%s", i, strings.Repeat("a", 140))
		query.Add("path", refs[i].Path)
	}
	client := ts.Client()
	get := func(target string) *http.Response {
		t.Helper()
		r, err := http.NewRequest("GET", ts.URL+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.AddCookie(c)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := get("/api/fs/archive?" + query.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized URL: %d", resp.StatusCode)
	}
	body, err := json.Marshal(map[string]any{"paths": refs})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest("POST", ts.URL+"/api/fs/archive/select", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(c)
	r.Header.Set("Origin", ts.URL)
	r.Header.Set("X-QFM-CSRF", s.sessions[c.Value].csrf)
	r.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("oversized selection: %d %s", resp.StatusCode, readBody(resp))
	}
	var result struct{ Sel string }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	resp = get("/api/fs/archive?sel=" + result.Sel)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || string(data) != "archive" || len(b.reqs) != 1 || len(b.reqs[0].Paths) != len(refs) {
		t.Fatalf("ticket download: %d %s err=%v", resp.StatusCode, data, err)
	}
	for i, ref := range refs {
		if string(b.reqs[0].Paths[i]) != strings.Replace(ref.Path, "/src/", "/real/", 1) {
			t.Fatalf("path %d was not resolved", i)
		}
	}
}

func TestArchiveSelectionBackendErrorAudit(t *testing.T) {
	s, b, _, c := archiveFixture(t, nil)
	readAudit := withAudit(t, s)
	sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
	b.err = fsx.ErrNoSpace
	w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	events := readAudit()
	if len(events) != 2 || events[1].Result != "error" || !strings.Contains(events[0].Detail, "sel") || !strings.Contains(events[1].Detail, "sel") {
		t.Fatalf("audit: %+v", events)
	}
	w = request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("failed archive did not consume selection: %d %s", w.Code, w.Body)
	}
}
