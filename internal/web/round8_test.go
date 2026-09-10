package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
)

// TestConcurrentReadOnlyTogglesStayConsistent proves the standard-P1/adv-1 fix:
// two (here many) concurrent admin toggles never leave the persisted file, the
// live guard and the audit trail disagreeing. The whole transition is serialised
// under cfgMu, so whichever runs last sets all three consistently.
func TestConcurrentReadOnlyTogglesStayConsistent(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(true)
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	logger, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, csrf := sessionCookie(t, s)
	s.sessions[c.Value].admin = true

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(v bool) {
			defer wg.Done()
			post(s, "/api/settings", c, csrf, fmt.Sprintf(`{"readOnly":%v}`, v)).Body.Close()
		}(i%2 == 0)
	}
	wg.Wait()

	// The live guard and the persisted file must agree.
	loaded, err := config.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReadOnly != s.guard.ReadOnly() {
		t.Fatalf("file readOnly=%v disagrees with live guard=%v", loaded.ReadOnly, s.guard.ReadOnly())
	}
	// The last audited readonly result must match the live guard too.
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(2000)
	if err != nil {
		t.Fatal(err)
	}
	last := ""
	for _, e := range events {
		if e.Op == "readonly" && e.Phase == "result" && e.Result == "ok" {
			last = e.Detail
		}
	}
	if want := fmt.Sprintf("readOnly=%v", s.guard.ReadOnly()); last != want {
		t.Fatalf("last audited result %q disagrees with live guard %q", last, want)
	}
}

// TestReadOnlyIntentDurableBeforeApply proves the intent-before-writes ordering
// (standard P1 / adv 1): the toggle INTENT is recorded durably BEFORE the config
// is persisted or the guard flipped. A ConfigPath whose parent does not exist
// makes config.Save fail, so the transition is refused at the persist step — yet
// the intent line is already durable and the guard was never flipped.
func TestReadOnlyIntentDurableBeforeApply(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(true)
	s.ConfigPath = filepath.Join(t.TempDir(), "no-such-dir", "config.json") // Save fails
	logger, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, csrf := sessionCookie(t, s)
	s.sessions[c.Value].admin = true

	resp := post(s, "/api/settings", c, csrf, `{"readOnly":false}`)
	if resp.StatusCode != 500 {
		t.Fatalf("status %d, want 500 (persist failed)", resp.StatusCode)
	}
	if !s.guard.ReadOnly() {
		t.Fatal("the live guard was flipped despite the persist failing")
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	intent := false
	for _, e := range events {
		if e.Op == "readonly" && e.Phase == "intent" && e.Detail == "readOnly=false" {
			intent = true
		}
	}
	if !intent {
		t.Fatalf("no durable readonly intent recorded before the persist failure among %d events", len(events))
	}
}

// leakyResolve returns a resolve error whose text names a resolved absolute path
// the caller never spelled, standing in for a worker openat failure naming an
// ancestor along the resolved chain.
type leakyResolve struct {
	*fakeBackend
}

func (leakyResolve) Resolve(context.Context, backend.Principal, string, bool) (string, error) {
	return "", fmt.Errorf("openat /private/resolved/secret: %w", fs.ErrPermission)
}

// leakyMutator resolves normally but returns worker errors whose text names the
// dispatched (resolved) path.
type leakyMutator struct {
	*fakeBackend
}

func (l leakyMutator) Mkdir(context.Context, backend.Principal, string, string, os.FileMode, bool) (fsx.Entry, error) {
	return fsx.Entry{}, fmt.Errorf("mkdir /private/resolved/target: %w", fs.ErrExist)
}

func (l leakyMutator) Delete(context.Context, backend.Principal, string) error {
	return fmt.Errorf("unlinkat /private/resolved/secret: %w", fs.ErrPermission)
}

// TestNoResolvedPathLeaksIntoClientJSON proves the adv-2 fix robustly: neither a
// resolve error nor a worker (mutator) error whose text contains a resolved path
// ever reaches the client JSON. The code is mapped and the requested path echoed,
// but the resolved spelling stays in the server log only.
func TestNoResolvedPathLeaksIntoClientJSON(t *testing.T) {
	// A resolve failure that names a resolved ancestor.
	t.Run("resolve", func(t *testing.T) {
		s, b := fixture(t, true)
		s.guard.SetReadOnly(false)
		s.mutator = leakyResolve{fakeBackend: b}
		c, csrf := sessionCookie(t, s)
		resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"x"}`)
		if resp.StatusCode != 403 {
			t.Fatalf("status %d, want 403 (permission)", resp.StatusCode)
		}
		if body := readBody(resp); strings.Contains(body, "private/resolved") {
			t.Fatalf("resolve error leaked a resolved path to the client: %s", body)
		}
	})
	// A worker error that names the dispatched (resolved) path.
	t.Run("mutator", func(t *testing.T) {
		s, b := fixture(t, true)
		s.guard.SetReadOnly(false)
		s.mutator = leakyMutator{fakeBackend: b}
		c, csrf := sessionCookie(t, s)
		resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"x"}`)
		if resp.StatusCode != 409 {
			t.Fatalf("status %d, want 409 (exists)", resp.StatusCode)
		}
		var e apiEnvelope
		body := readBody(resp)
		json.Unmarshal([]byte(body), &e)
		if e.Error.Code != "exists" {
			t.Fatalf("code %q, want exists", e.Error.Code)
		}
		if strings.Contains(body, "private/resolved") {
			t.Fatalf("worker error leaked a resolved path to the client: %s", body)
		}
		if e.Error.Path != "/x" {
			t.Fatalf("client path %q, want the requested /x", e.Error.Path)
		}
	})
}

// TestRenameOverwriteProtectedDestNotExisting proves the adv-3 fix: with
// overwrite:true the destination's OpDelete policy is checked ALWAYS, even when
// the destination does not currently exist. Renaming a file over a not-yet-present
// entry under /dev is refused, because /dev forbids deleting entries there.
func TestRenameOverwriteProtectedDestNotExisting(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "src.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// /dev/newnode does not exist yet.
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/rename", c, csrf, `{"path":"/src.txt","to":"/dev/newnode","overwrite":true}`)
	if resp.StatusCode != 403 {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "src.txt")); err != nil {
		t.Fatalf("source disturbed by a refused rename: %v", err)
	}
}

// TestBatchMilestoneResultReflectsOutcome proves the adv-5/6 fix: a large batch
// where some items fail records a milestone whose Result is "partial", matching
// the HTTP response, not a blanket "ok".
// TestAuditContextCancellation proves the round-6 fix: only a record of work
// that already happened (result ok/error/partial) is made cancellation-immune;
// an intent line (empty result) and a denial stay request-scoped, so a cancelled
// request cannot be forced to wait the full audit timeout on a wedged sink before
// any destructive work has happened (round-4 adv 4 / round-6 std+adv).
func TestAuditContextCancellation(t *testing.T) {
	cases := []struct {
		result     string
		stillBound bool // true => the returned context must still observe the cancel
	}{
		{"", true},         // intent (pre-work): must stay cancellable
		{"denied", true},   // no work happened: must stay cancellable
		{"ok", false},      // completed work: cancellation-immune
		{"error", false},   // dispatched then failed: still a record of an attempt
		{"partial", false}, // batch milestone: some work happened
		{"weird", true},    // an unrecognised result defaults to request-scoped (safe)
	}
	for _, tc := range cases {
		t.Run("result="+tc.result, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			ctx := auditContext(parent, tc.result)
			cancel()
			bound := ctx.Err() != nil
			if bound != tc.stillBound {
				t.Fatalf("result=%q: context bound to request cancel = %v, want %v", tc.result, bound, tc.stillBound)
			}
		})
	}
}

func TestBatchMilestoneResultReflectsOutcome(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.WriteFile(filepath.Join(b.dir, "d1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// d2 is missing → its delete fails. bigStat inflates sizes so the batch clears
	// the milestone threshold.
	s.backend = bigStat{fakeBackend: b}
	logger, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, csrf := sessionCookie(t, s)
	first := post(s, "/api/fs/delete", c, csrf, `{"paths":[{"path":"/d1"},{"path":"/d2"}]}`)
	var tok struct{ Confirm struct{ Token string } }
	json.NewDecoder(first.Body).Decode(&tok)
	if tok.Confirm.Token == "" {
		t.Fatal("no batch confirmation token")
	}
	resp := post(s, "/api/fs/delete", c, csrf, `{"paths":[{"path":"/d1"},{"path":"/d2"}],"confirm":"`+tok.Confirm.Token+`"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct{ Outcome string }
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Outcome != "partial" {
		t.Fatalf("HTTP outcome %q, want partial", out.Outcome)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(200)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Op == "delete" && e.Phase == "result" && strings.Contains(e.Detail, "batch delete:") {
			found = true
			if e.Result != "partial" {
				t.Fatalf("batch milestone Result %q, want partial", e.Result)
			}
		}
	}
	if !found {
		t.Fatal("no batch milestone recorded")
	}
}

// cancelAfterFirst cancels the request context once the first item has been
// deleted, so the batch loop's per-item cancellation check must stop the rest.
type cancelAfterFirst struct {
	*fakeBackend
	cancel context.CancelFunc
	n      int
}

func (m *cancelAfterFirst) Delete(ctx context.Context, p backend.Principal, name string) error {
	m.n++
	err := m.fakeBackend.Delete(ctx, p, name)
	if m.n == 1 {
		m.cancel()
	}
	return err
}

// TestBatchDeleteStopsOnContextCancel proves the adv-4 fix: a cancelled request
// stops the batch promptly rather than grinding through every remaining item. The
// context is cancelled after the first delete; the rest survive.
func TestBatchDeleteStopsOnContextCancel(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	for _, name := range []string{"d1", "d2", "d3", "d4"} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"},{"path":"/d4"}]}`
	first := post(s, "/api/fs/delete", c, csrf, body)
	var tok struct{ Confirm struct{ Token string } }
	json.NewDecoder(first.Body).Decode(&tok)
	if tok.Confirm.Token == "" {
		t.Fatal("no batch confirmation token")
	}
	confirmed := `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"},{"path":"/d4"}],"confirm":"` + tok.Confirm.Token + `"}`

	ctx, cancel := context.WithCancel(context.Background())
	s.mutator = &cancelAfterFirst{fakeBackend: b, cancel: cancel}
	r := httptest.NewRequest("POST", "/api/fs/delete", strings.NewReader(confirmed)).WithContext(ctx)
	r.AddCookie(c)
	r.Header.Set("X-QFM-CSRF", csrf)
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var out struct {
		Attempted int
		Outcome   string
		Results   []struct{ Path string }
	}
	json.NewDecoder(w.Body).Decode(&out)
	if out.Attempted >= 4 {
		t.Fatalf("batch did not stop on cancellation: attempted=%d", out.Attempted)
	}
	// A batch stopped after a success but with items left unattempted must report
	// "partial", never "ok" — a cancel must not masquerade as full success
	// (round-5 std/adv 3).
	if out.Outcome != "partial" {
		t.Fatalf("truncated batch outcome %q, want partial", out.Outcome)
	}
	// The un-attempted items survive on disk.
	if _, err := os.Stat(filepath.Join(b.dir, "d4")); err != nil {
		t.Fatalf("d4 should survive a cancelled batch: %v", err)
	}
}

// TestBatchMilestoneSurvivesCancel proves the round-5 adv-1/2 fix: a milestone
// that records work which ALREADY happened must be persisted even though the
// client cancelled. A big batch is cancelled after its first successful delete;
// the loop stops, but the batch milestone (written with a cancellation-immune
// context) must still land durably, marked "partial", so the destructive work
// leaves an audit record instead of vanishing with the disconnected client.
func TestBatchMilestoneSurvivesCancel(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	for _, name := range []string{"d1", "d2", "d3", "d4"} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// bigStat inflates measured sizes so the batch crosses the milestone threshold.
	s.backend = bigStat{fakeBackend: b}
	logger, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"},{"path":"/d4"}]}`
	first := post(s, "/api/fs/delete", c, csrf, body)
	var tok struct{ Confirm struct{ Token string } }
	json.NewDecoder(first.Body).Decode(&tok)
	if tok.Confirm.Token == "" {
		t.Fatal("no batch confirmation token")
	}
	confirmed := `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"},{"path":"/d4"}],"confirm":"` + tok.Confirm.Token + `"}`

	ctx, cancel := context.WithCancel(context.Background())
	s.mutator = &cancelAfterFirst{fakeBackend: b, cancel: cancel}
	r := httptest.NewRequest("POST", "/api/fs/delete", strings.NewReader(confirmed)).WithContext(ctx)
	r.AddCookie(c)
	r.Header.Set("X-QFM-CSRF", csrf)
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(200)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Op == "delete" && e.Phase == "result" && strings.Contains(e.Detail, "batch delete:") {
			found = true
			if e.Result != "partial" {
				t.Fatalf("batch milestone Result %q, want partial", e.Result)
			}
		}
	}
	if !found {
		t.Fatal("batch milestone lost after client cancellation; a completed deletion left no durable record")
	}
}

// TestReadHandlersEnforceGuardReadDenials proves the standard-P2 fix: the install
// config and the audit-log directory declared as OpRead/OpTraverse denials cannot
// be read back through the ordinary list/stat/text/download endpoints.
func TestReadHandlersEnforceGuardReadDenials(t *testing.T) {
	s, b := fixture(t, true)
	s.guard = guard.New("/app", false) // install dir with config+logs read denials
	for _, d := range []string{"app/config", "app/logs"} {
		if err := os.MkdirAll(filepath.Join(b.dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b.dir, "app/config/config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "app/logs/audit.jsonl"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := sessionCookie(t, s)
	for _, target := range []string{
		"/api/fs/list?path=/app/config",
		"/api/fs/stat?path=/app/config/config.json",
		"/api/fs/text?path=/app/logs/audit.jsonl",
		"/api/fs/download?path=/app/logs/audit.jsonl",
	} {
		w := request(s, "GET", target, c, nil)
		if w.Code != 403 {
			t.Fatalf("%s: status %d, want 403", target, w.Code)
		}
		var e apiEnvelope
		json.Unmarshal(w.Body.Bytes(), &e)
		if e.Error.Code != "protected" {
			t.Fatalf("%s: code %q, want protected", target, e.Error.Code)
		}
	}
	// An ordinary read is untouched by the guard check.
	if w := request(s, "GET", "/api/fs/stat?path=/a.txt", c, nil); w.Code != 200 {
		t.Fatalf("ordinary stat blocked: %d %s", w.Code, w.Body)
	}
}
