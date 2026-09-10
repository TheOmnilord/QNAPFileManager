package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
)

// mustSymlink creates a symlink or skips the test. Windows refuses symlink
// creation without the privilege, and the guard's parent-symlink resolution is
// a Linux concern (INV-2: never simulate the kernel), so a skip is correct.
func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
}

// post issues a POST with a JSON body and the session's CSRF header.
func post(s *Server, target string, cookie *http.Cookie, csrf, body string) *http.Response {
	r := httptest.NewRequest("POST", target, strings.NewReader(body))
	r.AddCookie(cookie)
	r.Header.Set("X-QFM-CSRF", csrf)
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Result()
}

func TestMkdirCreatesAndReturnsEntry(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"made"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("mkdir status %d", resp.StatusCode)
	}
	var entry struct {
		Name, Type string
	}
	json.NewDecoder(resp.Body).Decode(&entry)
	if entry.Name != "made" || entry.Type != "dir" {
		t.Fatalf("entry %+v", entry)
	}
	if fi, err := os.Stat(filepath.Join(b.dir, "made")); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created on disk: %v", err)
	}
}

func TestReadOnlyBlocksMutation(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(true)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"nope"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("read-only status %d", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "read_only" {
		t.Fatalf("code %q", e.Error.Code)
	}
	// api/session must also report the block.
	sess := request(s, "GET", "/api/session", c, nil)
	if !strings.Contains(sess.Body.String(), `"canWrite":false`) || !strings.Contains(sess.Body.String(), `"readOnly":true`) {
		t.Fatalf("session: %s", sess.Body)
	}
}

func TestProtectedDeleteRefused(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/bin"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("protected status %d", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q", e.Error.Code)
	}
}

func TestConfirmRequiredThenSucceeds(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	// A warn-class parent: creating inside /etc/config needs a confirmation token.
	if err := os.MkdirAll(filepath.Join(b.dir, "etc", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/etc/config","name":"new"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("first mkdir status %d, want 409", resp.StatusCode)
	}
	var first struct {
		Error   struct{ Code string }
		Confirm struct{ Token string }
	}
	json.NewDecoder(resp.Body).Decode(&first)
	if first.Error.Code != "confirm_required" || first.Confirm.Token == "" {
		t.Fatalf("no token: %+v", first)
	}
	body, _ := json.Marshal(map[string]any{"dir": "/etc/config", "name": "new", "confirm": first.Confirm.Token})
	resp2 := post(s, "/api/fs/mkdir", c, csrf, string(body))
	if resp2.StatusCode != 200 {
		t.Fatalf("confirmed mkdir status %d", resp2.StatusCode)
	}
	if fi, err := os.Stat(filepath.Join(b.dir, "etc", "config", "new")); err != nil || !fi.IsDir() {
		t.Fatalf("confirmed directory not created: %v", err)
	}
}

func TestMutationRequiresCSRF(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, _ := sessionCookie(t, s)
	r := httptest.NewRequest("POST", "/api/fs/mkdir", strings.NewReader(`{"dir":"/","name":"x"}`))
	r.AddCookie(c)
	r.Header.Set("Origin", "http://example.com") // no X-QFM-CSRF header
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF status %d, want 403", w.Code)
	}
}

func TestMutationAuditsIntentAndResult(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	s.AuditPath = path
	c, csrf := sessionCookie(t, s)
	if resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"audited"}`); resp.StatusCode != 200 {
		t.Fatalf("mkdir status %d", resp.StatusCode)
	}
	// Close flushes the drain; then Tail reads the file back.
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	var intent, result bool
	for _, e := range events {
		if e.Op == "mkdir" && e.Path == "/audited" && e.Actor == "dev" {
			if e.Phase == "intent" {
				intent = true
			}
			if e.Phase == "result" && e.Result == "ok" {
				result = true
			}
		}
	}
	if !intent || !result {
		t.Fatalf("audit missing phases: intent=%v result=%v events=%d", intent, result, len(events))
	}
	// The admin export streams the raw file.
	s.sessions[c.Value].admin = true
	exp := request(s, "GET", "/api/audit/export", c, nil)
	if exp.Code != 200 || !strings.Contains(exp.Body.String(), `"op":"mkdir"`) {
		t.Fatalf("export: %d %s", exp.Code, exp.Body)
	}
}

func TestSettingsToggleReadOnly(t *testing.T) {
	s, _ := fixture(t, true) // pins an admin/root dev session
	s.guard.SetReadOnly(true)
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	c, csrf := sessionCookie(t, s)
	s.sessions[c.Value].admin = true
	resp := post(s, "/api/settings", c, csrf, `{"readOnly":false}`)
	if resp.StatusCode != 200 {
		t.Fatalf("settings status %d", resp.StatusCode)
	}
	if s.readOnly() {
		t.Fatal("guard still read-only after toggle")
	}
	// Persisted to the config file, and readable back through config.Load.
	loaded, err := config.Load(s.ConfigPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.ReadOnly {
		t.Fatal("the saved config still has read-only on")
	}
	// A non-admin session is refused.
	s.sessions[c.Value].admin = false
	if resp := post(s, "/api/settings", c, csrf, `{"readOnly":true}`); resp.StatusCode != 403 {
		t.Fatalf("non-admin settings status %d, want 403", resp.StatusCode)
	}
}

// TestMkdirSymlinkAliasGuarded proves the standard-1/adv-1 fix: an alias whose
// parent directory is a symlink into a protected region is guarded on the
// resolved location, not the spelling the client sent.
func TestMkdirSymlinkAliasGuarded(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "etc", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(b.dir, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(b.dir, "etc", "config"), filepath.Join(b.dir, "warn-alias"))
	mustSymlink(t, filepath.Join(b.dir, "proc"), filepath.Join(b.dir, "deny-alias"))
	c, csrf := sessionCookie(t, s)

	// Alias into a warn region resolves to /etc/config → confirmation demanded,
	// not silently allowed as the lexical /warn-alias would be.
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/warn-alias","name":"x"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("aliased warn mkdir status %d, want 409", resp.StatusCode)
	}
	// Alias into a never-write region resolves to /proc → refused outright.
	resp2 := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/deny-alias","name":"y"}`)
	if resp2.StatusCode != 403 {
		t.Fatalf("aliased deny mkdir status %d, want 403", resp2.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp2.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("aliased deny code %q, want protected", e.Error.Code)
	}
}

// TestDeleteThroughAliasedParentGuarded proves the delete leg of standard 1:
// deleting file under a symlinked parent (config-alias -> /etc/config) is
// guarded on the resolved parent, while the deleted leaf stays unresolved.
func TestDeleteThroughAliasedParentGuarded(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "etc", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "etc", "config", "smb.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(b.dir, "etc", "config"), filepath.Join(b.dir, "config-alias"))
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/config-alias/smb.conf"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("aliased delete status %d, want 409 confirm_required", resp.StatusCode)
	}
}

// TestRenameOverProtectedDestination proves the standard-2/adv-2 fix: renaming a
// regular file over a device node (/dev/null) with overwrite:true is refused,
// because creation under /dev is allowed but deleting the node is not.
func TestRenameOverProtectedDestination(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "dev", "null"), []byte("node"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/rename", c, csrf, `{"path":"/a.txt","to":"/dev/null","overwrite":true}`)
	if resp.StatusCode != 403 {
		t.Fatalf("rename over /dev/null status %d, want 403", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
	// The device node is untouched.
	if _, err := os.Stat(filepath.Join(b.dir, "dev", "null")); err != nil {
		t.Fatalf("device node disturbed: %v", err)
	}
}

// TestRenameTokenDoesNotAuthoriseReverse proves the adv-5 fix at the route
// level: a confirmation token issued for A→B does not authorise B→A.
func TestRenameTokenDoesNotAuthoriseReverse(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "etc", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "etc", "config", "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	// A rename inside /etc/config is a warn op → first POST returns a token.
	resp := post(s, "/api/fs/rename", c, csrf, `{"path":"/etc/config/a","to":"/etc/config/b"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("first rename status %d, want 409", resp.StatusCode)
	}
	var first struct {
		Confirm struct{ Token string }
	}
	json.NewDecoder(resp.Body).Decode(&first)
	if first.Confirm.Token == "" {
		t.Fatal("no token issued")
	}
	// Re-post the token against the REVERSE direction: it must not be accepted,
	// so the server issues a fresh confirmation demand rather than renaming.
	body := `{"path":"/etc/config/b","to":"/etc/config/a","confirm":"` + first.Confirm.Token + `"}`
	resp2 := post(s, "/api/fs/rename", c, csrf, body)
	if resp2.StatusCode != 409 {
		t.Fatalf("reversed rename with A→B token status %d, want 409", resp2.StatusCode)
	}
}

// TestMkdirParentsRejected proves the standard-4/adv-6 fix: parents:true is a
// 400 in M1 rather than a bypass of the /share ban and per-intermediate checks.
func TestMkdirParentsRejected(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"x","parents":true}`)
	if resp.StatusCode != 400 {
		t.Fatalf("parents:true status %d, want 400", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "bad_request" {
		t.Fatalf("code %q, want bad_request", e.Error.Code)
	}
}

// flipReadOnlyOnDelete flips the guard to read-only the first time an item is
// deleted, so a batch's later items must observe the toggle mid-run.
type flipReadOnlyOnDelete struct {
	*fakeBackend
	g *guard.Guard
	n int
}

func (f *flipReadOnlyOnDelete) Delete(ctx context.Context, p backend.Principal, name string) error {
	f.n++
	if f.n == 1 {
		f.g.SetReadOnly(true)
	}
	return f.fakeBackend.Delete(ctx, p, name)
}

// TestBatchDeleteStopsOnReadOnly proves the standard-3/adv-7 fix: read-only
// enabled mid-batch stops the remaining dispatches; only the first item is
// deleted, the rest are recorded as read_only.
func TestBatchDeleteStopsOnReadOnly(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	for _, name := range []string{"d1", "d2", "d3"} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.mutator = &flipReadOnlyOnDelete{fakeBackend: b, g: s.guard}
	c, csrf := sessionCookie(t, s)
	// Every delete is permanent in M1, so the batch first demands a confirmation
	// token (decision 10); redeem it, then the batch runs and the read-only toggle
	// stops the later items.
	first := post(s, "/api/fs/delete", c, csrf, `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"}]}`)
	if first.StatusCode != 409 {
		t.Fatalf("first batch status %d, want 409 confirm_required", first.StatusCode)
	}
	var tok struct {
		Confirm struct{ Token string }
	}
	json.NewDecoder(first.Body).Decode(&tok)
	if tok.Confirm.Token == "" {
		t.Fatal("no batch confirmation token issued")
	}
	resp := post(s, "/api/fs/delete", c, csrf, `{"paths":[{"path":"/d1"},{"path":"/d2"},{"path":"/d3"}],"confirm":"`+tok.Confirm.Token+`"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("batch status %d", resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Path string
			OK   bool
			Code string
		}
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Results) != 3 {
		t.Fatalf("results len %d, want 3", len(out.Results))
	}
	if !out.Results[0].OK {
		t.Fatalf("first item should have been deleted: %+v", out.Results[0])
	}
	for _, r := range out.Results[1:] {
		if r.Code != "read_only" {
			t.Fatalf("item %s code %q, want read_only", r.Path, r.Code)
		}
	}
	// Only the first item is gone on disk.
	if _, err := os.Stat(filepath.Join(b.dir, "d1")); !os.IsNotExist(err) {
		t.Fatalf("d1 should be deleted")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "d2")); err != nil {
		t.Fatalf("d2 should survive the read-only toggle: %v", err)
	}
}

// bigStat reports a huge size for every Stat, so a delete of a small file still
// crosses the permanent-delete byte threshold (adv 9) without writing a GiB.
type bigStat struct {
	*fakeBackend
}

func (b bigStat) Stat(ctx context.Context, p backend.Principal, name string) (fsx.Entry, error) {
	e, err := b.fakeBackend.Stat(ctx, p, name)
	if err != nil {
		return e, err
	}
	e.Size = 2 << 30 // 2 GiB
	return e, nil
}

// TestLargeDeleteNeedsConfirmation proves the adv-9 fix: a multi-GiB permanent
// delete demands confirmation on scale alone, then proceeds with a valid token.
func TestLargeDeleteNeedsConfirmation(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.WriteFile(filepath.Join(b.dir, "big.bin"), []byte("small on disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.backend = bigStat{fakeBackend: b} // guard's size probe sees 2 GiB
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/big.bin"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("large delete status %d, want 409", resp.StatusCode)
	}
	var first struct {
		Error   struct{ Code string }
		Confirm struct{ Token string }
	}
	json.NewDecoder(resp.Body).Decode(&first)
	if first.Error.Code != "confirm_required" || first.Confirm.Token == "" {
		t.Fatalf("no confirmation token for a large delete: %+v", first)
	}
	body := `{"path":"/big.bin","confirm":"` + first.Confirm.Token + `"}`
	resp2 := post(s, "/api/fs/delete", c, csrf, body)
	if resp2.StatusCode != 200 {
		t.Fatalf("confirmed large delete status %d", resp2.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "big.bin")); !os.IsNotExist(err) {
		t.Fatal("file should be deleted after confirmation")
	}
}

// TestHeadSettingsDoesNotMutate proves the adv-3 fix: a HEAD to /api/settings is
// a read, never dispatched to postSettings, so it cannot flip read-only without
// CSRF.
func TestHeadSettingsDoesNotMutate(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(true)
	c, _ := sessionCookie(t, s)
	s.sessions[c.Value].admin = true
	// HEAD is a safe method, so no CSRF is required to reach the router; the body
	// asks to disable read-only. It must be ignored.
	r := httptest.NewRequest("HEAD", "/api/settings", strings.NewReader(`{"readOnly":false}`))
	r.AddCookie(c)
	r.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("HEAD settings status %d, want 200", w.Code)
	}
	if !s.readOnly() {
		t.Fatal("HEAD /api/settings mutated read-only mode")
	}
}

// TestCSRFRejectedMutationAudited proves the adv-10 fix: a mutation rejected for
// a missing CSRF header leaves a denial audit line.
func TestCSRFRejectedMutationAudited(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, _ := sessionCookie(t, s)
	// POST with the cookie but no X-QFM-CSRF header.
	r := httptest.NewRequest("POST", "/api/fs/mkdir", strings.NewReader(`{"dir":"/","name":"x"}`))
	r.AddCookie(c)
	r.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF status %d, want 403", w.Code)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := logger.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Result == "denied" && e.Code == "csrf" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no CSRF denial audited among %d events", len(events))
	}
}

// apiEnvelope mirrors the error wire shape for decoding in these tests.
type apiEnvelope struct {
	Error struct {
		Code, Message, Path, Op string
	} `json:"error"`
}
