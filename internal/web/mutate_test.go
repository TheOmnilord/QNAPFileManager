package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/config"
)

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

// apiEnvelope mirrors the error wire shape for decoding in these tests.
type apiEnvelope struct {
	Error struct {
		Code, Message, Path, Op string
	} `json:"error"`
}
