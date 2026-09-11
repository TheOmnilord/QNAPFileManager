package web

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
)

// TestMkdirIntoSymlinkedProtectedRootGuarded proves adv 1a at the route level:
// when a protected root is itself a symlink (/etc/config -> /real/config),
// resolving the mkdir parent would lose the warning, but guarding the requested
// spelling too keeps it. The fixture guard is not canonicalized, so the
// protection here comes purely from checking the requested path.
func TestMkdirIntoSymlinkedProtectedRootGuarded(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "real", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(b.dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// /etc/config -> /real/config (an ordinary directory), so the resolved parent
	// carries no rule.
	mustSymlink(t, filepath.Join(b.dir, "real", "config"), filepath.Join(b.dir, "etc", "config"))
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/etc/config","name":"x"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("mkdir into symlinked protected root status %d, want 409 (protection not erased)", resp.StatusCode)
	}
}

// TestGuardErrorReportsRequestedPath proves the resolution-oracle fix (adv
// resolve.go): a path that resolves into a protected region the caller could not
// name is refused, but the error reports the REQUESTED path and never leaks the
// resolved target.
func TestGuardErrorReportsRequestedPath(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// /private-link -> /proc (a never-write region).
	mustSymlink(t, filepath.Join(b.dir, "proc"), filepath.Join(b.dir, "private-link"))
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/private-link","name":"x"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("mkdir into /proc via symlink status %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "proc") {
		t.Fatalf("response leaked the resolved target: %s", body)
	}
	var e apiEnvelope
	json.Unmarshal(body, &e)
	if e.Error.Code != "protected" || e.Error.Path != "/private-link/x" {
		t.Fatalf("error should name the requested path: %+v", e.Error)
	}
}

// TestRenameToZfsRefused proves adv 2's destination-entry protection: renaming a
// file to a non-existent /data/.zfs is refused, because creating a ".zfs" entry
// is never allowed even though its parent is writable.
func TestRenameToZfsRefused(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "data", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/rename", c, csrf, `{"path":"/data/x","to":"/data/.zfs"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("rename to /data/.zfs status %d, want 403", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
}

// statErrBackend makes Stat of a chosen destination fail with a non-not-found
// error, so the rename destination's existence cannot be determined.
type statErrBackend struct {
	*fakeBackend
	failPath string
}

func (s statErrBackend) Stat(ctx context.Context, p backend.Principal, name string) (fsx.Entry, error) {
	if name == s.failPath {
		return fsx.Entry{}, fs.ErrPermission // not fs.ErrNotExist
	}
	return s.fakeBackend.Stat(ctx, p, name)
}

// TestRenameFailClosedOnStatError proves adv 2's fail-closed rule: when overwrite
// is set and the destination's existence cannot be determined, the replacement
// (OpDelete) guard is still applied rather than skipped, so a rename over a
// protected destination is refused.
func TestRenameFailClosedOnStatError(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.backend = statErrBackend{fakeBackend: b, failPath: "/dev/keep"}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/rename", c, csrf, `{"path":"/a.txt","to":"/dev/keep","overwrite":true}`)
	if resp.StatusCode != 403 {
		t.Fatalf("rename fail-closed status %d, want 403 (delete guard not skipped)", resp.StatusCode)
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
}

// TestEveryDeleteNeedsToken proves decision 10 / adv 9: in M1 every delete is
// permanent, so even a small, ordinary file requires a confirmation token.
// TestDeleteNonEmptyNamesBlockers proves the owner-hardware-test fix: a
// single-level delete of a directory that looks empty (its only entry is hidden,
// e.g. QNAP's .@__thumb) is refused as not_empty AND the response names the
// blocking entry, so the refusal explains itself instead of looking like a bug.
func TestDeleteNonEmptyNamesBlockers(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	// A folder whose only content is a hidden QNAP metadata entry.
	if err := os.MkdirAll(filepath.Join(b.dir, "Testtt", ".@__thumb"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "Testtt", ".@__thumb", "t.jpg"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The dispatched delete returns a real ENOTEMPTY (the Linux NAS behaviour);
	// os.Remove of a non-empty dir maps to "exists" on Windows, so a stub keeps the
	// test deterministic cross-platform while the real backend still lists the dir.
	s.mutator = notEmptyMutator{b}
	c, csrf := sessionCookie(t, s)
	first := post(s, "/api/fs/delete", c, csrf, `{"path":"/Testtt"}`)
	var tok struct{ Confirm struct{ Token string } }
	json.NewDecoder(first.Body).Decode(&tok)
	if tok.Confirm.Token == "" {
		t.Fatalf("no confirmation token for the delete")
	}
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/Testtt","confirm":"`+tok.Confirm.Token+`"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409 not_empty", resp.StatusCode)
	}
	var out struct {
		Error    struct{ Code string }
		Blockers []struct {
			Name   string
			Hidden bool
			Dir    bool
		}
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Error.Code != "not_empty" {
		t.Fatalf("code %q, want not_empty", out.Error.Code)
	}
	var found bool
	for _, blk := range out.Blockers {
		if blk.Name == ".@__thumb" {
			found = true
			if !blk.Hidden || !blk.Dir {
				t.Errorf(".@__thumb blocker = %+v, want hidden dir", blk)
			}
		}
	}
	if !found {
		t.Fatalf("the not_empty response did not name the hidden blocker; blockers=%+v", out.Blockers)
	}
	// The folder must still exist — nothing was deleted.
	if _, err := os.Stat(filepath.Join(b.dir, "Testtt")); err != nil {
		t.Fatalf("folder should survive a refused delete: %v", err)
	}
}

// notEmptyMutator dispatches a delete that fails with a real ENOTEMPTY, the Linux
// NAS behaviour for a non-empty directory, independent of the host os.Remove.
type notEmptyMutator struct{ *fakeBackend }

func (notEmptyMutator) Delete(context.Context, backend.Principal, string) error {
	return &fs.PathError{Op: "unlinkat", Path: "x", Err: syscall.ENOTEMPTY}
}

// fixedListBackend returns a chosen set of entries from List, standing in for a
// worker listing whose names crossed the JSON boundary (so a non-UTF-8 Name is
// already flattened while NameB64 carries the true bytes).
type fixedListBackend struct {
	*fakeBackend
	entries []fsx.Entry
}

func (b fixedListBackend) List(context.Context, backend.Principal, string, fsx.ListOptions) (fsx.Listing, error) {
	return fsx.Listing{Entries: b.entries, Total: len(b.entries)}, nil
}

// TestDeleteBlockersByteSafeName proves the review fix: a blocker whose name is
// not valid UTF-8 is reported by its byte-safe NameB64 spelling, not the
// JSON-flattened Name — so two distinct names cannot collide in the list.
func TestDeleteBlockersByteSafeName(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "Testtt"), 0o755); err != nil {
		t.Fatal(err)
	}
	var e fsx.Entry
	e.SetName([]byte("\xff\xfehidden")) // non-UTF-8: Name stays set, NameB64 populated
	e.Type = "dir"
	e.Hidden = true
	if e.NameB64 == "" {
		t.Fatal("precondition: NameB64 should be set for a non-UTF-8 name")
	}
	s.backend = fixedListBackend{fakeBackend: b, entries: []fsx.Entry{e}}
	s.mutator = notEmptyMutator{b}
	c, csrf := sessionCookie(t, s)
	first := post(s, "/api/fs/delete", c, csrf, `{"path":"/Testtt"}`)
	var tok struct{ Confirm struct{ Token string } }
	json.NewDecoder(first.Body).Decode(&tok)
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/Testtt","confirm":"`+tok.Confirm.Token+`"}`)
	var out struct {
		Blockers []struct{ Name string }
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Blockers) != 1 {
		t.Fatalf("blockers = %+v, want 1", out.Blockers)
	}
	if want := "b64:" + e.NameB64; out.Blockers[0].Name != want {
		t.Fatalf("blocker name = %q, want the byte-safe %q", out.Blockers[0].Name, want)
	}
}

func TestEveryDeleteNeedsToken(t *testing.T) {
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/a.txt"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("plain delete status %d, want 409 confirm_required", resp.StatusCode)
	}
	var first struct {
		Error   struct{ Code string }
		Confirm struct{ Token string }
	}
	json.NewDecoder(resp.Body).Decode(&first)
	if first.Error.Code != "confirm_required" || first.Confirm.Token == "" {
		t.Fatalf("no token for a plain delete: %+v", first)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "a.txt")); err != nil {
		t.Fatalf("file deleted without confirmation: %v", err)
	}
	resp2 := post(s, "/api/fs/delete", c, csrf, `{"path":"/a.txt","confirm":"`+first.Confirm.Token+`"}`)
	if resp2.StatusCode != 200 {
		t.Fatalf("confirmed delete status %d", resp2.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("file should be deleted after confirmation")
	}
}

// TestConfirmFailuresAudited proves adv 10: a confirmation challenge (no token)
// and an invalid presented token both leave a denial audit line, with distinct
// codes.
func TestConfirmFailuresAudited(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	c, csrf := sessionCookie(t, s)
	if resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/a.txt"}`); resp.StatusCode != 409 {
		t.Fatalf("challenge status %d", resp.StatusCode)
	}
	if resp := post(s, "/api/fs/delete", c, csrf, `{"path":"/a.txt","confirm":"not-a-real-token"}`); resp.StatusCode != 409 {
		t.Fatalf("invalid-token status %d", resp.StatusCode)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := logger.Tail(50)
	var required, invalid bool
	for _, e := range events {
		if e.Result == "denied" && e.Code == "confirm_required" {
			required = true
		}
		if e.Result == "denied" && e.Code == "confirm_invalid" {
			invalid = true
		}
	}
	if !required || !invalid {
		t.Fatalf("confirm failures not audited: required=%v invalid=%v", required, invalid)
	}
}

// TestUnauthenticatedMutationAudited proves adv 10: an unsafe request to a
// mutation route with no valid session leaves a denial audit line.
func TestUnauthenticatedMutationAudited(t *testing.T) {
	s, _ := fixture(t, false) // no pinned session
	s.guard.SetReadOnly(false)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	r := httptest.NewRequest("POST", "/api/fs/mkdir", strings.NewReader(`{"dir":"/","name":"x"}`))
	r.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthenticated mutation status %d, want 401", w.Code)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := logger.Tail(50)
	var found bool
	for _, e := range events {
		if e.Op == "auth" && e.Result == "denied" && e.Path == "/api/fs/mkdir" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unauthenticated mutation not audited among %d events", len(events))
	}
}

// TestAuthDeniedAuditSnapshotUnderLock proves the session.go fix: the
// CSRF-rejection audit reads the session identity under sess.mu, so it does not
// race a concurrent revalidation writing those fields. Run under -race.
func TestAuthDeniedAuditSnapshotUnderLock(t *testing.T) {
	s, _ := fixture(t, true)
	logger, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	defer logger.Close()
	sess := &session{id: "x", who: backend.Principal{User: "u", UID: 1}}
	r := httptest.NewRequest("POST", "/api/fs/mkdir", nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sess.mu.Lock()
			sess.who.User = "v"
			sess.admin = !sess.admin
			sess.who.Root = sess.admin
			sess.mu.Unlock()
		}
	}()
	for i := 0; i < 300; i++ {
		s.auditAuthDenied(r, sess, "csrf", "CSRF or Origin check failed")
	}
	close(stop)
	wg.Wait()
}
