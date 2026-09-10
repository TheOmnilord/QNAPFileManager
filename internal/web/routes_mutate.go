package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
)

// This file wires the M1 mutations (mkdir, rename, single/batch delete) into the
// web layer. Every mutation crosses the same three gates, in this order:
//
//  1. the guard (guard.Check), in the root front-end, before any dispatch (INV-1):
//     read-only mode, protected paths, and the confirmation-token flow;
//  2. an audit "intent" line before the work and a "result" line after, so a
//     crash mid-operation still leaves evidence of what was attempted;
//  3. the backend.Mutator, whose worker runs as the user and where the kernel
//     makes the real permission decision (INV-2).
//
// The mutator's errors are surfaced unchanged, mapped to the API vocabulary by
// fsx.Code and to a status by statusCode.

// bodyPath cleans an API path taken from a JSON body field, honouring the
// pathB64 companion the way the query decoder (requestPath) does.
func bodyPath(p, pathB64 string) (string, error) {
	if pathB64 != "" {
		raw, err := base64.RawURLEncoding.DecodeString(pathB64)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(pathB64)
		}
		if err != nil {
			return "", fmt.Errorf("invalid pathB64: %w", fsx.ErrBadName)
		}
		p = string(raw)
	}
	for _, component := range strings.Split(p, "/") {
		if component == "." || component == ".." {
			return "", fmt.Errorf("path contains a dot component: %w", fsx.ErrBadName)
		}
	}
	return fsx.Clean(p)
}

// decodeBody reads a small JSON request body into v, rejecting unknown fields
// so a typo in a hand-made request is an error rather than a silent no-op. It
// writes the error response itself and returns false on failure.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		s.fail(w, r, "bad_request", "The request body could not be read.", "", err.Error())
		return false
	}
	return true
}

// mutationsReady reports whether the write spine is wired. A read-only build (or
// a fixture without a guard) answers a clear 500 rather than panicking.
func (s *Server) mutationsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.guard == nil || s.mutator == nil {
		s.fail(w, r, "internal", "This build cannot make changes.", "", "")
		return false
	}
	return true
}

// auditAuthDenied records a mutation rejected at the authentication gate — a
// failed CSRF or Origin check on an unsafe request — as a denial (adv 10). It is
// a milestone (isMilestone fires on any denial), so a burst of forged requests
// is visible in QuLog. A nil session or auditor makes it a no-op.
func (s *Server) auditAuthDenied(r *http.Request, sess *session, code, detail string) {
	if s.auditor == nil || sess == nil {
		return
	}
	// Snapshot the identity under sess.mu: a concurrent forced revalidation
	// writes who/admin/Root under this same lock (session.go), so reading them
	// unlocked here is a data race (adv session.go). The caller reaches this
	// before it takes the session lock, so acquiring it now cannot self-deadlock.
	sess.mu.Lock()
	who, admin := sess.who, sess.admin
	sess.mu.Unlock()
	// A rejected unsafe request is a denial milestone; write it durably (adv 10).
	s.auditor.WriteSync(audit.Event{
		Actor:          who.User,
		UID:            who.UID,
		Admin:          admin,
		Root:           who.Root,
		IP:             ClientIP(r),
		Op:             "auth",
		Path:           r.URL.Path,
		Phase:          "result",
		Result:         "denied",
		Code:           code,
		Detail:         detail,
		ForceMilestone: true,
	})
}

// isMutationRoute reports whether p is a route that changes state, so an
// authentication failure reaching it is worth a denial audit line (adv 10).
func isMutationRoute(p string) bool {
	switch p {
	case "/api/fs/mkdir", "/api/fs/rename", "/api/fs/delete", "/api/settings":
		return true
	}
	return false
}

// auditUnauthenticated records an unsafe request to a mutation route that never
// reached a valid session — an expired or forged session, a store-full refusal
// (adv 10). No actor is known; the IP and path are. It is a milestone, written
// durably. The CSRF-rejection path audits with the session identity separately
// (auditAuthDenied), so this covers only the sessionless failures.
func (s *Server) auditUnauthenticated(r *http.Request, code, detail string) {
	if s.auditor == nil {
		return
	}
	s.auditor.WriteSync(audit.Event{
		IP:             ClientIP(r),
		Op:             "auth",
		Path:           r.URL.Path,
		Phase:          "result",
		Result:         "denied",
		Code:           code,
		Detail:         detail,
		ForceMilestone: true,
	})
}

// mutation carries the identity of one audited operation.
type mutation struct {
	op    string // "mkdir" | "rename" | "delete"
	path  string // primary audited path (the REQUESTED spelling, client-facing)
	dst   string // destination, for rename (requested spelling)
	files int64  // measured file count, for a large-delete milestone (adv 10)
	bytes int64  // measured byte total, for a large-delete milestone (adv 10)
	// subs maps a resolved-path spelling to the requested path it must be
	// reported as. The guard is checked on the symlink-resolved path for policy,
	// but a verdict or worker error must never echo the resolved target back to
	// the client: root can resolve locations the caller cannot name, which would
	// make the guard a resolution oracle (adv resolve.go). clean() rewrites every
	// resolved spelling to its requested counterpart before anything reaches the
	// client or the audit log.
	subs map[string]string
}

// clean rewrites any resolved-path spelling in msg to the requested path it
// stands for, so neither a guard verdict nor a worker error reveals a
// root-resolved target (adv resolve.go). A nil or identity subs map is a no-op.
func (m mutation) clean(msg string) string {
	for resolved, requested := range m.subs {
		if resolved != "" && resolved != requested {
			msg = strings.ReplaceAll(msg, resolved, requested)
		}
	}
	return msg
}

// writeAudit records one phase of a mutation. Durable lines — the pre-dispatch
// intent, any real denial, and any milestone — take the synchronous sink path so
// a crash cannot lose them (adv 10); a routine confirmation challenge and an
// ordinary success stay async. It is a no-op when no logger is wired.
func (s *Server) writeAudit(sess *session, r *http.Request, m mutation, phase, result, code, detail string, milestone bool) {
	if s.auditor == nil {
		return
	}
	ev := audit.Event{
		Actor:          sess.who.User,
		UID:            sess.who.UID,
		Admin:          sess.admin,
		Root:           sess.who.Root,
		IP:             ClientIP(r),
		Op:             m.op,
		Path:           m.path,
		Dst:            m.dst,
		Phase:          phase,
		Result:         result,
		Code:           code,
		Detail:         m.clean(detail),
		Files:          m.files,
		Bytes:          m.bytes,
		ForceMilestone: milestone,
	}
	// A confirmation *challenge* (no token yet) is a normal handshake, not a
	// security event: record it in the file but keep it async and off QuLog. An
	// invalid presented token, a protected/read-only refusal, the intent line and
	// any forced milestone are durable.
	durable := phase == "intent" || milestone || (result == "denied" && code != "confirm_required")
	if durable {
		s.auditor.WriteSync(ev)
		return
	}
	s.auditor.Write(ev)
}

// authorize applies the guard verdict guardErr (from guard.Check, or the worst
// of several checks) and drives the confirmation-token flow. It returns true
// when the operation may proceed. Otherwise it has written the response — a
// denial (403), a confirmation demand (409), or an unexpected guard error — and
// audited any denial, and returns false.
//
// tokenPaths and m.op identify a confirmation token; extraConfirm forces the
// confirm flow for a scale threshold (guard.NeedsConfirm) even when the path
// rules alone would allow the op.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, sess *session, guardErr error, extraConfirm bool, m mutation, respPath string, tokenPaths []string, ordered bool, confirm string, summary guard.Summary) bool {
	switch {
	case errors.Is(guardErr, guard.ErrReadOnly):
		s.writeAudit(sess, r, m, "result", "denied", "read_only", m.clean(guardErr.Error()), false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", respPath, m.op, "")
		return false
	case errors.Is(guardErr, guard.ErrProtected):
		msg := m.clean(guardErr.Error())
		s.writeAudit(sess, r, m, "result", "denied", "protected", msg, false)
		writeError(w, http.StatusForbidden, "protected", msg, respPath, m.op, "")
		return false
	case errors.Is(guardErr, guard.ErrConfirmRequired) || extraConfirm:
		if confirm != "" {
			if s.guard.Redeem(confirm, m.op, tokenPaths, ordered) == nil {
				return true
			}
			// A token was presented but does not verify (forged, expired, replayed,
			// wrong op/paths). That is a genuine denial, recorded durably (adv 10);
			// the client still gets a fresh confirm_required challenge.
			s.writeAudit(sess, r, m, "result", "denied", "confirm_invalid", "confirmation token invalid or expired", false)
		} else {
			// No token yet: a routine challenge, recorded but not a QuLog milestone.
			s.writeAudit(sess, r, m, "result", "denied", "confirm_required", "confirmation required", false)
		}
		message := "This change needs confirmation."
		if guardErr != nil {
			message = m.clean(guardErr.Error())
		}
		token, exp := s.guard.Issue(m.op, summary, tokenPaths, ordered)
		writeConfirmRequired(w, m.op, respPath, message, token, exp, summary)
		return false
	case guardErr != nil:
		code := fsx.Code(guardErr)
		detail := m.clean(guardErr.Error())
		s.writeAudit(sess, r, m, "result", "denied", code, detail, false)
		writeError(w, statusCode(code), code, "The change could not be completed.", respPath, m.op, detail)
		return false
	}
	return true
}

// writeConfirmRequired answers the first POST of a confirmable operation with a
// 409 carrying the single-use token and the (best-effort) scan summary, per
// backend-packaging-plan §6.3. The client re-posts the identical body with the
// token in its "confirm" field.
func writeConfirmRequired(w http.ResponseWriter, op, path, message, token string, exp time.Time, summary guard.Summary) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   map[string]string{"code": "confirm_required", "message": message, "path": path, "op": op},
		"confirm": map[string]any{"token": token, "expires": exp, "summary": summary},
	})
}

// finish records the result phase and maps a mutator error to the API response.
// It returns true on success (the caller then writes the success body). milestone
// forces the result line onto the durable, QuLog-mirrored path (a large delete,
// adv 10). Both the audited detail and the client-facing error are cleaned so a
// worker error on the dispatched (resolved) path does not leak that target.
func (s *Server) finish(w http.ResponseWriter, r *http.Request, sess *session, m mutation, err error, milestone bool) bool {
	if err != nil {
		code := fsx.Code(err)
		detail := m.clean(err.Error())
		s.writeAudit(sess, r, m, "result", "error", code, detail, milestone)
		msg := backendMessage(code)
		s.fail(w, r, code, msg, m.path, detail)
		return false
	}
	s.writeAudit(sess, r, m, "result", "ok", "", "", milestone)
	return true
}

// backendMessage is the plain-language message for a backend error code, shared
// with backendError.
func backendMessage(code string) string {
	messages := map[string]string{"permission": "Permission denied.", "not_found": "This path no longer exists.", "readonly": "This filesystem is read-only.", "unsupported": "This file cannot be opened here.", "internal": "The filesystem request failed."}
	if msg := messages[code]; msg != "" {
		return msg
	}
	return "The request could not be completed."
}

func (s *Server) mkdir(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Dir     string `json:"dir"`
		DirB64  string `json:"dirB64"`
		Name    string `json:"name"`
		Parents bool   `json:"parents"`
		Confirm string `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	dir, err := bodyPath(body.Dir, body.DirB64)
	if err != nil {
		s.fail(w, r, "bad_request", "Supply the parent directory as dir or dirB64.", "", err.Error())
		return
	}
	// parents:true would create intermediate directories the guard never sees,
	// bypassing the /share RAM-disk ban and per-intermediate protection
	// (standard 4 / adv 6). The UI only ever creates a single folder, so M1
	// refuses it outright; guarding every intermediate is deferred to a later
	// milestone.
	if body.Parents {
		s.fail(w, r, "bad_request", "Creating intermediate parent directories is not supported.", dir, "parents is not allowed in M1")
		return
	}
	if err := fsx.ValidName(body.Name); err != nil {
		s.fail(w, r, "bad_request", "Supply a valid folder name.", dir, err.Error())
		return
	}
	target := fsx.Join(dir, body.Name)
	// The worker resolves parent symlinks before it creates, so guard on the
	// resolved parent (standard 1 / adv 1); dir already exists, so resolve it
	// fully. But resolution can also *erase* a protected prefix — a protected root
	// that is itself a symlink, /etc/config -> /ordinary/config (adv 1a) — so the
	// requested spelling is guarded too and the stricter verdict governs. OpCreate
	// on the parent catches the /share RAM disk and never-write regions; a second
	// OpCreate on the target catches an entry-specific protection such as a ".zfs"
	// name (adv 6).
	resolvedDir := resolveForGuard(s.Root, dir, true)
	resolvedTarget := fsx.Join(resolvedDir, body.Name)
	m := mutation{op: "mkdir", path: target, subs: map[string]string{resolvedDir: dir, resolvedTarget: target}}
	guardErr := worstGuard(
		s.guard.Check(guard.OpCreate, dir),
		s.guard.Check(guard.OpCreate, target),
		s.guard.Check(guard.OpCreate, resolvedDir),
		s.guard.Check(guard.OpCreate, resolvedTarget),
	)
	if !s.authorize(w, r, sess, guardErr, false, m, target, []string{target}, false, body.Confirm, guard.Summary{Files: 1}) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", false)
	// Dispatch against the resolved parent, binding the operation as tightly as
	// possible to what was guarded (adv 1b / standard P1); see the residual-race
	// note in PLAN.md §2.0.
	entry, err := s.mutator.Mkdir(r.Context(), sess.who, resolvedDir, body.Name, os.FileMode(0), body.Parents)
	if !s.finish(w, r, sess, m, err, false) {
		return
	}
	// Report the requested child path, never the resolved one (adv resolve.go).
	entry.SetName([]byte(body.Name))
	entry.SetPath([]byte(target))
	entry.Class = s.class(target)
	writeJSON(w, entry)
}

func (s *Server) rename(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Path      string `json:"path"`
		PathB64   string `json:"pathB64"`
		To        string `json:"to"`
		ToB64     string `json:"toB64"`
		Overwrite bool   `json:"overwrite"`
		Confirm   string `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	from, err := bodyPath(body.Path, body.PathB64)
	if err != nil {
		s.fail(w, r, "bad_request", "Supply the item to rename as path or pathB64.", "", err.Error())
		return
	}
	// "to" is either a bare new name (renamed inside the same directory, which is
	// all M1 offers) or, when absolute, a full destination path. A name may not
	// contain a slash, so the two are unambiguous.
	toRaw := body.To
	if body.ToB64 != "" {
		raw, decErr := base64.RawURLEncoding.DecodeString(body.ToB64)
		if decErr != nil {
			raw, decErr = base64.StdEncoding.DecodeString(body.ToB64)
		}
		if decErr != nil {
			s.fail(w, r, "bad_request", "Invalid toB64.", from, decErr.Error())
			return
		}
		toRaw = string(raw)
	}
	var to string
	if strings.HasPrefix(toRaw, "/") {
		to, err = bodyPath(toRaw, "")
		if err != nil {
			s.fail(w, r, "bad_request", "Invalid destination path.", from, err.Error())
			return
		}
	} else {
		if err := fsx.ValidName(toRaw); err != nil {
			s.fail(w, r, "bad_request", "Supply a valid new name.", from, err.Error())
			return
		}
		to = fsx.Join(fsx.Parent(from), toRaw)
	}
	if to == from {
		s.fail(w, r, "bad_request", "The new name is the same as the old one.", from, "")
		return
	}
	// The worker resolves parent symlinks before it renames, so guard on the
	// resolved paths, keeping each final component unresolved: a rename operates
	// on the named entry, not its symlink target (standard 1 / adv 1). Resolution
	// can also erase a protected prefix (adv 1a), so the requested spellings are
	// guarded too and the stricter verdict governs.
	guardFrom := resolveForGuard(s.Root, from, false)
	guardTo := resolveForGuard(s.Root, to, false)
	m := mutation{op: "rename", path: from, dst: to, subs: map[string]string{guardFrom: from, guardTo: to}}
	// A rename removes the source entry from its old location and creates one at
	// the destination — and, with overwrite, replaces whatever is already there.
	// Guard every one of those, not just the destination's parent (standard 2 /
	// adv 2): OpRename and OpDelete on the source (moving a protected entry out),
	// OpCreate on the destination's parent, OpCreate on the destination entry
	// itself (so renaming to /data/.zfs is refused even when it does not yet
	// exist), and OpDelete on the destination when overwrite replaces something
	// there. Each is checked on both the requested and the resolved spelling. The
	// worst verdict governs.
	checks := []error{
		s.guard.Check(guard.OpRename, from),
		s.guard.Check(guard.OpRename, guardFrom),
		s.guard.Check(guard.OpDelete, from),
		s.guard.Check(guard.OpDelete, guardFrom),
		s.guard.Check(guard.OpCreate, fsx.Parent(to)),
		s.guard.Check(guard.OpCreate, fsx.Parent(guardTo)),
		s.guard.Check(guard.OpCreate, to),
		s.guard.Check(guard.OpCreate, guardTo),
	}
	if body.Overwrite {
		// Replacing the destination is an OpDelete on it. Check it whenever the
		// destination exists — and, when its existence cannot be determined (a Stat
		// error that is not "gone"), FAIL CLOSED and check it anyway (standard 2 /
		// adv 2), rather than silently skipping the replacement guard.
		_, statErr := s.backend.Stat(r.Context(), sess.who, to)
		if statErr == nil || fsx.Code(statErr) != "not_found" {
			checks = append(checks,
				s.guard.Check(guard.OpDelete, to),
				s.guard.Check(guard.OpDelete, guardTo),
			)
		}
	}
	guardErr := worstGuard(checks...)
	// The token binds an ordered, structured descriptor — direction and the
	// overwrite flag — so a token issued for A→B does not authorise B→A or a
	// switch to overwrite:true (adv 5). Issue and Redeem build the identical
	// descriptor from the request.
	tokenParts := renameTokenParts(from, to, body.Overwrite)
	if !s.authorize(w, r, sess, guardErr, false, m, from, tokenParts, true, body.Confirm, guard.Summary{Files: 1}) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", false)
	// Dispatch against the resolved paths, binding to what was guarded (adv 1b);
	// the residual race is documented in PLAN.md §2.0.
	err = s.mutator.Rename(r.Context(), sess.who, guardFrom, guardTo, body.Overwrite)
	if !s.finish(w, r, sess, m, err, false) {
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// renameTokenParts builds the ordered, structured descriptor a rename token
// binds: the source, the destination and the overwrite flag, each tagged with
// its role. Because the parts are ordered (not a sorted multiset), a token for
// one direction or overwrite value cannot be redeemed for another.
func renameTokenParts(from, to string, overwrite bool) []string {
	return []string{"from=" + from, "to=" + to, "overwrite=" + strconv.FormatBool(overwrite)}
}

// worstGuard reduces several guard.Check results to the single most severe one,
// so a caller that must check two paths reports one verdict. Read-only (global)
// outranks a protected deny, which outranks a confirmation demand; an
// unexpected error is returned as-is.
func worstGuard(errs ...error) error {
	var confirm, protectedErr, readOnlyErr error
	for _, e := range errs {
		switch {
		case e == nil:
		case errors.Is(e, guard.ErrReadOnly):
			readOnlyErr = e
		case errors.Is(e, guard.ErrProtected):
			protectedErr = e
		case errors.Is(e, guard.ErrConfirmRequired):
			if confirm == nil {
				confirm = e
			}
		default:
			return e
		}
	}
	switch {
	case readOnlyErr != nil:
		return readOnlyErr
	case protectedErr != nil:
		return protectedErr
	case confirm != nil:
		return confirm
	}
	return nil
}

// pathRef is one item of a batch delete: a path with its non-UTF-8 companion.
type pathRef struct {
	Path    string `json:"path"`
	PathB64 string `json:"pathB64"`
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Path    string    `json:"path"`
		PathB64 string    `json:"pathB64"`
		Paths   []pathRef `json:"paths"`
		Confirm string    `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	// Gather the target paths from either the single or the list form.
	refs := body.Paths
	if len(refs) == 0 && (body.Path != "" || body.PathB64 != "") {
		refs = []pathRef{{Path: body.Path, PathB64: body.PathB64}}
	}
	if len(refs) == 0 {
		s.fail(w, r, "bad_request", "Supply one path (or a paths list) to delete.", "", "")
		return
	}
	paths := make([]string, 0, len(refs))
	for _, ref := range refs {
		p, err := bodyPath(ref.Path, ref.PathB64)
		if err != nil {
			s.fail(w, r, "bad_request", "A path to delete was invalid.", "", err.Error())
			return
		}
		paths = append(paths, p)
	}

	if len(paths) == 1 {
		s.deleteSingle(w, r, sess, paths[0], body.Confirm)
		return
	}
	s.deleteBatch(w, r, sess, paths, body.Confirm)
}

// deleteSingle deletes one item and answers with the operation's own status —
// 403 for a protected or read-only refusal, 409 for a confirmation demand, the
// mutator's mapped error otherwise, or {ok:true}.
func (s *Server) deleteSingle(w http.ResponseWriter, r *http.Request, sess *session, p, confirm string) {
	// Delete removes the link itself, so resolve only the parent and keep the
	// final component (standard 1 / adv 1). Guard on both the requested and the
	// resolved spelling and take the stricter verdict (adv 1a).
	guardPath := resolveForGuard(s.Root, p, false)
	m := mutation{op: "delete", path: p, files: 1, subs: map[string]string{guardPath: p}}
	// Stat the target as the user to measure it. A stat failure (gone, unreadable)
	// simply leaves the size at zero; the guard's path rules and the worker's own
	// error still stand.
	summary := guard.Summary{Files: 1}
	big := false
	if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
		summary.Bytes = e.Size
		m.bytes = e.Size
		big = guard.NeedsConfirm(guard.OpDelete, guardPath, 1, e.Size)
	}
	// In M1 every delete is permanent (trash is M2), so a delete of any size
	// requires a redeemed confirmation token, not just a warn-class path or a
	// multi-GiB target (adv 9 / decision 10). extraConfirm is therefore always on.
	guardErr := worstGuard(
		s.guard.Check(guard.OpDelete, p),
		s.guard.Check(guard.OpDelete, guardPath),
	)
	if !s.authorize(w, r, sess, guardErr, true, m, p, []string{p}, false, confirm, summary) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", big)
	// Dispatch against the resolved path (adv 1b); residual race noted in §2.0.
	err := s.mutator.Delete(r.Context(), sess.who, guardPath)
	if !s.finish(w, r, sess, m, err, big) {
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// deleteBatch deletes several items sequentially and returns a per-item result
// array (partial success). Read-only mode refuses the whole batch up front;
// otherwise each item is re-checked immediately before its own dispatch, so a
// read-only toggle or a protected path stops that item (standard 3 / adv 7).
// Scale (more than 100 items or more than 1 GiB) or any warn path demands one
// confirmation token covering the whole set.
func (s *Server) deleteBatch(w http.ResponseWriter, r *http.Request, sess *session, paths []string, confirm string) {
	// Global read-only blocks everything; answer once rather than per item. The
	// per-item loop re-checks read-only too, so a toggle mid-batch still stops
	// the remaining dispatches.
	if s.guard.ReadOnly() {
		m := mutation{op: "delete"}
		s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", "", "delete", "")
		return
	}
	// Resolve each item's parent once (the leaf stays, as delete removes the link
	// itself). Measure the items as the user so a large-delete milestone sees the
	// real size (adv 9 / adv 10). In M1 every delete is permanent, so the batch
	// always needs a redeemed confirmation token, regardless of size or path
	// (decision 10) — the warn-path and scale checks below only feed the summary.
	resolved := make([]string, len(paths))
	var totalBytes int64
	for i, p := range paths {
		resolved[i] = resolveForGuard(s.Root, p, false)
		if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
			totalBytes += e.Size
		}
	}
	// big marks a batch worth a QuLog milestone: more than 100 files or more than
	// 1 GiB (adv 10). The measured totals are carried into the audit event.
	big := guard.NeedsConfirm(guard.OpDelete, "", len(paths), totalBytes)
	// A batch always needs confirmation now; audit the challenge/invalid-token
	// rejection as a denial (adv 10) before demanding the token.
	tokenRedeemed := false
	summary := guard.Summary{Files: int64(len(paths)), Bytes: totalBytes}
	if confirm != "" && s.guard.Redeem(confirm, "delete", paths, false) == nil {
		tokenRedeemed = true
	} else {
		bm := mutation{op: "delete", files: int64(len(paths)), bytes: totalBytes}
		if confirm != "" {
			s.writeAudit(sess, r, bm, "result", "denied", "confirm_invalid", "batch confirmation token invalid or expired", false)
		} else {
			s.writeAudit(sess, r, bm, "result", "denied", "confirm_required", fmt.Sprintf("confirmation required for %d items", len(paths)), false)
		}
		token, exp := s.guard.Issue("delete", summary, paths, false)
		writeConfirmRequired(w, "delete", "", fmt.Sprintf("Deleting %d items needs confirmation.", len(paths)), token, exp, summary)
		return
	}
	type itemResult struct {
		Path    string `json:"path"`
		PathB64 string `json:"pathB64,omitempty"`
		OK      bool   `json:"ok"`
		Code    string `json:"code,omitempty"`
	}
	results := make([]itemResult, 0, len(paths))
	for i, p := range paths {
		m := mutation{op: "delete", path: p, subs: map[string]string{resolved[i]: p}}
		res := itemResult{Path: p}
		// Re-check every item immediately before its own dispatch and honour every
		// guard verdict, not just ErrProtected: an administrator who enabled
		// read-only mid-batch must stop writes here, and a warn item may proceed
		// only because the batch token was actually redeemed for this set. Both the
		// requested and the resolved spelling are checked (adv 1a).
		err := worstGuard(
			s.guard.Check(guard.OpDelete, p),
			s.guard.Check(guard.OpDelete, resolved[i]),
		)
		switch {
		case errors.Is(err, guard.ErrReadOnly):
			s.writeAudit(sess, r, m, "result", "denied", "read_only", m.clean(err.Error()), false)
			res.Code = "read_only"
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrProtected):
			s.writeAudit(sess, r, m, "result", "denied", "protected", m.clean(err.Error()), false)
			res.Code = "protected"
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrConfirmRequired):
			if !tokenRedeemed {
				s.writeAudit(sess, r, m, "result", "denied", "confirm_required", m.clean(err.Error()), false)
				res.Code = "confirm_required"
				results = append(results, res)
				continue
			}
		case err != nil:
			code := fsx.Code(err)
			s.writeAudit(sess, r, m, "result", "denied", code, m.clean(err.Error()), false)
			res.Code = code
			results = append(results, res)
			continue
		}
		s.writeAudit(sess, r, m, "intent", "", "", "", false)
		// Dispatch against the resolved path (adv 1b); residual race noted in §2.0.
		if err := s.mutator.Delete(r.Context(), sess.who, resolved[i]); err != nil {
			code := fsx.Code(err)
			s.writeAudit(sess, r, m, "result", "error", code, m.clean(err.Error()), false)
			res.Code = code
		} else {
			s.writeAudit(sess, r, m, "result", "ok", "", "", false)
			res.OK = true
		}
		results = append(results, res)
	}
	// A large batch (>100 files or >1 GiB) is mirrored to QuLog as one milestone
	// carrying the measured totals (adv 10 / standard P2).
	if big {
		bm := mutation{op: "delete", files: int64(len(paths)), bytes: totalBytes}
		s.writeAudit(sess, r, bm, "result", "ok", "", fmt.Sprintf("batch delete of %d items", len(paths)), true)
	}
	writeJSON(w, map[string]any{"results": results})
}
