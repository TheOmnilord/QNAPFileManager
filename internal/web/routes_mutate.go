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
	s.auditor.Write(audit.Event{
		Actor:  sess.who.User,
		UID:    sess.who.UID,
		Admin:  sess.admin,
		Root:   sess.who.Root,
		IP:     ClientIP(r),
		Op:     "auth",
		Path:   r.URL.Path,
		Phase:  "result",
		Result: "denied",
		Code:   code,
		Detail: detail,
	})
}

// mutation carries the identity of one audited operation.
type mutation struct {
	op   string // "mkdir" | "rename" | "delete"
	path string // primary audited path
	dst  string // destination, for rename
}

// writeAudit records one phase of a mutation. It never blocks (audit.Write
// drops under overload) and is a no-op when no logger is wired.
func (s *Server) writeAudit(sess *session, r *http.Request, m mutation, phase, result, code, detail string, milestone bool) {
	if s.auditor == nil {
		return
	}
	s.auditor.Write(audit.Event{
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
		Detail:         detail,
		ForceMilestone: milestone,
	})
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
		s.writeAudit(sess, r, m, "result", "denied", "read_only", guardErr.Error(), false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", respPath, m.op, guardErr.Error())
		return false
	case errors.Is(guardErr, guard.ErrProtected):
		s.writeAudit(sess, r, m, "result", "denied", "protected", guardErr.Error(), false)
		writeError(w, http.StatusForbidden, "protected", guardErr.Error(), respPath, m.op, guardErr.Error())
		return false
	case errors.Is(guardErr, guard.ErrConfirmRequired) || extraConfirm:
		if confirm != "" && s.guard.Redeem(confirm, m.op, tokenPaths, ordered) == nil {
			return true
		}
		message := "This change needs confirmation."
		if guardErr != nil {
			message = guardErr.Error()
		}
		token, exp := s.guard.Issue(m.op, summary, tokenPaths, ordered)
		writeConfirmRequired(w, m.op, respPath, message, token, exp, summary)
		return false
	case guardErr != nil:
		s.writeAudit(sess, r, m, "result", "denied", fsx.Code(guardErr), guardErr.Error(), false)
		s.backendError(w, r, respPath, guardErr)
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
// It returns true on success (the caller then writes the success body).
func (s *Server) finish(w http.ResponseWriter, r *http.Request, sess *session, m mutation, err error) bool {
	if err != nil {
		code := fsx.Code(err)
		s.writeAudit(sess, r, m, "result", "error", code, err.Error(), false)
		s.backendError(w, r, m.path, err)
		return false
	}
	s.writeAudit(sess, r, m, "result", "ok", "", "", false)
	return true
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
	m := mutation{op: "mkdir", path: target}
	// The worker resolves parent symlinks before it creates, so guard on the
	// resolved parent, not the spelling the client sent (standard 1 / adv 1). dir
	// already exists, so resolve it fully. OpCreate is checked against the parent
	// directory ("may I create inside resolvedDir?"), which catches the /share
	// RAM disk and the never-write regions; a second OpCreate on the resolved
	// target catches an entry-specific protection such as a ".zfs" name (adv 6).
	resolvedDir := resolveForGuard(s.Root, dir, true)
	guardErr := worstGuard(
		s.guard.Check(guard.OpCreate, resolvedDir),
		s.guard.Check(guard.OpCreate, fsx.Join(resolvedDir, body.Name)),
	)
	if !s.authorize(w, r, sess, guardErr, false, m, target, []string{target}, false, body.Confirm, guard.Summary{Files: 1}) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", false)
	entry, err := s.mutator.Mkdir(r.Context(), sess.who, dir, body.Name, os.FileMode(0), body.Parents)
	if !s.finish(w, r, sess, m, err) {
		return
	}
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
	m := mutation{op: "rename", path: from, dst: to}
	// The worker resolves parent symlinks before it renames, so guard on the
	// resolved paths, keeping each final component unresolved: a rename operates
	// on the named entry, not its symlink target (standard 1 / adv 1).
	guardFrom := resolveForGuard(s.Root, from, false)
	guardTo := resolveForGuard(s.Root, to, false)
	// A rename removes the source entry from its old location and creates one at
	// the destination — and, with overwrite, replaces whatever is already there.
	// Guard every one of those, not just the destination's parent (standard 2 /
	// adv 2): OpRename and OpDelete on the source (moving a protected entry out),
	// OpCreate on the destination's parent, and OpDelete on the destination when
	// overwrite is set and the destination exists (replacing a protected entry or
	// a device node such as /dev/null). The worst verdict governs.
	checks := []error{
		s.guard.Check(guard.OpRename, guardFrom),
		s.guard.Check(guard.OpDelete, guardFrom),
		s.guard.Check(guard.OpCreate, fsx.Parent(guardTo)),
	}
	if body.Overwrite {
		if _, statErr := s.backend.Stat(r.Context(), sess.who, to); statErr == nil {
			checks = append(checks, s.guard.Check(guard.OpDelete, guardTo))
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
	err = s.mutator.Rename(r.Context(), sess.who, from, to, body.Overwrite)
	if !s.finish(w, r, sess, m, err) {
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
	m := mutation{op: "delete", path: p}
	// Delete removes the link itself, so resolve only the parent and keep the
	// final component (standard 1 / adv 1).
	guardPath := resolveForGuard(s.Root, p, false)
	// Stat the target as the user to measure it: a multi-GiB permanent delete
	// must cross the byte threshold and demand confirmation (adv 9). A stat
	// failure (gone, unreadable) simply skips the scale check; the guard's path
	// rules and the worker's own error still stand.
	summary := guard.Summary{Files: 1}
	extraConfirm := false
	if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
		summary.Bytes = e.Size
		if guard.NeedsConfirm(guard.OpDelete, guardPath, 1, e.Size) {
			extraConfirm = true
		}
	}
	guardErr := s.guard.Check(guard.OpDelete, guardPath)
	if !s.authorize(w, r, sess, guardErr, extraConfirm, m, p, []string{p}, false, confirm, summary) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", false)
	err := s.mutator.Delete(r.Context(), sess.who, p)
	if !s.finish(w, r, sess, m, err) {
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
	// itself) and guard on the resolved path (standard 1 / adv 1). Measure the
	// items as the user so the byte threshold sees the real size (adv 9). Decide
	// whether the batch as a whole needs a confirmation token: a warn path
	// anywhere, or the scale/byte threshold.
	resolved := make([]string, len(paths))
	var totalBytes int64
	for i, p := range paths {
		resolved[i] = resolveForGuard(s.Root, p, false)
		if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
			totalBytes += e.Size
		}
	}
	needConfirm := guard.NeedsConfirm(guard.OpDelete, "", len(paths), totalBytes)
	for _, rp := range resolved {
		if errors.Is(s.guard.Check(guard.OpDelete, rp), guard.ErrConfirmRequired) {
			needConfirm = true
			break
		}
	}
	// tokenRedeemed records whether a valid batch token was spent for this exact
	// set of paths. Only then may a warn-class item proceed in the loop below; a
	// missing or invalid token turns the whole batch into a confirmation demand.
	tokenRedeemed := false
	if needConfirm {
		summary := guard.Summary{Files: int64(len(paths)), Bytes: totalBytes}
		if confirm != "" && s.guard.Redeem(confirm, "delete", paths, false) == nil {
			tokenRedeemed = true
		} else {
			token, exp := s.guard.Issue("delete", summary, paths, false)
			writeConfirmRequired(w, "delete", "", fmt.Sprintf("Deleting %d items needs confirmation.", len(paths)), token, exp, summary)
			return
		}
	}
	type itemResult struct {
		Path    string `json:"path"`
		PathB64 string `json:"pathB64,omitempty"`
		OK      bool   `json:"ok"`
		Code    string `json:"code,omitempty"`
	}
	results := make([]itemResult, 0, len(paths))
	for i, p := range paths {
		m := mutation{op: "delete", path: p}
		res := itemResult{Path: p}
		// Re-check every item immediately before its own dispatch and honour every
		// guard verdict, not just ErrProtected: an administrator who enabled
		// read-only mid-batch must stop writes here, and a warn item may proceed
		// only because the batch token was actually redeemed for this set.
		err := s.guard.Check(guard.OpDelete, resolved[i])
		switch {
		case errors.Is(err, guard.ErrReadOnly):
			s.writeAudit(sess, r, m, "result", "denied", "read_only", err.Error(), false)
			res.Code = "read_only"
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrProtected):
			s.writeAudit(sess, r, m, "result", "denied", "protected", err.Error(), false)
			res.Code = "protected"
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrConfirmRequired):
			if !tokenRedeemed {
				s.writeAudit(sess, r, m, "result", "denied", "confirm_required", err.Error(), false)
				res.Code = "confirm_required"
				results = append(results, res)
				continue
			}
		case err != nil:
			code := fsx.Code(err)
			s.writeAudit(sess, r, m, "result", "denied", code, err.Error(), false)
			res.Code = code
			results = append(results, res)
			continue
		}
		s.writeAudit(sess, r, m, "intent", "", "", "", false)
		if err := s.mutator.Delete(r.Context(), sess.who, p); err != nil {
			code := fsx.Code(err)
			s.writeAudit(sess, r, m, "result", "error", code, err.Error(), false)
			res.Code = code
		} else {
			s.writeAudit(sess, r, m, "result", "ok", "", "", false)
			res.OK = true
		}
		results = append(results, res)
	}
	writeJSON(w, map[string]any{"results": results})
}
