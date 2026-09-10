package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, sess *session, guardErr error, extraConfirm bool, m mutation, respPath string, tokenPaths []string, confirm string, summary guard.Summary) bool {
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
		if confirm != "" && s.guard.Redeem(confirm, m.op, tokenPaths) == nil {
			return true
		}
		message := "This change needs confirmation."
		if guardErr != nil {
			message = guardErr.Error()
		}
		token, exp := s.guard.Issue(m.op, summary, tokenPaths)
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
	if err := fsx.ValidName(body.Name); err != nil {
		s.fail(w, r, "bad_request", "Supply a valid folder name.", dir, err.Error())
		return
	}
	target := fsx.Join(dir, body.Name)
	m := mutation{op: "mkdir", path: target}
	// OpCreate is checked against the parent directory: "may I create something
	// inside dir?" (guard.go). That is what catches the /share RAM disk and the
	// never-write regions.
	guardErr := s.guard.Check(guard.OpCreate, dir)
	if !s.authorize(w, r, sess, guardErr, false, m, target, []string{target}, body.Confirm, guard.Summary{Files: 1}) {
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
	// Renaming touches the source (OpRename) and creates at the destination's
	// parent (OpCreate). The worst verdict of the two governs.
	guardErr := worstGuard(s.guard.Check(guard.OpRename, from), s.guard.Check(guard.OpCreate, fsx.Parent(to)))
	if !s.authorize(w, r, sess, guardErr, false, m, from, []string{from, to}, body.Confirm, guard.Summary{Files: 1}) {
		return
	}
	s.writeAudit(sess, r, m, "intent", "", "", "", false)
	err = s.mutator.Rename(r.Context(), sess.who, from, to, body.Overwrite)
	if !s.finish(w, r, sess, m, err) {
		return
	}
	writeJSON(w, map[string]any{"ok": true})
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
	guardErr := s.guard.Check(guard.OpDelete, p)
	if !s.authorize(w, r, sess, guardErr, false, m, p, []string{p}, confirm, guard.Summary{Files: 1}) {
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
// otherwise each item's guard verdict and kernel error are reported in place,
// and each item is audited. Scale alone (more than 100 items) demands one
// confirmation token covering the whole set.
func (s *Server) deleteBatch(w http.ResponseWriter, r *http.Request, sess *session, paths []string, confirm string) {
	// Global read-only blocks everything; answer once rather than per item.
	if s.guard.ReadOnly() {
		m := mutation{op: "delete"}
		s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", "", "delete", "")
		return
	}
	// Decide whether the batch as a whole needs a confirmation token: a warn
	// path anywhere, or the scale threshold.
	needConfirm := guard.NeedsConfirm(guard.OpDelete, "", len(paths), 0)
	for _, p := range paths {
		if errors.Is(s.guard.Check(guard.OpDelete, p), guard.ErrConfirmRequired) {
			needConfirm = true
			break
		}
	}
	if needConfirm {
		if confirm == "" || s.guard.Redeem(confirm, "delete", paths) != nil {
			token, exp := s.guard.Issue("delete", guard.Summary{Files: int64(len(paths))}, paths)
			writeConfirmRequired(w, "delete", "", fmt.Sprintf("Deleting %d items needs confirmation.", len(paths)), token, exp, guard.Summary{Files: int64(len(paths))})
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
	for _, p := range paths {
		m := mutation{op: "delete", path: p}
		res := itemResult{Path: p}
		// A protected item is denied in place; confirmation was already handled
		// at the batch level, so a warn item may proceed here.
		if err := s.guard.Check(guard.OpDelete, p); errors.Is(err, guard.ErrProtected) {
			s.writeAudit(sess, r, m, "result", "denied", "protected", err.Error(), false)
			res.Code = "protected"
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
