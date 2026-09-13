package web

import (
	"context"
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
	"qnapfilemanager/internal/wproto"
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
		if len(component) > maxComponentBytes {
			return "", errLongComponent
		}
	}
	return fsx.Clean(p)
}

// maxComponentBytes is NAME_MAX: the kernel's own limit on one path component,
// 255 bytes on every filesystem QTS and QuTS hero carry. fsx.Clean deliberately
// leaves length to the kernel (INV-2: the app predicts, the kernel decides), and
// that is right for a spelling the kernel is about to see — but the front end
// builds job titles, audit lines and confirmation tokens out of these components
// BEFORE the worker ever looks at them, and those are retained. A component past
// NAME_MAX is one the kernel would refuse with ENAMETOOLONG anyway, so refusing
// it here costs nothing a caller could have used and bounds everything derived
// from it by construction (round-7 sweep: /api/jobs/size built a job title, and
// jobIntentDetail a durable audit line, out of an unbounded base name).
const maxComponentBytes = 255

var errLongComponent = fmt.Errorf("a name in the path is longer than %d bytes: %w", maxComponentBytes, fsx.ErrBadName)

// validNewName is fsx.ValidName plus the same NAME_MAX bound bodyPath applies,
// for the routes that take a bare new name rather than a path: a folder to
// create, an entry to rename. Without it the one component a client invents
// outright would be the only one still unbounded.
func validNewName(name string) error {
	if err := fsx.ValidName(name); err != nil {
		return err
	}
	if len(name) > maxComponentBytes {
		return errLongComponent
	}
	return nil
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
	s.auditor.WriteSync(r.Context(), audit.Event{
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
	case "/api/fs/mkdir", "/api/fs/rename", "/api/fs/delete", "/api/settings", "/api/fs/upload", "/api/jobs/search",
		"/api/jobs/delete", "/api/jobs/copy", "/api/jobs/move", "/api/trash/restore", "/api/trash/empty",
		// M3: the permission mutations, sync and as jobs (contract §10). The
		// job forms join too, exactly as the delete/copy/move job routes do —
		// an unauthenticated POST to one is as much a denial worth recording.
		"/api/fs/chmod", "/api/fs/chown", "/api/jobs/chmod", "/api/jobs/chown":
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
	s.auditor.WriteSync(r.Context(), audit.Event{
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

// mutation carries the identity of one audited operation. Every path it holds is
// the REQUESTED (client-named) spelling; the resolved (symlink-hardened) spelling
// used for the guard and the worker dispatch is deliberately NOT stored here, so
// nothing that reaches the client JSON or the audit log can echo it.
//
// Client-facing errors are built from the error CODE (fsx.Code) plus the
// requested path alone (disclosureFree, below); a worker or resolve error — which
// may contain the resolved absolute OR relative path — is kept only in the
// server-side log, never in the client "detail" or the audit Detail (adv 2). This
// replaces the earlier fragile string-substitution approach, which could
// double-map a resolved spelling back into its own output.
type mutation struct {
	op    string // "mkdir" | "rename" | "delete"
	path  string // primary audited path (the REQUESTED spelling, client-facing)
	dst   string // destination, for rename (requested spelling)
	files int64  // measured file count, for a large-delete milestone (adv 10)
	bytes int64  // measured byte total, for a large-delete milestone (adv 10)
}

// logRaw records a worker/resolve/guard error verbatim in the SERVER-SIDE log
// only (adv 2). The raw text can name a symlink-resolved target the caller could
// not otherwise reach, so it must never travel to the client JSON or the audit
// file — only here, where an operator investigating a failure can see it.
func (s *Server) logRaw(r *http.Request, op, requested string, err error) {
	if err == nil {
		return
	}
	s.logger.Printf("mutation ip=%q op=%q path=%q raw error: %v", ClientIP(r), op, requested, err)
}

// auditContext picks the context for a durable audit write. A record of work
// that ALREADY happened — a result of ok, error, or partial — is persisted with
// a cancellation-immune context, so a client disconnecting after a successful
// (or partly successful) mutation cannot discard the only durable proof it
// occurred, nor turn a landed durable write into a false context.Canceled
// (round-5 adv 1/2). WriteSync's own writeSyncTimeout still bounds the wait, so
// dropping the deadline does not risk an unbounded block. Everything else — the
// pre-work intent line (empty result) and denials (result "denied", no work
// happened) — stays request-scoped, so a cancelled request or batch stops
// promptly and a wedged sink cannot stall a live request (round-4 adv 4 /
// round-6 std+adv). The predicate keys on the RESULT value precisely so a
// milestone INTENT (milestone==true, result=="") is not swept in.
func auditContext(reqCtx context.Context, result string) context.Context {
	switch result {
	case "ok", "error", "partial":
		return context.WithoutCancel(reqCtx)
	default:
		return reqCtx
	}
}

// writeAudit records one phase of a mutation. Durable lines — the pre-dispatch
// intent, any real denial, and any milestone — take the synchronous sink path so
// a crash cannot lose them (adv 10); a routine confirmation challenge and an
// ordinary success stay async. It returns the durable-write error (nil when the
// line was async or no logger is wired), so an intent caller can refuse dispatch
// when the intent could not be persisted (adv 1 / standard P1).
func (s *Server) writeAudit(sess *session, r *http.Request, m mutation, phase, result, code, detail string, milestone bool) error {
	if s.auditor == nil {
		return nil
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
		Detail:         detail, // callers pass a PATH-FREE detail (adv 2); never a raw error
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
		// A milestone that records a mutation which ALREADY happened (result
		// ok/error/partial) must survive the client disconnecting: persist it with
		// a cancellation-immune context, or a cancel right after a successful large
		// delete would discard the only durable proof the destructive work occurred
		// (round-5 adv 2). WriteSync's own writeSyncTimeout still bounds the wait.
		// Intent (recorded before any work) and denials (no work happened) stay
		// request-scoped, so a cancelled batch still stops promptly and a wedged
		// sink cannot stall a live request (round-4 adv 4).
		return s.auditor.WriteSync(auditContext(r.Context(), result), ev)
	}
	s.auditor.Write(ev)
	return nil
}

// auditIntent writes a mutation's intent line durably and, on failure, refuses
// the mutation with a 500 "audit_unavailable" (adv 1 / standard P1): a change
// whose intent a crash could lose must not be dispatched. It returns true when
// the intent was persisted and the caller may proceed.
func (s *Server) auditIntent(w http.ResponseWriter, r *http.Request, sess *session, m mutation, milestone bool) bool {
	return s.auditIntentDetail(w, r, sess, m, milestone, "")
}

// auditIntentDetail is auditIntent with a path-free DETAIL naming what is about
// to be attempted. M3's sync routes use it so the durable record says what was
// ASKED (a mode spec, a pair of ids) beside the result line that says what
// landed (§11); the M1 routes, whose whole request is the path and the op, pass
// nothing and are unchanged.
func (s *Server) auditIntentDetail(w http.ResponseWriter, r *http.Request, sess *session, m mutation, milestone bool, detail string) bool {
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, milestone); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", m.path, m.op, err.Error())
		return false
	}
	return true
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
	return s.authorizeGraded(w, r, sess, guardErr, extraConfirm, m, respPath, tokenPaths, ordered, confirm, summary, 0)
}

// authorizeGraded is authorize plus the confirmation GRADE (ui-ux §4.2) the
// challenge carries. M3's aclmode ladder decides between a plain acknowledgement
// and a typed phrase from facts only the route knows — the mount's ACL backend,
// its aclmode, the entry's ACL state, the measured size of a recursion — and the
// guard's token machinery is deliberately grade-blind (a token is a token), so
// the grade travels beside the token rather than inside it. A zero grade omits
// the field entirely, which is what every pre-M3 route passes.
func (s *Server) authorizeGraded(w http.ResponseWriter, r *http.Request, sess *session, guardErr error, extraConfirm bool, m mutation, respPath string, tokenPaths []string, ordered bool, confirm string, summary guard.Summary, grade int) bool {
	switch {
	case errors.Is(guardErr, guard.ErrReadOnly):
		s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", respPath, m.op, "")
		return false
	case errors.Is(guardErr, guard.ErrProtected):
		// The guard error names the (possibly symlink-resolved) path, so keep it in
		// the server log only; the client gets a generic, path-free message plus the
		// requested path it named (adv 2). The audit Detail is path-free too.
		s.logRaw(r, m.op, respPath, guardErr)
		s.writeAudit(sess, r, m, "result", "denied", "protected", "protected path", false)
		writeError(w, http.StatusForbidden, "protected", "This location is protected and cannot be changed.", respPath, m.op, "")
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
		// A generic, path-free message; the summary already carries the guard's
		// path-free reasons (guard.Reasons), so the client can explain why without a
		// resolved spelling ever appearing (adv 2).
		token, exp := s.guard.Issue(m.op, summary, tokenPaths, ordered)
		writeConfirmRequiredGraded(w, m.op, respPath, "This change needs confirmation.", token, exp, summary, grade)
		return false
	case guardErr != nil:
		code := fsx.Code(guardErr)
		s.logRaw(r, m.op, respPath, guardErr)
		s.writeAudit(sess, r, m, "result", "denied", code, "", false)
		writeError(w, statusCode(code), code, "The change could not be completed.", respPath, m.op, "")
		return false
	}
	return true
}

// writeConfirmRequired answers the first POST of a confirmable operation with a
// 409 carrying the single-use token and the (best-effort) scan summary, per
// backend-packaging-plan §6.3. The client re-posts the identical body with the
// token in its "confirm" field.
func writeConfirmRequired(w http.ResponseWriter, op, path, message, token string, exp time.Time, summary guard.Summary) {
	writeConfirmRequiredGraded(w, op, path, message, token, exp, summary, 0)
}

// writeConfirmRequiredGraded is writeConfirmRequired with M3's explicit
// confirmation grade. The grade is omitted when it is zero, so the envelope of
// every pre-M3 route is byte-for-byte what it was and the client keeps grading
// those from the summary's own sentences.
func writeConfirmRequiredGraded(w http.ResponseWriter, op, path, message, token string, exp time.Time, summary guard.Summary, grade int) {
	confirm := map[string]any{"token": token, "expires": exp, "summary": summary}
	if grade > 0 {
		confirm["grade"] = grade
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   map[string]string{"code": "confirm_required", "message": message, "path": path, "op": op},
		"confirm": confirm,
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
		// The worker error can name the dispatched (resolved) path, so it goes to
		// the server log only; the client sees the code, a generic message and the
		// REQUESTED path (adv 2). The audit Detail stays path-free (Code carries it).
		s.logRaw(r, m.op, m.path, err)
		s.writeAudit(sess, r, m, "result", "error", code, "", milestone)
		s.fail(w, r, code, backendMessage(code), m.path, "")
		return false
	}
	s.writeAudit(sess, r, m, "result", "ok", "", "", milestone)
	return true
}

// deleteBlocker names one entry that is keeping a single-level delete from
// succeeding. It is the folder's own content, listed for the user who tried to
// delete it, so there is no disclosure concern.
type deleteBlocker struct {
	Name   string `json:"name"`
	Hidden bool   `json:"hidden"`
	Dir    bool   `json:"dir"`
}

// deleteBlockers lists a directory as the user (hidden entries included) to name
// what is keeping a single-level delete from succeeding: an "empty-looking" folder
// on QNAP often still holds hidden metadata (.@__thumb, .streams) that the default
// listing hides, so the refusal otherwise looks like a bug. Best-effort — a
// listing failure yields nil and the caller still reports not_empty — and capped,
// so a genuinely large directory does not produce an unbounded response. INV-1
// holds: the listing goes through the backend (the worker, as the user), never
// through fsops in this root front-end.
func (s *Server) deleteBlockers(ctx context.Context, sess *session, dir string) ([]deleteBlocker, int, bool) {
	l, err := s.backend.List(ctx, sess.who, dir, fsx.ListOptions{ShowHidden: true, ResolveLinks: false, Limit: 25})
	if err != nil {
		return nil, 0, false
	}
	out := make([]deleteBlocker, 0, len(l.Entries))
	for _, e := range l.Entries {
		// Prefer NameB64 WHENEVER it is present: SetName sets it exactly for a
		// non-UTF-8 name and leaves Name populated with the raw bytes, which the
		// worker's JSON serialisation then flattens to U+FFFD by the time it reaches
		// here — so keying on "Name is empty" would never pick the byte-safe form and
		// distinct names could collide (review of the not_empty fix).
		name := e.Name
		if e.NameB64 != "" {
			name = "b64:" + e.NameB64
		}
		out = append(out, deleteBlocker{Name: name, Hidden: e.Hidden, Dir: e.Type == "dir"})
	}
	return out, l.Total, l.Truncated
}

// failNotEmpty answers a single-level delete refused because the directory still
// has entries. It carries the blocking entries so the client can explain WHY an
// "empty-looking" folder will not delete, instead of a bare refusal. The path is
// the REQUESTED spelling; only the folder's own contents are named.
func (s *Server) failNotEmpty(w http.ResponseWriter, r *http.Request, path string, blockers []deleteBlocker, total int, truncated bool) {
	s.logger.Printf("request ip=%q method=%s op=%q code=%s path=%q", ClientIP(r), r.Method, r.URL.Path, "not_empty", path)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode("not_empty"))
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":     map[string]string{"code": "not_empty", "message": "The folder is not empty.", "path": path, "op": r.URL.Path},
		"blockers":  blockers,
		"total":     total,
		"truncated": truncated,
	})
}

// failResolve answers a failed user-side path resolution (round-3 finding 2). The
// worker resolved the operation's path as the user and returned the kernel's own
// error — a permission denial for an unsearchable component, ErrOutsideRoot for
// an escape, or another failure. It is surfaced honestly, mapped by fsx.Code,
// against the REQUESTED spelling; there is no lexical fallback and no root-side
// resolution. The error text names only the requested path (resolution stops at
// the failing component before any target is revealed), so no resolved spelling
// leaks.
func (s *Server) failResolve(w http.ResponseWriter, r *http.Request, requested string, err error) {
	code := fsx.Code(err)
	// The resolve error can name an ancestor along the resolved path (an openat
	// failure), so keep it in the server log only; the client sees the code and
	// the REQUESTED path alone (adv 2).
	s.logRaw(r, "resolve", requested, err)
	s.fail(w, r, code, backendMessage(code), requested, "")
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
	if err := validNewName(body.Name); err != nil {
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
	// Resolve dir AS THE USER inside the worker (round-3 finding 2): the user's
	// own traversal permissions apply, so a parent the user cannot search returns
	// permission here rather than being resolved by root. dir already exists, so
	// resolve it fully (followLeaf=true).
	resolvedDir, rerr := s.resolveForGuard(r.Context(), sess.who, dir, true)
	if rerr != nil {
		s.failResolve(w, r, dir, rerr)
		return
	}
	resolvedTarget := fsx.Join(resolvedDir, body.Name)
	m := mutation{op: "mkdir", path: target}
	// Resolution can also *erase* a protected prefix — a protected root that is
	// itself a symlink, /etc/config -> /ordinary/config (adv 1a) — so the requested
	// spelling is guarded too and the stricter verdict governs (worstGuard).
	guardErr := worstGuard(
		s.guard.Check(guard.OpCreate, dir),
		s.guard.Check(guard.OpCreate, target),
		s.guard.Check(guard.OpCreate, resolvedDir),
		s.guard.Check(guard.OpCreate, resolvedTarget),
	)
	if !s.authorize(w, r, sess, guardErr, false, m, target, []string{target}, false, body.Confirm, guard.Summary{Files: 1}) {
		return
	}
	if !s.auditIntent(w, r, sess, m, false) {
		return
	}
	// Decide who owns the new folder. For an admin session the worker runs as
	// root (decision 6), so a plain mkdir lands root-owned with a umask mode —
	// which File Station's real-uid users then cannot write into (owner hardware
	// report). So, ONLY for a root session AND ONLY in an ordinary (guard-normal)
	// location, ask the worker to chown the created folder to the real signed-in
	// user; the inherited group is kept (GID -1), so a setgid parent keeps it in
	// administrators, and NO mode is requested (Mode left 0) — chowning alone
	// makes the admin the owner (owner rwx in the umask mode) while the setgid bit
	// and any ACLs are left intact (findings B/D). BOTH spellings must classify
	// normal: the requested parent AND the resolved one (finding C). A warn or
	// protected requested parent that is a symlink into a normal location (e.g.
	// /etc/config -> an ordinary dir) resolves normal, and adopting that to the
	// admin's uid would be wrong — the stricter-of-both policy (§2.0/§2.5) governs
	// here too. A guard-warn or protected parent (/etc/config, the install tree,
	// mount roots, /proc, ...) is a genuine system location and stays root-owned.
	// A non-admin worker already runs as the user, so its content is user-owned
	// and As stays nil (a non-root worker chowning to another uid is EPERM
	// anyway). The front-end only ever names the session's OWN uid.
	var as *wproto.CreateAs
	if sess.who.Root && s.guard.Classify(dir) == "normal" && s.guard.Classify(resolvedDir) == "normal" {
		as = &wproto.CreateAs{UID: sess.who.UID, GID: -1} // Mode 0: chown only, never chmod
	}
	// Dispatch against the resolved parent, binding the operation as tightly as
	// possible to what was guarded (adv 1b / standard P1); see the residual-race
	// note in PLAN.md §2.0.
	entry, err := s.mutator.Mkdir(r.Context(), sess.who, resolvedDir, body.Name, os.FileMode(0), body.Parents, as)
	// The worker created the directory but could not chown it to the user (the
	// admin-as-real-user path): the error carries fsx.ErrOwnerUnset, so its code
	// is exactly "owner_unset" — positive proof the create happened and only the
	// ownership step failed (finding E / round-3 finding 2). Report that partial
	// state honestly so the UI refreshes and explains rather than showing a bare
	// refusal a retry would turn into "exists". The no-rollback behaviour is kept:
	// the folder stays. This keys on the CODE, never on the item merely existing —
	// a create that failed before it ran (a dead worker) over a pre-existing entry
	// must not be mislabelled as our partial create.
	if fsx.Code(err) == "owner_unset" {
		s.logRaw(r, m.op, m.path, err) // the raw cause may name the resolved path
		s.writeAudit(sess, r, m, "result", "error", "owner_unset", "folder created but owner could not be set", false)
		s.fail(w, r, "owner_unset", "The folder was created but could not be assigned to you; it is owned by the system — check it or delete it.", target, "")
		return
	}
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
		if err := validNewName(toRaw); err != nil {
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
	// Resolve both paths AS THE USER inside the worker (round-3 finding 2), each
	// keeping its final component literal (followLeaf=false): a rename operates on
	// the named entry, not its symlink target. A component the user cannot search
	// returns permission here rather than being resolved by root.
	guardFrom, rerr := s.resolveForGuard(r.Context(), sess.who, from, false)
	if rerr != nil {
		s.failResolve(w, r, from, rerr)
		return
	}
	guardTo, rerr := s.resolveForGuard(r.Context(), sess.who, to, false)
	if rerr != nil {
		s.failResolve(w, r, to, rerr)
		return
	}
	m := mutation{op: "rename", path: from, dst: to}
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
		// Replacing the destination is an OpDelete on it. The guard is a POLICY
		// check on the path, not on current existence, so run it ALWAYS when
		// overwrite is requested — regardless of whether the destination exists
		// right now (adv 3). The earlier not_found short-circuit let a rename with
		// overwrite:true replace an entry created after a Stat (a TOCTOU) even where
		// the destination's own delete policy forbids it (e.g. /dev/example). The
		// worst verdict over both the requested and the resolved spelling governs.
		checks = append(checks,
			s.guard.Check(guard.OpDelete, to),
			s.guard.Check(guard.OpDelete, guardTo),
		)
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
	if !s.auditIntent(w, r, sess, m, false) {
		return
	}
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

// deleteWarnings builds the confirmation summary's warning lines for a delete:
// the guard's path-free reasons for every spelling that is warn- or deny-class
// (so the client shows WHY a protected path needs a deliberate acknowledgement,
// standard P1 / adv 4), plus a scale note when the delete is large. The reasons
// never contain the path itself (guard.Reasons), so a resolved spelling cannot
// leak into the summary. Duplicate reasons across the requested and resolved
// spelling are collapsed.
func deleteWarnings(g *guard.Guard, requested, resolved string, big bool, files, bytes int64) []string {
	var out []string
	seen := map[string]bool{}
	add := func(reasons []string) {
		for _, reason := range reasons {
			if reason == "" || seen[reason] {
				continue
			}
			seen[reason] = true
			out = append(out, reason)
		}
	}
	add(g.Reasons(guard.OpDelete, requested))
	if resolved != requested {
		add(g.Reasons(guard.OpDelete, resolved))
	}
	if big {
		out = append(out, fmt.Sprintf("Large permanent delete: %d item(s), %d byte(s). This cannot be undone.", files, bytes))
	}
	return out
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
	// final component (followLeaf=false), AS THE USER inside the worker (round-3
	// finding 2): a parent the user cannot search returns permission here.
	guardPath, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
	if rerr != nil {
		s.failResolve(w, r, p, rerr)
		return
	}
	m := mutation{op: "delete", path: p, files: 1}
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
	// Show WHY this delete is confirmable: a protected/warn path's reasons and,
	// for a large delete, the measured totals (standard P1 / adv 4). The reasons
	// are path-free (guard.Reasons), so no resolved spelling leaks into the
	// summary; the client requires an explicit acknowledgement whenever they are
	// present. Both spellings contribute, since the stricter verdict governs.
	summary.Warnings = deleteWarnings(s.guard, p, guardPath, big, summary.Files, summary.Bytes)
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
	if !s.auditIntent(w, r, sess, m, big) {
		return
	}
	// Dispatch against the resolved path (adv 1b); residual race noted in §2.0.
	err := s.mutator.Delete(r.Context(), sess.who, guardPath)
	if err != nil && fsx.Code(err) == "not_empty" {
		// A single-level delete (M1; recursion is M2) hit a non-empty directory.
		// An "empty-looking" folder on QNAP usually still holds hidden metadata
		// (.@__thumb, .streams) the default listing hides, so NAME what is blocking
		// it rather than leaving a refusal that looks like a bug (owner hardware
		// test, 2026-09-11). The audit result is still recorded, path-free.
		s.logRaw(r, m.op, m.path, err)
		s.writeAudit(sess, r, m, "result", "error", "not_empty", "", big)
		blockers, total, truncated := s.deleteBlockers(r.Context(), sess, p)
		s.failNotEmpty(w, r, p, blockers, total, truncated)
		return
	}
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
	// Resolve each item's parent AS THE USER inside the worker (followLeaf=false;
	// the leaf stays, as delete removes the link itself) (round-3 finding 2). A
	// resolution failure for one item — a parent the user cannot search — is
	// recorded against that item and never dispatched, rather than aborting the
	// batch. Measure each item as the user so the summary and the milestone see
	// real sizes (adv 9 / adv 10). In M1 every delete is permanent, so the batch
	// always needs a redeemed confirmation token regardless of size or path
	// (decision 10); the warn-path and scale reasons below feed the summary.
	resolved := make([]string, len(paths))
	resolveErr := make([]error, len(paths))
	sizes := make([]int64, len(paths))
	var totalBytes int64
	var warnings []string
	warnSeen := map[string]bool{}
	addWarn := func(reasons []string) {
		for _, reason := range reasons {
			if reason == "" || warnSeen[reason] {
				continue
			}
			warnSeen[reason] = true
			warnings = append(warnings, reason)
		}
	}
	for i, p := range paths {
		rp, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
		if rerr != nil {
			resolveErr[i] = rerr
			// Even an unresolvable item contributes its requested-path warnings.
			addWarn(s.guard.Reasons(guard.OpDelete, p))
			continue
		}
		resolved[i] = rp
		if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
			sizes[i] = e.Size
			totalBytes += e.Size
		}
		addWarn(deleteWarnings(s.guard, p, rp, false, 0, 0))
	}
	// big marks a batch worth a QuLog milestone: more than 100 files or more than
	// 1 GiB (adv 10). The measured totals are carried into the audit event.
	big := guard.NeedsConfirm(guard.OpDelete, "", len(paths), totalBytes)
	if big {
		warnings = append(warnings, fmt.Sprintf("Large permanent delete: %d item(s), %d byte(s). This cannot be undone.", len(paths), totalBytes))
	}
	// A batch always needs confirmation now; the summary carries the path-free
	// reasons and the totals so the client shows them and requires an explicit
	// acknowledgement (standard P1 / adv 4). Audit the challenge/invalid-token
	// rejection as a denial (adv 10) before demanding the token.
	tokenRedeemed := false
	summary := guard.Summary{Files: int64(len(paths)), Bytes: totalBytes, Warnings: warnings}
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
	// Track what ACTUALLY happened, so the response outcome and the milestone
	// totals reflect the real result, never the requested totals (adv 6).
	var succeeded, failed int
	var succeededBytes int64
	for i, p := range paths {
		// Stop promptly if the request has been cancelled or its deadline passed,
		// rather than grinding through the rest of a large batch after the caller
		// is gone (adv 4). The remaining items are simply not attempted.
		if ctxErr := r.Context().Err(); ctxErr != nil {
			break
		}
		m := mutation{op: "delete", path: p}
		res := itemResult{Path: p}
		// An item whose path could not be resolved as the user (finding 2) is
		// reported with the kernel's own code and never dispatched. The raw resolve
		// error can name a resolved ancestor, so it stays in the server log; the
		// audit Detail is path-free (adv 2).
		if resolveErr[i] != nil {
			code := fsx.Code(resolveErr[i])
			s.logRaw(r, "delete", p, resolveErr[i])
			s.writeAudit(sess, r, m, "result", "denied", code, "", false)
			res.Code = code
			failed++
			results = append(results, res)
			continue
		}
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
			s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
			res.Code = "read_only"
			failed++
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrProtected):
			s.logRaw(r, "delete", p, err)
			s.writeAudit(sess, r, m, "result", "denied", "protected", "protected path", false)
			res.Code = "protected"
			failed++
			results = append(results, res)
			continue
		case errors.Is(err, guard.ErrConfirmRequired):
			if !tokenRedeemed {
				s.writeAudit(sess, r, m, "result", "denied", "confirm_required", "confirmation required", false)
				res.Code = "confirm_required"
				failed++
				results = append(results, res)
				continue
			}
		case err != nil:
			code := fsx.Code(err)
			s.logRaw(r, "delete", p, err)
			s.writeAudit(sess, r, m, "result", "denied", code, "", false)
			res.Code = code
			failed++
			results = append(results, res)
			continue
		}
		// The item's intent must be durably recorded before its dispatch; if it
		// cannot be, refuse this item rather than deleting without a record (adv 1).
		// A failure here is a persistent audit outage (or a cancelled context, which
		// WriteSync now observes), so STOP the batch rather than spending up to the
		// per-call timeout on every one of a thousand remaining items (adv 4).
		if aerr := s.writeAudit(sess, r, m, "intent", "", "", "", false); aerr != nil {
			res.Code = "audit_unavailable"
			failed++
			results = append(results, res)
			break
		}
		// Dispatch against the resolved path (adv 1b); residual race noted in §2.0.
		// A worker error can name the resolved path, so log it server-side only and
		// keep the audit Detail path-free (adv 2).
		if err := s.mutator.Delete(r.Context(), sess.who, resolved[i]); err != nil {
			code := fsx.Code(err)
			s.logRaw(r, "delete", p, err)
			s.writeAudit(sess, r, m, "result", "error", code, "", false)
			res.Code = code
			failed++
		} else {
			s.writeAudit(sess, r, m, "result", "ok", "", "", false)
			res.OK = true
			succeeded++
			succeededBytes += sizes[i]
		}
		results = append(results, res)
	}
	// Overall outcome from what actually happened. A batch stopped partway (a
	// cancelled context or an audit outage broke the loop) leaves items neither
	// tried nor deleted: those UNATTEMPTED targets must count against completion,
	// or a cancel right after the first success would masquerade as a full "ok"
	// (round-5 std/adv 3). So: none succeeded → "error"; any failure OR any target
	// left unattempted → "partial"; "ok" only when every requested item succeeded.
	attempted := len(results)
	unattempted := len(paths) - attempted
	outcome := "ok"
	switch {
	case succeeded == 0:
		outcome = "error"
	case failed > 0 || unattempted > 0:
		outcome = "partial"
	}
	// A large batch is mirrored to QuLog as one milestone whose Result is the TRUE
	// outcome — "error" when all failed, "partial" when some failed OR the batch
	// was stopped partway, "ok" only when every requested item succeeded — matching
	// the HTTP response, never a blanket "ok" for a mostly-failed or truncated
	// batch (round-5 std/adv 3 / round-4 adv 5,6). The denominator is the REQUESTED
	// count (len(paths)), so a truncated batch reads "1 of 100 (partial)", not
	// "1 of 1 (ok)"; the byte/file totals are the actual succeeded ones.
	if big {
		bm := mutation{op: "delete", files: int64(succeeded), bytes: succeededBytes}
		s.writeAudit(sess, r, bm, "result", outcome, "", fmt.Sprintf("batch delete: %d of %d items, %d bytes (%s)", succeeded, len(paths), succeededBytes, outcome), true)
	}
	writeJSON(w, map[string]any{"results": results, "outcome": outcome, "attempted": attempted, "succeeded": succeeded, "failed": failed})
}
