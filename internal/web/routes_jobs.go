package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/wproto"
)

// This file wires the M2-A job spine into the web layer: recursive delete (to
// trash or permanently), folder size, and the job list/cancel routes the panel
// polls. The gates are M1's, in the same order (routes_mutate.go): the guard
// before any dispatch (INV-1), a durable audit intent before the work and a
// result line after it, then the backend — here backend.Jobs, one long-lived
// RPC to the worker that runs as the user (INV-2).
//
// Two things are different from an M1 mutation:
//
//   - The HTTP request ends at 202, long before the work does. Anything the job
//     records afterwards must therefore be written from the JOB's context, never
//     the request's, or a record of completed destructive work would be
//     discarded the moment the browser moved on (the same reasoning as M1's
//     auditContext, which is why the job path uses context.WithoutCancel too).
//   - The session may be revalidated, or gone, while the job runs. The identity
//     an audit line needs is therefore snapshotted (jobActorOf) before Submit;
//     reading sess.who from the job goroutine would race a revalidation.
//
// M2-A review round 2 reshaped four things here, and each is marked at its
// site: the guard is re-run when a queued job actually STARTS (W1); the result
// audit line is written from the manager's completion hook rather than from
// inside the work function, so a job that never ran is still recorded exactly
// once (W2); a cancelled job publishes its partial result (W3); and everything
// a job publishes — warning paths, the current path, the error — is mapped back
// into the caller's own vocabulary and code-derived wording (W4/W5), since a
// job dispatches against RESOLVED roots.
const (
	// permanentWarning is the exact sentence a permanent delete's confirmation
	// summary carries. The client keys its grade-2 (typed phrase) dialog on this
	// string, so it is a pinned contract between the two halves, tested on both
	// sides.
	permanentWarning = "This delete is permanent and cannot be undone."
	// trashGradeRoots is how many selected roots promote even a move-to-trash
	// from grade 1 to grade 2 (ui-ux §4.2 L1: >100 items in one op).
	trashGradeRoots = 100
	// maxJobRoots bounds one job's selection. The guard resolves and stats every
	// root before dispatch, so an unbounded list is an unbounded amount of
	// front-end work inside one request.
	maxJobRoots = 1000
	// milestoneFiles/milestoneBytes are the audit-milestone thresholds for a
	// finished job, matching guard.NeedsConfirm's scale rule.
	milestoneFiles = 100
	milestoneBytes = 1 << 30
)

// jobPath matches the two job-id request forms, "/api/jobs/<id>" and
// "/api/jobs/<id>/cancel". The id must be exactly the 16 lower-case hex
// characters jobs.NewID mints, which is what keeps "/api/jobs/delete" a literal
// route rather than a job lookup.
func jobPath(p string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(p, "/api/jobs/")
	if !found || rest == "" {
		return "", "", false
	}
	if cut, isCancel := strings.CutSuffix(rest, "/cancel"); isCancel {
		rest, action = cut, "cancel"
	}
	if !validJobID(rest) {
		return "", "", false
	}
	return rest, action, true
}

// validJobID is jobs.ValidID: the route vocabulary and the manager's id
// vocabulary are deliberately the same one, so a caller-supplied id (W7) can
// never produce a job that /api/jobs/<id> cannot address.
func validJobID(id string) bool { return jobs.ValidID(id) }

// jobsReady reports whether the job spine is wired, mirroring mutationsReady.
func (s *Server) jobsReady(w http.ResponseWriter, r *http.Request) bool {
	if s.jobMgr == nil || s.jobRunner == nil {
		s.fail(w, r, "internal", "This build cannot run jobs.", "", "")
		return false
	}
	return true
}

// jobActor is the identity an audit line written from a job goroutine needs. It
// is a snapshot taken while the request is still on the stack: a concurrent
// forced revalidation writes sess.who under sess.mu, so the job goroutine must
// never read the live session.
type jobActor struct {
	actor string
	uid   int
	admin bool
	root  bool
	ip    string
}

func jobActorOf(sess *session, r *http.Request) jobActor {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return jobActor{actor: sess.who.User, uid: sess.who.UID, admin: sess.admin, root: sess.who.Root, ip: ClientIP(r)}
}

// jobAudit writes one audit line on behalf of a running job. The context is
// always made cancellation-immune for a durable line: by the time a job
// finishes, the HTTP request that started it is long over, and a record of work
// that ALREADY happened must not depend on a context that is already done (the
// same rule as M1's auditContext, arrived at from the other direction).
// WriteSync's own writeSyncTimeout still bounds the wait.
func (s *Server) jobAudit(ctx context.Context, who jobActor, ev audit.Event, milestone bool) {
	if s.auditor == nil {
		return
	}
	ev.Actor, ev.UID, ev.Admin, ev.Root, ev.IP = who.actor, who.uid, who.admin, who.root, who.ip
	ev.ForceMilestone = milestone
	if milestone || ev.Phase == "intent" {
		if err := s.auditor.WriteSync(context.WithoutCancel(ctx), ev); err != nil {
			s.logger.Printf("job audit: %s %s/%s could not be persisted: %v", ev.Op, ev.Phase, ev.Result, err)
		}
		return
	}
	s.auditor.Write(ev)
}

// jobResultView is what a job's Result field carries. The worker's JobResult is
// deliberately terse on the wire (single-letter keys); this is the UI-facing
// spelling, and it is where the trash ids an Undo needs are surfaced.
type jobResultView struct {
	Hits     []fsx.Entry `json:"hits,omitempty"`
	Files    int64       `json:"files"`
	Dirs     int64       `json:"dirs,omitempty"`
	Bytes    int64       `json:"bytes"`
	Skipped  int64       `json:"skipped,omitempty"`
	Warnings int         `json:"warnings,omitempty"`
	Detail   string      `json:"detail,omitempty"`
	TrashIDs []string    `json:"trashIds,omitempty"`
}

// ForList returns a copy of the result suitable for list responses, omitting hits to reduce bandwidth.
func (v jobResultView) ForList() jobResultView {
	return jobResultView{
		Files:    v.Files,
		Dirs:     v.Dirs,
		Bytes:    v.Bytes,
		Skipped:  v.Skipped,
		Warnings: v.Warnings,
		Detail:   v.Detail,
		TrashIDs: v.TrashIDs,
		// Hits intentionally omitted.
	}
}

// hitsKey is how a result that still carries hits begins. jobResultView declares
// Hits first and omits it when empty, so a settled search result does not
// contain these bytes anywhere.
var hitsKey = []byte(`"hits":`)

// jobListView keeps hits out of a list response.
//
// It used to do that by decoding every job's result and re-encoding it without
// the hits, which was the expensive half of the polling problem: the hits were
// in the manager, Manager.List copied them into every snapshot, and this then
// allocated them again to discard them. The hits are in the retention ledger
// now (routes_search.go), so for every settled job this is a scan of a few
// hundred bytes that finds nothing and marshals the job as it stands.
//
// The decode is kept for one narrow case rather than deleted: a search's result
// carries its hits from the instant the work function returns until the finish
// hook moves them, and a poll landing in that window would otherwise ship a
// megabyte of hits to a client that did not ask for them.
type jobListView struct {
	jobs.Job
}

func (v jobListView) MarshalJSON() ([]byte, error) {
	j := v.Job
	if bytes.Contains(j.Result, hitsKey) {
		var result *jobResultView
		if err := json.Unmarshal(j.Result, &result); err != nil {
			return nil, err
		}
		if result != nil {
			var err error
			j.Result, err = json.Marshal(result.ForList())
			if err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(j)
}

func viewOf(res wproto.JobResult) jobResultView {
	// TrashIDs is deliberately NOT copied here. It is filled only where a job is
	// known to have been a delete-to-trash (jobDelete), so that a result carrying
	// ids can never be published for an operation whose items are gone for good.
	return jobResultView{Files: res.Files, Dirs: res.Dirs, Bytes: res.Bytes, Skipped: res.Skipped, Warnings: res.Warnings, Detail: res.Detail}
}

// --- requested ⇄ resolved roots (findings W4 and W5) -------------------------

// jobRoots is one job's requested→resolved root mapping, captured at submit.
//
// A job is DISPATCHED against the resolved spellings (PLAN.md §2.0), so every
// path the worker then reports — a per-item warning, the current item, the
// trash-root refusal — is spelled in the resolved vocabulary, which may name a
// symlink target the caller never asked about and cannot otherwise see. The M1
// client-facing rule (routes_mutate.go) is that clients see error CODES and
// REQUESTED paths only, so those paths are mapped back here.
//
// The mapping is a PREFIX substitution and is safe precisely because both
// spellings of every root are known exactly — unlike the arbitrary
// string-substitution M1 rejected, which could double-map a spelling into its
// own output.
type jobRoots struct {
	requested []string
	resolved  []string
}

// mappedRoots pairs the two spellings of the same roots, in order.
func mappedRoots(requested, resolved []string) jobRoots {
	return jobRoots{requested: append([]string(nil), requested...), resolved: append([]string(nil), resolved...)}
}

// identityRoots is the mapping for a job dispatched against exactly what the
// client named (folder size, trash restore): there is nothing to map back, but
// the fallback rule below still applies to a path under no root at all.
func identityRoots(paths []string) jobRoots { return mappedRoots(paths, paths) }

// underRoot reports whether p is root or lies inside it, by whole components.
func underRoot(p, root string) bool {
	if root == "" {
		return false
	}
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// mapPath rewrites a worker-reported path into the caller's vocabulary: the
// resolved root prefix becomes the requested one, longest root first so a
// nested pair maps to the closer of the two. A path under NO known root is
// reported as the first requested root rather than published verbatim — the
// daemon cannot vouch for that spelling, and a job's own roots are the only
// paths the caller already knows. With no roots at all (emptying the trash)
// nothing is published: the code and the message carry the whole answer.
func (jr jobRoots) mapPath(p string) string {
	if p == "" {
		return ""
	}
	best := -1
	for i, root := range jr.resolved {
		if i >= len(jr.requested) || !underRoot(p, root) {
			continue
		}
		if best < 0 || len(root) > len(jr.resolved[best]) {
			best = i
		}
	}
	if best < 0 {
		if len(jr.requested) > 0 {
			return jr.requested[0]
		}
		return ""
	}
	root := jr.resolved[best]
	if p == root {
		return jr.requested[best]
	}
	return fsx.Join(jr.requested[best], strings.TrimPrefix(p, strings.TrimSuffix(root, "/")+"/"))
}

// --- sanitized job errors (finding W4) ---------------------------------------

// jobError is what a job's work function returns in place of the worker's own
// error. Job.Err is served to every client that may see the job, and a raw
// worker error can carry both the resolved spelling and the kernel's own text,
// so what is published is a code-derived generic sentence; the raw error goes
// to the server log alone. The original is still wrapped, so the manager's
// errors.Is(err, context.Canceled) and fsx.Code keep working, and ErrorCode
// (jobs.ErrCoder) names the API vocabulary the UI shares with the HTTP layer.
type jobError struct {
	code string
	msg  string
	err  error
}

func (e *jobError) Error() string     { return e.msg }
func (e *jobError) Unwrap() error     { return e.err }
func (e *jobError) ErrorCode() string { return e.code }

// jobErr sanitizes a worker error for publication and logs the original.
func (s *Server) jobErr(op, id string, err error) error {
	if err == nil {
		return nil
	}
	code := fsx.Code(err)
	s.logger.Printf("job %s op=%q raw error (%s): %v", id, op, code, err)
	return &jobError{code: code, msg: jobErrorMessage(code), err: err}
}

// jobErrorMessage is the published wording for an error code. It never contains
// a path: the job already names its own roots.
func jobErrorMessage(code string) string {
	switch code {
	case "cancelled":
		return "The operation was cancelled."
	case "read_only":
		return "Read-only mode is on, so the operation was refused."
	case "protected":
		return "This location is protected, so the operation was refused."
	case "no_trash":
		return "There is no Trash for this location."
	case "queue_full":
		return "Too many operations are already queued."
	case "worker_gone":
		return "The operation stopped because its worker process ended."
	}
	return backendMessage(code)
}

// jobWarnMessage is the published wording for ONE item's failure. The worker's
// own message is logged, never served: it is the kernel's text about a resolved
// path (W4).
func jobWarnMessage(code string) string {
	switch code {
	case "":
		return "This item could not be processed."
	case "protected":
		return "This location is protected and was skipped."
	case "not_empty":
		return "This folder is not empty."
	case "exists":
		return "An item with that name already exists."
	case "cancelled":
		return "The operation was cancelled."
	// The copy/move engine's per-item outcomes (M2-B). Each is the one line a
	// user reads under the job, so it says what happened to THIS item, not
	// what the engine did about it.
	case "kept":
		return "The source was kept because part of it could not be copied."
	case "changed":
		return "This file changed while it was being copied."
	case "times_unset":
		return "The item was copied but its timestamps could not be set."
	case "conflict":
		return "An item of a different kind already has this name; it was skipped."
	case "owner_unset":
		return "The item was created but its owner could not be set."
	case "no_space":
		return "There is not enough free space, or the quota is full."
	case "unsupported":
		return "This kind of item cannot be copied."
	case "invalid_target":
		return "The destination is inside the folder being copied."
	case "cross_device":
		return "The source and destination are on different volumes."
	case "capped":
		return "The scan hit its limit; the totals are a minimum."
	case "truncated":
		return "The search reached its limit; only partial results are shown."
	case "unverified":
		return "The copy could not be verified in time, so the original was kept."
	case "too_many":
		return "Too many folders to track safely; this item was skipped."
	case "shared_destination":
		return "The destination can be written by other users, so protection against a folder being swapped in during the copy is reduced."
	}
	return backendMessage(code)
}

// --- progress and warning sinks ----------------------------------------------

// progressSink and warnSink adapt the worker's in-band frames to the manager's
// progress handle. They are called on the RPC goroutine, in order, and both map
// the worker's paths back into the caller's vocabulary (W4).
func (s *Server) progressSink(jr jobRoots, p *jobs.Progress) func(wproto.Prog) {
	return func(pr wproto.Prog) {
		p.Set(pr.Files, pr.FilesTotal, pr.Bytes, pr.BytesTotal)
		if len(pr.Current) > 0 {
			p.Current(jr.mapPath(string(pr.Current)))
		}
		if pr.Phase != "" {
			p.Phase(pr.Phase)
		}
	}
}

func (s *Server) warnSink(jr jobRoots, op, id string, p *jobs.Progress) func(wproto.Warn) {
	return func(wn wproto.Warn) {
		// The worker's spelling and its message stay server-side; the job
		// publishes the requested path, the code, and the code's own wording.
		s.logger.Printf("job %s op=%q warning path=%q code=%q: %s", id, op, string(wn.Path), wn.Code, wn.Message)
		p.Warn(jr.mapPath(string(wn.Path)), wn.Code, jobWarnMessage(wn.Code))
	}
}

// --- the start-of-job guard re-check (finding W1) -----------------------------

// guardCheck is one op applied to a set of paths when a job starts.
type guardCheck struct {
	op    guard.Op
	paths []string
}

// recheckGuard re-runs the guard at the instant a queued job actually STARTS.
//
// A confirmed delete can sit in the queue behind a full concurrency class for
// minutes while an administrator turns read-only ON (or a protected rule starts
// matching). The submit-time verdict is then stale, and dispatching on it would
// write to the filesystem after the daemon was told to stop writing. So every
// destructive job re-checks, on BOTH spellings of every root, before it calls
// the worker; a refusal ends the job failed with the API code, and nothing is
// dispatched. A warn-class verdict is NOT a refusal here: the confirmation
// token that covered it was redeemed at submit.
func (s *Server) recheckGuard(checks ...guardCheck) error {
	if s.guard == nil {
		return nil
	}
	if s.guard.ReadOnly() {
		return &jobError{code: "read_only", msg: "Read-only mode was turned on before this operation started, so nothing was changed.", err: fsx.ErrReadOnly}
	}
	for _, check := range checks {
		for _, p := range check.paths {
			err := s.guard.Check(check.op, p)
			switch {
			case err == nil, errors.Is(err, guard.ErrConfirmRequired):
				continue
			case errors.Is(err, guard.ErrReadOnly):
				return &jobError{code: "read_only", msg: "Read-only mode was turned on before this operation started, so nothing was changed.", err: fsx.ErrReadOnly}
			case errors.Is(err, guard.ErrProtected):
				// The verdict can name a resolved spelling: server log only.
				s.logger.Printf("job guard re-check refused: %v", err)
				return &jobError{code: "protected", msg: "This location is protected, so the operation was refused before it started.", err: fsx.ErrProtected}
			default:
				code := fsx.Code(err)
				s.logger.Printf("job guard re-check failed (%s): %v", code, err)
				return &jobError{code: code, msg: jobErrorMessage(code), err: err}
			}
		}
	}
	return nil
}

// guardRefuses reports whether a guard verdict is a REFUSAL rather than a
// request for confirmation — exactly the set of verdicts authorize answers with
// an error instead of a token (routes_mutate.go). It exists so a refusal of our
// own can be ordered BEHIND the guard's without restating that precedence:
// R3-WA1's no_trash must not pre-empt read_only or protected.
func guardRefuses(err error) bool {
	return err != nil && !errors.Is(err, guard.ErrConfirmRequired)
}

// jobPaths decodes and cleans a job's root paths, honouring the pathB64
// companion. It writes the error response itself and returns false on failure.
func (s *Server) jobPaths(w http.ResponseWriter, r *http.Request, refs []pathRef) ([]string, bool) {
	if len(refs) == 0 {
		s.fail(w, r, "bad_request", "Supply the paths to act on.", "", "")
		return nil, false
	}
	if len(refs) > maxJobRoots {
		s.fail(w, r, "bad_request", fmt.Sprintf("Select at most %d items at a time.", maxJobRoots), "", "")
		return nil, false
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		p, err := bodyPath(ref.Path, ref.PathB64)
		if err != nil {
			s.fail(w, r, "bad_request", "One of the paths was invalid.", "", err.Error())
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// deleteJobTokenParts is the ordered, structured descriptor a delete-job
// confirmation token binds. Mode and the crossing flag are part of it, so a
// token issued for "move these to Trash" cannot be redeemed for "delete these
// permanently" or for a wider recursion (the same reasoning as M1's
// renameTokenParts). The paths are sorted so a client that reorders its own
// selection between the challenge and the re-post still redeems.
func deleteJobTokenParts(mode string, crossMounts bool, paths []string) []string {
	parts := []string{"job=delete", "mode=" + mode, "cross=" + strconv.FormatBool(crossMounts)}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	return append(parts, sorted...)
}

func deleteTitle(mode string, paths []string) string {
	verb := "Moving to Trash"
	if mode == "permanent" {
		verb = "Deleting permanently"
	}
	if len(paths) == 1 {
		return verb + ": " + fsx.Base(paths[0])
	}
	return fmt.Sprintf("%s: %d items", verb, len(paths))
}

// jobDelete is the recursive delete: to Trash by default, permanently on
// request. It is what makes a non-empty folder deletable at all (M1's
// /api/fs/delete is single-level and stays for API compatibility).
//
// The ladder (PLAN.md decision 10, ui-ux §4.2): BOTH modes require a redeemed
// confirmation token — uniform and replay-safe, as M1 decided for permanent
// deletes — and the Summary that comes back with the challenge is what drives
// the client's grade. A trash delete carries only the guard's own reasons
// (grade 1, a simple confirm) unless more than trashGradeRoots roots are
// selected; a permanent delete always carries permanentWarning, which the
// client renders as grade 2 (typed phrase).
func (s *Server) jobDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	var body struct {
		Paths       []pathRef `json:"paths"`
		Mode        string    `json:"mode"`
		CrossMounts bool      `json:"crossMounts"`
		Confirm     string    `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	mode := body.Mode
	if mode == "" {
		mode = "trash"
	}
	if mode != "trash" && mode != "permanent" {
		s.fail(w, r, "bad_request", `Supply mode as "trash" or "permanent".`, "", "")
		return
	}
	permanent := mode == "permanent"
	paths, ok := s.jobPaths(w, r, body.Paths)
	if !ok {
		return
	}

	// Resolve every root's parent AS THE USER inside the worker and guard both
	// the requested and the resolved spelling, taking the stricter verdict — the
	// M1 rule (routes_mutate.go), for the same reasons: resolution can reveal a
	// protected target behind an alias, and it can also erase a protected prefix.
	// A root that cannot be resolved refuses the WHOLE job rather than being
	// silently dropped: a job reports one outcome, so a partially-guarded
	// selection must never be dispatched.
	resolved := make([]string, len(paths))
	checks := make([]error, 0, 2*len(paths))
	var warnings []string
	seen := map[string]bool{}
	var totalBytes int64
	for i, p := range paths {
		rp, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
		if rerr != nil {
			s.failResolve(w, r, p, rerr)
			return
		}
		resolved[i] = rp
		checks = append(checks, s.guard.Check(guard.OpDelete, p), s.guard.Check(guard.OpDelete, rp))
		for _, reason := range deleteWarnings(s.guard, p, rp, false, 0, 0) {
			if reason == "" || seen[reason] {
				continue
			}
			seen[reason] = true
			warnings = append(warnings, reason)
		}
		// Measure each root as the user so the summary and the milestone see real
		// sizes. A stat failure simply leaves it out; the worker's own scan is the
		// authority once the job runs.
		if e, statErr := s.backend.Stat(r.Context(), sess.who, p); statErr == nil {
			totalBytes += e.Size
		}
	}
	if permanent && !seen[permanentWarning] {
		warnings = append(warnings, permanentWarning)
	}
	if len(paths) > trashGradeRoots {
		warnings = append(warnings, fmt.Sprintf("%d items are selected.", len(paths)))
	}
	summary := guard.Summary{Files: int64(len(paths)), Bytes: totalBytes, Warnings: warnings}
	// The audited path is the FIRST REQUESTED root (W7): a delete's durable
	// record has to say what was deleted, and the requested spelling is the one
	// the client is allowed to see. The rest of the selection is named in the
	// intent line's detail.
	m := mutation{op: "delete", path: paths[0], files: int64(len(paths)), bytes: totalBytes}
	roots := mappedRoots(paths, resolved)
	verdict := worstGuard(checks...)
	// The Trash switch is a NAS-wide setting (config.Trash.Enabled). With it off,
	// nothing may create the world-writable sticky directories decision 10
	// describes, so a trash-mode delete is refused outright (W6).
	//
	// R3-WA1 moved that refusal AHEAD of authorize. Refusing after it meant the
	// first POST minted and spent a confirmation token for a mode the daemon was
	// never going to run: the user confirmed "move to Trash", was told there is
	// no Trash, and had to confirm the permanent delete a second time — two
	// dialogs and a wasted single-use token for one decision. The guard keeps
	// precedence: a root that is protected, or a daemon in read-only mode,
	// refuses for its own reason first, because "there is no Trash" must never be
	// the answer to a delete that was not going to be allowed in any mode.
	if !permanent && !s.cfg.Trash.Enabled && !guardRefuses(verdict) {
		writeError(w, http.StatusConflict, "no_trash", "Trash is disabled on this NAS, so deleting is permanent.", paths[0], "delete", "")
		return
	}
	// extraConfirm is always on: every delete, trash or permanent, is redeemed
	// against a single-use token (decision 10).
	if !s.authorize(w, r, sess, verdict, true, m, "", deleteJobTokenParts(mode, body.CrossMounts, paths), true, body.Confirm, summary) {
		return
	}
	if !permanent {
		// The trash directory has to exist before the user's worker — which has
		// only their own permissions — can rename anything into it, so the root
		// front-end makes it: the one sanctioned front-end filesystem write
		// (decision 10, trashroot's package comment). No trash here is not an
		// error either, it is the fact that this delete would be permanent.
		if !s.ensureTrashRoots(w, r, sess, roots) {
			return
		}
	}

	// The id is chosen HERE, before the durable intent line is written (W7), so
	// the intent, the result and the /api/jobs/<id> the client polls are one
	// correlated record: without it two concurrent deletes cannot be told apart
	// in the audit trail, and after a retention sweep or a restart nothing says
	// what a given job id deleted.
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The delete could not be prepared.", paths[0], err.Error())
		return
	}
	modeDetail := mode
	if body.CrossMounts {
		modeDetail += ", including mounted sub-folders"
	}
	big := permanent || int64(len(paths)) >= milestoneFiles || totalBytes >= milestoneBytes
	// The intent names every root it can (capped), so the durable record says
	// WHAT was about to be deleted, not merely that something was.
	if err := s.writeAudit(sess, r, m, "intent", "", "", jobIntentDetail(id, modeDetail, paths), big); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", paths[0], m.op, err.Error())
		return
	}
	resultDetail := fmt.Sprintf("job %s: %s, %d root(s)", id, modeDetail, len(paths))

	// Dispatch the RESOLVED spellings, binding the work as tightly as possible to
	// what was guarded (PLAN.md §2.0 residual race).
	wire := make([][]byte, len(resolved))
	for i, p := range resolved {
		wire[i] = []byte(p)
	}
	reqBody, err := json.Marshal(wproto.DeleteReq{Paths: wire, Recursive: true, Trash: !permanent, CrossMounts: body.CrossMounts})
	if err != nil {
		s.fail(w, r, "internal", "The delete could not be prepared.", paths[0], err.Error())
		return
	}
	who, actor := sess.who, jobActorOf(sess, r)
	started := time.Now()
	meta := jobs.Meta{
		ID: id, Src: paths, Actor: who.User, UID: who.UID,
		// ALL result auditing happens in this hook (W2): a job cancelled while
		// still queued, or closed at shutdown, never runs the function below, so
		// a result line written from inside it would simply be missing for the
		// one destructive intent that most needs closing out.
		OnFinish: s.jobFinishHook(actor, "delete", id, m.path, resultDetail, big),
	}
	job, err := s.jobMgr.Submit(jobs.KindDelete, deleteTitle(mode, paths), meta, func(ctx context.Context, p *jobs.Progress) (any, error) {
		// W1: the queue may have held this job while read-only was switched on.
		if derr := s.recheckGuard(guardCheck{op: guard.OpDelete, paths: paths}, guardCheck{op: guard.OpDelete, paths: resolved}); derr != nil {
			return nil, derr
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobDelete, Body: reqBody}, s.progressSink(roots, p), s.warnSink(roots, "delete", id, p))
		view := viewOf(res)
		if !permanent {
			// The worker names the entries it created, which is the exact answer
			// and the one the Undo uses — and it names them on a CANCELLED job
			// too, for what it managed before it stopped (W3), which is why this
			// no longer waits for err == nil. No ids at all means a worker older
			// than this contract (JobResult.TrashIDs came after M2-A round 1),
			// and only then is the listing heuristic asked to guess.
			view.TrashIDs = res.TrashIDs
			if err == nil && len(view.TrashIDs) == 0 && res.Files+res.Dirs > 0 {
				view.TrashIDs = s.trashIDsFor(ctx, who, paths, started)
			}
		}
		// W3: the structured view goes back ALONGSIDE the error, so a cancelled
		// delete still publishes its partial counts, its retained warnings and
		// the trash ids an Undo needs.
		return view, s.jobErr("delete", id, err)
	})
	if err != nil {
		// R3-S2: the rejection names the id the intent line above already used.
		s.failJobSubmit(w, r, sess, m, id, err)
		return
	}
	s.writeJob(w, *job)
}

// jobIntentDetail composes a job's durable intent detail (W7): the correlation
// id, what the job will do, and the roots it will do it to. The paths are the
// REQUESTED spellings — the client's own vocabulary, never a resolved one — and
// the list is capped so a thousand-item selection does not write a thousand
// paths into one line. A root whose bytes are not valid UTF-8 is named in
// base64 rather than mangled into U+FFFD by the JSON encoder.
func jobIntentDetail(id, what string, paths []string) string {
	const maxNamed = 20
	named := paths
	extra := 0
	if len(named) > maxNamed {
		extra, named = len(named)-maxNamed, named[:maxNamed]
	}
	shown := make([]string, 0, len(named))
	for _, p := range named {
		if !utf8.ValidString(p) {
			p = "b64:" + base64.RawURLEncoding.EncodeToString([]byte(p))
		}
		shown = append(shown, p)
	}
	list := strings.Join(shown, ", ")
	if extra > 0 {
		list += fmt.Sprintf(", and %d more", extra)
	}
	return fmt.Sprintf("job %s: %s, %d root(s): %s", id, what, len(paths), list)
}

// ensureTrashRoots prepares <mount>/.@qfm_trash for every distinct trash root
// the selection touches. Creating a world-writable sticky directory inside
// somebody's share is a security-relevant act, so it is audited as a durable
// milestone naming the directory — disclosed, never hidden (decision 10).
//
// A location with no usable same-device trash answers 409 no_trash rather than
// silently promoting the delete to a copy or to a permanent unlink; the client
// re-asks at grade 2 with that reason (ui-ux §4.4). It is prepared for the
// RESOLVED roots — that is where the worker will rename to — but every answer
// names the REQUESTED spelling the caller supplied (W5), since a client is only
// ever shown paths it named itself.
func (s *Server) ensureTrashRoots(w http.ResponseWriter, r *http.Request, sess *session, roots jobRoots) bool {
	ensure := s.ensureTrash
	if ensure == nil {
		ensure = trashroot.Ensure
	}
	done := map[string]bool{}
	for i, p := range roots.resolved {
		// The path echoed back to the client and into the audit record.
		requested := p
		if i < len(roots.requested) {
			requested = roots.requested[i]
		}
		osPath, err := s.Root.OS(p)
		if err != nil {
			s.logRaw(r, "trash-root", requested, err)
			s.fail(w, r, "internal", "The Trash location for this item could not be determined.", requested, "")
			return false
		}
		if root, _, ok := s.platform.TrashRootFor(osPath); ok {
			if done[root] {
				continue
			}
			done[root] = true
		}
		dir, created, err := ensure(s.platform, osPath)
		switch {
		case errors.Is(err, trashroot.ErrNoTrash):
			s.logRaw(r, "trash-root", requested, err)
			writeError(w, http.StatusConflict, "no_trash", "There is no Trash on this volume, so deleting here is permanent.", requested, "delete", "")
			return false
		case err != nil:
			s.logRaw(r, "trash-root", requested, err)
			s.fail(w, r, "internal", "The Trash folder could not be prepared.", requested, "")
			return false
		}
		if !created {
			continue
		}
		// Durable, QuLog-mirrored, and it names the directory it made. If that
		// record cannot be persisted the delete is refused: the directory now
		// exists either way, but nothing destructive follows an unrecorded one.
		m := mutation{op: "trash-root", path: dir}
		if aerr := s.writeAudit(sess, r, m, "result", "ok", "", "created the trash directory "+dir, true); aerr != nil {
			writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", p, "delete", aerr.Error())
			return false
		}
	}
	return true
}

// trashIDsFor is the FALLBACK for naming what a finished trash delete produced,
// used only when the worker's JobResult carried no TrashIDs of its own — a
// worker older than the round-1 follow-up, since a job that trashed nothing has
// nothing to undo either way.
//
// The ids are then recovered from the caller's own trash listing: their own
// items, whose original path is one of the deleted roots, trashed no earlier
// than this job started. It is a guess, which is exactly why the worker's answer
// comes first: two deletes of the same path, or a clock a second out, are enough
// to make it name the wrong entry. Best effort — a listing failure simply leaves
// the Undo to the trash panel.
func (s *Server) trashIDsFor(ctx context.Context, who backend.Principal, paths []string, started time.Time) []string {
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	resp, err := s.jobRunner.TrashList(lookup, who)
	if err != nil {
		return nil
	}
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[p] = true
	}
	// A second of slack: the worker stamps deleted_at from its own clock.
	cutoff := started.Add(-time.Second).Unix()
	var ids []string
	for _, it := range resp.Items {
		if it.DeletedAt >= cutoff && want[string(it.OrigPath)] {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

// jobFinishHook builds the manager's completion hook: the ONE place a job's
// result line is written (W2).
//
// Auditing from inside the work function missed two terminal transitions
// entirely — a job cancelled while still queued, and one the manager closes at
// shutdown, neither of which ever calls the function — so a durable delete
// INTENT could stand forever with no result beside it. The manager now calls
// this exactly once per job, on every terminal transition, after the state is
// final; the identity is the snapshot taken at submit (jobActorOf), and the
// write is cancellation-immune, because by now the request is long gone.
func (s *Server) jobFinishHook(who jobActor, op, id, path, detail string, force bool) func(jobs.Job) {
	return func(j jobs.Job) { s.auditJobFinish(who, op, id, path, detail, force, j) }
}

func (s *Server) auditJobFinish(who jobActor, op, id, path, detail string, force bool, j jobs.Job) {
	// The worker's own summary is the authority on what happened; the manager's
	// live counters are the fallback for a job that never published one.
	files, bytes, warnings := j.Files, j.Bytes, j.WarningCount
	var skipped int64
	var view jobResultView
	if len(j.Result) > 0 && json.Unmarshal(j.Result, &view) == nil {
		files, bytes, skipped = view.Files, view.Bytes, view.Skipped
		if view.Warnings > warnings {
			warnings = view.Warnings
		}
	}
	// R3-S1: the outcome is classified from the RECONCILED counts, not from the
	// live frame counter alone — see jobFinishOutcome.
	result, code := jobFinishOutcome(j, warnings, skipped)
	full := fmt.Sprintf("%s: %d item(s), %d byte(s)", detail, files, bytes)
	if warnings > 0 {
		full += fmt.Sprintf(", %d warning(s)", warnings)
	}
	if skipped > 0 {
		// R3-S1: what the job did NOT do belongs in the line that claims what it
		// did, so a "partial" is legible without cross-referencing the job.
		full += fmt.Sprintf(", %d skipped", skipped)
	}
	switch result {
	case "cancelled":
		// Partial is the manager's own record of whether the work ever started:
		// a job cancelled in the queue changed nothing at all, and says so.
		if j.Partial {
			full += "; cancelled, partial work remains and was not rolled back"
		} else {
			full += "; cancelled before it started, nothing was changed"
		}
	case "denied", "error":
		full += "; " + code
	}
	s.jobAudit(context.Background(), who, audit.Event{
		Op: op, Job: id, Path: path, Phase: "result", Result: result, Code: code,
		Files: files, Bytes: bytes, Detail: full,
	}, jobMilestone(force, result, files, bytes))
}

// jobMilestone decides whether a finished job is mirrored to QuLog: a permanent
// delete (or an emptied trash) always, any job that touched a hundred items or
// a gigabyte — the same scale rule as guard.NeedsConfirm — and any DENIAL, which
// is the record that the daemon refused destructive work somebody had already
// confirmed (W1).
func jobMilestone(force bool, result string, files, bytes int64) bool {
	return force || result == "denied" || files >= milestoneFiles || bytes >= milestoneBytes
}

// jobFinishOutcome maps a terminal job to the audit vocabulary. A cancellation
// is its own result, not an error: the work stopped because somebody asked, and
// the counts it carries are what actually happened before it did. A failure the
// GUARD caused — read-only switched on, a path that became protected while the
// job waited in the queue (W1) — is a denial rather than an error, so the trail
// reads the same whether the refusal came before or after the 202.
//
// warnings and skipped are the RECONCILED totals the caller computed, not the
// job's live counters, and that is finding R3-S1: Job.WarningCount counts the
// warn FRAMES that arrived, and a frame can be dropped (a slow consumer, a
// truncated stream, a worker that summarises instead of streaming), whereas the
// terminal JobResult carries the worker's own authoritative totals. Classifying
// from the counter alone let a destructive job that skipped items be audited
// "ok" — the one word the durable record must never get wrong about a delete. An
// item the worker skipped is an item that is still there, so Skipped promotes to
// "partial" just as a warning does, even when nothing was warned about.
func jobFinishOutcome(j jobs.Job, warnings int, skipped int64) (result, code string) {
	switch j.State {
	case jobs.StateCancelled:
		return "cancelled", fsx.Code(context.Canceled)
	case jobs.StateFailed:
		code = j.ErrCode
		if code == "" {
			code = "internal"
		}
		switch code {
		case "read_only", "readonly", "protected", "confirm_required", "confirm_invalid":
			return "denied", code
		}
		return "error", code
	default:
		if warnings > 0 || skipped > 0 {
			// Some items failed or were skipped; the job as a whole did not.
			return "partial", ""
		}
		return "ok", ""
	}
}

// failJobSubmit answers a job the manager would not take. A full queue is the
// one the client can act on (wait and retry); everything else is the daemon's
// own failure.
//
// id is the job id the route already minted, and passing it is finding R3-S2.
// The id is chosen BEFORE the durable intent line (W7), so a refused submission
// leaves an intent naming "job <id>" with a result line that named no job at
// all: the durable trail held an unclosed destructive intent that nothing could
// be paired with. The rejection now carries the same "job <id>" detail form the
// completion hook writes, so intent and result pair on the id whatever happened
// to the submission.
func (s *Server) failJobSubmit(w http.ResponseWriter, r *http.Request, sess *session, m mutation, id string, err error) {
	code := fsx.Code(err)
	if errors.Is(err, jobs.ErrClosed) {
		code = "worker_gone"
	}
	s.logRaw(r, m.op, m.path, err)
	detail := ""
	if id != "" {
		detail = fmt.Sprintf("job %s: not started (%s)", id, code)
	}
	s.writeAudit(sess, r, m, "result", "error", code, detail, false)
	message := "The operation could not be started."
	if code == "queue_full" {
		message = "Too many operations are already queued. Wait for some to finish, then try again."
	}
	s.fail(w, r, code, message, m.path, "")
}

// writeJob answers a submitted job with 202 Accepted: the work has been
// accepted, not done, and the client polls /api/jobs for the rest.
//
// The snapshot Submit hands back has no result yet, so the hit-free view costs
// a scan of a few dozen bytes that finds nothing. It is written this way so the
// rule holds by construction rather than by timing: the single-job GET is the
// only route that serves hits, because it is the only one that pays for them.
func (s *Server) writeJob(w http.ResponseWriter, job jobs.Job) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"job": jobListView{Job: job}})
}

// jobSize measures trees for the properties dialog. It is a read, so there is
// no confirmation token and no read-only refusal; the guard's OpTraverse rules
// still apply, so the audit log and the install config are not measurable.
//
// Like the M1 read path (PLAN.md §2.5), the check is on the REQUESTED spelling
// only: no Resolve round-trip, and the worker re-resolves as the user anyway.
func (s *Server) jobSize(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.jobsReady(w, r) {
		return
	}
	var body struct {
		Paths       []pathRef `json:"paths"`
		CrossMounts bool      `json:"crossMounts"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	paths, ok := s.jobPaths(w, r, body.Paths)
	if !ok {
		return
	}
	for _, p := range paths {
		if err := s.guard.Check(guard.OpTraverse, p); err != nil {
			code := fsx.Code(err)
			s.logRaw(r, "size", p, err)
			s.fail(w, r, code, "This location cannot be measured.", p, "")
			return
		}
	}
	wire := make([][]byte, len(paths))
	for i, p := range paths {
		wire[i] = []byte(p)
	}
	reqBody, err := json.Marshal(wproto.SizeReq{Paths: wire, CrossMounts: body.CrossMounts})
	if err != nil {
		s.fail(w, r, "internal", "The size request could not be prepared.", "", err.Error())
		return
	}
	// bodyPath bounds every component at NAME_MAX, so this is bounded already;
	// clipping is for the row itself, and keeps the rule uniform with search's
	// title (round-7 sweep). A size job is the one job route that never resolves
	// its paths through the worker, so it never had the kernel's refusal to lean
	// on the way delete, copy, move, search and archive do.
	title := "Calculating size: " + clipUTF8(fsx.Base(paths[0]), maxJobTitleBytes)
	if len(paths) > 1 {
		title = fmt.Sprintf("Calculating size: %d items", len(paths))
	}
	who := sess.who
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The size request could not be prepared.", paths[0], err.Error())
		return
	}
	// A size job dispatches exactly what the client named, so the mapping is the
	// identity — but the sinks still run through it, so a warning about a path
	// under NO root is answered with a root rather than a worker spelling (W4).
	roots := identityRoots(paths)
	job, err := s.jobMgr.Submit(jobs.KindSize, title, jobs.Meta{ID: id, Src: paths, Actor: who.User, UID: who.UID}, func(ctx context.Context, p *jobs.Progress) (any, error) {
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobSize, Body: reqBody}, s.progressSink(roots, p), s.warnSink(roots, "size", id, p))
		// W3: a cancelled measurement still publishes what it counted.
		return viewOf(res), s.jobErr("size", id, err)
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, mutation{op: "size"}, id, err)
		return
	}
	s.writeJob(w, *job)
}

// maySeeJob decides visibility. A job belongs to the identity that submitted
// it; an administrator sees every job, because an administrator is the person
// who has to answer for what the daemon is doing. Anyone else gets not_found
// for somebody else's job — the same answer as for a job that never existed, so
// the route is not an oracle for other people's activity.
func maySeeJob(sess *session, j jobs.Job) bool {
	return sess.admin || (j.Actor == sess.who.User && j.UID == sess.who.UID)
}

func (s *Server) jobList(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.jobsReady(w, r) {
		return
	}
	all := s.jobMgr.List() // newest first
	out := make([]jobListView, 0, len(all))
	for _, j := range all {
		if maySeeJob(sess, j) {
			out = append(out, jobListView{Job: j})
		}
	}
	writeJSON(w, map[string]any{"jobs": out})
}

func (s *Server) jobGet(w http.ResponseWriter, r *http.Request, sess *session, id string) {
	if !s.jobsReady(w, r) {
		return
	}
	// Belt to the middleware's braces (bodiedRead in server.go): a read with a
	// body must not block this handler at its first write while it holds a
	// bulk-result slot.
	if r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
	j, ok := s.jobMgr.Get(id)
	if !ok || !maySeeJob(sess, j) {
		s.fail(w, r, "not_found", "No such job.", "", "")
		return
	}
	// A search's hits live in the retention ledger, not in the manager, so that
	// a poll of the whole list never touches them (routes_search.go). This is the
	// one request that asks about a single job, so it is the one that pays — and
	// paying is bounded: a large result is admitted a few at a time and written
	// under a deadline, or the buffers it needs are held by however many
	// requests a client cares to open and never read (round-11 P1).
	// Built FIRST, then admitted on what it actually weighs. Admitting on what
	// the ledger holds instead left a hole: a GET landing after a search went
	// terminal but before the finish hook recorded it found an empty ledger,
	// skipped the slot and the deadline, and then served the hits out of the
	// manager's own copy anyway (round-12 P1).
	result, live := s.searchResultOf(j)
	if !live {
		s.fail(w, r, "not_found", "This job is no longer available.", "", "")
		return
	}
	j.Result = result
	done, ok := s.admitBulkResult(w, r, sess, len(j.Result))
	if !ok {
		return
	}
	defer done()
	writeJSON(w, map[string]any{"job": j})
}

// jobCancel stops a job. Cancelling is a safety action, so it is not refused in
// read-only mode; it is still a POST, so CSRF and the Origin check apply.
//
// Two things stop the work: the manager cancels the job's context, which the
// pool turns into a cancel on the worker and then keeps draining for the
// worker's own partial result; and, for the caller's OWN job, a separate
// immediate CancelJob RPC makes that prompt. An administrator cancelling
// somebody else's job does not send that second RPC — it would go to the
// admin's root worker, not the owner's — and relies on the context alone.
func (s *Server) jobCancel(w http.ResponseWriter, r *http.Request, sess *session, id string) {
	if !s.jobsReady(w, r) {
		return
	}
	j, ok := s.jobMgr.Get(id)
	if !ok || !maySeeJob(sess, j) {
		s.fail(w, r, "not_found", "No such job.", "", "")
		return
	}
	cancelled := s.jobMgr.Cancel(id)
	if j.Actor == sess.who.User && j.UID == sess.who.UID {
		if err := s.jobRunner.CancelJob(r.Context(), sess.who, id); err != nil {
			s.logger.Printf("job cancel: %s could not be cancelled on the worker: %v", id, err)
		}
	}
	s.writeAudit(sess, r, mutation{op: "cancel"}, "result", "ok", "", "cancel requested for job "+id, false)
	after, _ := s.jobMgr.Get(id)
	// The cancel reply never carries hits. GET /api/jobs/<id> is the ONE route
	// that serves a search's hits, and it pays for them: it is admitted a few at
	// a time and written under a deadline (admitBulkResult). Cancel has neither,
	// and it serialises whatever the manager holds — so a cancel arriving after
	// a search went terminal but before the finish hook moved the hits into the
	// retention ledger shipped the whole result, unbounded and unadmitted (879
	// KiB in the reproduction). The list view is the same hit-free spelling the
	// polling route uses, and for the same reason.
	writeJSON(w, map[string]any{"ok": cancelled, "job": jobListView{Job: after}})
}
