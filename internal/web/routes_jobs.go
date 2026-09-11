package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

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
// characters jobs.newID mints, which is what keeps "/api/jobs/delete" a literal
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

func validJobID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

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
	Files    int64    `json:"files"`
	Dirs     int64    `json:"dirs,omitempty"`
	Bytes    int64    `json:"bytes"`
	Skipped  int64    `json:"skipped,omitempty"`
	Warnings int      `json:"warnings,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	TrashIDs []string `json:"trashIds,omitempty"`
}

func viewOf(res wproto.JobResult) jobResultView {
	// TrashIDs is deliberately NOT copied here. It is filled only where a job is
	// known to have been a delete-to-trash (jobDelete), so that a result carrying
	// ids can never be published for an operation whose items are gone for good.
	return jobResultView{Files: res.Files, Dirs: res.Dirs, Bytes: res.Bytes, Skipped: res.Skipped, Warnings: res.Warnings, Detail: res.Detail}
}

// progressSink and warnSink adapt the worker's in-band frames to the manager's
// progress handle. They are called on the RPC goroutine, in order.
func progressSink(p *jobs.Progress) func(wproto.Prog) {
	return func(pr wproto.Prog) {
		p.Set(pr.Files, pr.FilesTotal, pr.Bytes, pr.BytesTotal)
		if len(pr.Current) > 0 {
			p.Current(string(pr.Current))
		}
		if pr.Phase != "" {
			p.Phase(pr.Phase)
		}
	}
}

func warnSink(p *jobs.Progress) func(wproto.Warn) {
	return func(wn wproto.Warn) { p.Warn(string(wn.Path), wn.Code, wn.Message) }
}

// waitJobID hands the manager's job id to the work function. Submit starts the
// goroutine before it returns the Job, so the id cannot simply be captured;
// the function blocks on this channel until the caller publishes it (or the
// job is cancelled while still queued).
func waitJobID(ctx context.Context, ch <-chan string) (string, bool) {
	select {
	case id, ok := <-ch:
		return id, ok
	case <-ctx.Done():
		return "", false
	}
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
	m := mutation{op: "delete", files: int64(len(paths)), bytes: totalBytes}
	// extraConfirm is always on: every delete, trash or permanent, is redeemed
	// against a single-use token (decision 10).
	if !s.authorize(w, r, sess, worstGuard(checks...), true, m, "", deleteJobTokenParts(mode, body.CrossMounts, paths), true, body.Confirm, summary) {
		return
	}
	// The trash directory has to exist before the user's worker — which has only
	// their own permissions — can rename anything into it, so the root front-end
	// makes it: the one sanctioned front-end filesystem write (decision 10,
	// trashroot's package comment). No trash here is not an error, it is the
	// fact that this delete would be permanent, and the client re-asks at grade 2.
	if !permanent && !s.ensureTrashRoots(w, r, sess, resolved) {
		return
	}

	detail := mode
	if body.CrossMounts {
		detail += ", including mounted sub-folders"
	}
	detail += fmt.Sprintf(", %d root(s)", len(paths))
	big := permanent || int64(len(paths)) >= milestoneFiles || totalBytes >= milestoneBytes
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, big); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", m.op, err.Error())
		return
	}

	// Dispatch the RESOLVED spellings, binding the work as tightly as possible to
	// what was guarded (PLAN.md §2.0 residual race).
	wire := make([][]byte, len(resolved))
	for i, p := range resolved {
		wire[i] = []byte(p)
	}
	reqBody, err := json.Marshal(wproto.DeleteReq{Paths: wire, Recursive: true, Trash: !permanent, CrossMounts: body.CrossMounts})
	if err != nil {
		s.fail(w, r, "internal", "The delete could not be prepared.", "", err.Error())
		return
	}
	who, actor := sess.who, jobActorOf(sess, r)
	started := time.Now()
	idCh := make(chan string, 1)
	job, err := s.jobMgr.Submit(jobs.KindDelete, deleteTitle(mode, paths), jobs.Meta{Src: paths, Actor: who.User, UID: who.UID}, func(ctx context.Context, p *jobs.Progress) (any, error) {
		id, ok := waitJobID(ctx, idCh)
		if !ok {
			return nil, ctx.Err()
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobDelete, Body: reqBody}, progressSink(p), warnSink(p))
		view := viewOf(res)
		if err == nil && !permanent {
			// The worker names the entries it created, which is the exact answer
			// and the one the Undo uses. No ids at all means a worker older than
			// this contract (JobResult.TrashIDs came after M2-A round 1), and
			// only then is the listing heuristic asked to guess.
			view.TrashIDs = res.TrashIDs
			if len(view.TrashIDs) == 0 && res.Files+res.Dirs > 0 {
				view.TrashIDs = s.trashIDsFor(ctx, who, paths, started)
			}
		}
		s.auditJobResult(ctx, actor, "delete", id, res, err, big, detail)
		if err != nil {
			return nil, err
		}
		return view, nil
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, m, err)
		return
	}
	idCh <- job.ID
	s.writeJob(w, *job)
}

// ensureTrashRoots prepares <mount>/.@qfm_trash for every distinct trash root
// the selection touches. Creating a world-writable sticky directory inside
// somebody's share is a security-relevant act, so it is audited as a durable
// milestone naming the directory — disclosed, never hidden (decision 10).
//
// A location with no usable same-device trash answers 409 no_trash rather than
// silently promoting the delete to a copy or to a permanent unlink; the client
// re-asks at grade 2 with that reason (ui-ux §4.4).
func (s *Server) ensureTrashRoots(w http.ResponseWriter, r *http.Request, sess *session, paths []string) bool {
	ensure := s.ensureTrash
	if ensure == nil {
		ensure = trashroot.Ensure
	}
	done := map[string]bool{}
	for _, p := range paths {
		osPath, err := s.Root.OS(p)
		if err != nil {
			s.logRaw(r, "trash-root", p, err)
			s.fail(w, r, "internal", "The Trash location for this item could not be determined.", p, "")
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
			s.logRaw(r, "trash-root", p, err)
			writeError(w, http.StatusConflict, "no_trash", "There is no Trash on this volume, so deleting here is permanent.", p, "delete", "")
			return false
		case err != nil:
			s.logRaw(r, "trash-root", p, err)
			s.fail(w, r, "internal", "The Trash folder could not be prepared.", p, "")
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

// auditJobResult records what a job actually did. It runs on the job goroutine,
// after the HTTP request is long gone, which is exactly why jobAudit makes the
// durable write cancellation-immune.
//
// A cancelled job records result "cancelled" with the partial counts the worker
// reported before it stopped — nothing is rolled back (design §3), so the
// record says what remains rather than pretending the work was undone.
func (s *Server) auditJobResult(ctx context.Context, who jobActor, op, id string, res wproto.JobResult, err error, force bool, detail string) {
	result, code := jobOutcome(res, err)
	full := fmt.Sprintf("%s: %d item(s), %d byte(s)", detail, res.Files, res.Bytes)
	if res.Warnings > 0 {
		full += fmt.Sprintf(", %d warning(s)", res.Warnings)
	}
	switch result {
	case "cancelled":
		full += "; cancelled, partial work remains and was not rolled back"
	case "error":
		full += "; " + code
	}
	s.jobAudit(ctx, who, audit.Event{
		Op: op, Job: id, Phase: "result", Result: result, Code: code,
		Files: res.Files, Bytes: res.Bytes, Detail: full,
	}, jobMilestone(force, res))
}

// jobOutcome maps a finished job to the audit vocabulary. A cancellation is its
// own result, not an error: the work stopped because somebody asked, and the
// counts it carries are what actually happened before it did.
func jobOutcome(res wproto.JobResult, err error) (result, code string) {
	switch {
	case err == nil:
		if res.Warnings > 0 {
			// Some items failed and were skipped; the job as a whole did not.
			return "partial", ""
		}
		return "ok", ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled", fsx.Code(context.Canceled)
	default:
		return "error", fsx.Code(err)
	}
}

// jobMilestone decides whether a finished job is mirrored to QuLog: a permanent
// delete (or an emptied trash) always, and any job that touched a hundred items
// or a gigabyte — the same scale rule as guard.NeedsConfirm.
func jobMilestone(force bool, res wproto.JobResult) bool {
	return force || res.Files >= milestoneFiles || res.Bytes >= milestoneBytes
}

// failJobSubmit answers a job the manager would not take. A full queue is the
// one the client can act on (wait and retry); everything else is the daemon's
// own failure.
func (s *Server) failJobSubmit(w http.ResponseWriter, r *http.Request, sess *session, m mutation, err error) {
	code := fsx.Code(err)
	if errors.Is(err, jobs.ErrClosed) {
		code = "worker_gone"
	}
	s.logRaw(r, m.op, m.path, err)
	s.writeAudit(sess, r, m, "result", "error", code, "", false)
	message := "The operation could not be started."
	if code == "queue_full" {
		message = "Too many operations are already queued. Wait for some to finish, then try again."
	}
	s.fail(w, r, code, message, m.path, "")
}

// writeJob answers a submitted job with 202 Accepted: the work has been
// accepted, not done, and the client polls /api/jobs for the rest.
func (s *Server) writeJob(w http.ResponseWriter, job jobs.Job) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"job": job})
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
	title := "Calculating size: " + fsx.Base(paths[0])
	if len(paths) > 1 {
		title = fmt.Sprintf("Calculating size: %d items", len(paths))
	}
	who := sess.who
	idCh := make(chan string, 1)
	job, err := s.jobMgr.Submit(jobs.KindSize, title, jobs.Meta{Src: paths, Actor: who.User, UID: who.UID}, func(ctx context.Context, p *jobs.Progress) (any, error) {
		id, ok := waitJobID(ctx, idCh)
		if !ok {
			return nil, ctx.Err()
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobSize, Body: reqBody}, progressSink(p), warnSink(p))
		if err != nil {
			return nil, err
		}
		return viewOf(res), nil
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, mutation{op: "size"}, err)
		return
	}
	idCh <- job.ID
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
	out := make([]jobs.Job, 0, len(all))
	for _, j := range all {
		if maySeeJob(sess, j) {
			out = append(out, j)
		}
	}
	writeJSON(w, map[string]any{"jobs": out})
}

func (s *Server) jobGet(w http.ResponseWriter, r *http.Request, sess *session, id string) {
	if !s.jobsReady(w, r) {
		return
	}
	j, ok := s.jobMgr.Get(id)
	if !ok || !maySeeJob(sess, j) {
		s.fail(w, r, "not_found", "No such job.", "", "")
		return
	}
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
	writeJSON(w, map[string]any{"ok": cancelled, "job": after})
}
