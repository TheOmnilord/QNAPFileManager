package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/wproto"
)

// The trash panel: list what this user has deleted, restore some of it, or
// empty it. Listing is a plain worker read (not a job), so the panel opens
// without a job round-trip; restore and empty are jobs, because either can be
// thousands of items.
//
// Everything here is scoped to the caller's own per-uid subdirectory inside
// <mount>/.@qfm_trash, which the sticky bit enforces in the kernel (INV-2):
// this layer never has to decide whose file is whose.

// maxTrashIDs bounds one restore. Ids are tiny, but the request is validated and
// cross-checked against a listing before dispatch, so the list is bounded.
const maxTrashIDs = 1000

// trashItem is one listed item. The byte-safe companions follow the fsx.Entry
// convention: they are present only when the raw bytes are not valid UTF-8, and
// a client prefers the companion WHENEVER it is present (the same rule
// deleteBlockers documents — Name still carries the raw bytes, which JSON has
// already flattened by the time a browser sees it).
type trashItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	NameB64     string `json:"nameB64,omitempty"`
	OrigPath    string `json:"origPath"`
	OrigPathB64 string `json:"origPathB64,omitempty"`
	Type        string `json:"type"`
	Size        int64  `json:"size"`
	// DeletedAt is unix seconds, as the worker's sidecar records it.
	DeletedAt int64  `json:"deletedAt"`
	Trash     string `json:"trash"`
}

// byteText splits raw filesystem bytes into the display string and its base64
// companion, which is empty for valid UTF-8.
func byteText(raw []byte) (string, string) {
	if utf8.Valid(raw) {
		return string(raw), ""
	}
	return string(raw), base64.RawURLEncoding.EncodeToString(raw)
}

// validTrashID accepts the worker's "<unix>-<8hex>" entry-directory names and
// nothing that could be a path. The worker validates too; this keeps a
// hand-made request from reaching it at all.
func validTrashID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// trashDisabled answers the three trash routes when the NAS-wide Trash switch
// is off (config.Trash.Enabled, PLAN.md decision 10 / finding W6). With the
// switch off no .@qfm_trash directory may be created and none is expected to
// exist, so listing, restoring and emptying have nothing to act on: they say so
// plainly rather than returning an empty panel or a worker error.
func (s *Server) trashDisabled(w http.ResponseWriter, r *http.Request, op string) bool {
	if s.cfg.Trash.Enabled {
		return false
	}
	s.logger.Printf("request ip=%q method=%s op=%q code=%s", ClientIP(r), r.Method, r.URL.Path, "no_trash")
	writeError(w, http.StatusConflict, "no_trash", "Trash is disabled on this NAS, so deleting is permanent and there is nothing in Trash.", "", op, "")
	return true
}

func (s *Server) trashList(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.jobsReady(w, r) {
		return
	}
	if s.trashDisabled(w, r, "trash-list") {
		return
	}
	resp, err := s.jobRunner.TrashList(r.Context(), sess.who)
	if err != nil {
		s.logRaw(r, "trash-list", "", err)
		code := fsx.Code(err)
		s.fail(w, r, code, backendMessage(code), "", "")
		return
	}
	items := make([]trashItem, 0, len(resp.Items))
	for _, it := range resp.Items {
		item := trashItem{ID: it.ID, Type: it.Type, Size: it.Size, DeletedAt: it.DeletedAt}
		item.Name, item.NameB64 = byteText(it.Name)
		item.OrigPath, item.OrigPathB64 = byteText(it.OrigPath)
		item.Trash, _ = byteText(it.Trash)
		items = append(items, item)
	}
	// The location is disclosed rather than hidden: the front-end created these
	// world-writable sticky directories (decision 10) and says where they are.
	writeJSON(w, map[string]any{"items": items, "dirName": trashroot.DirName})
}

// trashRestore moves items back to where they came from. Restoring recreates
// nothing: a missing parent reports not_found and a collision reports exists
// (M2-A decision), both per item, as job warnings.
//
// The original paths are looked up from the caller's own listing and put
// through the guard (OpCreate) before dispatch, so an item that was trashed
// from a location the rules now protect cannot be written back into it.
func (s *Server) trashRestore(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	if s.trashDisabled(w, r, "trash-restore") {
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > maxTrashIDs {
		s.fail(w, r, "bad_request", fmt.Sprintf("Supply between 1 and %d items to restore.", maxTrashIDs), "", "")
		return
	}
	for _, id := range body.IDs {
		if !validTrashID(id) {
			s.fail(w, r, "bad_request", "One of the item identifiers was invalid.", "", "")
			return
		}
	}
	m := mutation{op: "trash-restore", files: int64(len(body.IDs))}
	if s.guard.ReadOnly() {
		s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", "", m.op, "")
		return
	}
	resp, err := s.jobRunner.TrashList(r.Context(), sess.who)
	if err != nil {
		s.logRaw(r, m.op, "", err)
		code := fsx.Code(err)
		s.fail(w, r, code, backendMessage(code), "", "")
		return
	}
	known := make(map[string]wproto.TrashItem, len(resp.Items))
	for _, it := range resp.Items {
		known[it.ID] = it
	}
	// The destinations, kept so the guard can be re-run when the job actually
	// starts (W1) and so a worker warning can be mapped back to a path the
	// caller already knows (W4). They are the worker's own listing of the
	// caller's own items, so the requested and dispatched spellings are one.
	dsts := make([]string, 0, len(body.IDs))
	parents := make([]string, 0, len(body.IDs))
	for _, id := range body.IDs {
		it, ok := known[id]
		if !ok {
			s.fail(w, r, "not_found", "One of those items is no longer in the Trash.", "", "")
			return
		}
		dst := string(it.OrigPath)
		if err := worstGuard(s.guard.Check(guard.OpCreate, fsx.Parent(dst)), s.guard.Check(guard.OpCreate, dst)); err != nil {
			s.logRaw(r, m.op, dst, err)
			s.writeAudit(sess, r, mutation{op: m.op, dst: dst}, "result", "denied", "protected", "protected destination", false)
			writeError(w, http.StatusForbidden, "protected", "That item came from a protected location and cannot be restored here.", dst, m.op, "")
			return
		}
		dsts = append(dsts, dst)
		parents = append(parents, fsx.Parent(dst))
	}
	// The correlation id is chosen before the intent line so the two phases of
	// one restore can be paired in the durable record (W7); the intent names the
	// destinations, which is what a restore actually changes.
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The restore could not be prepared.", "", err.Error())
		return
	}
	m.path = dsts[0]
	if err := s.writeAudit(sess, r, m, "intent", "", "", jobIntentDetail(id, fmt.Sprintf("restore of %d item(s)", len(body.IDs)), dsts), false); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", m.op, err.Error())
		return
	}
	reqBody, err := json.Marshal(wproto.TrashRestoreReq{IDs: body.IDs})
	if err != nil {
		s.fail(w, r, "internal", "The restore could not be prepared.", "", err.Error())
		return
	}
	s.submitTrashJob(w, r, sess, trashJob{
		id:        id,
		kind:      jobs.KindTrashRestore,
		wireKind:  wproto.JobTrashRestore,
		title:     fmt.Sprintf("Restoring %d item(s) from Trash", len(body.IDs)),
		body:      reqBody,
		roots:     identityRoots(dsts),
		checks:    []guardCheck{{op: guard.OpCreate, paths: dsts}, {op: guard.OpCreate, paths: parents}},
		detail:    fmt.Sprintf("job %s: restore of %d item(s)", id, len(body.IDs)),
		milestone: false,
	}, m)
}

// trashEmpty permanently deletes everything in the caller's own trash. It is
// the canonical grade-2 action (ui-ux §4.2 L2): nothing about it is reversible,
// so it always demands a redeemed token whose summary carries permanentWarning,
// and it is always a milestone in the audit log.
func (s *Server) trashEmpty(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	if s.trashDisabled(w, r, "trash-empty") {
		return
	}
	var body struct {
		Confirm string `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	m := mutation{op: "trash-empty"}
	if s.guard.ReadOnly() {
		s.writeAudit(sess, r, m, "result", "denied", "read_only", "read-only mode", false)
		writeError(w, http.StatusForbidden, "read_only", "Read-only mode is on. Turn it off in Settings to make changes.", "", m.op, "")
		return
	}
	// Count what is about to go, so the dialog states a fact rather than a guess.
	// A listing failure is not fatal: the summary simply has no totals.
	summary := guard.Summary{Warnings: []string{permanentWarning}}
	if resp, err := s.jobRunner.TrashList(r.Context(), sess.who); err == nil {
		summary.Files = int64(len(resp.Items))
		for _, it := range resp.Items {
			summary.Bytes += it.Size
		}
	}
	m.files, m.bytes = summary.Files, summary.Bytes
	// No path rule governs the trash root, so the guard verdict is nil and
	// extraConfirm alone drives the token flow.
	if !s.authorize(w, r, sess, nil, true, m, "", []string{"job=trash-empty", "uid=" + fmt.Sprint(sess.who.UID)}, true, body.Confirm, summary) {
		return
	}
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The request could not be prepared.", "", err.Error())
		return
	}
	detail := fmt.Sprintf("job %s: permanent, %d item(s), %d byte(s)", id, summary.Files, summary.Bytes)
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, true); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", "", m.op, err.Error())
		return
	}
	reqBody, err := json.Marshal(wproto.TrashEmptyReq{})
	if err != nil {
		s.fail(w, r, "internal", "The request could not be prepared.", "", err.Error())
		return
	}
	// Emptying the trash has no path roots at all: there is nothing to map a
	// worker path onto, so a per-item warning publishes its code and nothing
	// else (jobRoots.mapPath). The start-of-job re-check is therefore only the
	// read-only one, which recheckGuard makes first (W1).
	s.submitTrashJob(w, r, sess, trashJob{
		id:        id,
		kind:      jobs.KindTrashEmpty,
		wireKind:  wproto.JobTrashEmpty,
		title:     "Emptying Trash",
		body:      reqBody,
		detail:    detail,
		milestone: true,
	}, m)
}

// trashJob is one submitted trash job: what to run, what to re-check when it
// starts, and how to describe it in the durable record.
type trashJob struct {
	id        string // the correlation id, chosen before the intent line (W7)
	kind      jobs.Kind
	wireKind  string
	title     string
	body      []byte
	roots     jobRoots     // for mapping worker paths back (W4); may be empty
	checks    []guardCheck // re-run when the job actually starts (W1)
	detail    string
	milestone bool
}

// submitTrashJob is the shared tail of restore and empty: one job whose result
// line is written by the manager's completion hook, so a job cancelled before
// it ever ran is recorded too (W2).
func (s *Server) submitTrashJob(w http.ResponseWriter, r *http.Request, sess *session, tj trashJob, m mutation) {
	who, actor := sess.who, jobActorOf(sess, r)
	meta := jobs.Meta{
		ID: tj.id, Actor: who.User, UID: who.UID,
		OnFinish: s.jobFinishHook(actor, m.op, tj.id, m.path, tj.detail, tj.milestone),
	}
	job, err := s.jobMgr.Submit(tj.kind, tj.title, meta, func(ctx context.Context, p *jobs.Progress) (any, error) {
		// W1: read-only may have been turned on while this sat in the queue.
		if derr := s.recheckGuard(tj.checks...); derr != nil {
			return nil, derr
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: tj.id, Kind: tj.wireKind, Body: tj.body}, s.progressSink(tj.roots, p), s.warnSink(tj.roots, m.op, tj.id, p))
		// W3: the partial view travels with the error, not instead of it.
		return viewOf(res), s.jobErr(m.op, tj.id, err)
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, m, err)
		return
	}
	s.writeJob(w, *job)
}
