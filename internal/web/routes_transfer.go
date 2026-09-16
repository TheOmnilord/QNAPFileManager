package web

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

// The route's own notice sentences. They are a contract with the client, like
// permanentWarning: the wire carries no flag telling a guard reason from a
// route notice, so transfer.js grades its dialog by recognising exactly these
// strings (TRANSFER_NOTICES / CROSS_DEVICE_MARK) — anything else in the summary
// is a guard reason and promotes the dialog to a typed phrase. A reworded
// sentence here would silently demand the typed folder name for every
// overwrite; TestTransferNoticesArePinnedToTheClient keeps both halves equal.
const (
	noticeSizeMinimum  = "The size could not be fully measured; the totals shown are a minimum."
	noticeSizeOverflow = "The sizes exceed what can be counted; the totals shown are a minimum."
	noticeCrossUnknown = "We could not tell whether this move crosses volumes; it may need to copy and then delete the source."
	noticeOverwrite    = "Existing files may be overwritten by this operation."
	// crossDeviceMark is the invariant middle of the EXDEV prediction, whose
	// whole sentence names the two folders and the size.
	crossDeviceMark = "are on different volumes, so this move copies"
)

// transferJobTokenParts binds the direction and policy as ordered fields, with
// only the selection sorted so reordering roots does not change the token.
func transferJobTokenParts(mode, conflict string, cross bool, dest string, roots []string) []string {
	parts := []string{"job=" + mode, "conflict=" + conflict, "cross=" + strconv.FormatBool(cross), "dest=" + dest}
	sorted := append([]string(nil), roots...)
	sort.Strings(sorted)
	return append(parts, sorted...)
}

func transferTitle(mode string, paths []string, dest string) string {
	verb := "Copying"
	if mode == "move" {
		verb = "Moving"
	}
	if len(paths) == 1 {
		return verb + ": " + fsx.Base(paths[0])
	}
	return fmt.Sprintf("%s %d items to %s", verb, len(paths), fsx.Base(dest))
}

// transferSize measures a root through the user's worker, never the root
// front-end. The shared request deadline bounds the whole pre-flight scan.
//
// maxEntries is the walk's own entry budget, or 0 for the size job's default.
// A transfer pre-flight passes 0 — it is already bounded by its 30 s context and
// it wants the real totals for the dialog; M3's permissions pre-scan passes the
// contract's bound and reads Capped as "unknown".
func (s *Server) transferSize(ctx context.Context, who backend.Principal, root string, cross bool, maxEntries int64) (wproto.JobResult, error) {
	id, err := jobs.NewID()
	if err != nil {
		return wproto.JobResult{}, err
	}
	body, err := json.Marshal(wproto.SizeReq{Paths: [][]byte{[]byte(root)}, CrossMounts: cross, MaxEntries: maxEntries})
	if err != nil {
		return wproto.JobResult{}, err
	}
	return s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobSize, Body: body}, nil, nil)
}

func transferBytes(n int64) string {
	if n < 0 {
		return "an unknown amount of data"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v, unit := float64(n), 0
	for v >= 1024 && unit < len(units)-1 {
		v /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", v, units[unit])
}

// jobTransfer shares the copy/move pre-flight and submission spine. The worker
// decides whether a move can rename; filesystem identity is only a prediction.
func (s *Server) jobTransfer(w http.ResponseWriter, r *http.Request, sess *session, mode string) {
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	var body struct {
		Paths       []pathRef `json:"paths"`
		Dest        pathRef   `json:"dest"`
		Conflict    string    `json:"conflict"`
		CrossMounts bool      `json:"crossMounts"`
		Confirm     string    `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	if body.Conflict == "" {
		body.Conflict = wproto.ConflictSkip
	}
	switch body.Conflict {
	case wproto.ConflictSkip, wproto.ConflictOverwrite, wproto.ConflictRename:
	default:
		writeError(w, http.StatusUnprocessableEntity, "bad_request", "Supply conflict as skip, overwrite or rename.", "", mode, "")
		return
	}
	paths, ok := s.jobPaths(w, r, body.Paths)
	if !ok {
		return
	}
	dest, err := bodyPath(body.Dest.Path, body.Dest.PathB64)
	if err != nil {
		s.fail(w, r, "bad_request", "The destination path was invalid.", "", "")
		return
	}
	who := sess.who
	resolved := make([]string, len(paths))
	for i, p := range paths {
		resolved[i], err = s.resolveForGuard(r.Context(), who, p, false)
		if err != nil {
			s.failResolve(w, r, p, err)
			return
		}
	}
	rdest, err := s.resolveForGuard(r.Context(), who, dest, true)
	if err != nil {
		s.failResolve(w, r, dest, err)
		return
	}
	for i, p := range paths {
		if underRoot(dest, p) || underRoot(rdest, resolved[i]) {
			writeError(w, http.StatusConflict, "invalid_target", "The destination is inside a source folder or is the source itself.", dest, mode, "")
			return
		}
		if mode == "move" && body.Conflict != wproto.ConflictRename && (dest == fsx.Parent(p) || rdest == fsx.Parent(resolved[i])) {
			writeError(w, http.StatusConflict, "exists", "This item is already in the destination folder.", dest, mode, "")
			return
		}
	}
	var checks []guardCheck
	var verdicts []error
	summary := guard.Summary{}
	seen := map[string]bool{}
	warn := func(reason string) {
		if reason != "" && !seen[reason] {
			seen[reason] = true
			summary.Warnings = append(summary.Warnings, reason)
		}
	}
	check := func(op guard.Op, ps ...string) {
		checks = append(checks, guardCheck{op: op, paths: ps})
		for _, p := range ps {
			verdicts = append(verdicts, s.guard.Check(op, p))
			for _, reason := range s.guard.Reasons(op, p) {
				warn(reason)
			}
		}
	}
	check(guard.OpCreate, dest, rdest)
	// INV-1 keeps the guard in the front-end: the worker cannot consult it,
	// and a recursive scan here would touch user data as root. Containment is
	// instead static over the prefix table, including absent protected paths,
	// on BOTH spellings. A protected path created after this check through a
	// changed resolution remains the engine's ProtectWrite residual. The table
	// is immutable after startup, so queued jobs only need the existing checks
	// for mutable guard state (notably read-only mode).
	contains := func(ps ...string) {
		for _, p := range ps {
			if hit, ok := s.guard.Contains(p); ok {
				verdict := guard.ErrConfirmRequired
				if hit.Deny {
					verdict = guard.ErrProtected
				}
				verdicts = append(verdicts, verdict)
				warn(hit.Reason)
			}
		}
	}
	for i, p := range paths {
		check(guard.OpRead, p, resolved[i])
		check(guard.OpTraverse, p, resolved[i])
		if mode == "move" {
			check(guard.OpRename, p, resolved[i])
			check(guard.OpDelete, p, resolved[i])
		}
		dst, rdst := fsx.Join(dest, fsx.Base(p)), fsx.Join(rdest, fsx.Base(resolved[i]))
		check(guard.OpCreate, dst, rdst)
		if body.Conflict == wproto.ConflictOverwrite {
			check(guard.OpDelete, dst, rdst)
		}
		contains(p, resolved[i], dst, rdst)
	}
	verdict := worstGuard(verdicts...)
	m := mutation{op: mode, path: paths[0], dst: dest}
	parts := transferJobTokenParts(mode, body.Conflict, body.CrossMounts, rdest, resolved)
	if guardRefuses(verdict) {
		s.authorize(w, r, sess, verdict, false, m, "", parts, true, body.Confirm, summary)
		return
	}
	// A failed or bounded scan states that the displayed totals are a minimum.
	// Saturating addition keeps an enormous selection from wrapping the ladder.
	add := func(total *int64, n int64) {
		if n < 0 {
			warn(noticeSizeMinimum)
			return
		}
		if *total > math.MaxInt64-n {
			*total = math.MaxInt64
			warn(noticeSizeOverflow)
		} else {
			*total += n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	crossDevice := false
	var destID wproto.FSIdentityResp
	var destErr error
	if mode == "move" {
		destID, destErr = s.jobRunner.FSIdentity(ctx, who, rdest)
	}
	for i, root := range resolved {
		size, sizeErr := s.transferSize(ctx, who, root, body.CrossMounts, 0)
		// Files counts every entry the job will create — directories included,
		// since a hundred empty folders are as much "one big operation" for the
		// ladder and the audit milestone as a hundred files. Size reports them
		// apart in Dirs, so a directory-only tree would otherwise count as zero
		// items and slip under the >100-item confirmation (round-6 review).
		add(&summary.Files, size.Files)
		add(&summary.Files, size.Dirs)
		add(&summary.Bytes, size.Bytes)
		if sizeErr != nil || size.Cancelled || size.Warnings > 0 || size.Skipped > 0 {
			warn(noticeSizeMinimum)
		}
		if mode == "move" {
			srcID, srcErr := s.jobRunner.FSIdentity(ctx, who, root)
			if srcErr != nil || destErr != nil {
				warn(noticeCrossUnknown)
			} else if !srcID.Same(destID) {
				crossDevice = true
				n := size.Bytes
				if sizeErr != nil || size.Cancelled || size.Warnings > 0 || size.Skipped > 0 {
					n = -1
				}
				summary.Warnings = append(summary.Warnings, fmt.Sprintf("%s and %s "+crossDeviceMark+" %s and then deletes the source instead of an instant rename; it can be cancelled, and a cancelled move leaves both copies.", fsx.Base(paths[i]), fsx.Base(dest), transferBytes(n)))
			}
		}
	}
	if body.Conflict == wproto.ConflictOverwrite {
		warn(noticeOverwrite)
	}
	m.files, m.bytes = summary.Files, summary.Bytes
	// NeedsConfirm takes int; clamp the count before conversion on 32-bit hosts.
	count := int(min(summary.Files, int64(milestoneFiles+1)))
	extra := guard.NeedsConfirm(guard.OpCreate, dest, count, summary.Bytes) || body.Conflict == wproto.ConflictOverwrite || len(summary.Warnings) > 0 || crossDevice
	// A supplied token must still match if a fresh measurement is now smaller.
	extra = extra || body.Confirm != ""
	if !s.authorize(w, r, sess, verdict, extra, m, "", parts, true, body.Confirm, summary) {
		return
	}
	opts := wproto.CopyOptions{Conflict: body.Conflict, PreserveTimes: true, CrossMounts: body.CrossMounts}
	// Same rule as mkdir and upload: a break-glass session has no real user, so
	// a copy it makes is root-owned (contract §2.4).
	if mode == "copy" && who.Root && sess.door != audit.DoorLocal && s.guard.Classify(dest) == "normal" && s.guard.Classify(rdest) == "normal" {
		opts.As = &wproto.CreateAs{UID: who.UID, GID: -1} // chown only, never chmod
	}
	wire := make([][]byte, len(resolved))
	for i, root := range resolved {
		wire[i] = []byte(root)
	}
	reqBody, err := json.Marshal(wproto.CopyReq{Src: wire, DstDir: []byte(rdest), Opts: opts})
	if err != nil {
		s.fail(w, r, "internal", "The operation could not be prepared.", "", err.Error())
		return
	}
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The operation could not be prepared.", "", err.Error())
		return
	}
	big := summary.Files >= milestoneFiles || summary.Bytes >= milestoneBytes
	detail := jobIntentDetail(id, mode+" to "+dest, paths)
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, big); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", paths[0], mode, err.Error())
		return
	}
	kind, wireKind := jobs.KindCopy, wproto.JobCopy
	if mode == "move" {
		kind, wireKind = jobs.KindMove, wproto.JobMove
	}
	roots := mappedRoots(append(append([]string(nil), paths...), dest), append(append([]string(nil), resolved...), rdest))
	meta := jobs.Meta{ID: id, Src: paths, Dst: dest, Actor: who.User, UID: who.UID,
		OnFinish: s.jobFinishHook(jobActorOf(sess, r), mode, id, m.path, detail, big)}
	job, err := s.jobMgr.Submit(kind, transferTitle(mode, paths, dest), meta, func(ctx context.Context, p *jobs.Progress) (any, error) {
		if err := s.recheckGuard(checks...); err != nil {
			return nil, err
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wireKind, Body: reqBody}, s.progressSink(roots, p), s.warnSink(roots, mode, id, p))
		return viewOf(res), s.jobErr(mode, id, err)
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, m, id, err)
		return
	}
	s.writeJob(w, *job)
}
