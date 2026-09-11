package worker

// The M2 job spine: one long-lived RPC per job, with progress and per-item
// warnings flowing back on the same request id until a terminal ok or err frame
// closes it (identity plan §2.5).
//
// There is no second channel and no correlation problem: a prog frame carries
// the id of the JobReq it belongs to, so the pool's pending table routes it to
// the caller that is already waiting, and the terminal frame is naturally
// ordered after the last update. What this file adds on top of that is the
// discipline the socket needs — progress is coalesced to at most ten frames a
// second or one per 8 MiB — and the guarantee the record needs: every warning
// is also folded into the terminal JobResult, so a warn frame dropped by a slow
// reader is never a lost fact.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The coalescing rule from identity plan §2.5: a progress frame goes out when
// either bound is reached, whichever comes first, so a million-file delete
// sends ten frames a second and a 200 GB copy sends one per 8 MiB.
const (
	progInterval = 100 * time.Millisecond
	progBytes    = 8 << 20
)

// runJob serves one OpJob request from start to finish on its own goroutine.
//
// The job runs under a context derived from the request's, registered under the
// JobID so an OpCancel naming the job stops it — and still cancelled by the
// request's own context, so a dead connection or a cancellation by frame id
// stops it too. Partial work is never rolled back; a cancelled job reports what
// it managed to do, and the front-end says so rather than pretending otherwise
// (backend plan §3).
func (s *session) runJob(ctx context.Context, f wproto.Frame) {
	var req wproto.JobReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if req.JobID != "" {
		s.beginJob(req.JobID, cancel)
		defer s.endJob(req.JobID)
	}

	e := &progEmitter{s: s, id: f.ID}
	res, err := s.jobWork(jctx, req, e)
	e.fold(&res)

	switch {
	case err == nil:
		s.replyOK(f.ID, res)
	case jctx.Err() != nil:
		// Cancelled, by the front-end or by the connection going away. The code
		// is "cancelled" (fsx.Code of context.Canceled) and the partial counts
		// travel in the message, because the wire's err frame carries a code, an
		// errno, a message and a path and has no room for a JobResult — a
		// contract this side does not get to change.
		s.replyErr(f.ID, e.cancelled(res), nil)
	default:
		s.replyErr(f.ID, err, nil)
	}
}

// jobWork dispatches one job kind. Everything it can do is a call into fsops,
// which is the only package in the tree that touches user data (INV-1).
func (s *session) jobWork(ctx context.Context, req wproto.JobReq, e *progEmitter) (wproto.JobResult, error) {
	emit := e.emit()
	switch req.Kind {
	case wproto.JobDelete, wproto.JobTrash:
		var body wproto.DeleteReq
		if err := jobBody(req.Body, &body); err != nil {
			return wproto.JobResult{}, err
		}
		// JobTrash is the older spelling of "delete to trash" and means exactly
		// DeleteReq.Trash, so either way of asking lands in the same place.
		if body.Trash || req.Kind == wproto.JobTrash {
			return fsops.Trash(ctx, s.root, s.plat, s.uid(), pathsOf(body.Paths), emit)
		}
		return fsops.DeleteTree(ctx, s.root, s.plat, pathsOf(body.Paths),
			fsops.DeleteOptions{Recursive: body.Recursive, CrossMounts: body.CrossMounts}, emit)

	case wproto.JobSize:
		var body wproto.SizeReq
		if err := jobBody(req.Body, &body); err != nil {
			return wproto.JobResult{}, err
		}
		return fsops.Size(ctx, s.root, s.plat, pathsOf(body.Paths), body.CrossMounts, emit)

	case wproto.JobTrashRestore:
		var body wproto.TrashRestoreReq
		if err := jobBody(req.Body, &body); err != nil {
			return wproto.JobResult{}, err
		}
		return fsops.TrashRestore(ctx, s.root, s.plat, s.uid(), body.IDs, emit)

	case wproto.JobTrashEmpty:
		return fsops.TrashEmpty(ctx, s.root, s.plat, s.uid(), emit)
	}
	return wproto.JobResult{}, fmt.Errorf("the %q job kind is not implemented by this worker: %w", req.Kind, fsx.ErrUnsupported)
}

// trashList answers the trash panel. It is a plain request rather than a job,
// so the panel opens without a job round-trip, and it lists only this worker's
// own uid subdirectory on every trash root it can reach.
func (s *session) trashList(ctx context.Context, f wproto.Frame) {
	items, err := fsops.TrashList(ctx, s.root, s.plat, s.uid())
	if err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	s.replyOK(f.ID, wproto.TrashListResp{Items: items})
}

// uid is the identity whose trash subdirectory this worker owns.
//
// It is asked of the kernel rather than taken from the hello frame, because the
// kernel is the only party that knows: the parent asked for a uid at fork time
// and HelloResp reports back what it actually got, which is the check the pool
// makes. The hello request carries no uid of its own to prefer.
//
// os.Getuid returns -1 on Windows, where this process is the in-process worker
// of the dev loop: there is no impersonation and no second user, so the trash
// lands in a single deterministic "0" subdirectory there.
func (s *session) uid() int {
	if uid := os.Getuid(); uid >= 0 {
		return uid
	}
	return 0
}

// jobBody decodes a job's request body, tolerating an absent one: the two trash
// management kinds have empty request types, and "no body" is how an empty
// struct arrives.
func jobBody(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// pathsOf converts the wire's byte paths into the strings fsops takes. The
// conversion is lossless in both directions: a Go string holds arbitrary bytes,
// which is exactly why a non-UTF-8 Linux filename survives the whole round trip
// (the wire keeps it as []byte precisely so JSON cannot mangle it).
func pathsOf(raw [][]byte) []string {
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, string(p))
	}
	return out
}

// progEmitter is the throttle and the warning ledger of one running job.
type progEmitter struct {
	s  *session
	id uint64

	mu sync.Mutex
	// last and lastBytes are the coalescing state: when the last frame went out
	// and how many bytes it reported.
	last      time.Time
	lastBytes int64
	// total is the last denominator a progress update carried, kept so the
	// cancellation message can say "after N of M".
	total int64
	// warnings counts every per-item failure; warns keeps the first WarnCap of
	// them verbatim for the terminal result.
	warnings int
	warns    []wproto.Warn
}

// emit hands fsops the two hooks it reports through.
func (e *progEmitter) emit() fsops.Emit {
	return fsops.Emit{Prog: e.prog, Warn: e.warn}
}

// prog coalesces progress. The first update of a job always goes out — the zero
// time is older than any interval — so a UI sees the job start moving at once;
// after that a frame is sent only when 100 ms have passed or 8 MiB have moved.
//
// Frames dropped here are not lost information: every one carries absolute
// counters rather than a delta, and the terminal JobResult carries the totals.
func (e *progEmitter) prog(p wproto.Prog) {
	e.mu.Lock()
	if p.FilesTotal > 0 {
		e.total = p.FilesTotal
	}
	now := time.Now()
	send := now.Sub(e.last) >= progInterval || p.Bytes-e.lastBytes >= progBytes
	if send {
		e.last = now
		e.lastBytes = p.Bytes
	}
	e.mu.Unlock()
	if !send {
		return
	}
	f, err := wproto.NewProg(e.id, p)
	if err != nil {
		return
	}
	e.s.reply(f)
}

// warn sends a per-item failure immediately and keeps it.
//
// Both halves matter. The frame is what makes a warning visible while a
// twenty-minute job is still running; the copy folded into the terminal result
// is what makes it a record, because a front-end that missed the frame — a slow
// reader, a reconnect — would otherwise report a clean job that was not one.
func (e *progEmitter) warn(w wproto.Warn) {
	e.mu.Lock()
	e.warnings++
	if len(e.warns) < wproto.WarnCap {
		e.warns = append(e.warns, w)
	}
	e.mu.Unlock()

	f, err := wproto.NewWarn(e.id, w)
	if err != nil {
		return
	}
	e.s.reply(f)
}

// fold copies the warning ledger into the terminal result.
func (e *progEmitter) fold(res *wproto.JobResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	res.Warnings = e.warnings
	res.Warns = e.warns
}

// cancelled builds the terminal error of a cancelled job: the "cancelled" code
// plus the partial counts, so the front-end can say what was done before the
// user stopped it and make clear that it was not undone.
func (e *progEmitter) cancelled(res wproto.JobResult) error {
	e.mu.Lock()
	total := e.total
	e.mu.Unlock()
	done := res.Files + res.Dirs
	if total > 0 {
		return fmt.Errorf("cancelled after %d of %d items (%d bytes, %d warnings); what was done is not undone: %w",
			done, total, res.Bytes, res.Warnings, context.Canceled)
	}
	return fmt.Errorf("cancelled after %d items (%d bytes, %d warnings); what was done is not undone: %w",
		done, res.Bytes, res.Warnings, context.Canceled)
}
