package workerpool

import (
	"context"
	"errors"
	"fmt"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// --- backend.Jobs ------------------------------------------------------
//
// A job is ONE long-lived RPC (identity plan §2.5). The JobReq goes out under a
// request id, the worker's progress and per-item warnings come back on that
// same id, and a terminal ok or err closes it. There is no second channel and
// no correlation problem, and the job's completion is naturally ordered after
// its last progress update.

var (
	_ backend.Jobs    = (*Pool)(nil)
	_ backend.Backend = (*Pool)(nil)
	_ backend.Mutator = (*Pool)(nil)
)

// jobFrames is the pending-channel depth for a job. An ordinary call needs one
// slot; a job receives a stream, and the worker coalesces progress to ten
// frames a second, so this is roughly half a minute of updates for a caller
// that has stopped reading entirely. Beyond it deliver drops the oldest frame —
// a superseded Prog or a Warn, both of which the terminal JobResult folds back
// in — and never the terminal one.
const jobFrames = 256

// jobCancelGrace is how long a cancelled job is still listened to. The caller
// has gone, but the worker has not: it is finishing the item it was on and will
// report what it managed to do, and that report (with its partial counts) is
// worth waiting a little for. A worker still silent past this is not finishing
// an item, it is not stopping — so it is terminated rather than abandoned
// (F13); see cancelAndDrain.
const jobCancelGrace = 10 * time.Second

// cancelGrace is jobCancelGrace unless a test shortened it.
func (p *Pool) cancelGrace() time.Duration {
	if d := p.opts.jobCancelGrace; d > 0 {
		return d
	}
	return jobCancelGrace
}

// Job runs one job to completion as the principal.
//
// The worker's client is held for the whole job, not just for the write: while
// a job is in flight the worker counts as in flight too, which is what stops
// the janitor reaping it underneath its own work (PLAN.md decision 5 — a worker
// with a running job is never reaped). The worker serves requests concurrently,
// so this user's interactive listings are not queued behind their own job.
//
// onProg and onWarn may be nil. They are called on this goroutine, in the order
// the worker sent them; a slow callback can cost a progress frame or a warning
// frame (both are recoverable — the JobResult carries the warning count) but
// never the result.
//
// A CANCELLED job returns a non-zero JobResult AND a non-nil error (F7): the
// result has Cancelled set and carries the partial Files/Bytes/Dirs/Skipped,
// the warning count and the retained warnings, and the error is
// context.Canceled. Callers must read the result even when err != nil — nothing
// rolls the partial work back, and those counts are all there is to show for
// it. jobs.Manager does exactly that: cancelled, Partial, and the result kept.
func (p *Pool) Job(ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	if req.JobID == "" {
		return wproto.JobResult{}, fmt.Errorf("a job needs an id: %w", fsx.ErrBadName)
	}
	if req.Kind == "" {
		return wproto.JobResult{}, fmt.Errorf("job %s has no kind: %w", req.JobID, fsx.ErrBadName)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		return wproto.JobResult{}, err
	}
	defer p.release(c)
	return p.runJob(ctx, c, req, onProg, onWarn)
}

// runJob is Job with the worker already held. It deliberately does not go
// through call: a call is bounded by CallTimeout, and a job is not — a
// four-million-file delete is hours of legitimate work, and the bound that
// matters for it is the caller's context and the worker's own liveness.
func (p *Pool) runJob(ctx context.Context, c *client, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	if err := ctx.Err(); err != nil {
		return wproto.JobResult{}, err
	}
	id := p.nextID.Add(1)
	frame, err := wproto.NewReq(id, wproto.OpJob, req)
	if err != nil {
		return wproto.JobResult{}, err
	}
	pend := &pending{ch: make(chan result, jobFrames)}

	c.mu.Lock()
	if c.dead {
		err := c.deadErr
		c.mu.Unlock()
		if err == nil {
			err = workerGone(c.key, nil)
		}
		return wproto.JobResult{}, err
	}
	c.pending[id] = pend
	c.calls++
	c.mu.Unlock()
	// Whatever ends this job — the result, a cancellation, a dead worker — the
	// pending slot goes and anything left in it is closed, exactly as call does.
	defer c.abandon(id, pend)

	if err := p.writeFrame(ctx, c, frame); err != nil {
		// F12: an expired deadline that never touched the transport is this
		// submission's problem and nobody else's. Abandoning the pending entry
		// (the deferred abandon above) is the whole of the cleanup; closing the
		// connection here would fail every other call this worker is serving
		// with worker_gone and retire a process that is perfectly healthy.
		var nw *notWritten
		if errors.As(err, &nw) {
			return wproto.JobResult{}, nw.err
		}
		gone := workerGone(c.key, err)
		// A write that failed part-way has desynchronised the framing and a
		// write that timed out has left a worker that is not reading; neither is
		// something to send a second frame down.
		_ = c.tr.Close()
		c.fail(gone)
		p.opts.Logger.Printf("workerpool: %s did not take the job frame for %s (%v); retiring it", c.key, req.JobID, err)
		go p.retire(c, gone)
		return wproto.JobResult{}, gone
	}

	track := &jobTrack{}
	for {
		select {
		case r := <-pend.ch:
			done, res, err := p.jobFrame(c, r, track, onProg, onWarn)
			if done {
				return jobOutcomeOf(res, err)
			}
		case <-c.gone:
			return p.jobWorkerGone(c, pend, track, onProg, onWarn)
		case <-ctx.Done():
			// The caller has given up. The worker has not: it is still deleting
			// files under this job id, and dropping this end would leave it
			// running with nobody to stop it.
			return p.cancelAndDrain(ctx, c, req.JobID, pend, track, onProg, onWarn)
		}
	}
}

// jobTrack is what this end remembers of a running job while it runs: the last
// progress state and the warnings it was shown. It is only ever touched from
// the single goroutine inside runJob, so it needs no lock.
//
// It exists for the one outcome that arrives without a terminal frame: a worker
// that would not stop within the cancellation grace and had to be terminated
// (F13). The counts it kept are then the only account of what that job did.
type jobTrack struct {
	last     wproto.Prog
	warnings int
	warns    []wproto.Warn
}

// result turns what was observed into the partial JobResult of a job that never
// reported one.
func (t *jobTrack) result() wproto.JobResult {
	return wproto.JobResult{
		Files:     t.last.Files,
		Bytes:     t.last.Bytes,
		Warnings:  t.warnings,
		Warns:     append([]wproto.Warn(nil), t.warns...),
		Cancelled: true,
	}
}

// jobOutcomeOf applies the cancellation convention (F7) to a terminal frame's
// outcome.
//
// A worker that stopped on a cancellation reports it as an OK frame whose
// JobResult has Cancelled set and carries the partial counts and the folded
// warnings. The pool hands those back to its caller TOGETHER WITH
// context.Canceled — a non-zero result beside a non-nil error, deliberately —
// because the numbers are exactly what a caller has to show for a destructive
// operation that stopped half way, and nothing rolls that work back.
//
// A worker that predates the convention answers with an err frame carrying the
// "cancelled" code instead; remoteError unwraps that to context.Canceled and
// the result is simply empty, which is the old behaviour unchanged.
func jobOutcomeOf(res wproto.JobResult, err error) (wproto.JobResult, error) {
	if err == nil && res.Cancelled {
		return res, context.Canceled
	}
	return res, err
}

// jobFrame dispatches one received frame. done is true for a terminal frame,
// whose result and error are the job's.
func (p *Pool) jobFrame(c *client, r result, track *jobTrack, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (done bool, res wproto.JobResult, err error) {
	// A job passes no descriptors. One that arrives anyway is closed here
	// rather than left open in the root front-end until the daemon restarts.
	if len(r.files) > 0 {
		p.opts.Logger.Printf("workerpool: %s attached %d descriptors to a %s frame on request %d; closing them",
			c.key, len(r.files), r.f.Kind, r.f.ID)
		closeAll(r.files)
	}

	switch r.f.Kind {
	case wproto.KindProg:
		var prog wproto.Prog
		if err := r.f.Unmarshal(&prog); err != nil {
			// A malformed progress frame is not worth ending a running job for:
			// progress is advisory and the terminal frame is what decides the
			// outcome. It is logged so the protocol bug is not silent.
			p.opts.Logger.Printf("workerpool: %s sent an unreadable progress frame on request %d: %v", c.key, r.f.ID, err)
			return false, wproto.JobResult{}, nil
		}
		if track != nil {
			track.last = prog
		}
		if onProg != nil {
			onProg(prog)
		}
		return false, wproto.JobResult{}, nil

	case wproto.KindWarn:
		var warn wproto.Warn
		if err := r.f.Unmarshal(&warn); err != nil {
			p.opts.Logger.Printf("workerpool: %s sent an unreadable warning frame on request %d: %v", c.key, r.f.ID, err)
			return false, wproto.JobResult{}, nil
		}
		if track != nil {
			track.warnings++
			if len(track.warns) < wproto.WarnCap {
				track.warns = append(track.warns, warn)
			}
		}
		if onWarn != nil {
			onWarn(warn)
		}
		return false, wproto.JobResult{}, nil

	case wproto.KindOK:
		var out wproto.JobResult
		if len(r.f.Body) > 0 {
			if err := r.f.Unmarshal(&out); err != nil {
				return true, wproto.JobResult{}, err
			}
		}
		return true, out, nil

	case wproto.KindErr:
		// remoteError keeps the worker's code, so a job the worker itself
		// cancelled still classifies as "cancelled" through fsx.Code, and a
		// per-path permission failure still classifies as "permission".
		return true, wproto.JobResult{}, remoteError(r.f.Err)

	default:
		return true, wproto.JobResult{}, fmt.Errorf("the worker sent a %q frame for a job: %w", r.f.Kind, wproto.ErrProtocol)
	}
}

// jobWorkerGone reports a worker that died mid-job — after first taking
// anything it had already delivered. A job that finished an instant before the
// process went is a finished job, not a lost one, and the select that brought
// us here cannot tell the two apart.
//
// When there is nothing buffered the job is lost and the partial work it did
// stands: there is no rollback, and the caller says so.
func (p *Pool) jobWorkerGone(c *client, pend *pending, track *jobTrack, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	for {
		select {
		case r := <-pend.ch:
			done, res, err := p.jobFrame(c, r, track, onProg, onWarn)
			if done {
				return jobOutcomeOf(res, err)
			}
		default:
			if err := c.deadError(); err != nil {
				return wproto.JobResult{}, err
			}
			return wproto.JobResult{}, workerGone(c.key, nil)
		}
	}
}

// cancelAndDrain tells the worker to stop the job and then keeps reading until
// it says what it managed to do, so the caller gets the worker's own partial
// counts rather than a bare cancellation. The wait is bounded: the caller is
// already gone and this must not become a second one.
//
// The error is the worker's if it reported one (its own "cancelled" carries the
// code through fsx.Code), and the context's otherwise, because the contract is
// that a cancelled job returns ctx.Err().
//
// When the grace runs out the worker is RETIRED rather than merely abandoned
// (F13), and that costs the user their worker — the pool spawns a fresh one on
// their next request. It is the only honest option. A destructive job that is
// still inside a filesystem call after ten seconds of being asked to stop is
// still deleting files; walking away from the pending slot while telling the
// caller "cancelled" and releasing the semaphore left that job running under a
// worker the pool then considered idle, reusable and evictable. Terminating the
// process (SIGTERM, then SIGKILL) is what actually makes the mutation stop.
func (p *Pool) cancelAndDrain(ctx context.Context, c *client, jobID string, pend *pending, track *jobTrack, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	p.cancelJob(c, jobID)

	grace := p.cancelGrace()
	t := time.NewTimer(grace)
	defer t.Stop()
	for {
		select {
		case r := <-pend.ch:
			done, res, err := p.jobFrame(c, r, track, onProg, onWarn)
			if !done {
				continue
			}
			res, err = jobOutcomeOf(res, err)
			if err == nil {
				err = ctx.Err()
			}
			return res, err
		case <-c.gone:
			res, err := p.jobWorkerGone(c, pend, track, onProg, onWarn)
			return res, err
		case <-t.C:
			p.opts.Logger.Printf("workerpool: %s did not stop the cancelled job %s within %s; terminating the worker so the job cannot carry on mutating",
				c.key, jobID, grace)
			gone := workerGone(c.key, fmt.Errorf("the cancelled job %s did not stop within %s", jobID, grace))
			// Detach FIRST, synchronously, so the pool's table no longer holds
			// this worker by the time it becomes observably dead: closing the
			// transport below makes the read loop mark the client dead at once,
			// and if the table were only cleared by the retire goroutine there
			// would be a window in which a dead worker is still this user's
			// worker (the flaky grace-expiry test). Then the transport goes so
			// nothing else is written down it, then the process itself. retire
			// runs on its own goroutine: it waits out the signal ladder, and this
			// caller — whose context expired a while ago — must not wait with it.
			// The hold taken by Job is released by its own defer as usual, after
			// this returns; retire never touches the in-flight count, so the
			// accounting stays balanced either way.
			p.detach(c)
			_ = c.tr.Close()
			go p.retire(c, gone)

			res := track.result()
			res.Detail = "worker did not stop within grace; it was terminated — partial work remains"
			err := ctx.Err()
			if err == nil {
				err = context.Canceled
			}
			return res, err
		}
	}
}

// CancelJob asks the principal's worker to stop a job.
//
// It uses the LIVE worker or nothing: spawning a process to tell it to stop
// work it never started would be absurd, and the job cannot have survived the
// worker that was running it. No live worker therefore means there is nothing
// to cancel, which is a success.
func (p *Pool) CancelJob(ctx context.Context, who backend.Principal, jobID string) error {
	if jobID == "" {
		return fmt.Errorf("cancelling a job needs its id: %w", fsx.ErrBadName)
	}
	p.mu.Lock()
	c := p.workers[who.Key()]
	if p.closed || c == nil || c.isDead() {
		p.mu.Unlock()
		return nil
	}
	// Counted as in flight for as long as the cancellation takes, so the
	// janitor cannot reap the worker between the lookup and the write.
	c.hold(p.now())
	p.mu.Unlock()
	defer p.release(c)

	if err := ctx.Err(); err != nil {
		return err
	}
	return p.cancelJob(c, jobID)
}

// cancelJob writes one OpCancel{JobID} frame. Like cancelRemote it is best
// effort and never waits for the acknowledgement — the worker looks the job up
// in its own table and cancels the context it runs under, and the Job call is
// what observes the outcome.
//
// The write is bounded for the same reason cancelRemote's is: this runs when
// the caller has already given up, so there is no deadline left to inherit, and
// a worker that has stopped reading would otherwise turn a cancellation into a
// permanent hang in the root front-end.
func (p *Pool) cancelJob(c *client, jobID string) error {
	if jobID == "" {
		return nil
	}
	cid := p.nextID.Add(1)
	req, err := wproto.NewReq(cid, wproto.OpCancel, wproto.CancelReq{JobID: jobID})
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.dead {
		// Nothing to cancel: the worker is gone and took the job with it.
		c.mu.Unlock()
		return nil
	}
	// The acknowledgement is registered so the reader drops it quietly instead
	// of logging a reply to an unknown request; deliver removes the entry.
	ack := &pending{ch: make(chan result, 1)}
	c.pending[cid] = ack
	c.mu.Unlock()

	if err := c.tr.WriteWithin(cancelTimeout, req, nil); err != nil {
		c.abandon(cid, ack)
		p.opts.Logger.Printf("workerpool: %s did not take the cancellation of job %s (%v); retiring it", c.key, jobID, err)
		gone := workerGone(c.key, err)
		_ = c.tr.Close()
		go p.retire(c, gone)
		return gone
	}
	return nil
}

// TrashList lists the principal's own trashed items. It is a plain request, not
// a job: the trash panel opens without a job round-trip.
func (p *Pool) TrashList(ctx context.Context, who backend.Principal) (wproto.TrashListResp, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return wproto.TrashListResp{}, err
	}
	defer p.release(c)
	f, files, err := p.call(ctx, c, wproto.OpTrashList, wproto.TrashListReq{})
	if err != nil {
		return wproto.TrashListResp{}, err
	}
	closeAll(files)
	var resp wproto.TrashListResp
	if err := f.Unmarshal(&resp); err != nil {
		return wproto.TrashListResp{}, err
	}
	return resp, nil
}

// FSIdentity asks the principal's worker which filesystem holds path. Like
// TrashList it is a plain request: the answer is a prediction for a dialog,
// not a step of the job.
func (p *Pool) FSIdentity(ctx context.Context, who backend.Principal, path string) (wproto.FSIdentityResp, error) {
	c, err := p.acquire(ctx, who)
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	defer p.release(c)
	f, files, err := p.call(ctx, c, wproto.OpFSIdentity, wproto.FSIdentityReq{Path: []byte(path)})
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	closeAll(files)
	var resp wproto.FSIdentityResp
	if err := f.Unmarshal(&resp); err != nil {
		return wproto.FSIdentityResp{}, err
	}
	return resp, nil
}
