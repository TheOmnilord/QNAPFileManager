package workerpool

// The two M2-C operations that outlive their own RPC, and the one rule that
// makes them safe: a streaming operation stays PINNED to the worker that
// started it (M2-C review round 1, finding 1).
//
// Every other call here is a round trip. acquire counts the caller in flight,
// the reply comes back, release lets go, and the worker is free to be reaped as
// idle or evicted to make room for another user's. An archive and an upload are
// not round trips. The reply is only the BEGINNING:
//
//   - an archive's reply carries a pipe, and the worker goes on walking a
//     200 GB share into the other end of it for minutes afterwards. A pool that
//     reaped that worker as "idle" — it has no calls in flight, after all —
//     killed the producer mid-stream and handed the user a truncated zip with
//     no error anywhere to explain it;
//   - an upload's reply carries a descriptor and an opaque handle for an inode
//     the WORKER holds. Finalize has to reach that same process. A pool that
//     let the worker be replaced in between sent the Finalize to a stranger
//     that had never heard of the handle — reported to the user as an upload
//     that simply failed after every byte had already been transferred, and, on
//     an unlucky day, as an upload that succeeded against a different inode.
//
// The pin is the hold itself. acquire's in-flight count is already what stops
// the janitor reaping a worker (client.idleSince) and what stops
// makeRoomLocked evicting one (client.busy), so "keep the hold until the stream
// ends" needs no second mechanism and cannot drift out of step with the first.
// What this file adds is the bookkeeping that says WHEN a stream ends:
//
//   - an archive's hold is released when the caller closes the ReadCloser. The
//     route copies the pipe to the response and closes it, whether the download
//     completed or the client disconnected, so the hold ends exactly when the
//     download does;
//   - an upload's hold is kept in a table keyed by the worker's own handle id,
//     and released by the Finalize (or Discard) that claims it. A Finalize for
//     a handle this pool is not holding is answered worker_gone, which is the
//     truth: the inode it named lived in a process that is no longer there.
//
// Neither of those can be trusted on its own, so there is a backstop. A route
// that returns without closing the reader, or a Finalize that never arrives,
// would otherwise pin a worker for the life of the daemon. The worker itself
// already throws an unfinished upload away after ten minutes (contract §1.3)
// but has no way to tell the pool, so the pool keeps its own, longer timeout:
// past uploadPinTimeout the pin is dropped and logged, which releases the
// worker and turns any later Finalize into the same worker_gone.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// uploadPinTimeout is the pool's backstop on an upload handle, and it is
// deliberately LONGER than the worker's own ten minutes: the worker is the
// authority on when an inode is thrown away, and a pool that gave up first
// would report worker_gone for a handle the worker was still perfectly willing
// to publish. Five minutes of slack covers a Finalize that crossed with the
// worker's sweep.
const uploadPinTimeout = 15 * time.Minute

// uploadPin is one upload handle the pool is holding a worker for.
type uploadPin struct {
	c *client
	// key is the principal that opened it. It is checked at claim time even
	// though the handle is sixteen unguessable hex digits from the worker,
	// because "only the user who opened it may finish it" is a rule that should
	// not rest on a random number.
	key string
	at  time.Time
}

// heldStream is a descriptor the worker is still writing into, plus the hold on
// the worker that is doing the writing.
//
// Close is the whole point of it: it closes the pipe — which is what tells the
// worker's producer to stop, through EPIPE — and only then lets go of the
// worker. The once is not decoration: io.Copy failures, a route's defer and an
// explicit close can all reach here, and releasing a hold twice would make the
// pool believe a busy worker was idle.
type heldStream struct {
	f    *os.File
	p    *Pool
	c    *client
	id   string
	once sync.Once
}

func (h *heldStream) Read(b []byte) (int, error) { return h.f.Read(b) }

// File is the pipe's own descriptor, for the one caller that needs the
// descriptor rather than the reader: the route duplicates it into a pollable
// one so that a client disconnect interrupts a blocked read
// (internal/web/download_linux.go).
//
// It is a LOAN and not a handover. Closing what this returns does not release
// the worker — only Close on the stream does — so a caller that borrows it must
// still close the stream itself.
func (h *heldStream) File() *os.File { return h.f }

func (h *heldStream) Close() error {
	err := h.f.Close()
	h.once.Do(func() { h.p.release(h.c) })
	return err
}

// Outcome asks the worker that produced this archive what became of it
// (adversarial finding 6).
//
// It goes to the SAME client, which is the whole reason the hold exists: the
// verdict lives in that one process's memory, so a pool that had replaced the
// worker in the meantime would have nobody left to ask. The client is addressed
// directly rather than through acquire, so this works after Close has released
// the hold as well as before — the record outlives the producer by minutes.
//
// A worker that has gone reports that rather than inventing a verdict: an
// archive whose outcome cannot be established is not one the audit may record
// as complete.
func (h *heldStream) Outcome(ctx context.Context) (wproto.ArchiveStatusResp, error) {
	if h.id == "" {
		return wproto.ArchiveStatusResp{}, fmt.Errorf("this archive carries no id: %w", fsx.ErrUnsupported)
	}
	f, files, err := h.p.call(ctx, h.c, wproto.OpArchiveStatus, wproto.ArchiveStatusReq{ID: h.id})
	if err != nil {
		return wproto.ArchiveStatusResp{}, err
	}
	closeAll(files)
	var resp wproto.ArchiveStatusResp
	if err := f.Unmarshal(&resp); err != nil {
		return wproto.ArchiveStatusResp{}, err
	}
	return resp, nil
}

// heldStream wraps a descriptor the worker keeps writing into, keeping c held
// until the reader is closed. The caller must not release c itself.
func (p *Pool) heldStream(c *client, f *os.File, id string) backend.ArchiveStream {
	return &heldStream{f: f, p: p, c: c, id: id}
}

// pinUpload records that c is holding an open inode under the worker's handle
// id, and that the hold on c belongs to that handle from now on.
func (p *Pool) pinUpload(id string, who backend.Principal, c *client) {
	p.pinsMu.Lock()
	defer p.pinsMu.Unlock()
	if p.pins == nil {
		p.pins = map[string]*uploadPin{}
	}
	p.pins[id] = &uploadPin{c: c, key: who.Key(), at: p.now()}
}

// claimUpload takes a handle out of the table and returns the worker that owns
// it. The caller owns the hold from then on and must release it.
//
// Everything that is not "this user's live worker is still holding it" is
// worker_gone, and that is the honest answer rather than a convenient one: the
// inode the handle names exists only inside one process's memory, so if that
// process is gone, or was never this caller's, there is nothing left to publish
// and the route has to tell the user the upload failed.
func (p *Pool) claimUpload(id string, who backend.Principal) (*client, error) {
	if id == "" {
		return nil, fmt.Errorf("this upload carries no handle: %w", fsx.ErrBadName)
	}
	p.pinsMu.Lock()
	pin := p.pins[id]
	if pin != nil && pin.key == who.Key() {
		delete(p.pins, id)
	}
	p.pinsMu.Unlock()

	switch {
	case pin == nil:
		return nil, fmt.Errorf("this upload is no longer being held by any worker: %w", fsx.ErrWorkerGone)
	case pin.key != who.Key():
		// Left in the table on purpose: it is not this caller's to take away.
		return nil, fmt.Errorf("this upload belongs to another session: %w", fsx.ErrWorkerGone)
	case pin.c.isDead():
		p.release(pin.c)
		return nil, fmt.Errorf("the worker holding this upload is gone: %w", fsx.ErrWorkerGone)
	}
	return pin.c, nil
}

// keptTheHandle reports that a failed Finalize left the worker still holding
// the upload, so its pin must go back (round 2 adversarial, finding 3).
//
// Two cases, and both are refusals made BEFORE the finalizer ran:
//
//   - the caller's context was already done, so p.call never sent the frame at
//     all;
//   - the worker answered queue_full, which its read loop does from the
//     semaphore before the handler exists. The handle table was never touched.
//
// Everything else — an OK, a not_found, a conflict, an exists, a worker that
// died — means the worker either consumed the handle or no longer has it, and
// the pin is spent. The rule errs towards KEEPING the pin, because a pin that
// outlives its handle costs one "not found" on the next attempt while a pin
// dropped too early costs the user an upload they had already transferred.
func keptTheHandle(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, fsx.ErrQueueFull)
}

// repinUpload puts a claimed handle back, keeping the hold the claim handed
// over (adversarial finding 2). The original pin time is NOT restored: the
// backstop measures how long the pool has been holding a worker for an upload
// nobody finished, and a Finalize that failed on its way out is a fresh reason
// to keep waiting a little.
func (p *Pool) repinUpload(id string, who backend.Principal, c *client) {
	now := p.now()
	p.pinsMu.Lock()
	if p.pins == nil {
		p.pins = map[string]*uploadPin{}
	}
	_, taken := p.pins[id]
	if !taken {
		p.pins[id] = &uploadPin{c: c, key: who.Key(), at: now}
	}
	p.pinsMu.Unlock()
	if taken {
		// Somebody re-opened the same id, which the worker's sixteen random hex
		// digits make impossible. The hold is then this call's to let go of
		// rather than something to attach to a pin that is already somebody
		// else's. Released outside the lock, which is never held across one.
		p.release(c)
	}
}

// sweepUploadPins drops the pins nobody ever claimed. It runs on the janitor's
// tick, beside reapIdle, and it is what stops a route that returned without
// finalising from pinning a worker for the life of the daemon.
func (p *Pool) sweepUploadPins() {
	now := p.now()
	var stale []*uploadPin
	p.pinsMu.Lock()
	for id, pin := range p.pins {
		if now.Sub(pin.at) >= uploadPinTimeout {
			delete(p.pins, id)
			stale = append(stale, pin)
		}
	}
	p.pinsMu.Unlock()
	for _, pin := range stale {
		p.opts.Logger.Printf("workerpool: an upload on the worker for %s was never finished; releasing it after %s",
			pin.key, uploadPinTimeout)
		p.release(pin.c)
	}
}

// dropUploadPins releases every pin at once. It runs at the start of a
// shutdown, while the clients it is letting go of are still ordinary ones —
// after the shutdown has begun collecting them, a release would be racing the
// termination it is supposed to precede.
func (p *Pool) dropUploadPins() {
	p.pinsMu.Lock()
	all := make([]*uploadPin, 0, len(p.pins))
	for id, pin := range p.pins {
		delete(p.pins, id)
		all = append(all, pin)
	}
	p.pinsMu.Unlock()
	for _, pin := range all {
		p.release(pin.c)
	}
}
