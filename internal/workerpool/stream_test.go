package workerpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"os"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// M2-C review round 1, finding 1: an archive and an upload outlive their own
// RPC, so the worker that is producing one must not be reaped as idle,
// evicted to make room, or replaced before Finalize arrives.
//
// These drive the pool's own machinery rather than a real worker, because the
// property under test is the pool's bookkeeping and because Archive and
// OpenWrite refuse the in-process mode outright. The end-to-end trips are in
// m2c_root_linux_test.go.

// pinPool is a pool with the package's own movable clock and an idle timeout
// short enough to reap on demand.
func pinPool(t *testing.T) (*Pool, *clock) {
	t.Helper()
	return testPool(t, func(o *Options) { o.IdleTimeout = time.Minute })
}

// hasWorker reports whether a key still has a worker, without the Fatal
// workerForTest makes of an absent one: here the absence is the assertion.
func hasWorker(p *Pool, key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.workers[key]
	return ok
}

// TestAHeldStreamKeepsItsWorkerAcrossAReap is the archive half: while the
// reader is open the producer is still writing, and the janitor must leave the
// worker alone however long it has been since the last request frame.
func TestAHeldStreamKeepsItsWorkerAcrossAReap(t *testing.T) {
	p, clock := pinPool(t)

	who := alice()
	ctx := context.Background()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	stream := p.heldStream(c, r, "")

	clock.advance(time.Hour)
	p.reapIdle()
	if !hasWorker(p, who.Key()) {
		t.Fatal("the worker producing an archive was reaped while the download was still running")
	}
	// The bytes still flow, which is the thing the reap would have destroyed.
	if _, werr := w.Write([]byte("still streaming")); werr != nil {
		t.Fatalf("writing into the pipe: %v", werr)
	}
	buf := make([]byte, len("still streaming"))
	if _, rerr := io.ReadFull(stream, buf); rerr != nil {
		t.Fatalf("reading the stream: %v", rerr)
	}

	// Closing the reader is what lets go of the worker.
	if cerr := stream.Close(); cerr != nil {
		t.Fatalf("closing the stream: %v", cerr)
	}
	clock.advance(time.Hour)
	p.reapIdle()
	if hasWorker(p, who.Key()) {
		t.Fatal("closing the stream must let the worker be reaped")
	}
	// Idempotent: a route's defer and an explicit close both reach here, and a
	// hold released twice would make the pool think a busy worker was idle.
	_ = stream.Close()
}

// TestAnUploadPinKeepsItsWorkerUntilFinalize is the upload half: the inode
// lives inside one process, so the pin has to survive an idle timeout and be
// released by the claim.
func TestAnUploadPinKeepsItsWorkerUntilFinalize(t *testing.T) {
	p, clock := pinPool(t)

	who := alice()
	ctx := context.Background()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	p.pinUpload("handle-1", who, c)

	clock.advance(time.Hour)
	p.reapIdle()
	if !hasWorker(p, who.Key()) {
		t.Fatal("the worker holding an open upload was reaped before Finalize")
	}

	// Another session may not take it, and the attempt must not unpin it
	// either.
	if _, cerr := p.claimUpload("handle-1", bob()); !errors.Is(cerr, fsx.ErrWorkerGone) {
		t.Fatalf("another session's claim = %v, want worker_gone", cerr)
	}
	got, cerr := p.claimUpload("handle-1", who)
	if cerr != nil {
		t.Fatalf("claim: %v", cerr)
	}
	if got != c {
		t.Fatal("Finalize must go to the worker the handle was opened on")
	}
	p.release(got)

	// Claimed once and once only.
	if _, cerr := p.claimUpload("handle-1", who); !errors.Is(cerr, fsx.ErrWorkerGone) {
		t.Fatalf("a second claim = %v, want worker_gone", cerr)
	}
	clock.advance(time.Hour)
	p.reapIdle()
	if hasWorker(p, who.Key()) {
		t.Fatal("finalizing must let the worker be reaped")
	}
}

// TestAnUploadOnADeadWorkerIsWorkerGone: the inode was in that process, so
// there is nothing left to publish and the route has to say the upload failed
// rather than ask a stranger to create a file.
func TestAnUploadOnADeadWorkerIsWorkerGone(t *testing.T) {
	p, _ := pinPool(t)

	who := alice()
	ctx := context.Background()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	p.pinUpload("handle-2", who, c)
	c.fail(errors.New("the worker crashed"))

	if _, cerr := p.claimUpload("handle-2", who); !errors.Is(cerr, fsx.ErrWorkerGone) {
		t.Fatalf("claim on a dead worker = %v, want worker_gone", cerr)
	}
	// And the pin is gone with it, rather than holding a dead worker's slot.
	p.pinsMu.Lock()
	left := len(p.pins)
	p.pinsMu.Unlock()
	if left != 0 {
		t.Fatalf("%d pins left behind", left)
	}
}

// TestAnAbandonedUploadPinIsSweptUp is the backstop: a route that never
// finalises must not pin a worker for the life of the daemon. The pool's own
// timeout is longer than the worker's ten minutes, because the worker is the
// authority on when the inode goes.
func TestAnAbandonedUploadPinIsSweptUp(t *testing.T) {
	p, clock := pinPool(t)

	who := alice()
	ctx := context.Background()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	p.pinUpload("handle-3", who, c)

	// Eleven minutes: past the worker's own expiry, inside the pool's.
	clock.advance(11 * time.Minute)
	p.sweepUploadPins()
	if _, cerr := p.claimUpload("handle-3", who); cerr != nil {
		t.Fatalf("the pool must not give up before the worker does: %v", cerr)
	}
	p.pinUpload("handle-3", who, c)

	clock.advance(uploadPinTimeout + time.Minute)
	p.sweepUploadPins()
	if _, cerr := p.claimUpload("handle-3", who); !errors.Is(cerr, fsx.ErrWorkerGone) {
		t.Fatalf("an abandoned pin = %v, want worker_gone", cerr)
	}
	clock.advance(time.Hour)
	p.reapIdle()
	if hasWorker(p, who.Key()) {
		t.Fatal("sweeping the pin must release the worker")
	}
}

// TestFinalizeWithoutAPinNeverReachesAWorker: an unknown handle must not be
// sent anywhere. This is the shape of the bug the pin exists for — a Finalize
// arriving at a process that never had the inode.
func TestFinalizeWithoutAPinNeverReachesAWorker(t *testing.T) {
	p, _ := pinPool(t)

	p.opts.Mode = ModeProcess // the mode check must not be what refuses this

	_, err := p.Finalize(context.Background(), alice(), wproto.FinalizeReq{
		Tmp: []byte("deadbeefdeadbeef"), Final: []byte("x.txt"),
	})
	if !errors.Is(err, fsx.ErrWorkerGone) {
		t.Fatalf("err = %v, want worker_gone", err)
	}
	if fsx.Code(err) != "worker_gone" {
		t.Errorf("code = %q", fsx.Code(err))
	}
}

// TestACancelledFinalizeKeepsThePin is adversarial finding 2. A Finalize whose
// context is already done never reaches the worker — p.call refuses to send —
// so consuming the pin would have thrown the upload away without telling the
// worker anything, and the route's follow-up Discard would then report
// worker_gone over an inode the worker was still holding.
func TestACancelledFinalizeKeepsThePin(t *testing.T) {
	p, _ := pinPool(t)
	who := alice()

	if err := p.Ping(context.Background(), who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(context.Background(), who)
	if err != nil {
		t.Fatal(err)
	}
	p.pinUpload("handle-5", who, c)
	// Only now: the worker is up, and the mode check must not be what refuses
	// the Finalize below.
	p.opts.Mode = ModeProcess

	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ferr := p.Finalize(dead, who, wproto.FinalizeReq{Tmp: []byte("handle-5"), Final: []byte("x.txt")}); !errors.Is(ferr, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", ferr)
	}
	// The pin — and the hold that goes with it — is still there, so the Discard
	// the route sends next reaches the worker that has the inode.
	got, cerr := p.claimUpload("handle-5", who)
	if cerr != nil {
		t.Fatalf("a cancelled Finalize must not consume the handle: %v", cerr)
	}
	if got != c {
		t.Fatal("the restored pin must name the same worker")
	}
	p.release(got)
}

// fakeWorker attaches a hand-made client to a pool and answers every request
// with the frame the test supplies. It is how a pool-level test can put a
// specific worker REPLY in front of Finalize, which the in-process worker — a
// real one — will not produce on demand.
func scriptedWorker(t *testing.T, who backend.Principal, reply func(id uint64) wproto.Frame) *client {
	t.Helper()
	ours, theirs := net.Pipe()
	c := newClient(who)
	c.tr = wproto.NewTransport(ours)
	terminates(c, ours, theirs)
	go c.readLoop(nil)

	peer := wproto.NewTransport(theirs)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			f, files, err := peer.Read()
			for _, file := range files {
				file.Close()
			}
			if err != nil {
				return
			}
			if werr := peer.Write(reply(f.ID), nil); werr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = c.tr.Close()
		_ = peer.Close()
		<-done
	})
	return c
}

// TestAQueueFullFinalizeKeepsThePin is round 2 adversarial finding 3. The
// worker's semaphore refuses a request on its read loop, BEFORE the handler
// that would consume the handle exists — so the inode is still there, and a
// pool that dropped the pin turned the route's next Discard into worker_gone
// over an upload the worker was perfectly willing to finish.
func TestAQueueFullFinalizeKeepsThePin(t *testing.T) {
	p, _ := pinPool(t)
	p.opts.Mode = ModeProcess // the mode check must not be what refuses this
	who := alice()

	c := scriptedWorker(t, who, func(id uint64) wproto.Frame {
		return wproto.NewErr(id, fmt.Errorf("64 requests are already running: %w", fsx.ErrQueueFull), nil)
	})
	c.hold(p.now()) // the hold OpenWrite would have taken
	p.pinUpload("handle-6", who, c)

	_, err := p.Finalize(context.Background(), who, wproto.FinalizeReq{Tmp: []byte("handle-6"), Final: []byte("x.txt")})
	if !errors.Is(err, fsx.ErrQueueFull) {
		t.Fatalf("err = %v, want queue_full", err)
	}
	got, cerr := p.claimUpload("handle-6", who)
	if cerr != nil {
		t.Fatalf("a queue_full refusal must not consume the handle: %v", cerr)
	}
	if got != c {
		t.Fatal("the restored pin must name the same worker")
	}
	p.release(got)
}

// TestAConsumingFinalizeSpendsThePin is the other half of the rule: an answer
// that means the worker DID look at the handle spends the pin, or a worker
// would be held for an upload that no longer exists.
func TestAConsumingFinalizeSpendsThePin(t *testing.T) {
	p, _ := pinPool(t)
	p.opts.Mode = ModeProcess
	who := alice()

	c := scriptedWorker(t, who, func(id uint64) wproto.Frame {
		return wproto.NewErr(id, fmt.Errorf("%q is a folder: %w", "x.txt", syscall.EBUSY), nil)
	})
	c.hold(p.now())
	p.pinUpload("handle-7", who, c)

	if _, err := p.Finalize(context.Background(), who, wproto.FinalizeReq{Tmp: []byte("handle-7"), Final: []byte("x.txt")}); err == nil {
		t.Fatal("the conflict must be reported")
	}
	if _, cerr := p.claimUpload("handle-7", who); !errors.Is(cerr, fsx.ErrWorkerGone) {
		t.Fatalf("a conflict answer must spend the handle, got %v", cerr)
	}
}

// TestShutdownReleasesEveryPin: a pool that is going away must not leave holds
// behind that its own shutdown then waits on.
func TestShutdownReleasesEveryPin(t *testing.T) {
	p, _ := pinPool(t)

	who := alice()
	ctx := context.Background()

	if err := p.Ping(ctx, who); err != nil {
		t.Fatal(err)
	}
	c, err := p.acquire(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	p.pinUpload("handle-4", who, c)

	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if serr := p.Shutdown(sctx); serr != nil {
		t.Fatalf("shutdown: %v", serr)
	}
	p.pinsMu.Lock()
	left := len(p.pins)
	p.pinsMu.Unlock()
	if left != 0 {
		t.Fatalf("%d pins survived the shutdown", left)
	}
}

func bob() backend.Principal {
	return backend.Principal{User: "bob", UID: 1002, GID: 1002}
}
