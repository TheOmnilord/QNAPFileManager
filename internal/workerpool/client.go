package workerpool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// client is the pool's end of one worker: the transport, the table of
// in-flight request ids, and whatever is needed to stop the thing.
//
// One reader goroutine owns Read. Everything else goes through the mutex.
type client struct {
	key string
	who backend.Principal
	// cred is the identity this worker's kernel credentials were fixed at, in
	// a form that can be compared. It never changes for the life of the
	// process, which is the whole reason acquire has to compare it.
	cred creds

	tr  wproto.Transport
	cmd *exec.Cmd // nil in in-process mode
	pid int

	// exited is closed when the worker's process (or goroutine) is gone.
	exited chan struct{}
	// gone is closed when the reader loop stops, whether by EOF, a decode
	// error or a deliberate termination.
	gone chan struct{}
	// kill ends the underlying process. Nil when there is nothing to signal.
	kill func(context.Context)

	mu          sync.Mutex
	pending     map[uint64]*pending
	dead        bool
	deadErr     error
	inflight    int
	lastUsed    time.Time
	calls       uint64
	started     time.Time
	hello       wproto.HelloResp
	terminating bool
	// retiring marks a worker that must not take new work — its credentials
	// have been superseded — and that is stopped as soon as the calls it
	// already accepted have finished.
	retiring bool
}

// creds is a principal's kernel identity, reduced to something comparable.
// Groups are sorted and de-duplicated first: the identity source may hand back
// the same membership in a different order, and respawning a worker over that
// would be a self-inflicted restart storm.
type creds struct {
	uid, gid int
	groups   string
	root     bool
}

func credsOf(who backend.Principal) creds {
	sorted := make([]int, 0, len(who.Groups))
	seen := make(map[int]bool, len(who.Groups))
	for _, g := range who.Groups {
		if !seen[g] {
			seen[g] = true
			sorted = append(sorted, g)
		}
	}
	sort.Ints(sorted)
	var b strings.Builder
	for i, g := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(g))
	}
	return creds{uid: who.UID, gid: who.GID, groups: b.String(), root: who.Root}
}

func (c creds) String() string {
	return fmt.Sprintf("uid=%d gid=%d groups=[%s] root=%t", c.uid, c.gid, c.groups, c.root)
}

type result struct {
	f     wproto.Frame
	files []*os.File
}

// pending is one registered request id. Delivery and cancellation both take
// c.mu and both act on this struct, which is what makes the handover of a
// received descriptor atomic: either the deliverer puts it in the channel for a
// caller that is still there, or it closes it because the entry is already
// abandoned. There is no third outcome in which nobody owns it.
type pending struct {
	ch chan result
	// abandoned marks an entry whose caller has given up. Anything that arrives
	// for it afterwards is the deliverer's to close.
	abandoned bool
}

func newClient(who backend.Principal) *client {
	return &client{
		key:     who.Key(),
		who:     who,
		cred:    credsOf(who),
		exited:  make(chan struct{}),
		gone:    make(chan struct{}),
		pending: map[uint64]*pending{},
		started: time.Now(),
	}
}

func (c *client) setHello(h wproto.HelloResp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hello = h
	if h.PID != 0 {
		c.pid = h.PID
	}
}

// hold marks one more call in flight and returns how long the worker had been
// unused. The caller must hold the pool lock.
func (c *client) hold(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	idle := time.Duration(0)
	if c.inflight == 0 && !c.lastUsed.IsZero() {
		idle = now.Sub(c.lastUsed)
	}
	c.inflight++
	c.lastUsed = now
	return idle
}

// done releases one in-flight call and reports whether that was the last one a
// retiring worker was waiting for, so the caller can stop it.
func (c *client) done(now time.Time) (retireNow bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight > 0 {
		c.inflight--
	}
	c.lastUsed = now
	return c.retiring && c.inflight == 0 && !c.terminating
}

// markRetired flags a worker as superseded and reports whether it can be
// stopped straight away. A worker with calls in flight is left to finish them:
// its credentials are stale, but the operations already accepted were
// authorised under them, and killing a download mid-stream to apply a group
// change a moment sooner would be the worse trade.
func (c *client) markRetired() (idleNow bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retiring = true
	return c.inflight == 0 && !c.terminating
}

func (c *client) busy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight > 0
}

func (c *client) lastUse() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastUsed
}

// idleSince reports whether the worker has had nothing to do for d. A worker
// with a call in flight is never idle, whatever the clock says.
func (c *client) idleSince(now time.Time, d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight > 0 || c.lastUsed.IsZero() {
		return false
	}
	return now.Sub(c.lastUsed) >= d
}

func (c *client) isDead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

// startTerminating returns true for the first caller only, so terminate is
// idempotent however many goroutines decide a worker has to go.
func (c *client) startTerminating() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminating {
		return false
	}
	c.terminating = true
	return true
}

func (c *client) stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		UID:      c.who.UID,
		Root:     c.who.Root,
		PID:      c.pid,
		HelloUID: c.hello.UID,
		HelloGID: c.hello.GID,
		Groups:   c.hello.Groups,
		Started:  c.started,
		LastUsed: c.lastUsed,
		InFlight: c.inflight,
		Calls:    c.calls,
	}
}

// fail marks the worker dead and hands every waiting caller a worker_gone
// error. It is the single place a crash becomes visible to callers.
func (c *client) fail(cause error) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	c.deadErr = cause
	waiting := make([]*pending, 0, len(c.pending))
	ids := make([]uint64, 0, len(c.pending))
	for id, p := range c.pending {
		// abandoned is written by abandon under c.mu, so it must be read
		// here, under the same lock, not after it is released.
		if p.abandoned {
			continue
		}
		waiting = append(waiting, p)
		ids = append(ids, id)
	}
	c.pending = map[uint64]*pending{}
	c.mu.Unlock()

	for i, p := range waiting {
		select {
		case p.ch <- result{f: wproto.NewErr(ids[i], cause, nil)}:
		default:
		}
	}
	close(c.gone)
}

// readLoop drains the transport for the life of the worker.
func (c *client) readLoop(logger *log.Logger) {
	for {
		f, files, err := c.tr.Read()
		if err != nil {
			closeAll(files)
			c.fail(workerGone(c.key, err))
			return
		}
		switch f.Kind {
		case wproto.KindProg, wproto.KindWarn:
			// M2 territory: a job's progress does not end the request, so the
			// id stays registered. Nothing sends these yet.
			c.deliver(f, files, false, logger)
		default:
			c.deliver(f, files, true, logger)
		}
	}
}

// deliver hands one frame to the call that is waiting for it, or closes what it
// carries.
//
// The send happens under c.mu, together with the lookup. That is the whole
// point: with the lock released in between, a caller could cancel after the
// deliverer had taken the channel and before it used it, and the descriptor of
// a cancelled download would sit in a buffered channel nobody would ever read
// again — a file the root front-end holds open until the daemon restarts.
// Under the lock, a cancellation either happens before the send and is seen
// here, or after it and finds the result in the channel to close (see abandon).
func (c *client) deliver(f wproto.Frame, files []*os.File, terminal bool, logger *log.Logger) {
	c.mu.Lock()
	p, ok := c.pending[f.ID]
	if ok && terminal {
		delete(c.pending, f.ID)
	}
	if ok && !p.abandoned {
		select {
		case p.ch <- result{f: f, files: files}:
			c.mu.Unlock()
			return
		default:
			// The caller is not reading (a job's progress frames outran it).
		}
		if terminal {
			// A terminal frame is the one thing that must never be dropped. A
			// job's caller is waiting for exactly this frame, and the id has
			// just been taken out of the table above, so a drop here would be a
			// call that waits for a reply which has already come and gone —
			// until the context or the worker's death ended it, long after the
			// job itself had finished. Room is made by discarding the oldest
			// buffered frame instead, which is a superseded Prog or a Warn: the
			// two the contract explicitly allows to be lost, because the
			// terminal JobResult folds the warning count in (wproto.JobResult).
			// Only deliver (one goroutine) and fail (after clearing the table)
			// ever send here, and a reader only makes more room, so one slot is
			// enough.
			select {
			case dropped := <-p.ch:
				closeAll(dropped.files)
			default:
			}
			select {
			case p.ch <- result{f: f, files: files}:
				c.mu.Unlock()
				return
			default:
			}
		}
	}
	c.mu.Unlock()

	// Nobody owns what arrived. The descriptor it carries is ours to close, or
	// it leaks in the root front-end for as long as the daemon runs.
	closeAll(files)
	if !ok && logger != nil {
		logger.Printf("workerpool: %s sent a reply for the unknown request %d", c.key, f.ID)
	}
}

// workerGone wraps whatever ended the connection in the sentinel the API maps
// to a 500 with an honest message.
func workerGone(key string, cause error) error {
	if errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) || errors.Is(cause, io.ErrClosedPipe) {
		return fmt.Errorf("the worker process for %s stopped unexpectedly: %w", key, fsx.ErrWorkerGone)
	}
	return fmt.Errorf("the worker process for %s stopped unexpectedly (%v): %w", key, cause, fsx.ErrWorkerGone)
}

// call sends one request and waits for its terminal frame. The returned files
// belong to the caller.
func (p *Pool) call(ctx context.Context, c *client, op wproto.Op, body any) (wproto.Frame, []*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, p.opts.CallTimeout)
	defer cancel()
	// A request whose caller has already gone away is not worth a worker's
	// time, and sending it would make the outcome a race between the reply
	// and the cancellation.
	if err := ctx.Err(); err != nil {
		return wproto.Frame{}, nil, err
	}

	id := p.nextID.Add(1)
	req, err := wproto.NewReq(id, op, body)
	if err != nil {
		return wproto.Frame{}, nil, err
	}
	pend := &pending{ch: make(chan result, 1)}

	c.mu.Lock()
	if c.dead {
		err := c.deadErr
		c.mu.Unlock()
		if err == nil {
			err = workerGone(c.key, nil)
		}
		return wproto.Frame{}, nil, err
	}
	c.pending[id] = pend
	c.calls++
	c.mu.Unlock()

	if err := p.writeFrame(ctx, c, req); err != nil {
		c.abandon(id, pend)
		gone := workerGone(c.key, err)
		// A write that failed part-way has desynchronised the framing, and a
		// write that timed out has left a worker that is not reading. Neither
		// is something to send a second frame down: the transport goes.
		_ = c.tr.Close()
		c.fail(gone)
		// And the process goes with it. Marking the client failed only settles
		// this end of the conversation: the worker on the other side is still
		// running, still holding a user's credentials and still counted against
		// Max, and nothing else was scheduled to end it — it survived until the
		// next acquire happened to notice or the janitor's idle sweep came
		// round, which for a worker wedged mid-handler could be never.
		//
		// The bye of a shutdown is the exception: terminate is already stopping
		// that worker and owns the rest of the ladder.
		if op != wproto.OpBye {
			p.opts.Logger.Printf("workerpool: %s did not take a %s frame (%v); retiring it", c.key, op, err)
			go p.retire(c, gone)
		}
		return wproto.Frame{}, nil, gone
	}

	select {
	case r := <-pend.ch:
		if r.f.Kind == wproto.KindErr {
			closeAll(r.files)
			return wproto.Frame{}, nil, remoteError(r.f.Err)
		}
		return r.f, r.files, nil
	case <-c.gone:
		c.abandon(id, pend)
		if err := c.deadError(); err != nil {
			return wproto.Frame{}, nil, err
		}
		return wproto.Frame{}, nil, workerGone(c.key, nil)
	case <-ctx.Done():
		c.abandon(id, pend)
		// The worker is still running this request. Tell it to stop: dropping
		// the caller only frees this end, and the operation on the other end
		// would go on holding a worker slot — and, for a fifo or a directory on
		// a wedged mount, a blocked syscall — long after the browser has gone.
		//
		// A goodbye is the exception. There is no handler to stop, the worker
		// is about to be signalled anyway, and sending one used to hang the
		// whole shutdown: the worker had already stopped reading to wait out
		// its handlers, so the cancellation went into a pipe nobody was
		// draining and terminate never reached the kill.
		if op != wproto.OpBye {
			p.cancelRemote(c, id)
		}
		return wproto.Frame{}, nil, ctx.Err()
	}
}

// writeTimeout bounds a single frame's journey into the transport. It is not a
// call timeout — the reply has its own — only a bound on how long the front-end
// will wait for a worker to take the bytes.
const writeTimeout = 10 * time.Second

// writeFrame puts one frame on a worker's transport without ever blocking
// indefinitely on a worker that has stopped reading.
func (p *Pool) writeFrame(ctx context.Context, c *client, f wproto.Frame) error {
	d := writeTimeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < d {
			d = left
		}
	}
	if d <= 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.DeadlineExceeded
	}
	return c.tr.WriteWithin(d, f, nil)
}

// abandon takes one request out of the pending table on behalf of a caller that
// has given up, and closes anything the worker had already delivered for it.
// Together with the send inside deliver's critical section this makes ownership
// of a received descriptor total: it is either handed to a live caller or
// closed, never left in a channel with nobody to read it.
//
// The entry is passed in rather than looked up, because the case that leaks is
// exactly the one where the lookup would fail: a terminal reply has already
// been delivered — taking the id out of the table on its way past — and the
// caller's select happened to pick its cancellation instead of the result now
// sitting in the channel.
func (c *client) abandon(id uint64, p *pending) {
	c.mu.Lock()
	if cur, ok := c.pending[id]; ok && cur == p {
		delete(c.pending, id)
	}
	p.abandoned = true
	c.mu.Unlock()
	for {
		select {
		case r := <-p.ch:
			closeAll(r.files)
		default:
			return
		}
	}
}

// cancelTimeout bounds the cancellation write. The caller it is sent on behalf
// of has already given up, so this must never become a second wait of its own.
const cancelTimeout = 2 * time.Second

// cancelRemote tells a worker that a request it is still running is no longer
// wanted. It is best effort and never waits for the acknowledgement: the caller
// has already gone, and there is nobody left to report a failure to.
//
// The write is bounded, and it has to be. It runs after the caller's context
// has already expired, so there is no deadline left to inherit; without one, a
// worker that had stopped reading would turn a cancellation into a permanent
// hang in the root front-end. A cancellation that cannot be delivered means the
// worker is no longer listening at all, so the transport is closed and the
// worker retired — which cancels the request far more thoroughly anyway.
func (p *Pool) cancelRemote(c *client, id uint64) {
	cid := p.nextID.Add(1)
	req, err := wproto.NewReq(cid, wproto.OpCancel, wproto.CancelReq{ReqID: id})
	if err != nil {
		return
	}
	c.mu.Lock()
	if c.dead {
		// Nothing to cancel: the worker is gone and took the work with it.
		c.mu.Unlock()
		return
	}
	// The acknowledgement is registered so the reader drops it quietly instead
	// of logging a reply to an unknown request; deliver removes the entry.
	ack := &pending{ch: make(chan result, 1)}
	c.pending[cid] = ack
	c.mu.Unlock()
	if err := c.tr.WriteWithin(cancelTimeout, req, nil); err != nil {
		c.abandon(cid, ack)
		p.opts.Logger.Printf("workerpool: %s did not take the cancellation of request %d (%v); retiring it", c.key, id, err)
		_ = c.tr.Close()
		go p.retire(c, workerGone(c.key, err))
	}
}

func (c *client) deadError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadErr
}

// RemoteError is a failure that happened inside a worker. It keeps the code
// and the raw errno the worker reported, and unwraps to the sentinel that
// fsx.Code maps back to that same code, so the HTTP layer classifies a remote
// ENOENT exactly as it classifies a local one.
type RemoteError struct {
	Code    string
	Errno   int
	Message string
	Path    string
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Path != "" {
		return e.Path + ": " + e.Message
	}
	return e.Message
}

// Unwrap picks the sentinel for the code. The errno is deliberately not turned
// into a syscall.Errno: the numbers are Linux's, and comparing them against
// this platform's syscall package on a Windows dev box would map EACCES onto
// whatever Windows calls 13.
func (e *RemoteError) Unwrap() error {
	switch e.Code {
	case "not_found":
		return fs.ErrNotExist
	case "permission":
		return fs.ErrPermission
	case "exists":
		return fs.ErrExist
	case "not_empty":
		return syscall.ENOTEMPTY
	case "bad_request":
		return fsx.ErrBadName
	case "protected":
		return fsx.ErrProtected
	case "readonly":
		return fsx.ErrReadOnly
	case "ramdisk":
		return fsx.ErrRAMDisk
	case "cross_device":
		return fsx.ErrCrossDevice
	case "no_space":
		return fsx.ErrNoSpace
	case "unsupported":
		return fsx.ErrUnsupported
	case "confirm_required":
		return fsx.ErrConfirmRequired
	case "queue_full":
		return fsx.ErrQueueFull
	case "worker_gone":
		return fsx.ErrWorkerGone
	case "cancelled":
		return context.Canceled
	}
	return nil
}

func remoteError(e *wproto.Err) error {
	if e == nil {
		return errors.New("the worker reported a failure with no detail")
	}
	return &RemoteError{Code: e.Code, Errno: e.Errno, Message: e.Message, Path: string(e.Path)}
}
