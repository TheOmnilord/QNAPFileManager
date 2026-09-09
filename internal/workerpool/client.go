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
	pending     map[uint64]chan result
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

func newClient(who backend.Principal) *client {
	return &client{
		key:     who.Key(),
		who:     who,
		cred:    credsOf(who),
		exited:  make(chan struct{}),
		gone:    make(chan struct{}),
		pending: map[uint64]chan result{},
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
	waiting := make([]chan result, 0, len(c.pending))
	ids := make([]uint64, 0, len(c.pending))
	for id, ch := range c.pending {
		waiting = append(waiting, ch)
		ids = append(ids, id)
	}
	c.pending = map[uint64]chan result{}
	c.mu.Unlock()

	for i, ch := range waiting {
		select {
		case ch <- result{f: wproto.NewErr(ids[i], cause, nil)}:
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

func (c *client) deliver(f wproto.Frame, files []*os.File, terminal bool, logger *log.Logger) {
	c.mu.Lock()
	ch, ok := c.pending[f.ID]
	if ok && terminal {
		delete(c.pending, f.ID)
	}
	c.mu.Unlock()
	if !ok {
		// A reply to a call that has already given up (its context expired).
		// The descriptor it carries is ours to close, or it leaks in the root
		// front-end for as long as the daemon runs.
		closeAll(files)
		if logger != nil {
			logger.Printf("workerpool: %s sent a reply for the unknown request %d", c.key, f.ID)
		}
		return
	}
	select {
	case ch <- result{f: f, files: files}:
	default:
		closeAll(files)
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
	ch := make(chan result, 1)

	c.mu.Lock()
	if c.dead {
		err := c.deadErr
		c.mu.Unlock()
		if err == nil {
			err = workerGone(c.key, nil)
		}
		return wproto.Frame{}, nil, err
	}
	c.pending[id] = ch
	c.calls++
	c.mu.Unlock()

	if err := c.tr.Write(req, nil); err != nil {
		c.unregister(id)
		gone := workerGone(c.key, err)
		c.fail(gone)
		return wproto.Frame{}, nil, gone
	}

	select {
	case r := <-ch:
		if r.f.Kind == wproto.KindErr {
			closeAll(r.files)
			return wproto.Frame{}, nil, remoteError(r.f.Err)
		}
		return r.f, r.files, nil
	case <-c.gone:
		c.unregister(id)
		if err := c.deadError(); err != nil {
			return wproto.Frame{}, nil, err
		}
		return wproto.Frame{}, nil, workerGone(c.key, nil)
	case <-ctx.Done():
		c.unregister(id)
		return wproto.Frame{}, nil, ctx.Err()
	}
}

func (c *client) unregister(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
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
