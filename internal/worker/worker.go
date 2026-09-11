// Package worker is the main loop of a per-user worker process: the thing on
// the far end of the socketpair that internal/workerpool spawns.
//
// A worker is this same binary re-executed with -worker, with the kernel
// already holding it to a uid, gid and group set it cannot change back
// (identity plan §2.4). It has no listener, has never read the config file —
// which it could not read anyway — and learns everything it needs from the
// first frame on fd 3. From then on it is the only place in the system where a
// syscall touches user data.
//
// Two rules shape the loop:
//
//   - Requests are served concurrently, one goroutine per request id, so a
//     long job cannot block the interactive listing of the same user (§2.8).
//   - The loop exits on EOF or any decode error, unconditionally. That is the
//     real parent-death guarantee: Pdeathsig is best-effort, but a read on the
//     socketpair returns EOF the moment the front-end goes away, and a worker
//     that outlived its parent would be an unsupervised process holding a
//     user's credentials.
package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// DefaultMaxConcurrent bounds the goroutines one worker will run at once. It
// is a backstop against a front-end bug, not a queue: a request that arrives
// when all slots are taken is refused with queue_full rather than parked, so
// the front-end learns about the overload instead of waiting on it.
const DefaultMaxConcurrent = 64

// GCPercent is the garbage collector target for a worker. Eight workers on a
// 1 GB ARM NAS is the case being defended against (§2.4).
const GCPercent = 40

// Options configures Run.
type Options struct {
	// Version is reported in HelloResp so the front-end can spot a worker
	// left over from an upgraded binary.
	Version string
	// Log receives protocol-level complaints. Never nil after normalise.
	Log *log.Logger
	// Platform is the mount table. Nil means detect it at hello time, which
	// is what the real worker does.
	Platform *platform.Platform
	// IDs resolves uid/gid to names. Nil means open the usual files.
	IDs *idmap.Map
	// MaxConcurrent overrides DefaultMaxConcurrent.
	MaxConcurrent int
	// InProcess suppresses the process-wide side effects of hello — umask and
	// the GC target — because in that mode this "worker" is a goroutine
	// inside the front-end and must not reconfigure it.
	InProcess bool

	// dispatch replaces every operation handler with one function. It is
	// unexported, so only a test in this package can set it, and it exists for
	// the one thing no real filesystem call can be relied on to do: run until
	// its request context is cancelled and not a moment before.
	dispatch func(ctx context.Context, f wproto.Frame) (any, error)
}

func (o Options) normalise() Options {
	if o.Log == nil {
		o.Log = log.New(io.Discard, "", 0)
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = DefaultMaxConcurrent
	}
	return o
}

// Run serves one connection until the peer goes away, sends bye, or the
// framing breaks. In the ordinary case it does not close rw — the process exit
// (or, in-process, the pool) owns that — but an unrecoverable write does close
// it; see session.fatal.
//
// The first frame must be a hello request. Anything else is a protocol error
// and ends the connection, because a worker that started serving before it
// knew its jail root would be serving the wrong filesystem.
func Run(ctx context.Context, rw io.ReadWriter, o Options) error {
	o = o.normalise()
	s := &session{
		tr:       wproto.NewTransport(rw),
		opts:     o,
		sem:      make(chan struct{}, o.MaxConcurrent),
		inflight: map[uint64]context.CancelFunc{},
		jobs:     map[string]context.CancelFunc{},
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.hello(); err != nil {
		return err
	}
	// The jail's descriptor is this worker's; nothing outlives the loop that
	// could still resolve a path through it.
	defer func() { _ = s.root.Close() }()
	return s.serve(ctx)
}

type session struct {
	tr   wproto.Transport
	opts Options

	root fsx.Root
	plat *platform.Platform
	lim  wproto.Limits

	sem chan struct{}
	wg  sync.WaitGroup

	// inflight holds one cancel function per running request, so an OpCancel
	// frame can stop the handler rather than only unregistering the caller at
	// the other end (§2.8). It is guarded by inflightMu, which is never held
	// across a handler or a write.
	inflightMu sync.Mutex
	inflight   map[uint64]context.CancelFunc

	// jobs holds one cancel function per running job, keyed by the JobID the
	// front-end chose (identity plan §2.5). It is separate from inflight
	// because the two identifiers are: a job outlives any single frame, and the
	// front-end's jobs.Manager knows the job by its own id long after it has
	// forgotten which request frame started it. Guarded by jobsMu, which is
	// never held across a handler or a write.
	jobsMu sync.Mutex
	jobs   map[string]context.CancelFunc

	// fatalOnce/fatalErr record the first unrecoverable transport failure.
	fatalOnce sync.Once
	fatalErr  atomic.Pointer[error]
}

// fatal ends the connection on an unrecoverable framing or write failure.
//
// A frame that was only half written desynchronises the stream: every reply
// after it is read as a continuation of this one, so the front-end hands a user
// the wrong listing, or waits forever for a remainder that never comes. There
// is nothing to carry on with and nothing to apologise with either, since the
// apology would go down the same broken stream. The transport is closed, which
// makes the read loop return and this worker exit; the parent sees the socket
// close, reports worker_gone, and spawns a replacement.
func (s *session) fatal(err error) {
	s.fatalOnce.Do(func() {
		s.fatalErr.Store(&err)
		s.opts.Log.Printf("worker: %v; closing the connection", err)
		_ = s.tr.Close()
		s.cancelAll()
	})
}

func (s *session) fatalError() error {
	if p := s.fatalErr.Load(); p != nil {
		return *p
	}
	return nil
}

// begin registers a request's cancel function and returns the context its
// handler runs under. end must be called for every begin.
func (s *session) begin(ctx context.Context, id uint64) (context.Context, context.CancelFunc) {
	rctx, cancel := context.WithCancel(ctx)
	s.inflightMu.Lock()
	s.inflight[id] = cancel
	s.inflightMu.Unlock()
	return rctx, cancel
}

func (s *session) end(id uint64, cancel context.CancelFunc) {
	s.inflightMu.Lock()
	delete(s.inflight, id)
	s.inflightMu.Unlock()
	cancel()
}

// cancelRequest stops one running handler. An id that is not running is not an
// error: the reply and the cancellation race by nature, and the front-end
// sending one for a request that has just finished is the ordinary case.
func (s *session) cancelRequest(id uint64) {
	s.inflightMu.Lock()
	cancel := s.inflight[id]
	s.inflightMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// beginJob registers a running job's cancel function under its JobID.
func (s *session) beginJob(id string, cancel context.CancelFunc) {
	s.jobsMu.Lock()
	s.jobs[id] = cancel
	s.jobsMu.Unlock()
}

// endJob unregisters a job that has finished. The job's own defer cancels its
// context; this only drops the name.
func (s *session) endJob(id string) {
	s.jobsMu.Lock()
	delete(s.jobs, id)
	s.jobsMu.Unlock()
}

// cancelJob stops a running job by its JobID. An id that is not running is not
// an error, for the same reason cancelRequest's is not: the job finishing and
// the user pressing cancel race by nature.
func (s *session) cancelJob(id string) {
	s.jobsMu.Lock()
	cancel := s.jobs[id]
	s.jobsMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// cancelAll stops every running handler, for the case where the connection
// itself has ended. Nothing they produce can be delivered any more, and serve
// waits for them before it returns — so without this, a worker whose front-end
// had gone would sit out a listing of a million files on behalf of nobody.
func (s *session) cancelAll() {
	s.inflightMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.inflight))
	for _, cancel := range s.inflight {
		cancels = append(cancels, cancel)
	}
	s.inflightMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// hello reads the first frame, applies everything it carries, and answers with
// what the kernel actually made this process — not with what it was told to
// be, so the front-end can verify the identity it asked for.
func (s *session) hello() error {
	f, files, err := s.tr.Read()
	closeAll(files)
	if err != nil {
		return fmt.Errorf("reading the hello frame: %w", err)
	}
	if f.Kind != wproto.KindReq || f.Op != wproto.OpHello {
		err := fmt.Errorf("first frame was %s/%s, not a hello request: %w", f.Kind, f.Op, wproto.ErrProtocol)
		_ = s.tr.Write(wproto.NewErr(f.ID, err, nil), nil)
		return err
	}
	var req wproto.HelloReq
	if err := f.Unmarshal(&req); err != nil {
		_ = s.tr.Write(wproto.NewErr(f.ID, err, nil), nil)
		return err
	}

	root, err := fsx.NewRoot(req.JailRoot)
	if err != nil {
		_ = s.tr.Write(wproto.NewErr(f.ID, err, nil), nil)
		return err
	}
	s.root = root
	s.lim = req.Limits

	if !s.opts.InProcess {
		// The umask is set explicitly rather than inherited so created modes
		// are deterministic and do not depend on what App Center's shell left
		// behind (§2.4).
		setUmask(req.Umask)
		debug.SetGCPercent(GCPercent)
	}

	s.plat = s.opts.Platform
	if s.plat == nil {
		s.plat = platform.Detect()
	}
	ids := s.opts.IDs
	if ids == nil {
		ids = idmap.Open("", "")
	}
	fsops.SetIDMap(ids)

	groups, gerr := os.Getgroups()
	if gerr != nil {
		s.opts.Log.Printf("worker: reading the group set: %v", gerr)
	}
	resp := wproto.HelloResp{
		UID:     os.Getuid(),
		GID:     os.Getgid(),
		Groups:  groups,
		PID:     os.Getpid(),
		Version: s.opts.Version,
	}
	ok, err := wproto.NewOK(f.ID, resp)
	if err != nil {
		return err
	}
	return s.tr.Write(ok, nil)
}

// serve is the read loop. It never returns while a handler is still running.
func (s *session) serve(ctx context.Context) error {
	defer s.wg.Wait()
	// bye is non-nil once a goodbye has been accepted, and closes when the
	// goroutine that waits out the running handlers has answered it.
	var bye chan struct{}
	defer func() {
		if bye != nil {
			<-bye
		}
	}()
	for {
		f, files, err := s.tr.Read()
		if err != nil {
			closeAll(files)
			// However the connection ended, nothing a running handler produces
			// can reach anyone now. Stop them before waiting for them.
			s.cancelAll()
			if bye != nil {
				// This is the goodbye closing the transport under us, which is
				// the orderly end of the session rather than a failure.
				return nil
			}
			if ferr := s.fatalError(); ferr != nil {
				// The read only failed because fatal closed the transport
				// underneath it; report what actually went wrong.
				return ferr
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// The front-end is gone. Nothing here is worth reporting as a
				// failure: this is the expected end of every worker's life.
				return nil
			}
			return err
		}
		// Nothing the front-end sends carries a descriptor; accepting one
		// silently would be a leak.
		closeAll(files)

		if f.Kind != wproto.KindReq {
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("%s frames are not requests: %w", f.Kind, wproto.ErrProtocol), nil))
			continue
		}
		if bye != nil && f.Op != wproto.OpCancel {
			// The goodbye has been accepted; only a cancellation for something
			// still running is still useful.
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("this worker is shutting down: %w", fsx.ErrWorkerGone), nil))
			continue
		}

		switch f.Op {
		case wproto.OpBye:
			// Finish what is in flight, then answer and stop. The reply is
			// the front-end's signal that this exit was orderly rather than a
			// crash.
			//
			// The wait happens on its own goroutine and this loop carries on
			// reading. Waiting here instead used to deadlock the whole
			// shutdown: the front-end bounds a request by its own deadline and
			// then tells the worker to cancel it, and on the unbuffered
			// in-process pipe that cancellation blocked forever against a
			// worker that had stopped reading — so the handler never finished,
			// the goodbye never completed, and the process was never signalled.
			bye = make(chan struct{})
			go func(id uint64, answered chan struct{}) {
				defer close(answered)
				s.wg.Wait()
				if ok, err := wproto.NewOK(id, nil); err == nil {
					s.reply(ok)
				}
				// Closing the transport is what ends the read loop, which is
				// still draining frames on purpose.
				_ = s.tr.Close()
			}(f.ID, bye)
			continue
		case wproto.OpHello:
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("hello was already sent: %w", wproto.ErrProtocol), nil))
			continue
		case wproto.OpCancel:
			// Answered on the read loop rather than through the semaphore: a
			// cancellation that queued behind the very requests it is meant to
			// stop would be no cancellation at all.
			s.cancel(f)
			continue
		}

		select {
		case s.sem <- struct{}{}:
		default:
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("%d requests are already running: %w", cap(s.sem), fsx.ErrQueueFull), nil))
			continue
		}
		rctx, cancel := s.begin(ctx, f.ID)
		s.wg.Add(1)
		go func(f wproto.Frame) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.end(f.ID, cancel)
			s.dispatch(rctx, f)
		}(f)
	}
}

// cancel stops the handler an OpCancel frame names and acknowledges it.
func (s *session) cancel(f wproto.Frame) {
	var req wproto.CancelReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if req.ReqID != 0 {
		s.cancelRequest(req.ReqID)
	}
	if req.JobID != "" {
		s.cancelJob(req.JobID)
	}
	s.replyOK(f.ID, nil)
}

func (s *session) reply(f wproto.Frame) {
	if err := s.tr.Write(f, nil); err != nil {
		s.fatal(fmt.Errorf("writing the reply to request %d: %w", f.ID, err))
	}
}

// replyErr answers a request with a classified failure. path is echoed so the
// front-end can name the file without keeping the request around.
func (s *session) replyErr(id uint64, err error, path []byte) {
	s.reply(wproto.NewErr(id, err, path))
}

func (s *session) replyOK(id uint64, v any) {
	f, err := wproto.NewOK(id, v)
	if err != nil {
		s.replyErr(id, err, nil)
		return
	}
	s.reply(f)
}

func (s *session) dispatch(ctx context.Context, f wproto.Frame) {
	if s.opts.dispatch != nil {
		v, err := s.opts.dispatch(ctx, f)
		if err != nil {
			s.replyErr(f.ID, err, nil)
			return
		}
		s.replyOK(f.ID, v)
		return
	}
	switch f.Op {
	case wproto.OpPing:
		s.replyOK(f.ID, nil)
	case wproto.OpList:
		s.list(ctx, f)
	case wproto.OpStat:
		s.stat(ctx, f)
	case wproto.OpReadlink:
		s.readlink(ctx, f)
	case wproto.OpResolve:
		s.resolve(ctx, f)
	case wproto.OpMkdir:
		s.mkdir(ctx, f)
	case wproto.OpRename:
		s.rename(ctx, f)
	case wproto.OpDelete:
		s.delete(ctx, f)
	case wproto.OpOpenRead:
		s.openRead(ctx, f)
	case wproto.OpJob:
		s.runJob(ctx, f)
	case wproto.OpTrashList:
		s.trashList(ctx, f)
	default:
		s.replyErr(f.ID, fmt.Errorf("the %q operation is not implemented by this worker: %w", f.Op, fsx.ErrUnsupported), nil)
	}
}

func (s *session) list(ctx context.Context, f wproto.Frame) {
	var req wproto.ListReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if s.lim.ListMax > 0 && (req.Opts.Limit <= 0 || req.Opts.Limit > s.lim.ListMax) {
		// The worker enforces the front-end's cap itself rather than trusting
		// each request to carry it (§2.4).
		req.Opts.Limit = s.lim.ListMax
	}
	l, err := fsops.List(ctx, s.root, s.plat, string(req.Dir), req.Opts)
	if err != nil {
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	s.replyOK(f.ID, wproto.ListResp{Listing: l})
}

func (s *session) stat(ctx context.Context, f wproto.Frame) {
	var req wproto.StatReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	var (
		e   fsx.Entry
		err error
	)
	if req.Follow {
		e, err = fsops.StatFollow(ctx, s.root, s.plat, string(req.Path))
	} else {
		e, err = fsops.Stat(ctx, s.root, s.plat, string(req.Path))
	}
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, wproto.StatResp{Entry: e})
}

func (s *session) readlink(ctx context.Context, f wproto.Frame) {
	var req wproto.ReadlinkReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	target, err := fsops.Readlink(ctx, s.root, string(req.Path))
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	resp := wproto.ReadlinkResp{Target: []byte(target)}
	if e, err := fsops.Stat(ctx, s.root, s.plat, string(req.Path)); err == nil && e.LinkResolved != "" {
		resp.Resolved = []byte(e.LinkResolved)
	}
	s.replyOK(f.ID, resp)
}

// resolve canonicalises an API path as the user and replies with the canonical
// spelling. It runs the same O_PATH walk every other operation does, so the
// resolution enforces the user's own traversal permissions instead of the root
// front-end resolving symlinks it could reach but the user could not (INV-2).
func (s *session) resolve(ctx context.Context, f wproto.Frame) {
	var req wproto.ResolveReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	api, err := fsops.ResolvePath(ctx, s.root, string(req.Path), req.FollowLeaf)
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, wproto.ResolveResp{Path: []byte(api)})
}

// mkdir creates a directory as the user and replies with the new entry. The
// kernel applies the worker's umask and enforces write permission on the
// parent, so a directory this returns is one the user was allowed to create.
func (s *session) mkdir(ctx context.Context, f wproto.Frame) {
	var req wproto.MkdirReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	e, err := fsops.Mkdir(ctx, s.root, string(req.Dir), string(req.Name), os.FileMode(req.Mode), req.Parents)
	if err != nil {
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	s.replyOK(f.ID, wproto.StatResp{Entry: e})
}

// rename moves one item to another name or directory as the user, and replies
// with an empty ok.
func (s *session) rename(ctx context.Context, f wproto.Frame) {
	var req wproto.RenameReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if err := fsops.Rename(ctx, s.root, string(req.From), string(req.To), req.Overwrite); err != nil {
		s.replyErr(f.ID, err, req.From)
		return
	}
	s.replyOK(f.ID, nil)
}

// delete removes one item as the user (M1: single, non-recursive) and replies
// with an empty ok.
func (s *session) delete(ctx context.Context, f wproto.Frame) {
	var req wproto.DeleteOneReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if err := fsops.Delete(ctx, s.root, string(req.Path)); err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, nil)
}

// openRead answers with the file descriptor itself, on the reply frame. The
// front-end never opens a user's file: it only ever receives one that the
// kernel already agreed this uid could open.
func (s *session) openRead(ctx context.Context, f wproto.Frame) {
	var req wproto.OpenReadReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if !s.tr.PassesFDs() {
		s.replyErr(f.ID, fmt.Errorf("this worker's transport cannot pass a file descriptor: %w", fsx.ErrUnsupported), req.Path)
		return
	}
	file, e, err := fsops.OpenRead(ctx, s.root, string(req.Path))
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	defer file.Close()

	ok, err := wproto.NewOK(f.ID, wproto.OpenReadResp{Entry: e})
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	ok.NFD = 1
	if err := s.tr.Write(ok, []*os.File{file}); err != nil {
		// The descriptor may or may not have reached the front-end, and the
		// frame that says how many arrived may be half written. Neither side
		// can tell any more, so the connection goes.
		s.fatal(fmt.Errorf("passing the descriptor for request %d: %w", f.ID, err))
	}
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
