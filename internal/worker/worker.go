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
// framing breaks. It does not close rw: the process exit (or, in-process, the
// pool) owns that.
//
// The first frame must be a hello request. Anything else is a protocol error
// and ends the connection, because a worker that started serving before it
// knew its jail root would be serving the wrong filesystem.
func Run(ctx context.Context, rw io.ReadWriter, o Options) error {
	o = o.normalise()
	s := &session{
		tr:   wproto.NewTransport(rw),
		opts: o,
		sem:  make(chan struct{}, o.MaxConcurrent),
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.hello(); err != nil {
		return err
	}
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
	for {
		f, files, err := s.tr.Read()
		if err != nil {
			closeAll(files)
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
		switch f.Op {
		case wproto.OpBye:
			// Finish what is in flight, then answer and stop. The reply is
			// the front-end's signal that this exit was orderly rather than a
			// crash.
			s.wg.Wait()
			if ok, err := wproto.NewOK(f.ID, nil); err == nil {
				s.reply(ok)
			}
			return nil
		case wproto.OpHello:
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("hello was already sent: %w", wproto.ErrProtocol), nil))
			continue
		}

		select {
		case s.sem <- struct{}{}:
		default:
			s.reply(wproto.NewErr(f.ID, fmt.Errorf("%d requests are already running: %w", cap(s.sem), fsx.ErrQueueFull), nil))
			continue
		}
		s.wg.Add(1)
		go func(f wproto.Frame) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.dispatch(ctx, f)
		}(f)
	}
}

func (s *session) reply(f wproto.Frame) {
	if err := s.tr.Write(f, nil); err != nil {
		s.opts.Log.Printf("worker: writing a reply to request %d: %v", f.ID, err)
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
	switch f.Op {
	case wproto.OpPing:
		s.replyOK(f.ID, nil)
	case wproto.OpList:
		s.list(ctx, f)
	case wproto.OpStat:
		s.stat(ctx, f)
	case wproto.OpReadlink:
		s.readlink(ctx, f)
	case wproto.OpOpenRead:
		s.openRead(ctx, f)
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
		s.opts.Log.Printf("worker: passing the descriptor for request %d: %v", f.ID, err)
	}
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
