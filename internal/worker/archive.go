package worker

// The worker's half of the archive download (M2-C contract §2): validate,
// answer with a pipe, then walk the trees into it.
//
// The order is the whole design. Everything that could be an honest error frame
// — an unknown format, no paths at all, a root the user cannot reach — is
// decided BEFORE the reply, because once the reply has gone the front-end is
// already streaming bytes to a browser and the only way left to say "that
// failed" is to truncate the archive. After the reply there is no error
// channel, and none is pretended: the walk's own per-item failures go into an
// ERROR.txt member inside the archive itself.
//
// The goroutine runs under the SESSION's context, not the request's. The
// request ends the moment the pipe has been handed over — that is what the
// reply frame means — and a walk bounded by it would be cancelled before it had
// written a byte. What stops it is the front-end closing its end of the pipe
// (the client went away, and the walk ends quietly on EPIPE) or the session
// ending, which cancels the context underneath it.

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"time"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// maxArchiveStreams bounds the producers one session may run at once (M2-C
// review round 1, finding 2).
//
// MaxConcurrent bounds nothing here, and that is the point of this number
// existing at all: an OpArchive hands over a pipe and RETURNS, so its request
// slot is given back while the producer is still walking a share. Without a
// bound of its own, a front-end bug — or a user holding down a toolbar button —
// would start one producer per click, each holding a pipe, a transfer buffer, a
// deflate window and a stack of open directory descriptors, on a NAS with a
// gigabyte of memory.
//
// Two is the byte-mover job class's number, and for the same reason: an archive
// is bounded by the disk it reads, so a third concurrent one makes nothing
// finish sooner. Past it the answer is queue_full, which the route turns into a
// 429 — an honest "try again in a moment" rather than a download that dies of
// exhaustion half way through.
const maxArchiveStreams = 2

const (
	// maxArchiveRecords bounds the outcomes one session remembers, and
	// archiveRecordTTL how long it remembers them. The front-end asks for a
	// verdict immediately after its copy loop ends, so ten minutes is
	// generous; the count is what stops a long session from accumulating one
	// record per download.
	maxArchiveRecords = 32
	archiveRecordTTL  = 10 * time.Minute
)

// archiveRecord is one producer's life, from the reply that started it to the
// verdict the front-end audits.
type archiveRecord struct {
	started time.Time
	done    bool
	ended   time.Time
	resp    wproto.ArchiveStatusResp
}

func (s *session) archive(ctx context.Context, f wproto.Frame) {
	var req wproto.ArchiveReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if !s.tr.PassesFDs() {
		s.replyErr(f.ID, fmt.Errorf("this worker's transport cannot pass a file descriptor: %w", fsx.ErrUnsupported),
			firstPath(req.Paths))
		return
	}
	plan, err := fsops.ArchiveCheck(ctx, s.root, s.plat, req)
	if err != nil {
		s.replyErr(f.ID, err, firstPath(req.Paths))
		return
	}
	// Reserved BEFORE the pipe is handed over, because after the reply there is
	// no way left to refuse: the front-end is already streaming to a browser.
	select {
	case s.archiveSem <- struct{}{}:
	default:
		s.replyErr(f.ID, fmt.Errorf("%d archives are already being written by this worker: %w",
			maxArchiveStreams, fsx.ErrQueueFull), firstPath(req.Paths))
		return
	}
	// From here every path either starts the producer (which releases the slot
	// when it exits) or gives the slot back itself.
	release := func() { <-s.archiveSem }

	id, err := s.startArchive()
	if err != nil {
		release()
		s.replyErr(f.ID, err, firstPath(req.Paths))
		return
	}
	rp, wp, err := os.Pipe()
	if err != nil {
		s.forgetArchive(id)
		release()
		s.replyErr(f.ID, err, firstPath(req.Paths))
		return
	}
	ok, err := wproto.NewOK(f.ID, wproto.ArchiveResp{Name: plan.Name, ID: id})
	if err != nil {
		rp.Close()
		wp.Close()
		s.forgetArchive(id)
		release()
		s.replyErr(f.ID, err, firstPath(req.Paths))
		return
	}
	ok.NFD = 1
	werr := s.tr.Write(ok, []*os.File{rp})
	// Our copy of the READ end goes now, whether or not it was sent. Keeping it
	// would mean the pipe never reports EPIPE when the front-end lets go, so a
	// cancelled download would archive a whole share into a buffer nobody reads.
	rp.Close()
	if werr != nil {
		wp.Close()
		s.forgetArchive(id)
		release()
		// The descriptor may or may not have arrived and the frame may be half
		// written: neither side can tell any more (openRead's rule).
		s.fatal(fmt.Errorf("passing the archive pipe for request %d: %w", f.ID, werr))
		return
	}

	// Deliberately not registered with the session's WaitGroup. A goodbye waits
	// for that group before it answers, and an archive of a 200 GB share would
	// then hold the shutdown open for as long as the client cared to read. The
	// session context is what stops this instead, and the pipe's write end is
	// closed by the deferred pair below — after the verdict is recorded, and on
	// every path including a panic.
	go func() {
		// The slot comes back however this ends — complete, cancelled, or the
		// reader going away — which is the only thing that makes the bound a
		// bound rather than a quota that runs out once.
		defer release()

		// The pessimistic verdict, so that even a panic inside the walk records
		// something truthful rather than leaving a producer that looks like it
		// is still running for ever.
		res := fsops.ArchiveResult{
			Truncated: true,
			Reason:    "the archive stopped before it reported an outcome",
		}
		// The ORDER here is the whole of round 2's finding, and it is by
		// construction rather than by luck. This worker holds the only write end
		// of the pipe, so the front-end cannot see EOF until wp.Close() runs —
		// and that happens strictly after endArchive has put the verdict in the
		// table, under its lock. There is therefore no instant at which "the
		// stream ended" and "there is no verdict yet" are both true: a status
		// request that follows EOF always finds the answer. Closing inside
		// fsops.Archive got this backwards, and a front-end that asked the
		// moment it saw EOF audited a finished download as unknown.
		defer func() {
			s.endArchive(id, res)
			wp.Close()
		}()

		var err error
		res, err = fsops.Archive(s.sessionCtx(), s.root, s.plat, req, plan, wp)
		if err != nil {
			s.opts.Log.Printf("worker: the archive of %s ended early: %v", firstPath(req.Paths), err)
		}
	}()
}

// startArchive registers a producer that is about to begin, and returns the id
// the reply carries.
//
// The record exists so that OpArchiveStatus can be answered after the pipe has
// closed. It is bounded two ways — a count and an age — because a worker that
// remembered every download of a long session would be a slow leak in the one
// process that must not have any.
func (s *session) startArchive() (string, error) {
	id, err := handleID()
	if err != nil {
		return "", err
	}
	s.archivesMu.Lock()
	defer s.archivesMu.Unlock()
	if s.archives == nil {
		s.archives = map[string]*archiveRecord{}
	}
	s.pruneArchivesLocked(s.now())
	s.archives[id] = &archiveRecord{started: s.now()}
	return id, nil
}

// forgetArchive drops a record whose producer never started, so a reply that
// could not be sent does not leave a "still running" verdict behind.
func (s *session) forgetArchive(id string) {
	s.archivesMu.Lock()
	delete(s.archives, id)
	s.archivesMu.Unlock()
}

// endArchive records a producer's verdict.
func (s *session) endArchive(id string, res fsops.ArchiveResult) {
	s.archivesMu.Lock()
	defer s.archivesMu.Unlock()
	rec := s.archives[id]
	if rec == nil {
		// Pruned while it ran, which only a pathological session reaches. The
		// front-end then gets "not found", which is the honest answer.
		return
	}
	rec.done = true
	rec.ended = s.now()
	rec.resp = wproto.ArchiveStatusResp{
		Done:      true,
		Truncated: res.Truncated,
		Bytes:     res.Bytes,
		Error:     res.Reason,
	}
}

// archiveStatus answers what became of one archive (adversarial finding 6).
//
// An id this worker has no record of is not_found rather than a guess: it may
// have expired, or belong to a worker that has been replaced, and answering
// "complete" for either would be exactly the lie this operation exists to
// prevent.
func (s *session) archiveStatus(_ context.Context, f wproto.Frame) {
	var req wproto.ArchiveStatusReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	s.archivesMu.Lock()
	rec := s.archives[req.ID]
	var resp wproto.ArchiveStatusResp
	if rec != nil {
		resp = rec.resp
		resp.Done = rec.done
	}
	s.archivesMu.Unlock()
	if rec == nil {
		s.replyErr(f.ID, fmt.Errorf("this worker has no record of the archive %q: %w", req.ID, fs.ErrNotExist), nil)
		return
	}
	s.replyOK(f.ID, resp)
}

// pruneArchivesLocked drops the records nobody is going to ask about: the ones
// that ended longer ago than archiveRecordTTL, and — when the table is full —
// the oldest finished one. A RUNNING producer is never dropped, because its
// record is the only place its verdict can land.
func (s *session) pruneArchivesLocked(now time.Time) {
	for id, rec := range s.archives {
		if rec.done && now.Sub(rec.ended) >= archiveRecordTTL {
			delete(s.archives, id)
		}
	}
	for len(s.archives) >= maxArchiveRecords {
		var (
			oldestID  string
			oldestRec *archiveRecord
		)
		for id, rec := range s.archives {
			if !rec.done {
				continue
			}
			if oldestRec == nil || rec.ended.Before(oldestRec.ended) {
				oldestID, oldestRec = id, rec
			}
		}
		if oldestRec == nil {
			// Every record is a running producer, which maxArchiveStreams makes
			// impossible past two. Nothing to drop and nothing to do about it.
			return
		}
		delete(s.archives, oldestID)
	}
}

// sweepArchives drops expired records on the session's own tick, so a worker
// that served one download and then browsed for an hour does not keep the
// record of it.
func (s *session) sweepArchives() {
	s.archivesMu.Lock()
	defer s.archivesMu.Unlock()
	now := s.now()
	for id, rec := range s.archives {
		if rec.done && now.Sub(rec.ended) >= archiveRecordTTL {
			delete(s.archives, id)
		}
	}
}

// firstPath names the selection in an error frame. One path is all the frame
// has room for, and the first is the one a user recognises.
func firstPath(paths [][]byte) []byte {
	if len(paths) == 0 {
		return nil
	}
	return paths[0]
}

// sessionCtx is the context everything that outlives one request runs under. It
// is set when the serve loop starts; the fallback keeps a unit test that drives
// a handler directly from panicking on a nil context.
func (s *session) sessionCtx() context.Context {
	if s.sessCtx != nil {
		return s.sessCtx
	}
	return context.Background()
}
