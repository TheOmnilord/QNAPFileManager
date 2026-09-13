package worker

// The worker's half of the upload (M2-C contract §1): two operations and a
// table.
//
// OpOpenWrite creates the file as the user and hands the front-end a descriptor
// for it; OpFinalize publishes or discards what was written. Between them the
// worker holds the inode and the destination directory open, which is what
// makes the whole thing safe: the front-end never names anything, and the
// object being published at Finalize is the very object that was created at
// OpenWrite rather than whatever now answers to a path.
//
// The table is per SESSION, and that word carries the guarantee. A handle
// expires ten minutes after it was opened without a Finalize, and every handle
// still in the table when the session ends is closed — the unnamed ones vanish
// with their descriptors and the named `.qfm-upload-*.part` files are unlinked
// by identity. A worker that dies takes them all with it for free, which is the
// same property the descriptor discipline gives everything else here.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"time"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// uploadIdleTimeout is contract §1.3's ten minutes: how long a handle survives
// without a Finalize.
//
// It is a bound on a RESOURCE, not on an upload. The clock starts when the
// descriptor is handed over, and a transfer that is still running has a
// front-end holding the other end of it — but a browser that was closed mid-way
// leaves nothing to notice, and an unfinalised handle holds two descriptors and
// (on the fallback path) a `.part` file in somebody's folder. Ten minutes is
// long enough for a slow upload of something a browser would attempt and short
// enough that abandoned ones do not accumulate.
const uploadIdleTimeout = 10 * time.Minute

// maxUploadHandles bounds how many unfinished uploads one session may hold. It
// is the request semaphore's number for the same reason: each handle costs two
// descriptors, and a front-end bug that opened uploads and never finalised them
// would otherwise exhaust the worker's file table rather than being told it is
// overloaded.
const maxUploadHandles = 64

// now is the clock the expiry is measured against.
//
// It is a session field rather than a package variable because a test that
// replaced a global would be writing it while a worker goroutine reads it,
// which is a data race whether or not the two ever overlap in wall time.
// Options.now is unexported, exactly as Options.dispatch is, so only a test in
// this package can supply one.
func (s *session) now() time.Time {
	if s.opts.now != nil {
		return s.opts.now()
	}
	return time.Now()
}

// uploadSweepInterval is how often a session looks for expired handles and
// stale archive records on its own, without being asked (adversarial finding
// 3). It is a minute because the thing it is enforcing is ten: a tick that
// costs one map walk over a table of at most sixty-four entries, once a minute,
// against a handle that would otherwise hold two descriptors and a `.part` file
// for as long as the user keeps the session open.
const uploadSweepInterval = time.Minute

// sweeper is that tick. It ends with the session.
//
// The ticker is wall-clock — there is nothing else for a real worker to tick on
// — while what it compares against is s.now(), so a test with its own clock
// still decides what counts as expired; it simply calls sweepUploads directly
// rather than waiting for the tick.
func (s *session) sweeper(stop <-chan struct{}) {
	t := time.NewTicker(uploadSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.sweepUploads()
			s.sweepArchives()
		}
	}
}

// uploadEntry is one handle in the session's table.
type uploadEntry struct {
	h       *fsops.UploadHandle
	opened  time.Time
	apiPath string
}

// openWrite creates the upload's file as the user and answers with its
// descriptor on the reply frame, plus the opaque handle id.
//
// The descriptor direction is the only one there is (identity plan §2.5): it
// travels worker → front-end. The front-end never opens a user's file, and what
// it is given here is an inode the kernel already agreed this uid could create
// in this directory.
func (s *session) openWrite(ctx context.Context, f wproto.Frame) {
	var req wproto.OpenWriteReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if !s.tr.PassesFDs() {
		s.replyErr(f.ID, fmt.Errorf("this worker's transport cannot pass a file descriptor: %w", fsx.ErrUnsupported), req.Dir)
		return
	}
	// Every upload operation sweeps too. The session's own tick is what makes
	// the expiry independent of upload traffic (sweeper); this is what makes it
	// immediate for the case that matters most — the next upload into the same
	// folder, which would otherwise meet a `.part` nobody is writing to.
	s.sweepUploads()

	id, err := handleID()
	if err != nil {
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	file, h, err := fsops.OpenWrite(ctx, s.root, s.plat, req)
	if err != nil {
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	// The front-end's copy is closed here whatever happens next: it has either
	// been sent — in which case the kernel duplicated it into the socket and
	// this process has no further use for it — or it never will be.
	defer file.Close()

	if err := s.addUpload(id, h); err != nil {
		h.Close()
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	ok, err := wproto.NewOK(f.ID, wproto.OpenWriteResp{Tmp: []byte(id)})
	if err != nil {
		s.dropUpload(id)
		s.replyErr(f.ID, err, req.Dir)
		return
	}
	ok.NFD = 1
	if err := s.tr.Write(ok, []*os.File{file}); err != nil {
		// The descriptor may or may not have reached the front-end and the frame
		// that says how many arrived may be half written, so neither side can
		// tell any more: the connection goes (openRead's rule). The handle goes
		// with it, because a front-end that never learned the id could never
		// finalise or discard it.
		s.dropUpload(id)
		s.fatal(fmt.Errorf("passing the upload descriptor for request %d: %w", f.ID, err))
	}
}

// finalize publishes or discards one upload.
//
// The handle is TAKEN out of the table before anything is done with it, so two
// Finalize frames for one id cannot both act on the same inode: the second
// finds nothing and is answered with "not found", which is also the answer for
// an id that expired.
func (s *session) finalize(ctx context.Context, f wproto.Frame) {
	var req wproto.FinalizeReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	s.sweepUploads()
	ent := s.takeUpload(string(req.Tmp))
	if ent == nil {
		s.replyErr(f.ID, fmt.Errorf("this upload is not in progress on this worker (it may have expired): %w", fs.ErrNotExist), req.Final)
		return
	}
	// fsops.Finalize consumes the handle on every path, published or not.
	resp, err := fsops.Finalize(ctx, ent.h, req)
	if err != nil {
		s.replyErr(f.ID, err, []byte(ent.apiPath))
		return
	}
	s.replyOK(f.ID, resp)
}

// addUpload registers a handle, refusing rather than growing without bound.
func (s *session) addUpload(id string, h *fsops.UploadHandle) error {
	s.uploadsMu.Lock()
	defer s.uploadsMu.Unlock()
	if s.uploads == nil {
		s.uploads = map[string]*uploadEntry{}
	}
	if len(s.uploads) >= maxUploadHandles {
		return fmt.Errorf("%d uploads are already open on this worker and none has been finished: %w",
			len(s.uploads), fsx.ErrQueueFull)
	}
	if _, taken := s.uploads[id]; taken {
		// Sixteen random hex digits colliding means the random source is not
		// one, which is not something to carry on through.
		return fmt.Errorf("the upload id %q is already in use: %w", id, fsx.ErrUnsupported)
	}
	s.uploads[id] = &uploadEntry{h: h, opened: s.now(), apiPath: h.Path()}
	return nil
}

// takeUpload removes one handle from the table and hands it over. The caller
// owns it from then on.
func (s *session) takeUpload(id string) *uploadEntry {
	if id == "" {
		return nil
	}
	s.uploadsMu.Lock()
	defer s.uploadsMu.Unlock()
	ent := s.uploads[id]
	delete(s.uploads, id)
	return ent
}

// dropUpload takes a handle and throws it away.
func (s *session) dropUpload(id string) {
	if ent := s.takeUpload(id); ent != nil {
		ent.h.Close()
	}
}

// sweepUploads closes every handle that has been open for longer than
// uploadIdleTimeout without being finalised.
func (s *session) sweepUploads() {
	now := s.now()
	var stale []*uploadEntry
	s.uploadsMu.Lock()
	for id, ent := range s.uploads {
		if now.Sub(ent.opened) >= uploadIdleTimeout {
			delete(s.uploads, id)
			stale = append(stale, ent)
		}
	}
	s.uploadsMu.Unlock()
	// Closed outside the lock: the named fallback's cleanup makes syscalls, and
	// the table's mutex is never held across one.
	for _, ent := range stale {
		s.opts.Log.Printf("worker: the upload of %q was never finished and was thrown away after %s",
			ent.apiPath, uploadIdleTimeout)
		ent.h.Close()
	}
}

// closeUploads throws away every unfinished upload. It runs when the session
// ends, however it ends, which is what makes "per session" the guarantee it
// sounds like.
func (s *session) closeUploads() {
	s.uploadsMu.Lock()
	all := make([]*uploadEntry, 0, len(s.uploads))
	for id, ent := range s.uploads {
		delete(s.uploads, id)
		all = append(all, ent)
	}
	s.uploadsMu.Unlock()
	for _, ent := range all {
		s.opts.Log.Printf("worker: the session ended with the upload of %q unfinished; it was thrown away", ent.apiPath)
		ent.h.Close()
	}
}

// handleID is the opaque handle the wire carries: sixteen hex digits of
// crypto/rand.
//
// It is unguessable on purpose. The id is the only thing that names an open
// inode belonging to this user, and a predictable one would let anything that
// could reach the socket finalise somebody else's upload into a name of its
// choosing — on a socket only the front-end holds, which is why this is defence
// in depth rather than the whole of it.
func handleID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
