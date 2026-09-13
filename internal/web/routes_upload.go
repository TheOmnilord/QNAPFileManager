package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/wproto"
)

// The upload route emits exactly one notice sentence (noticeOverwrite from
// the transfer route, which is shared). The client grades its confirm dialog
// by recognising this sentence, and treats any other summary line as a guard
// reason that demands the typed phrase. TestUploadNoticesArePinnedToTheClient
// keeps the client and server in sync.
// refuseUpload wraps a ResponseWriter to close the connection on any response
// written before the body has been fully consumed. This prevents Chrome and
// similar clients from silently retrying when an error occurs early (readiness,
// validation, guard, auth, OpenWrite, multipart parsing) and the connection
// stays open. The 201 success response does NOT use this wrapper to preserve
// keep-alive for connection pooling.
//
// Early errors write a non-2xx status before io.CopyBuffer reads any body bytes.
// If the connection stays open, the client may retry the same POST, creating
// duplicates when conflict=rename (producing (2), (3), etc. copies).
func refuseUpload(w http.ResponseWriter) http.ResponseWriter {
	return uploadRefusal{w}
}

type uploadRefusal struct{ http.ResponseWriter }

func (w uploadRefusal) WriteHeader(code int) {
	if code < 200 || code >= 300 {
		// Any error response before body is fully read closes the connection.
		w.Header().Set("Connection", "close")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w uploadRefusal) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap is how http.ResponseController reaches the real ResponseWriter, and so
// the connection underneath it. Without it SetReadDeadline answers
// ErrNotSupported and the upload stall timeout silently does nothing — which is
// exactly what happened the first time this was wired up, because serve()
// wraps every upload POST in this type before the handler ever sees it.
func (w uploadRefusal) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// --- concurrency and stall limits (round-7 adversarial P1) -------------------
//
// An upload request holds front-end memory from the moment it starts reading
// until it finishes, and until this was added nothing bounded how many could be
// doing that at once. The worker's own handle limit and its expiry sweep only
// begin at OpenWrite, and a multipart request that never sends its first
// boundary never gets there: it sits blocked in NextPart, holding the megabyte
// copy buffer, with no read deadline of any kind. Ninety-six of them — which
// one ordinary user can open from one browser — retained 96.7 MiB in a daemon
// running as root, with not a single OpenWrite call to show for it.
//
// Three things close it, and all three are needed. A slot bounds how many
// uploads may be in flight at all. The buffer is not allocated until bytes are
// actually being copied, so the requests that are waiting hold nothing. And a
// read deadline drops a request that has stopped sending, which is what turns
// "holds memory forever" into "holds memory for half a minute".
const (
	// maxUploadsPerSession is what one browser may have in flight. Chrome opens
	// six connections to an origin, so four leaves an honest client room to
	// pipeline without letting one session take the whole daemon.
	maxUploadsPerSession = 4
	// maxUploadsTotal is the process-wide ceiling, and with the buffer below it
	// is also the ceiling on copy-buffer memory: 32 MiB.
	maxUploadsTotal = 32
	// uploadCopyBuffer is the copy buffer, allocated only once bytes are moving.
	uploadCopyBuffer = 1 << 20
	// uploadStallWindow is how long a request may go without producing a byte
	// before it is dropped. It is an IDLE timeout, not a throughput floor — see
	// uploadDeadline.sawBytes.
	uploadStallWindow = 30 * time.Second
	// uploadExtendEvery is how much data may pass before the window is re-armed,
	// which bounds the SetReadDeadline syscalls on a fast upload.
	uploadExtendEvery = 1 << 20
	// maxMultipartTail is how much of a multipart body AFTER the file part this
	// end will read before giving up on it and closing the connection instead.
	// A closing boundary is tens of bytes and a few trailing form fields are a
	// few hundred; 64 KiB is far past anything honest and small enough that
	// reading it is never the slow part.
	maxMultipartTail = 64 << 10
)

// uploadLimiter is the slot store: how many uploads each session has in flight
// and how many the process does. The zero value works and uses the constants
// above; the limits and the window are settable for tests, before serving, the
// way Server.Now is.
type uploadLimiter struct {
	perSessionLimit, totalLimit int
	window                      time.Duration

	mu         sync.Mutex
	perSession map[string]int
	total      int
}

func (u *uploadLimiter) limits() (int, int) {
	perSession, total := u.perSessionLimit, u.totalLimit
	if perSession <= 0 {
		perSession = maxUploadsPerSession
	}
	if total <= 0 {
		total = maxUploadsTotal
	}
	return perSession, total
}

func (u *uploadLimiter) stallWindow() time.Duration {
	if u.window > 0 {
		return u.window
	}
	return uploadStallWindow
}

// acquire takes a slot for one request, or reports which ceiling refused it.
func (u *uploadLimiter) acquire(sessionID string) (release func(), reason string) {
	perSession, total := u.limits()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.total >= total {
		return nil, "The server is handling as many uploads as it can. Try again in a moment."
	}
	if u.perSession[sessionID] >= perSession {
		return nil, "This session already has as many uploads in flight as it may. Let one finish first."
	}
	if u.perSession == nil {
		u.perSession = make(map[string]int)
	}
	u.perSession[sessionID]++
	u.total++
	var once sync.Once
	return func() {
		once.Do(func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			if u.perSession[sessionID] <= 1 {
				delete(u.perSession, sessionID)
			} else {
				u.perSession[sessionID]--
			}
			if u.total > 0 {
				u.total--
			}
		})
	}, ""
}

// uploadDeadline drives the request body's read deadline. It is armed before
// the first read and re-armed as data arrives, so a client that is still
// sending is never dropped and one that has stopped is dropped within a window.
//
// Re-arming happens after another megabyte OR after half a window, whichever
// comes first. The second clause is the difference between an idle timeout and
// a throughput floor: re-arming on bytes alone would drop a live upload that
// simply moves less than a megabyte per window — 35 KB/s, which is an ordinary
// phone on a bad connection — and dropping a client that is doing exactly what
// was asked of it is not a memory fix, it is a bug. The clause costs one clock
// read per Read call and at most two syscalls per window.
//
// A platform (or a test's ResponseRecorder) that has no read deadline turns the
// whole thing off at the first refusal rather than asking again on every byte;
// the slot limit still bounds those.
type uploadDeadline struct {
	rc     *http.ResponseController
	window time.Duration
	armed  time.Time
	next   int64
	off    bool
}

func (d *uploadDeadline) arm(total int64) {
	if d.off {
		return
	}
	// Wall-clock deliberately, not Server.now: this is a deadline on a socket,
	// and a test that freezes the server's clock must not freeze the network.
	now := time.Now()
	if err := d.rc.SetReadDeadline(now.Add(d.window)); err != nil {
		d.off = true
		return
	}
	d.armed, d.next = now, total+uploadExtendEvery
}

func (d *uploadDeadline) sawBytes(total int64) {
	if d.off {
		return
	}
	if total >= d.next || time.Since(d.armed) >= d.window/2 {
		d.arm(total)
	}
}

// clear drops the read deadline once the body is in. Everything after this
// point — Close, Finalize, the worker's rename and fsync — is OUR work, and a
// window meant for a client that stopped sending must not be measuring it. A
// slow finalize on a busy volume would otherwise return 408 for an upload that
// arrived in full (round-13 P2).
func (d *uploadDeadline) clear() {
	if d.off {
		return
	}
	if err := d.rc.SetReadDeadline(time.Time{}); err != nil {
		d.off = true
	}
}

// uploadStalled reports whether an error ending a body read is this end giving
// up on a silent client rather than the client sending something malformed. A
// timeout must not be reported as a bad request: the request was fine, it just
// stopped arriving.
func uploadStalled(err error, r *http.Request) bool {
	if r.Context().Err() != nil {
		return true
	}
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, sess *session) {
	// Method and the three CSRF locks are enforced by serve/authenticate before
	// dispatch, including for non-JSON bodies.
	if !s.mutationsReady(w, r) {
		return
	}

	// Before the buffer and before the body: a request that cannot have a slot
	// must not get as far as holding anything. Released on every exit, including
	// the confirmation round trip's 409 and every validation refusal below.
	release, refusal := s.uploads.acquire(sess.id)
	if refusal != "" {
		s.fail(refuseUpload(w), r, "queue_full", refusal, "", "")
		return
	}
	defer release()

	q := r.URL.Query()
	dir, err := bodyPath(q.Get("dir"), q.Get("dirB64"))
	name, conflict := q.Get("name"), q.Get("conflict")
	if err != nil {
		s.fail(refuseUpload(w), r, "bad_request", "Supply a valid folder and file name.", "", "")
		return
	}
	// validNewName, not fsx.ValidName: the upload name is a component the client
	// invents, and it was the one that escaped the NAME_MAX rule bodyPath applies
	// to every component of dir. A hundred CJK characters is a perfectly ordinary
	// Windows filename and 300 bytes here, so the name passed validation, the
	// worker created the inode, the whole body streamed across, and only
	// Finalize's lstat came back ENAMETOOLONG — a large upload spent end to end
	// for a name the kernel was never going to accept. Refused here instead:
	// before the guard, before the audit intent, before a single body byte is
	// read, and through refuseUpload so the connection closes rather than
	// inviting the client to retry the same POST.
	if nameErr := validNewName(name); nameErr != nil {
		// The length case gets its own sentence rather than the generic one: the
		// name came from a file picker, not from something the user typed, and
		// "supply a valid file name" is no help at all when the name looks
		// perfectly ordinary on the machine it came from. The UI shows message
		// and not detail, so the reason has to be in the message.
		message := "Supply a valid folder and file name."
		if len(name) > maxComponentBytes {
			message = "That file's name is longer than " + strconv.Itoa(maxComponentBytes) + " bytes, which is more than the filesystem allows. Rename it and try again."
		}
		s.fail(refuseUpload(w), r, "bad_request", message, "", nameErr.Error())
		return
	}

	if conflict == "" {
		conflict = wproto.ConflictSkip
	}

	switch conflict {
	case wproto.ConflictSkip, wproto.ConflictOverwrite, wproto.ConflictRename:
	default:
		s.fail(refuseUpload(w), r, "bad_request", "Supply conflict as skip, overwrite or rename.", "", "")
		return
	}

	var size, mtime int64
	for key, dst := range map[string]*int64{"size": &size, "mtime": &mtime} {
		if q.Has(key) {
			*dst, err = strconv.ParseInt(q.Get(key), 10, 64)
			if err != nil || key == "size" && *dst < 0 {
				s.fail(refuseUpload(w), r, "bad_request", "Invalid upload size or modification time.", "", "")
				return
			}
		}
	}

	rdir, err := s.resolveForGuard(r.Context(), sess.who, dir, true)
	if err != nil {
		s.failResolve(refuseUpload(w), r, dir, err)
		return
	}

	target, rtarget := fsx.Join(dir, name), fsx.Join(rdir, name)
	m := mutation{op: "upload", path: target, bytes: size}

	var verdicts []error
	summary := guard.Summary{Files: 1, Bytes: size}

	seen := map[string]bool{}

	warn := func(reason string) {
		if reason != "" && !seen[reason] {
			seen[reason] = true
			summary.Warnings = append(summary.Warnings, reason)
		}
	}

	for _, p := range []string{dir, target, rdir, rtarget} {
		verdicts = append(verdicts, s.guard.Check(guard.OpCreate, p))
		for _, reason := range s.guard.Reasons(guard.OpCreate, p) {
			warn(reason)
		}

		if hit, ok := s.guard.Contains(p); ok {
			v := guard.ErrConfirmRequired
			if hit.Deny {
				v = guard.ErrProtected
			}

			verdicts = append(verdicts, v)
			warn(hit.Reason)
		}
	}

	overwrite := conflict == wproto.ConflictOverwrite
	if overwrite {
		warn(noticeOverwrite)
	}

	parts := []string{"op=upload", "conflict=" + conflict, "dest=" + rtarget}

	if !s.authorize(refuseUpload(w), r, sess, worstGuard(verdicts...), overwrite, m, target, parts, true, q.Get("confirm"), summary) {
		// Flush the complete response now. Connection: close lets net/http close
		// the unread body without draining an arbitrarily large upload first.
		if w.Header().Get("Connection") == "close" {
			_ = http.NewResponseController(w).Flush()
		}

		return
	}

	// Bind the open to the directory that was just cleared, not to its name.
	// Everything above authorized a PATHNAME, and the worker does not open the
	// destination until the file part's headers arrive — a gap the client
	// controls: rename the authorized directory away, drop a symlink into the
	// install tree in its place, then send the body, and the write lands
	// somewhere the guard never saw (round-13 P1). Taken here, before any part
	// is read, so the identity is the one the verdict was made about.
	//
	// A build with no job spine (a fixture, the placeholder server in cmd) has
	// nothing to ask; the worker then simply opens by name as before.
	var dirIdentity *wproto.FSIdentityResp
	if s.jobRunner != nil {
		id, err := s.jobRunner.FSIdentity(r.Context(), sess.who, rdir)
		if err != nil {
			// The directory we resolved a moment ago cannot be identified now.
			// Whatever the reason, this upload cannot be bound to it, and going
			// ahead unbound is the very thing this exists to prevent.
			s.failResolve(refuseUpload(w), r, dir, err)
			return
		}
		dirIdentity = &id
	}

	// The copy buffer is NOT allocated here. A multipart request that stalls
	// before its first boundary waits inside NextPart below, and it used to wait
	// holding this megabyte; now it holds a slot and nothing else, and the
	// allocation happens only once there are bytes to move.
	var buf []byte
	copyBuf := func() []byte {
		if buf == nil {
			buf = make([]byte, uploadCopyBuffer)
		}
		return buf
	}
	// Armed before the first read of the body, whichever shape it has.
	deadline := &uploadDeadline{rc: http.NewResponseController(w), window: s.uploads.stallWindow()}
	deadline.arm(0)
	stalled := func(err error, message string) {
		if uploadStalled(err, r) {
			s.fail(refuseUpload(w), r, "cancelled", "The upload stopped sending and was dropped.", target, "")
			return
		}
		s.fail(refuseUpload(w), r, "bad_request", message, target, "")
	}

	var source io.Reader = r.Body
	media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	multipartBody := media == "multipart/form-data"
	if multipartBody {
		mr, err := r.MultipartReader()
		if err != nil || mediaErr != nil {
			stalled(err, "Invalid multipart upload.")
			return
		}

		for {
			part, err := mr.NextPart()
			if err != nil {
				stalled(err, "Supply a file in the multipart upload.")
				return
			}

			if part.FileName() != "" {
				source = part
				break
			}

			skip := &uploadReader{downloadReader: downloadReader{ctx: r.Context(), reader: part}, deadline: deadline}
			if _, err := io.CopyBuffer(io.Discard, skip, copyBuf()); err != nil {
				stalled(err, "The multipart upload was interrupted.")
				return
			}
		}
	}

	if !s.auditIntent(refuseUpload(w), r, sess, m, false) {
		return
	}

	var as *wproto.CreateAs
	if sess.who.Root && s.guard.Classify(dir) == "normal" && s.guard.Classify(rdir) == "normal" {
		as = &wproto.CreateAs{UID: sess.who.UID, GID: -1}
	}

	f, opened, err := s.mutator.OpenWrite(r.Context(), sess.who, wproto.OpenWriteReq{
		Dir: []byte(rdir), Name: []byte(name), Size: size, MTime: mtime, Conflict: conflict, As: as,
		DirIdentity: dirIdentity,
	})
	m.bytes = 0
	if err != nil {
		// changedAtOpen: from here, "changed" is the destination's identity
		// check failing, not the file's bytes.
		s.finishUpload(w, r, sess, m, err, true)
		return
	}

	defer f.Close()
	finished := false
	discard := func() {
		if !finished {
			finished = true
			_ = f.Close()
			// The request may already be cancelled. Cleanup still must reach the
			// worker; only it may discard the inode (INV-1).
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
			defer cancel()
			_, err := s.mutator.Finalize(ctx, sess.who, wproto.FinalizeReq{Tmp: opened.Tmp, Discard: true})
			s.logRaw(r, "upload-discard", target, err)
		}
	}

	defer discard()
	reader := &uploadReader{downloadReader: downloadReader{ctx: r.Context(), reader: source}, deadline: deadline}
	// Hide File.ReadFrom as well as Reader.WriteTo so CopyBuffer really uses
	// the 1 MiB buffer and checks the context on every read.
	m.bytes, err = io.CopyBuffer(struct{ io.Writer }{f}, reader, copyBuf())
	if err == nil {
		err = r.Context().Err()
	}
	// For a multipart upload, the file part ending is NOT the body ending: the
	// closing boundary and any trailing fields are still to come, and a client
	// is free to simply withhold them. net/http drains an unread request body
	// before it writes the response, so the 201 itself — once it is long enough
	// to overflow the response buffer, which a long destination path does —
	// would block in that drain, inside the handler, holding the upload slot for
	// as long as the client stayed quiet (round-14 P1).
	//
	// So the tail is consumed HERE, while the stall window is still armed, and
	// under a hard bound. Whatever becomes of it the upload itself is complete:
	// the file's bytes are already written. A tail that never arrives, never
	// ends, or is larger than any legitimate epilogue costs the connection and
	// nothing else.
	closeConn := reader.err != nil
	if err == nil && multipartBody {
		n, tailErr := io.Copy(io.Discard, io.LimitReader(r.Body, maxMultipartTail))
		// Timed out, broke, or ran past the bound: stop reading and let
		// net/http close instead of draining. closeAfterReply skips the drain.
		closeConn = closeConn || tailErr != nil || n >= maxMultipartTail
	}
	if closeConn {
		w.Header().Set("Connection", "close")
	}
	// The body is in (or has failed); either way the stall window has nothing
	// left to watch. Cleared BEFORE Close and Finalize, which are our own
	// flush, rename and fsync and may legitimately outlast it.
	deadline.clear()

	if err != nil {
		discard()
		if reader.err != nil || r.Context().Err() != nil {
			s.writeAudit(sess, r, m, "result", "aborted", "cancelled", "upload body interrupted", false)
			s.fail(refuseUpload(w), r, "cancelled", "The upload was interrupted.", target, "")
		} else {
			s.finishUpload(w, r, sess, m, err, false)
		}

		return
	}

	if err = f.Close(); err != nil {
		discard()
		s.finishUpload(w, r, sess, m, err, false)
		return
	}

	// A tail we gave up on cancels the request context — net/http cancels it on
	// any read error, and the stall deadline expiring inside that drain is one.
	// The file is complete by then, so publishing it must not be sunk by our own
	// timeout; the detached context gets a bound of its own instead, exactly as
	// the discard path does.
	finalCtx := r.Context()
	if closeConn {
		var cancel context.CancelFunc
		finalCtx, cancel = context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
	}
	res, err := s.mutator.Finalize(finalCtx, sess.who, wproto.FinalizeReq{
		Tmp: opened.Tmp, Final: []byte(name), MTimeUnix: mtime, Conflict: conflict,
	})
	if err != nil {
		discard()
	} else {
		finished = true
	}

	// Where the bytes actually landed, in the caller's vocabulary — mapped
	// BEFORE the result audit line is written, not after it. With
	// conflict=rename and something already at the destination the worker
	// publishes "a (2).txt", and writing the result first made both records of
	// the pair name "a.txt": the durable log said a file had been overwritten
	// that was never touched, and never named the file that was created.
	//
	// The record keeps the INTENT's path, so intent and result still pair by op
	// and path the way every other audited mutation does, and the landed
	// spelling goes in Dst — the field a rename already uses to say where the
	// operation ended up. Only when it differs: an upload that landed exactly
	// where it was asked to has no "elsewhere" to report.
	landed := mappedRoots([]string{dir}, []string{rdir}).mapPath(string(res.Path))
	if landed == "" {
		landed = target
	}
	if err == nil && landed != target {
		m.dst = landed
	}

	if !s.finishUpload(w, r, sess, m, err, false) {
		return
	}

	res.Entry.SetPath([]byte(landed))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"entry": res.Entry, "path": landed})
}

type uploadReader struct {
	downloadReader
	err error
	// deadline is re-armed as bytes arrive, so the window only ever expires on
	// a client that has gone quiet. Nil is allowed; it simply does nothing.
	deadline *uploadDeadline
	total    int64
}

func (r *uploadReader) Read(p []byte) (int, error) {
	n, err := r.downloadReader.Read(p)
	// Never re-arm on the read that ends the body. A Read may return bytes AND
	// io.EOF together — a 1 MiB body into a 1 MiB buffer does exactly that — and
	// re-arming there leaves a live read deadline on a connection nobody is
	// going to read from again. The HTTP server has by then started its own
	// background read of the connection, so the window expires against that and
	// cancels a request whose upload is already complete (round-13 P2).
	if n > 0 && err == nil && r.deadline != nil {
		r.total += int64(n)
		r.deadline.sawBytes(r.total)
	}
	if err != nil && err != io.EOF {
		r.err = err
	}

	return n, err
}

func (s *Server) finishUpload(w http.ResponseWriter, r *http.Request, sess *session, m mutation, err error, changedAtOpen bool) bool {
	if err != nil && (fsx.Code(err) == "cancelled" || r.Context().Err() != nil) {
		s.writeAudit(sess, r, m, "result", "aborted", "cancelled", "upload interrupted", false)
		s.fail(refuseUpload(w), r, "cancelled", "The upload was interrupted.", m.path, "")
		return false
	}

	if err != nil && fsx.Code(err) == "changed" {
		// "changed" arrives from two places and means two different things to
		// the person reading it. From OpenWrite it is the destination directory
		// failing its identity check — the folder was swapped between the guard
		// clearing it and the worker opening it — and nothing has been uploaded
		// yet. From Finalize it is the file's own bytes, after a whole upload.
		// Same code and same status; the sentence has to say which.
		message := "The upload changed before it could be published."
		if changedAtOpen {
			message = "The destination folder changed before the upload could start. Try again."
		}
		s.logRaw(r, m.op, m.path, err)
		s.writeAudit(sess, r, m, "result", "error", "changed", "", false)
		writeError(refuseUpload(w), http.StatusConflict, "changed", message, m.path, m.op, "")
		return false
	}

	return s.finish(refuseUpload(w), r, sess, m, err, false)
}
