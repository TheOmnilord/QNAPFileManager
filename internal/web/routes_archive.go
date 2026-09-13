package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/wproto"
)

func (s *Server) archive(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	// Belt to the middleware's braces (bodiedRead in server.go): if a read with
	// a body ever reaches this route — a future entry point, a handler wired
	// past serve — Connection: close still makes net/http skip the drain that
	// would otherwise block this handler at its first write while it holds a
	// slot, a worker and a pipe.
	if r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
	// Admitted before anything is resolved, and held until this handler returns
	// — which is until closeReader has run, so the slot covers the worker hold
	// and the pipe descriptors as well as the copy buffer (round-12 P1).
	release, refusal := s.archiveReads.acquire(sess.id)
	if refusal != "" {
		w.Header().Set("Retry-After", "2")
		w.Header().Set("Connection", "close")
		s.fail(w, r, "queue_full", refusal, "", "")
		return
	}
	defer release()
	// Do not let malformed parameters disappear before checking sel exclusivity.
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.fail(w, r, "bad_request", "Invalid archive query.", "", "")
		return
	}
	if q.Has("sel") {
		if len(q) != 1 || len(q["sel"]) != 1 {
			s.fail(w, r, "bad_request", "Supply sel alone for an archive selection.", "", "")
			return
		}
		selection, ok := s.consumeArchiveSelection(sess.id, q.Get("sel"))
		if !ok {
			s.fail(w, r, "not_found", "No such archive selection.", "", "")
			return
		}
		// A ticket records what the user ASKED FOR and nothing we decided about
		// it. Everything the POST computed — resolved spellings, the guard's
		// verdict — is recomputed here, because the filesystem may have changed
		// under the stored pathnames in the meantime: in a root session, select
		// /safe/config while /safe is an ordinary directory, then replace /safe
		// with a symlink into the install tree, and archiving the stored
		// resolution would hand out protected content that a direct GET of the
		// same path refuses. Same pipeline, same instant as the dispatch.
		request, ok := s.authorizeArchive(w, r, sess, selection.refs, selection.format, selection.name, selection.crossMounts)
		if !ok {
			return
		}
		s.streamArchive(w, r, sess, request, true)
		return
	}
	refs := make([]pathRef, 0, len(q["path"])+len(q["pathB64"]))
	for _, p := range q["path"] {
		refs = append(refs, pathRef{Path: p})
	}
	for _, p := range q["pathB64"] {
		refs = append(refs, pathRef{PathB64: p})
	}
	format, name := q.Get("format"), q.Get("name")
	cross, err := boolQuery(r, "crossMounts")
	if err != nil {
		s.fail(w, r, "bad_request", "Invalid archive format, name or crossing option.", "", "")
		return
	}
	request, ok := s.authorizeArchive(w, r, sess, refs, format, name, cross)
	if ok {
		s.streamArchive(w, r, sess, request, false)
	}
}

const (
	maxArchiveSelections = 16
	archiveSelectionTTL  = 60 * time.Second
	// maxArchiveName bounds the download filename a client may choose, in bytes.
	// NAME_MAX is 255 on every filesystem QTS and QuTS hero carry, so a longer
	// name is unusable anyway — and without a cap it was a megabyte of retained
	// heap per ticket (the select body is capped at 1 MiB, not the field).
	maxArchiveName = 255
	// maxArchiveSelectionBytes bounds what ONE ticket may retain: roughly 1000
	// roots (maxJobRoots) averaging ~230 bytes, which is far past any real NAS
	// selection. Larger selections are refused at select time rather than held.
	maxArchiveSelectionBytes = 256 << 10
	// maxArchiveStoreBytes bounds what EVERY live ticket retains together, so a
	// client cannot multiply the per-session bound by opening sessions. 8 MiB is
	// 32 maximal tickets; past it select answers queue_full and the caller waits
	// for the 60-second TTL, which every select and consume now collects.
	maxArchiveStoreBytes = 8 << 20
	// archiveRefOverhead is the fixed cost of one stored pathRef (two string
	// headers) charged on top of its bytes, so that a selection of a thousand
	// one-character paths is not accounted as free.
	archiveRefOverhead = 32

	// --- concurrent downloads (round-12 P1) ---
	//
	// The worker bounds how many archives it will PRODUCE at once. That bounds
	// nothing on this side: the producer's semaphore is released as soon as the
	// last byte reaches the pipe, while the handler is still holding a megabyte
	// copy buffer, the pipe descriptors and the worker hold, blocked writing
	// bytes to a client that has stopped reading. Thirty-two such responses sat
	// there with not a single producer active. So the web side admits them too,
	// and a download that goes silent is cut.
	maxArchiveDownloadsPerSession = 2
	maxArchiveDownloadsTotal      = 4
	// archiveStallWindow is how long one chunk write may take before the
	// download is abandoned. It is re-armed per chunk (archiveWriter.arm), so
	// it is an idle limit and not a total: a genuine multi-gigabyte download
	// over a slow link keeps extending it, and only silence ends it.
	archiveStallWindow = 60 * time.Second
)

// archiveSelection is a ticket: the REQUESTED spellings and the options the
// client chose, and deliberately nothing else. No resolved path and no guard
// verdict is stored, because neither stays true while the ticket waits — see
// the sel branch of archive.
type archiveSelection struct {
	refs        []pathRef
	format      string
	name        string
	crossMounts bool
	bytes       int // retained payload, for the per-ticket and store budgets
	expires     time.Time
}

// archiveRequest is one AUTHORIZED archive, valid only for the instant
// authorizeArchive produced it: the worker-facing request built from spellings
// just resolved and guarded, plus the requested spellings for audit and for
// client-facing errors (a resolved spelling is never disclosed).
type archiveRequest struct {
	req   wproto.ArchiveReq
	paths []string
	name  string
}

// archiveSelectionSize is what a ticket would retain. It counts the request as
// it arrived — a pathB64 companion is stored verbatim, so its base64 inflation
// is charged honestly rather than discounted to the decoded length.
func archiveSelectionSize(refs []pathRef, format, name string) int {
	n := len(format) + len(name)
	for _, ref := range refs {
		n += len(ref.Path) + len(ref.PathB64) + archiveRefOverhead
	}
	return n
}

func (s *Server) archiveSelect(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Paths       []pathRef `json:"paths"`
		Format      string    `json:"format"`
		Name        string    `json:"name"`
		CrossMounts bool      `json:"crossMounts"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	// The budget is checked before the pipeline: refusing an oversized selection
	// costs nothing, where authorizing one walks a thousand roots through the
	// worker. The name cap itself lives in the pipeline, so the direct GET form
	// is held to it too.
	size := archiveSelectionSize(body.Paths, body.Format, body.Name)
	if size > maxArchiveSelectionBytes {
		s.fail(w, r, "too_large", "That selection is too large to hold for a download. Archive it in smaller batches.", "", "")
		return
	}
	// Authorizing here is a courtesy, not a decision: the user learns about a
	// protected root or a network mount at select time instead of watching a
	// download fail. Nothing it computes is kept — the ticket below stores only
	// what the request said, and the GET authorizes again from scratch.
	if _, ok := s.authorizeArchive(w, r, sess, body.Paths, body.Format, body.Name, body.CrossMounts); !ok {
		return
	}
	selection := archiveSelection{refs: body.Paths, format: body.Format, name: body.Name, crossMounts: body.CrossMounts, bytes: size}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		s.fail(w, r, "internal", "The archive selection could not be prepared.", "", "")
		return
	}
	token := hex.EncodeToString(random[:])
	s.mu.Lock()
	now := s.now()
	if live := s.sessions[sess.id]; live == nil || live.dead.Load() || !now.Before(live.expires) {
		s.mu.Unlock()
		s.fail(w, r, "not_found", "No such session.", "", "")
		return
	}
	// Collect EVERY session's expired tickets, not just this one's. Before, an
	// abandoned selection was reclaimed only by another select in the same
	// session, by its own consumption, or by the session going away: sixteen
	// abandoned tickets sat on their payload for as long as the session lived.
	retained := s.sweepArchiveSelectionsLocked(now)
	if retained+selection.bytes > maxArchiveStoreBytes {
		s.mu.Unlock()
		s.fail(w, r, "queue_full", "The server is holding too many pending archive selections. Try again in a minute.", "", "")
		return
	}
	if s.archiveSelections == nil {
		s.archiveSelections = make(map[string]map[string]archiveSelection)
	}
	// Fetched after the sweep, which may have dropped this session's whole map.
	entries := s.archiveSelections[sess.id]
	if entries == nil {
		entries = make(map[string]archiveSelection)
		s.archiveSelections[sess.id] = entries
	}
	if len(entries) >= maxArchiveSelections {
		s.mu.Unlock()
		s.fail(w, r, "queue_full", "Too many pending archive selections. Download one or wait a minute.", "", "")
		return
	}
	selection.expires = now.Add(archiveSelectionTTL)
	entries[token] = selection
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]string{"sel": token})
}

func (s *Server) consumeArchiveSelection(sessionID, token string) (archiveSelection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entries := s.archiveSelections[sessionID]
	selection, ok := entries[token]
	// Deletion is the single-use marker, atomic with lookup even for concurrent GETs.
	delete(entries, token)
	// This consume pays for the whole store, the same as a select does, so a
	// client that only ever downloads still collects everyone's leftovers. The
	// sweep runs after the lookup above, so it can never race the single-use
	// delete for this token; it also drops the session's map once empty.
	s.sweepArchiveSelectionsLocked(now)
	return selection, ok && now.Before(selection.expires)
}

// sweepArchiveSelectionsLocked drops every expired ticket across the whole
// store and returns the bytes the survivors retain. Callers hold s.mu.
func (s *Server) sweepArchiveSelectionsLocked(now time.Time) int {
	retained := 0
	for id, entries := range s.archiveSelections {
		for token, entry := range entries {
			if !now.Before(entry.expires) {
				delete(entries, token)
				continue
			}
			retained += entry.bytes
		}
		if len(entries) == 0 {
			delete(s.archiveSelections, id)
		}
	}
	return retained
}

// ReapArchiveSelections collects expired archive tickets without any request
// having to arrive. Select and consume both sweep the whole store already, and
// the byte budgets above bound the store even at zero traffic, so this is the
// periodic backstop a caller's janitor ticker can call (the same minute ticker
// that drives jobs.Manager.Reap); it is safe to call at any time.
func (s *Server) ReapArchiveSelections() {
	s.mu.Lock()
	s.sweepArchiveSelectionsLocked(s.now())
	s.mu.Unlock()
}

// authorizeArchive is the ONE path by which an archive is authorized, shared by
// the direct path-list GET and by a ticket's consumption so the two cannot
// drift apart. In order: decode and clean the requested spellings, settle the
// format and name, refuse a network mount by the requested spelling before
// anything can block on it, resolve through the worker as the user (INV-2), and
// check OpRead, OpTraverse and guard.Contains on BOTH the requested and the
// resolved spelling. Everything it returns is derived from the filesystem as it
// is right now; nothing here may be cached across a request boundary.
func (s *Server) authorizeArchive(w http.ResponseWriter, r *http.Request, sess *session, refs []pathRef, format, name string, cross bool) (archiveRequest, bool) {
	paths, ok := s.jobPaths(w, r, refs)
	if !ok {
		return archiveRequest{}, false
	}
	if format == "" {
		format = "zip"
	}
	if format != "zip" && format != "tgz" || name != "" && fsx.ValidName(name) != nil {
		s.fail(w, r, "bad_request", "Invalid archive format, name or crossing option.", "", "")
		return archiveRequest{}, false
	}
	if len(name) > maxArchiveName {
		s.fail(w, r, "too_large", "That download name is too long.", "", "")
		return archiveRequest{}, false
	}
	wire := make([][]byte, len(paths))
	m := mutation{op: "archive", path: paths[0]}
	for i, p := range paths {
		osPath, err := s.Root.OS(p)
		if err != nil {
			s.failResolve(w, r, p, err)
			return archiveRequest{}, false
		}
		// Even resolving a root on a dead network mount can block indefinitely.
		if s.platform != nil {
			if caps, _ := s.platform.ForLiteral(osPath); caps.Network {
				s.fail(w, r, "protected", "This location is a network mount and cannot be archived from here.", p, "")
				return archiveRequest{}, false
			}
		}
		resolved, err := s.resolveForGuard(r.Context(), sess.who, p, false)
		if err != nil {
			s.failResolve(w, r, p, err)
			return archiveRequest{}, false
		}
		for _, spelling := range []string{p, resolved} {
			verdict := worstGuard(s.guard.Check(guard.OpRead, spelling), s.guard.Check(guard.OpTraverse, spelling))
			if _, contains := s.guard.Contains(spelling); contains || verdict != nil {
				// Archives cannot safely filter a protected subtree out of the
				// worker's pipe. Refuse it outright, with no confirmation ladder.
				s.authorize(w, r, sess, guard.ErrProtected, false, m, p, nil, false, "", guard.Summary{})
				return archiveRequest{}, false
			}
		}
		wire[i] = []byte(resolved)
	}
	return archiveRequest{req: wproto.ArchiveReq{Paths: wire, Format: format, CrossMounts: cross}, paths: paths, name: name}, true
}

func (s *Server) streamArchive(w http.ResponseWriter, r *http.Request, sess *session, selection archiveRequest, ticket bool) {
	format, name := selection.req.Format, selection.name
	m := mutation{op: "archive", path: selection.paths[0]}
	label := "archive " + format
	if ticket {
		label += " sel"
	}
	detail := jobIntentDetail("", label, selection.paths)
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, false); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The archive could not be audited.", m.path, m.op, "")
		return
	}
	finishError := func(err error) {
		code := fsx.Code(err)
		s.logRaw(r, m.op, m.path, err)
		s.writeAudit(sess, r, m, "result", "error", code, detail, false)
		s.fail(w, r, code, backendMessage(code), m.path, "")
	}
	reader, res, err := s.backend.Archive(r.Context(), sess.who, selection.req)
	if err != nil {
		finishError(err)
		return
	}
	// The body is read from a pollable duplicate of the pipe where the platform
	// has one, so a client disconnect interrupts a blocked read. The ArchiveStream
	// itself is NOT replaced by it: closing the stream is what releases the
	// worker that is producing the archive (workerpool/stream.go), and it is
	// also what answers Outcome afterwards. The descriptor is borrowed, so both
	// are closed below.
	body := io.Reader(reader)
	var dup io.Closer
	if src, ok := reader.(interface{ File() *os.File }); ok && r.Method != http.MethodHead {
		stream, err := prepareDownloadStream(src.File())
		if err != nil {
			_ = reader.Close()
			finishError(err)
			return
		}
		if stream != src.File() {
			dup, body = stream, stream
		}
	}
	// Close also interrupts a blocked pipe read on disconnect. Serialize the
	// close so readers need not implement concurrent Close themselves.
	var once sync.Once
	closeReader := func() {
		once.Do(func() {
			if dup != nil {
				_ = dup.Close()
			}
			_ = reader.Close()
		})
	}
	defer closeReader()
	stop := context.AfterFunc(r.Context(), closeReader)
	defer stop()
	if name == "" {
		name = string(res.Name)
		if fsx.ValidName(name) != nil {
			name = "download." + format
		}
	}
	ascii := strings.Map(func(c rune) rune {
		if c < 32 || c > 126 || c == '"' || c == '\\' || c == ';' {
			return '_'
		}
		return c
	}, name)
	ct := "application/zip"
	if format == "tgz" {
		ct = "application/gzip"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+ascii+`"; filename*=UTF-8''`+strings.ReplaceAll(url.QueryEscape(strings.ToValidUTF8(name, "_")), "+", "%20"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	_ = controller.Flush() // Prevent inferred Content-Length even for a short archive.

	// The audit outcome has two sources, and this end's own failures come
	// first: a client that went away, or a response we could not write, is an
	// aborted download whatever the producer went on to do, and a pipe we
	// could not read is an error. Only a stream that ended cleanly here asks
	// the worker what it actually produced — a pipe cannot tell a complete
	// archive from a truncated one (round-1 adversarial finding 13), and "ok"
	// on EOF alone recorded truncated downloads as successful.
	result, code := "", ""
	if r.Method != http.MethodHead {
		dst := &archiveWriter{w: w, controller: controller, window: s.archiveReads.stallWindow()}
		defer dst.clear()
		m.bytes, err = io.CopyBuffer(dst, downloadReader{ctx: r.Context(), reader: body}, make([]byte, 1<<20))
		if err != nil || r.Context().Err() != nil {
			if dst.err != nil || r.Context().Err() != nil {
				result, code = "aborted", "cancelled"
			} else {
				result, code = "error", fsx.Code(err)
				detail += "; truncated"
			}
			s.logRaw(r, m.op, m.path, err)
		}
	}
	if result == "" {
		// Clean EOF at this end: the worker is the authority on what it was.
		// Asked BEFORE the reader is closed — Close is what releases the hold
		// on the worker, and a released worker may be retiring or evicted by
		// the time the question arrives (round-2 review). A short deadline of
		// its own, because the request context may already be done and the
		// answer is one small frame from a worker we still hold.
		outcomeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		outcome, outcomeErr := reader.Outcome(outcomeCtx)
		closeReader()
		switch {
		case outcomeErr != nil:
			// The worker is gone, or never knew this archive: say so rather
			// than guess either way.
			result, code = "unknown", ""
			detail += "; outcome: " + outcomeErr.Error()
		case !outcome.Done:
			// EOF with the producer not finished is the worker having died
			// under it (a live producer holds the write end): not an outcome.
			result, code = "unknown", ""
			detail += "; outcome: the producer did not report an end"
		case outcome.Truncated:
			result = "truncated"
			if outcome.Error != "" {
				detail += "; " + outcome.Error
			}
		default:
			result = "ok"
		}
	}

	s.writeAudit(sess, r, m, "result", result, code, detail, false)
}

type archiveWriter struct {
	w          http.ResponseWriter
	controller *http.ResponseController
	pending    int64
	err        error
	// window is the rolling write deadline, re-armed before every chunk. An
	// archive has no size known in advance — it can legitimately take hours —
	// so one flat deadline is the wrong shape: this is an IDLE limit. A client
	// still taking bytes keeps extending it; one that has stopped is cut, which
	// closes the reader, releases the worker and audits the download as aborted
	// (round-12 P1). Zero means the platform has no deadline and we stop asking.
	window time.Duration
	noArm  bool
}

func (w *archiveWriter) Write(p []byte) (int, error) {
	w.arm()
	n, err := w.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.pending += int64(n)
	if err == nil && w.pending >= 4<<20 {
		err = w.controller.Flush()
		if err == http.ErrNotSupported {
			err = nil
		}
		w.pending = 0
	}
	w.err = err
	return n, err
}

// arm re-arms the rolling write deadline before a chunk goes out. One chunk is
// a megabyte, so this costs one syscall per megabyte and never more.
func (w *archiveWriter) arm() {
	if w.noArm || w.window <= 0 {
		return
	}
	if err := w.controller.SetWriteDeadline(time.Now().Add(w.window)); err != nil {
		// No deadline on this platform (or a test's recorder). Stop asking
		// rather than paying for the refusal on every chunk; the admission
		// slots still bound how many of these can exist at once.
		w.noArm = true
	}
}

// clear drops the deadline on the way out, so a kept-alive connection does not
// carry this download's limit into whatever request reuses it.
func (w *archiveWriter) clear() {
	if !w.noArm && w.window > 0 {
		_ = w.controller.SetWriteDeadline(time.Time{})
	}
}
