package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

type mountResolveBackend struct {
	*resolveStub
	ResolveCalls []string
}

func (b *mountResolveBackend) Resolve(_ context.Context, _ backend.Principal, name string, _ bool) (string, error) {
	b.ResolveCalls = append(b.ResolveCalls, name)
	return name, nil
}

func TestArchiveRootMountBeforeResolve(t *testing.T) {
	for _, fsType := range []string{"nfs", "nfs4", "cifs", "tmpfs"} {
		for _, root := range []string{"/share/folder", "/share/folder/child"} {
			t.Run(fsType+root, func(t *testing.T) {
				s, b, rs, c := archiveFixture(t, []byte("archive"))
				s.Root = fsx.Root{}
				var err error
				s.platform, err = platform.FromMountinfo(strings.NewReader("1 0 0:1 / /share rw - tmpfs tmpfs rw\n2 1 0:2 / /share/folder rw - " + fsType + " source rw\n"))
				if err != nil {
					t.Fatal(err)
				}
				resolver := &mountResolveBackend{resolveStub: rs}
				s.mutator = resolver
				q := url.Values{"path": {root}, "crossMounts": {"true"}}
				w := request(s, "GET", "/api/fs/archive?"+q.Encode(), c, nil)
				if fsType == "tmpfs" {
					if w.Code != http.StatusOK || len(resolver.ResolveCalls) != 1 || len(b.reqs) != 1 {
						t.Fatalf("tmpfs: %d %s resolves=%v archives=%v", w.Code, w.Body, resolver.ResolveCalls, b.reqs)
					}
					return
				}
				if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"code":"protected"`) || !strings.Contains(w.Body.String(), "network mount") {
					t.Fatalf("%d %s", w.Code, w.Body)
				}
				if len(resolver.ResolveCalls) != 0 || len(b.reqs) != 0 {
					t.Fatalf("network mount touched: resolves=%v archives=%v", resolver.ResolveCalls, b.reqs)
				}
			})
		}
	}
}

type archiveBackend struct {
	*fakeBackend
	reqs     []wproto.ArchiveReq
	reader   backend.ArchiveStream
	name     string
	err      error
	deadline bool
}

func (b *archiveBackend) Archive(ctx context.Context, _ backend.Principal, req wproto.ArchiveReq) (backend.ArchiveStream, wproto.ArchiveResp, error) {
	b.reqs = append(b.reqs, req)
	_, b.deadline = ctx.Deadline()
	return b.reader, wproto.ArchiveResp{Name: []byte(b.name)}, b.err
}

type archiveReader struct {
	io.Reader
	closed      bool
	outcomeResp wproto.ArchiveStatusResp
	outcomeErr  error
}

func (r *archiveReader) Close() error { r.closed = true; return nil }

// Outcome is the M2-C ArchiveStream half. The fake produced whatever it was
// given, so it reports a complete archive unless a test says otherwise.
func (r *archiveReader) Outcome(context.Context) (wproto.ArchiveStatusResp, error) {
	if r.outcomeErr != nil {
		return wproto.ArchiveStatusResp{}, r.outcomeErr
	}
	if r.outcomeResp.Done == false && r.outcomeResp.Truncated == false {
		r.outcomeResp.Done = true
	}
	return r.outcomeResp, nil
}

func archiveFixture(t *testing.T, data []byte) (*Server, *archiveBackend, *resolveStub, *http.Cookie) {
	t.Helper()
	s, b := fixture(t, true)
	rs := &resolveStub{fakeBackend: b, aliases: map[string]string{"/src": "/real", "/": "/"}}
	s.mutator = rs
	ab := &archiveBackend{fakeBackend: b, reader: &archiveReader{Reader: bytes.NewReader(data)}, name: "bundle.zip"}
	s.backend = ab
	c, _ := sessionCookie(t, s)
	return s, ab, rs, c
}

type archiveRecorder struct {
	*httptest.ResponseRecorder
	flushes int
	fail    bool
}

func (w *archiveRecorder) Flush() { w.flushes++; w.ResponseRecorder.Flush() }
func (w *archiveRecorder) Write(p []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseRecorder.Write(p)
}

func TestArchiveStreamsHeadersAndAudit(t *testing.T) {
	for _, format := range []string{"zip", "tgz"} {
		t.Run(format, func(t *testing.T) {
			data := bytes.Repeat([]byte("archive\x00"), (9<<20)/8)
			s, b, _, c := archiveFixture(t, data)
			readAudit := withAudit(t, s)
			q := url.Values{"path": {"/src/folder"}, "pathB64": {base64.RawURLEncoding.EncodeToString([]byte("/src/other"))}, "format": {format}, "name": {"følder archive." + format}, "crossMounts": {"true"}}
			r := httptest.NewRequest("GET", "/api/fs/archive?"+q.Encode(), nil)
			r.AddCookie(c)
			w := &archiveRecorder{ResponseRecorder: httptest.NewRecorder()}
			s.Handler().ServeHTTP(w, r)
			ct := "application/zip"
			if format == "tgz" {
				ct = "application/gzip"
			}
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) || w.Header().Get("Content-Type") != ct || w.Header().Get("Content-Length") != "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("%d %v bytes=%d", w.Code, w.Header(), w.Body.Len())
			}
			if w.flushes < 3 {
				t.Fatalf("flushes=%d", w.flushes)
			}
			if d := w.Header().Get("Content-Disposition"); !strings.Contains(d, "attachment;") || !strings.Contains(d, "filename*=UTF-8''f%C3%B8lder%20archive.") {
				t.Fatal(d)
			}
			if !b.reader.(*archiveReader).closed || b.deadline {
				t.Fatal("reader not closed or handler deadline applied")
			}
			if len(b.reqs) != 1 || string(b.reqs[0].Paths[0]) != "/real/folder" || string(b.reqs[0].Paths[1]) != "/real/other" || !b.reqs[0].CrossMounts || b.reqs[0].Format != format {
				t.Fatalf("request: %+v", b.reqs)
			}
			events := readAudit()
			if len(events) != 2 || events[0].Phase != "intent" || events[1].Result != "ok" || events[1].Bytes != int64(len(data)) || !strings.Contains(events[0].Detail, "/src/other") {
				t.Fatalf("audit: %+v", events)
			}
		})
	}
}

func TestArchiveGuards(t *testing.T) {
	for _, tc := range []struct{ path, parent, resolved string }{
		{"/app/logs/file", "/app/logs", "/normal"},
		{"/src/logs", "/src", "/app"},
		{"/app", "/", "/"},
		{"/src/app", "/src", "/"},
		{"/etc", "/", "/normal"},
		{"/src/etc", "/src", "/"},
	} {
		t.Run(tc.path+tc.resolved, func(t *testing.T) {
			s, b, rs, c := archiveFixture(t, nil)
			s.guard = guard.New("/app", false)
			rs.aliases[tc.parent] = tc.resolved
			w := request(s, "GET", "/api/fs/archive?path="+url.QueryEscape(tc.path), c, nil)
			if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"protected"`) || strings.Contains(w.Body.String(), `"confirm"`) || len(b.reqs) != 0 {
				t.Fatalf("%d %s requests=%d", w.Code, w.Body, len(b.reqs))
			}
		})
	}
}

// TestArchiveTicketIsReguardedAtConsumption is the round-7 adversarial P1: a
// ticket used to carry the spellings the POST had already resolved and cleared,
// so the guard never saw the path again. In a root session that was a window:
// select /safe/config while /safe is an ordinary directory, then replace /safe
// with a symlink into the daemon's own install tree and download the ticket —
// the worker resolved the stored pathname afresh and archived protected
// content that a direct GET of the very same path refuses.
func TestArchiveTicketIsReguardedAtConsumption(t *testing.T) {
	s, b, rs, c := archiveFixture(t, []byte("archive data"))
	s.guard = guard.New("/app", false)
	// Selected while /src is an ordinary directory resolving to /real, so
	// /src/logs is an ordinary folder the guard has nothing to say about.
	sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/logs"}]}`)
	// Consumed after /src became a symlink into the install tree, which puts
	// the very same requested spelling on top of the daemon's own audit log.
	rs.aliases["/src"] = "/app"
	w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(body, `"code":"protected"`) || len(b.reqs) != 0 {
		t.Fatalf("swapped parent was archived: %d %s requests=%d", w.Code, body, len(b.reqs))
	}
	if strings.Contains(body, "/app") {
		t.Fatalf("the resolved spelling leaked to the client: %s", body)
	}
	// A refused ticket is still spent: single use is about the token, not the
	// verdict, so the swap cannot be retried against a racing restore.
	if w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil); w.Code != http.StatusNotFound {
		t.Fatalf("refused ticket survived: %d %s", w.Code, w.Body)
	}
	// The direct path-list form is unaffected where the guard allows the path.
	rs.aliases["/src"] = "/real"
	w = request(s, "GET", "/api/fs/archive?path=/src/logs", c, nil)
	if w.Code != http.StatusOK || w.Body.String() != "archive data" || len(b.reqs) != 1 || string(b.reqs[0].Paths[0]) != "/real/logs" {
		t.Fatalf("direct form: %d %s requests=%v", w.Code, w.Body, b.reqs)
	}
}

// TestArchiveSelectionExpiryReapsEverySession is the round-7 adversarial P2(b):
// an abandoned ticket used to wait for another select in its OWN session, its
// own consumption, or the session's removal, so sixteen of them sat on their
// payload for hours. Every select and every consume now collects the whole
// store, and ReapArchiveSelections does it with no request at all.
func TestArchiveSelectionExpiryReapsEverySession(t *testing.T) {
	s, _, _, owner := archiveFixture(t, nil)
	now := time.Now()
	s.Now = func() time.Time { return now }
	other, _ := sessionCookie(t, s)
	selectArchive(t, s, other, `{"paths":[{"path":"/src/file"}]}`)
	abandoned := selectArchive(t, s, owner, `{"paths":[{"path":"/src/file"}]}`)
	now = now.Add(archiveSelectionTTL)
	if _, ok := s.consumeArchiveSelection(owner.Value, abandoned); ok {
		t.Fatal("an expired ticket was honoured")
	}
	if len(s.archiveSelections) != 0 {
		t.Fatalf("a consume left another session's expired tickets: %v", s.archiveSelections)
	}
	selectArchive(t, s, other, `{"paths":[{"path":"/src/file"}]}`)
	selectArchive(t, s, owner, `{"paths":[{"path":"/src/file"}]}`)
	now = now.Add(archiveSelectionTTL)
	selectArchive(t, s, owner, `{"paths":[{"path":"/src/file"}]}`)
	if len(s.archiveSelections) != 1 || len(s.archiveSelections[owner.Value]) != 1 {
		t.Fatalf("a select left another session's expired tickets: %v", s.archiveSelections)
	}
	now = now.Add(archiveSelectionTTL)
	s.ReapArchiveSelections()
	if len(s.archiveSelections) != 0 {
		t.Fatalf("the janitor backstop left entries: %v", s.archiveSelections)
	}
}

// TestArchiveSelectionByteBudgets is the round-7 adversarial P2(a) and (c): a
// ticket's retained payload, the download name inside it, and the store's total
// are all bounded, so neither one selection nor many sessions can pin memory
// for the length of the TTL.
func TestArchiveSelectionByteBudgets(t *testing.T) {
	s, b, _, c := archiveFixture(t, nil)
	csrf := s.sessions[c.Value].csrf
	// bodyPath caps every component at NAME_MAX, so the only way to a heavy
	// selection is many near-maximal names — which is also the only shape a real
	// client could ever send. maxJobRoots (1000) and the 255-byte component cap
	// together put the largest possible selection just over the per-ticket
	// budget, so this needs most of that thousand.
	ref := `{"path":"/src/` + strings.Repeat("p", 250) + `"}`
	refs := func(n int) string { return `{"paths":[` + ref + strings.Repeat(","+ref, n-1) + `]}` }
	oversized := refs(950)
	resp := post(s, "/api/fs/archive/select", c, csrf, oversized)
	if got := readBody(resp); resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(got, `"code":"too_large"`) || len(s.archiveSelections) != 0 || len(b.reqs) != 0 {
		t.Fatalf("oversized selection: %d %s", resp.StatusCode, got)
	}
	resp.Body.Close()
	// The name is capped on its own: it is one field, and it was the megabyte.
	resp = post(s, "/api/fs/archive/select", c, csrf, `{"paths":[{"path":"/src/file"}],"name":"`+strings.Repeat("n", maxArchiveName+1)+`"}`)
	if got := readBody(resp); resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(got, `"code":"too_large"`) || len(s.archiveSelections) != 0 {
		t.Fatalf("oversized name: %d %s", resp.StatusCode, got)
	}
	resp.Body.Close()
	selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}],"name":"`+strings.Repeat("n", maxArchiveName)+`"}`)
	// The same cap holds on the direct form, which shares the pipeline.
	w := request(s, "GET", "/api/fs/archive?path=/src/file&name="+strings.Repeat("n", maxArchiveName+1), c, nil)
	if w.Code != http.StatusRequestEntityTooLarge || len(b.reqs) != 0 {
		t.Fatalf("direct oversized name: %d %s", w.Code, w.Body)
	}

	// The store-wide cap: several sessions together cannot retain more than
	// maxArchiveStoreBytes, so opening sessions does not multiply the bound.
	s, _, _, first := archiveFixture(t, nil)
	cookies := []*http.Cookie{first}
	for range 2 {
		extra, _ := sessionCookie(t, s)
		cookies = append(cookies, extra)
	}
	big := refs(850)
	accepted, refused := 0, ""
	for _, cookie := range cookies {
		for range maxArchiveSelections {
			resp := post(s, "/api/fs/archive/select", cookie, s.sessions[cookie.Value].csrf, big)
			got := readBody(resp)
			resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				accepted++
				continue
			}
			if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(got, `"code":"queue_full"`) {
				t.Fatalf("select %d: %d %s", accepted, resp.StatusCode, got)
			}
			if len(s.archiveSelections[cookie.Value]) >= maxArchiveSelections {
				t.Fatalf("the per-session bound refused before the store-wide one after %d", accepted)
			}
			refused = got
			break
		}
		if refused != "" {
			break
		}
	}
	retained := 0
	for _, entries := range s.archiveSelections {
		for _, entry := range entries {
			retained += entry.bytes
		}
	}
	if refused == "" || accepted == 0 || retained > maxArchiveStoreBytes {
		t.Fatalf("store budget: accepted=%d retained=%d refused=%q", accepted, retained, refused)
	}
}

func TestArchiveValidationMethodsAndDefault(t *testing.T) {
	for _, query := range []string{"", "path=/src/file&format=tar", "path=/src/file&name=../bad", "path=/src/file&crossMounts=nope", "pathB64=%%%", strings.Repeat("path=/src/file&", maxJobRoots+1)} {
		s, b, _, c := archiveFixture(t, nil)
		w := request(s, "GET", "/api/fs/archive?"+query, c, nil)
		if w.Code != 400 || len(b.reqs) != 0 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	s, b, _, c := archiveFixture(t, []byte("fake"))
	w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 200 || b.reqs[0].Format != "zip" || !strings.Contains(w.Header().Get("Content-Disposition"), `filename="bundle.zip"`) {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	csrf := s.sessions[c.Value].csrf
	resp := post(s, "/api/fs/archive?path=/src/file", c, csrf, "")
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET" || len(b.reqs) != 1 {
		t.Fatalf("%d %s", resp.StatusCode, readBody(resp))
	}
}

type blockedArchive struct {
	started, closed chan struct{}
	once            sync.Once
	taken           atomic.Bool
}

func (r *blockedArchive) Read([]byte) (int, error) {
	// Only the FIRST consumer blocks. A second one means a request that should
	// have been refused got through to the worker, and it must fail the test
	// cleanly rather than deadlock it or panic on a re-closed channel.
	if !r.taken.CompareAndSwap(false, true) {
		return 0, io.ErrClosedPipe
	}
	close(r.started)
	<-r.closed
	return 0, io.ErrClosedPipe
}
func (r *blockedArchive) Close() error { r.once.Do(func() { close(r.closed) }); return nil }

func (r *blockedArchive) Outcome(context.Context) (wproto.ArchiveStatusResp, error) {
	return wproto.ArchiveStatusResp{Done: false}, nil
}

func TestArchiveDisconnectClosesReader(t *testing.T) {
	s, b, _, c := archiveFixture(t, nil)
	readAudit := withAudit(t, s)
	br := &blockedArchive{started: make(chan struct{}), closed: make(chan struct{})}
	b.reader = br
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "/api/fs/archive?path=/src/file", nil).WithContext(ctx)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.Handler().ServeHTTP(w, r) }()
	select {
	case <-br.started:
	case <-time.After(3 * time.Second):
		t.Fatal("archive did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not unblock archive")
	}
	events := readAudit()
	// The client left: aborted at this end, whatever the producer reports.
	if len(events) != 2 || events[1].Result != "aborted" || events[1].Code != "cancelled" {
		t.Fatalf("audit: %+v", events)
	}
}

type failedArchiveRead struct{}

func (failedArchiveRead) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestArchiveStreamErrors(t *testing.T) {
	for _, writeFail := range []bool{true, false} {
		s, b, _, c := archiveFixture(t, []byte("archive"))
		readAudit := withAudit(t, s)
		if !writeFail {
			b.reader = &archiveReader{Reader: failedArchiveRead{}, outcomeResp: wproto.ArchiveStatusResp{Done: true, Truncated: true}}
		}
		r := httptest.NewRequest("GET", "/api/fs/archive?path=/src/file", nil)
		r.AddCookie(c)
		w := &archiveRecorder{ResponseRecorder: httptest.NewRecorder(), fail: writeFail}
		s.Handler().ServeHTTP(w, r)
		events := readAudit()
		// A response we could not write is an aborted download; a pipe we could
		// not read is an error. Neither asks the producer — its "truncated"
		// answer on the read-failure fixture must not override this end's own
		// failure.
		want := "error"
		if writeFail {
			want = "aborted"
		}
		if len(events) != 2 || events[1].Result != want || !b.reader.(*archiveReader).closed {
			t.Fatalf("audit: %+v", events)
		}
	}
	s, b, _, c := archiveFixture(t, nil)
	b.err = fsx.ErrNoSpace
	readAudit := withAudit(t, s)
	w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 507 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if events := readAudit(); len(events) != 2 || events[1].Result != "error" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestArchiveHEADDoesNotRead(t *testing.T) {
	s, b, _, c := archiveFixture(t, nil)
	b.reader = &archiveReader{Reader: unreadUpload{t}}
	w := request(s, "HEAD", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 200 || w.Body.Len() != 0 || !b.reader.(*archiveReader).closed {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestArchiveOutcomeTruncatedIsAudited(t *testing.T) {
	s, b, _, c := archiveFixture(t, []byte("data"))
	readAudit := withAudit(t, s)
	// Simulate worker reporting truncation.
	b.reader = &archiveReader{
		Reader:      bytes.NewReader([]byte("data")),
		outcomeResp: wproto.ArchiveStatusResp{Done: true, Truncated: true, Error: "quota_exceeded"},
	}
	w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	events := readAudit()
	if len(events) != 2 || events[1].Result != "truncated" || !strings.Contains(events[1].Detail, "quota_exceeded") {
		t.Fatalf("audit: %+v", events)
	}
}

func TestArchiveOutcomeErrorReportsUnknown(t *testing.T) {
	s, b, _, c := archiveFixture(t, []byte("data"))
	readAudit := withAudit(t, s)
	// Simulate worker gone or unreachable.
	b.reader = &archiveReader{
		Reader:     bytes.NewReader([]byte("data")),
		outcomeErr: io.ErrClosedPipe,
	}
	w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	events := readAudit()
	if len(events) != 2 || events[1].Result != "unknown" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestArchiveOutcomeCleanOkWithBytes(t *testing.T) {
	data := []byte("clean archive data")
	s, b, _, c := archiveFixture(t, data)
	readAudit := withAudit(t, s)
	// Simulate clean worker completion.
	b.reader = &archiveReader{
		Reader:      bytes.NewReader(data),
		outcomeResp: wproto.ArchiveStatusResp{Done: true, Truncated: false},
	}
	w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatalf("%d bytes=%d", w.Code, w.Body.Len())
	}
	events := readAudit()
	if len(events) != 2 || events[1].Result != "ok" || events[1].Bytes != int64(len(data)) {
		t.Fatalf("audit: %+v", events)
	}
}

// --- concurrent downloads (round-12 P1) --------------------------------------

// archiveDeadlineRecorder is an archiveRecorder that also records the write
// deadlines http.ResponseController sets on it. A ResponseRecorder has none, and
// a real socket is no good here: how much a kernel buffers for a client that has
// stopped reading varies wildly between this box and the CI runner, so the
// deadline has to be observed directly rather than inferred from a stall.
type archiveDeadlineRecorder struct {
	*archiveRecorder
	set []time.Time
}

func (w *archiveDeadlineRecorder) SetWriteDeadline(t time.Time) error {
	w.set = append(w.set, t)
	return nil
}

// TestArchiveDownloadsAreAdmitted is round-12 P1. The worker bounds how many
// archives it will PRODUCE at once, and that bounds nothing here: the producer's
// semaphore is released as soon as the last byte reaches the pipe, while this
// end is still holding a megabyte copy buffer, the pipe descriptors and the
// worker hold, blocked writing to a client that stopped reading. Thirty-two such
// responses sat there with not one producer active.
func TestArchiveDownloadsAreAdmitted(t *testing.T) {
	s, b, _, first := archiveFixture(t, []byte("archive data"))
	s.archiveReads.perSessionLimit, s.archiveReads.totalLimit = 1, 2
	second, _ := sessionCookie(t, s)

	// A blocked producer holds the handler exactly where a stalled client would:
	// inside the response, with the reader still open.
	br := &blockedArchive{started: make(chan struct{}), closed: make(chan struct{})}
	b.reader = br
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		request(s, "GET", "/api/fs/archive?path=/src/file", first, nil)
	}()
	select {
	case <-br.started:
	case <-time.After(3 * time.Second):
		t.Fatal("the archive never started")
	}

	// This session already has its one download.
	w := request(s, "GET", "/api/fs/archive?path=/src/file", first, nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"code":"queue_full"`) {
		t.Fatalf("per-session: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "archive downloads") {
		t.Fatalf("the refusal does not say what it is refusing: %s", w.Body)
	}
	// Retry-After and a closed connection, the same shape as the upload refusal.
	if w.Header().Get("Retry-After") == "" || w.Header().Get("Connection") != "close" {
		t.Fatalf("headers: %v", w.Header())
	}
	// A refused request must not have reached the worker.
	if len(b.reqs) != 1 {
		t.Fatalf("the refusal dispatched an archive: %+v", b.reqs)
	}

	// The slot is held until the HANDLER returns — past closeReader, so it
	// covers the worker hold and the pipe, not merely the copy buffer.
	br.Close()
	wg.Wait()
	s.archiveReads.mu.Lock()
	total := s.archiveReads.total
	s.archiveReads.mu.Unlock()
	if total != 0 {
		t.Fatalf("the slot was not released: %d", total)
	}
	// And a second session was never blocked by the first session's ceiling.
	b.reader = &archiveReader{Reader: bytes.NewReader([]byte("archive data"))}
	if w := request(s, "GET", "/api/fs/archive?path=/src/file", second, nil); w.Code != http.StatusOK {
		t.Fatalf("second session: %d %s", w.Code, w.Body)
	}
}

// TestArchiveWriteDeadlineIsRolling is the other half: an archive has no size
// known in advance, so one flat deadline is the wrong shape. The window is
// re-armed before every chunk, which lets a genuine multi-gigabyte download over
// a slow link continue and cuts one that has gone silent.
func TestArchiveWriteDeadlineIsRolling(t *testing.T) {
	data := bytes.Repeat([]byte("archive\x00"), (5<<20)/8) // five chunks and a bit
	s, b, _, c := archiveFixture(t, data)
	s.archiveReads.writeGrace = 90 * time.Second

	r := httptest.NewRequest("GET", "/api/fs/archive?path=/src/file", nil)
	r.AddCookie(c)
	w := &archiveDeadlineRecorder{archiveRecorder: &archiveRecorder{ResponseRecorder: httptest.NewRecorder()}}
	before := time.Now()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatalf("%d bytes=%d", w.Code, w.Body.Len())
	}
	// One per chunk written, plus the clear on the way out — never a single
	// deadline covering the whole download.
	if len(w.set) < 5 {
		t.Fatalf("armed %d times for %d bytes: %v", len(w.set), len(data), w.set)
	}
	if last := w.set[len(w.set)-1]; !last.IsZero() {
		t.Fatalf("the deadline was left on the connection: %v", last)
	}
	for i, at := range w.set[:len(w.set)-1] {
		if d := at.Sub(before); d < 90*time.Second || d > 95*time.Second {
			t.Fatalf("deadline %d is %v from the start, want about 90s", i, d)
		}
	}
	// Each one is armed later than the one before: this is a rolling window,
	// not the same instant computed once.
	for i := 1; i < len(w.set)-1; i++ {
		if !w.set[i].After(w.set[i-1]) && !w.set[i].Equal(w.set[i-1]) {
			t.Fatalf("deadline %d went backwards: %v then %v", i, w.set[i-1], w.set[i])
		}
	}
	if !b.reader.(*archiveReader).closed {
		t.Fatal("reader not closed")
	}
}

// TestReadWithABodyIsRefusedBeforeAnySlot is round-13 P1. net/http drains an
// unread request body — up to 256 KiB — before it writes response headers,
// unless the response is already closeAfterReply, and nothing arms a read
// deadline for that drain. So a GET with "Content-Length: 1" and no body blocks
// its handler at the FIRST WRITE, holding whatever that handler holds: here an
// archive's admission slot, its worker hold and its pipe, with the audit pair
// unfinished. A handful of them empties the global pool while the client sends
// nothing at all.
//
// Driven over a real socket, because the whole mechanism is net/http's drain of
// a connection: a ResponseRecorder has no connection and cannot show it.
func TestReadWithABodyIsRefusedBeforeAnySlot(t *testing.T) {
	s, b, _, c := archiveFixture(t, []byte("archive data"))
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, head string }{
		{"content-length", "Content-Length: 1\r\n"},
		{"chunked", "Transfer-Encoding: chunked\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// Generous, but the point is that the answer comes at once: a
			// blocked drain would sit here until this expires.
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(conn, "GET /api/fs/archive?path=/src/file HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n%s\r\n", u.Host, c.String(), tc.head); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("the handler blocked on a body that never came: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte(`"code":"bad_request"`)) {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
			if !resp.Close {
				t.Fatal("the refusal kept the connection, so net/http would still drain it")
			}
		})
	}

	// Nothing was taken: no admission slot, no worker hold, no dispatch — the
	// refusal happens before routing, so the archive route never ran.
	s.archiveReads.mu.Lock()
	total := s.archiveReads.total
	s.archiveReads.mu.Unlock()
	if total != 0 || len(b.reqs) != 0 {
		t.Fatalf("a refused read took a slot or reached the worker: slots=%d reqs=%+v", total, b.reqs)
	}
	// And the same request without the body is served as usual.
	if w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil); w.Code != http.StatusOK {
		t.Fatalf("bodyless GET: %d %s", w.Code, w.Body)
	}
}

// TestArchiveDispatchesResolvedSpellings pins what the worker is asked to
// archive. The guard clears a RESOLVED path — it resolves parent symlinks as
// the user and takes the stricter of the two verdicts — so the request that
// follows must carry that same spelling. Dispatching the user's own spelling
// would hand the worker a name whose meaning can differ from the one that was
// cleared, which is the whole shape of the round-14 worker-side findings.
func TestArchiveDispatchesResolvedSpellings(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		s, b, _, c := archiveFixture(t, []byte("archive data"))
		w := request(s, "GET", "/api/fs/archive?path=/src/file", c, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if len(b.reqs) != 1 || string(b.reqs[0].Paths[0]) != "/real/file" {
			t.Fatalf("ArchiveReq carried the user's spelling: %q", b.reqs[0].Paths[0])
		}
	})

	t.Run("ticket", func(t *testing.T) {
		s, b, _, c := archiveFixture(t, []byte("archive data"))
		sel := selectArchive(t, s, c, `{"paths":[{"path":"/src/file"}]}`)
		// The ticket stores the REQUESTED spelling; consuming it resolves again
		// and dispatches the resolved one.
		if held := s.archiveSelections[c.Value][sel]; len(held.refs) != 1 || held.refs[0].Path != "/src/file" {
			t.Fatalf("the ticket stored something other than the request: %+v", held.refs)
		}
		w := request(s, "GET", "/api/fs/archive?sel="+sel, c, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if len(b.reqs) != 1 || string(b.reqs[0].Paths[0]) != "/real/file" {
			t.Fatalf("a replayed ticket carried the user's spelling: %q", b.reqs[0].Paths[0])
		}
	})
}
