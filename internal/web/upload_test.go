package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/wproto"
)

// Extend the existing fixture by embedding it, keeping M2-C's seams entirely
// in the new test files. Only this fake creates a file in the front-end process.
type uploadBackend struct {
	*resolveStub
	t                 *testing.T
	openReqs          []wproto.OpenWriteReq
	finalReqs         []wproto.FinalizeReq
	file              string
	openErr, finalErr error
	finalDelay        time.Duration
	deadline          bool
	onOpen            func()
	// finalName, when set, is the name Finalize actually publishes, which need
	// not be the one that was asked for: with conflict=rename and something
	// already at the destination a real worker keeps both and lands "a (2).txt".
	finalName string
}

func (b *uploadBackend) OpenWrite(ctx context.Context, who backend.Principal, req wproto.OpenWriteReq) (*os.File, wproto.OpenWriteResp, error) {
	b.openReqs = append(b.openReqs, req)
	_, b.deadline = ctx.Deadline()
	if b.onOpen != nil {
		b.onOpen()
	}
	if b.openErr != nil {
		return nil, wproto.OpenWriteResp{}, b.openErr
	}
	f, err := os.CreateTemp(b.t.TempDir(), "upload")
	if err != nil {
		b.t.Fatal(err)
	}
	b.file = f.Name()
	return f, wproto.OpenWriteResp{Tmp: []byte("opaque")}, nil
}

func (b *uploadBackend) Finalize(ctx context.Context, who backend.Principal, req wproto.FinalizeReq) (wproto.FinalizeResp, error) {
	b.finalReqs = append(b.finalReqs, req)
	if b.finalDelay > 0 && !req.Discard {
		// A real Finalize renames and fsyncs; on a busy volume that is slow. It
		// is also an RPC to the worker, so a cancelled request context fails it
		// — which is exactly how a read deadline that outlived the body turned a
		// complete upload into a 408.
		select {
		case <-time.After(b.finalDelay):
		case <-ctx.Done():
			return wproto.FinalizeResp{}, ctx.Err()
		}
	}
	if req.Discard {
		if ctx.Err() != nil {
			b.t.Error("discard inherited cancelled context")
		}
		return wproto.FinalizeResp{}, nil
	}
	final := req.Final
	if b.finalName != "" {
		final = []byte(b.finalName)
	}
	p := fsx.Join(string(b.openReqs[len(b.openReqs)-1].Dir), string(final))
	e := fsx.Entry{Type: "file"}
	e.SetName(final)
	e.SetPath([]byte(p))
	return wproto.FinalizeResp{Entry: e, Path: []byte(p)}, b.finalErr
}

func uploadFixture(t *testing.T) (*Server, *uploadBackend, *http.Cookie, string) {
	t.Helper()
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	ub := &uploadBackend{t: t, resolveStub: &resolveStub{fakeBackend: b, aliases: map[string]string{"/dest": "/real"}}}
	s.mutator = ub
	c, csrf := sessionCookie(t, s)
	return s, ub, c, csrf
}

func uploadRequest(target string, c *http.Cookie, csrf string, body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", target, body)
	if c != nil {
		r.AddCookie(c)
	}
	r.Header.Set("X-QFM-CSRF", csrf)
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/octet-stream")
	return r
}

func TestUploadRawAndLimitExemption(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	readAudit := withAudit(t, s)
	data := bytes.Repeat([]byte{0, 1, 255}, 1<<20)
	r := uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&size=3145728&mtime=1700000000&conflict=rename", c, csrf, bytes.NewReader(data))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	got, err := os.ReadFile(b.file)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream mismatch: %v, %d bytes", err, len(got))
	}
	if b.deadline {
		t.Fatal("upload inherited handler deadline")
	}
	o, f := b.openReqs[0], b.finalReqs[0]
	if string(o.Dir) != "/real" || o.Size != int64(len(data)) || o.MTime != 1700000000 || string(f.Final) != "a.bin" || f.MTimeUnix != 1700000000 || f.Conflict != "rename" || string(f.Tmp) != "opaque" {
		t.Fatalf("open=%+v final=%+v", o, f)
	}
	if !strings.Contains(w.Body.String(), `"path":"/dest/a.bin"`) || strings.Contains(w.Body.String(), "/real") {
		t.Fatal(w.Body)
	}
	events := readAudit()
	if len(events) != 2 || events[0].Phase != "intent" || events[0].Bytes != int64(len(data)) || events[1].Result != "ok" || events[1].Bytes != int64(len(data)) {
		t.Fatalf("audit: %+v", events)
	}
	resp := post(s, "/api/fs/mkdir", c, csrf, `{"dir":"/","name":"`+strings.Repeat("x", 2<<20)+`"}`)
	if resp.StatusCode == 200 {
		t.Fatal("mkdir accepted oversized body")
	}
}

func TestUploadMultipartFirstFile(t *testing.T) {
	for _, hasFile := range []bool{true, false} {
		t.Run(map[bool]string{true: "file", false: "no file"}[hasFile], func(t *testing.T) {
			s, b, c, csrf := uploadFixture(t)
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			_ = mw.WriteField("ignored", "field")
			if hasFile {
				p, _ := mw.CreateFormFile("file", "ignored-name")
				_, _ = p.Write([]byte("first\x00file"))
				p, _ = mw.CreateFormFile("file", "second")
				_, _ = p.Write([]byte("not uploaded"))
			}
			_ = mw.Close()
			r := uploadRequest("/api/fs/upload?dir=/dest&name=query-name", c, csrf, &body)
			r.Header.Set("Content-Type", mw.FormDataContentType())
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if !hasFile {
				if w.Code != 400 || len(b.openReqs) != 0 {
					t.Fatalf("%d %s", w.Code, w.Body)
				}
				return
			}
			got, _ := os.ReadFile(b.file)
			if w.Code != 201 || string(got) != "first\x00file" || string(b.finalReqs[0].Final) != "query-name" {
				t.Fatalf("%d %s data=%q", w.Code, w.Body, got)
			}
		})
	}
}

type unreadUpload struct{ t *testing.T }

func (b unreadUpload) Read([]byte) (int, error) {
	b.t.Fatal("body read before confirmation")
	return 0, io.EOF
}

// TestUploadNameIsBoundedByNAMEMAX is the round-7 sweep's last escape: dir went
// through bodyPath and was capped at NAME_MAX, but the upload NAME is a
// component the client invents, and fsx.ValidName says nothing about length. A
// hundred CJK characters is an everyday Windows filename and 300 bytes here, so
// it passed, OpenWrite created the inode, the whole body crossed to the worker,
// and only Finalize's lstat came back ENAMETOOLONG.
func TestUploadNameIsBoundedByNAMEMAX(t *testing.T) {
	for _, tc := range []struct{ what, name string }{
		{"ascii", strings.Repeat("n", maxComponentBytes+1)},
		// 100 three-byte runes: legal on Windows, 300 bytes to the kernel. The
		// cap is in bytes, which is what NAME_MAX counts.
		{"cjk", strings.Repeat("文", 100)},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s, b, c, csrf := uploadFixture(t)
			readAudit := withAudit(t, s)
			// unreadUpload fails the test if a single byte is read, so this also
			// proves nothing streamed before the refusal.
			r := uploadRequest("/api/fs/upload?dir=/dest&conflict=rename&name="+url.QueryEscape(tc.name), c, csrf, unreadUpload{t})
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"bad_request"`) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), "longer than 255 bytes") {
				t.Fatalf("the refusal does not say why: %s", w.Body)
			}
			// Every early refusal closes the connection, or Chrome retries the
			// POST and conflict=rename quietly makes an (2) copy.
			if w.Header().Get("Connection") != "close" {
				t.Fatalf("headers: %v", w.Header())
			}
			if len(b.openReqs) != 0 || len(b.finalReqs) != 0 {
				t.Fatalf("the worker was asked to create anything: open=%v final=%v", b.openReqs, b.finalReqs)
			}
			// Refused before the guard and before the durable intent line.
			if events := readAudit(); len(events) != 0 {
				t.Fatalf("audit: %+v", events)
			}
		})
	}

	// A name AT the cap is ordinary and still uploads, in either alphabet.
	for _, name := range []string{strings.Repeat("n", maxComponentBytes), strings.Repeat("文", maxComponentBytes/3)} {
		s, b, c, csrf := uploadFixture(t)
		r := uploadRequest("/api/fs/upload?dir=/dest&conflict=rename&name="+url.QueryEscape(name), c, csrf, strings.NewReader("payload"))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("%d bytes: %d %s", len(name), w.Code, w.Body)
		}
		if len(b.openReqs) != 1 || string(b.openReqs[0].Name) != name {
			t.Fatalf("open: %+v", b.openReqs)
		}
	}
}

func TestUploadConfirmationBeforeBody(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	target := "/api/fs/upload?dir=/dest&name=a&conflict=overwrite"
	r := uploadRequest(target, c, csrf, unreadUpload{t})
	r.Header.Set("Content-Type", "multipart/form-data; boundary=unread")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 409 || w.Header().Get("Connection") != "close" || !w.Flushed || len(b.openReqs) != 0 {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	var env confirmEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "confirm_required" || env.Confirm.Token == "" {
		t.Fatal(w.Body)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest(target+"&confirm="+url.QueryEscape(env.Confirm.Token), c, csrf, strings.NewReader("confirmed")))
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// stalledBody is a request body that never produces a byte until the test lets
// it, which is what a multipart upload that never sends its first boundary
// looks like from inside NextPart.
type stalledBody struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newStalledBody() *stalledBody {
	return &stalledBody{started: make(chan struct{}), release: make(chan struct{})}
}

func (b *stalledBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return 0, io.EOF
}

// TestUploadSlotsBoundConcurrentRequests is the round-7 adversarial P1: an
// upload that stalls before its first multipart boundary waits inside NextPart,
// which is before OpenWrite — so neither the worker's handle limit nor its
// expiry sweep has anything to say about it, and until this was added it waited
// holding a megabyte of copy buffer. One session could open as many as the
// browser would allow.
func TestUploadSlotsBoundConcurrentRequests(t *testing.T) {
	s, b, first, csrf := uploadFixture(t)
	s.uploads.perSessionLimit, s.uploads.totalLimit = 2, 3
	second, csrf2 := sessionCookie(t, s)

	var wg sync.WaitGroup
	var bodies []*stalledBody
	stall := func(c *http.Cookie, token string) {
		t.Helper()
		body := newStalledBody()
		bodies = append(bodies, body)
		r := uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, token, body)
		r.Header.Set("Content-Type", "multipart/form-data; boundary=stalled")
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Handler().ServeHTTP(httptest.NewRecorder(), r)
		}()
		select {
		case <-body.started:
		case <-time.After(3 * time.Second):
			t.Error("upload never reached the body")
		}
	}
	// refused runs in THIS goroutine, so unreadUpload's t.Fatal is legal and a
	// body read would fail the test: the refusal must come before the buffer is
	// allocated and before anything is read.
	refused := func(c *http.Cookie, token, want string) {
		t.Helper()
		r := uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, token, unreadUpload{t})
		r.Header.Set("Content-Type", "multipart/form-data; boundary=stalled")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"code":"queue_full"`) {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("refusal names the wrong ceiling: %s", w.Body)
		}
		// Every early refusal closes the connection, or the client retries.
		if w.Header().Get("Connection") != "close" {
			t.Fatalf("headers: %v", w.Header())
		}
	}

	stall(first, csrf)
	stall(first, csrf)
	// The third from this session is over the per-session ceiling, while the
	// process still has room — so the per-session rule is what refused it.
	refused(first, csrf, "This session already has")
	// Another session still gets the free process slot...
	stall(second, csrf2)
	// ...and is then refused by the process-wide ceiling, not its own.
	refused(second, csrf2, "as many uploads as it can")

	if len(b.openReqs) != 0 {
		t.Fatalf("a stalled upload reached the worker: %+v", b.openReqs)
	}
	for _, body := range bodies {
		close(body.release)
	}
	wg.Wait()
	// Every slot is released on the way out, whatever the outcome was.
	s.uploads.mu.Lock()
	total, sessions := s.uploads.total, len(s.uploads.perSession)
	s.uploads.mu.Unlock()
	if total != 0 || sessions != 0 {
		t.Fatalf("slots leaked: total=%d sessions=%d", total, sessions)
	}
	// And the route works again once they are.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", first, csrf, strings.NewReader("payload")))
	if w.Code != http.StatusCreated {
		t.Fatalf("after release: %d %s", w.Code, w.Body)
	}
}

// uploadConn opens a raw connection and writes the request head, so a test can
// control exactly when body bytes arrive. The real net/http server is needed:
// the read deadline is set on the connection, which a ResponseRecorder has not
// got.
func uploadConn(t *testing.T, server *httptest.Server, c *http.Cookie, csrf, query, contentType string, length int) net.Conn {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = fmt.Fprintf(conn, "POST /api/fs/upload?%s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: %s\r\nX-QFM-CSRF: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		query, u.Host, c.String(), server.URL, csrf, contentType, length)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// TestUploadStallIsDroppedAndSlowUploadSurvives is the other half of the P1: a
// slot that is never released is not a bound. A client that stops sending is
// dropped within a window; one that is merely slow is not, however little it
// sends — the window is an idle timeout, not a throughput floor.
func TestUploadStallIsDroppedAndSlowUploadSurvives(t *testing.T) {
	t.Run("stalled", func(t *testing.T) {
		s, b, c, csrf := uploadFixture(t)
		// Short: this one only has to fire.
		s.uploads.window = 200 * time.Millisecond
		server := httptest.NewServer(s.Handler())
		defer server.Close()
		// Content-Length promises bytes that never come.
		conn := uploadConn(t, server, c, csrf, "dir=/dest&name=a.bin&conflict=skip", "multipart/form-data; boundary=stalled", 4096)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("the stalled upload was never dropped: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusRequestTimeout || !bytes.Contains(body, []byte(`"code":"cancelled"`)) {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		if !resp.Close {
			t.Fatal("a dropped upload left the connection open")
		}
		if len(b.openReqs) != 0 {
			t.Fatalf("a stalled upload reached the worker: %+v", b.openReqs)
		}
		// The slot goes back, or one stalled client per slot kills the route.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s.uploads.mu.Lock()
			total := s.uploads.total
			s.uploads.mu.Unlock()
			if total == 0 {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatal("the stalled upload kept its slot")
	})

	t.Run("slow but live", func(t *testing.T) {
		s, b, c, csrf := uploadFixture(t)
		// Generous: a scheduler or GC pause between two writes must not be
		// mistaken for a stalled client and make this test flaky. The gap below
		// is a fifth of the window.
		const window = time.Second
		s.uploads.window = window
		server := httptest.NewServer(s.Handler())
		defer server.Close()
		payload := []byte("trickled")
		conn := uploadConn(t, server, c, csrf, "dir=/dest&name=a.bin&conflict=skip", "application/octet-stream", len(payload))
		// A byte at a time, with gaps inside the window but many windows in
		// total, and nothing like a megabyte: a throughput floor would drop
		// this, an idle timeout must not.
		for i := range payload {
			time.Sleep(window / 5)
			if _, err := conn.Write(payload[i : i+1]); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("a live upload was dropped: %d %s", resp.StatusCode, body)
		}
		if len(b.openReqs) != 1 {
			t.Fatalf("open: %+v", b.openReqs)
		}
	})
}

// Exercise net/http's real unread-body behavior as well as the recorder: the
// client sends only headers and waits for 409 before sending any upload bytes.
func TestUploadConfirmationHTTPBeforeBody(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "POST /api/fs/upload?dir=/dest&name=a&conflict=overwrite HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: %s\r\nX-QFM-CSRF: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: 3145728\r\n\r\n", u.Host, c.String(), server.URL, csrf)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response waited for the body: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 409 || !resp.Close || !bytes.Contains(body, []byte("confirm_required")) || len(b.openReqs) != 0 {
		t.Fatalf("response: %d close=%v body=%s err=%v", resp.StatusCode, resp.Close, body, err)
	}
}

func TestUploadTokenBoundToDestination(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	target := "/api/fs/upload?dir=/dest&name=a&conflict=overwrite"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest(target, c, csrf, unreadUpload{t}))
	var env confirmEnvelope
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest(strings.Replace(target, "name=a", "name=b", 1)+"&confirm="+url.QueryEscape(env.Confirm.Token), c, csrf, unreadUpload{t}))
	if w.Code != 409 || len(b.openReqs) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUploadAuditIntentPrecedesOpen(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	_ = withAudit(t, s)
	b.onOpen = func() {
		events, err := s.auditor.Tail(10)
		if err != nil || len(events) != 1 || events[0].Phase != "intent" {
			t.Fatalf("OpenWrite before durable intent: %+v %v", events, err)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a", c, csrf, strings.NewReader("bytes")))
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// TestUploadKeepBothAuditNamesTheLandedFile is the round-16 P2. With
// conflict=rename and something already at the destination, Finalize keeps both
// and publishes "a (2).txt" — but the success line was written before res.Path
// was mapped back into the caller's vocabulary, so BOTH records of the pair
// named "a.txt". The durable log then said a file had been written that was
// never touched, and never named the file that was actually created.
//
// The intent path stays the path of both records, so they still pair by op and
// path; the landed spelling goes in Dst, as a rename's destination does.
func TestUploadKeepBothAuditNamesTheLandedFile(t *testing.T) {
	for _, tc := range []struct{ name, landed, wantDst string }{
		{"kept both", "a (2).txt", "/dest/a (2).txt"},
		{"landed where it was asked to", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, c, csrf := uploadFixture(t)
			b.finalName = tc.landed
			readAudit := withAudit(t, s)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.txt&size=7&conflict=rename", c, csrf, strings.NewReader("payload")))
			if w.Code != 201 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			wantPath := "/dest/a.txt"
			if tc.landed != "" {
				wantPath = "/dest/" + tc.landed
			}
			// The 201 already named the landed file; the audit is the half that did not.
			if !strings.Contains(w.Body.String(), `"path":"`+wantPath+`"`) || strings.Contains(w.Body.String(), "/real") {
				t.Fatalf("201 body: %s", w.Body)
			}
			events := readAudit()
			if len(events) != 2 {
				t.Fatalf("audit: %+v", events)
			}
			intent, result := events[0], events[1]
			if intent.Phase != "intent" || intent.Op != "upload" || intent.Path != "/dest/a.txt" || intent.Dst != "" {
				t.Fatalf("intent: %+v", intent)
			}
			if result.Phase != "result" || result.Result != "ok" || result.Op != "upload" || result.Path != "/dest/a.txt" {
				t.Fatalf("result: %+v", result)
			}
			if result.Dst != tc.wantDst {
				t.Fatalf("the result record names dst=%q, want %q", result.Dst, tc.wantDst)
			}
			// Never the worker's own spelling, in either field.
			if strings.Contains(result.Path+result.Dst, "/real") {
				t.Fatalf("resolved spelling in the audit: %+v", result)
			}
		})
	}
}

func TestUploadGuardsAndCreateAs(t *testing.T) {
	for _, tc := range []struct {
		name, dir, resolved, code string
		root, as                  bool
		status                    int
	}{
		{"normal user", "/dest", "/real", "", false, false, 201},
		{"root normal", "/dest", "/real", "", true, true, 201},
		{"requested warn", "/etc/config", "/real", "", true, false, 201},
		{"resolved warn", "/dest", "/etc/config", "", true, false, 201},
		{"requested deny", "/app/config", "/real", "protected", false, false, 403},
		{"resolved deny", "/dest", "/app/config", "protected", false, false, 403},
		{"ramdisk requested", "/share", "/real", "protected", false, false, 403},
		{"ramdisk resolved", "/dest", "/share", "protected", false, false, 403},
		{"contains requested", "/etc", "/real", "protected", false, false, 403},
		{"contains resolved", "/dest", "/etc", "protected", false, false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, c, csrf := uploadFixture(t)
			s.guard = guard.New("/app", true)
			b.aliases[tc.dir] = tc.resolved
			s.sessions[c.Value].who.Root = tc.root
			target := "/api/fs/upload?dir=" + url.QueryEscape(tc.dir) + "&name=a"
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, uploadRequest(target, c, csrf, strings.NewReader("a")))
			if w.Code == 409 && tc.status == 201 {
				var env confirmEnvelope
				_ = json.Unmarshal(w.Body.Bytes(), &env)
				w = httptest.NewRecorder()
				s.Handler().ServeHTTP(w, uploadRequest(target+"&confirm="+url.QueryEscape(env.Confirm.Token), c, csrf, strings.NewReader("a")))
			}
			if w.Code != tc.status {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatal(w.Body)
			}
			if tc.status == 201 {
				as := b.openReqs[0].As
				if (as != nil) != tc.as {
					t.Fatalf("As=%+v want %v", as, tc.as)
				}
				if as != nil && (as.UID != 1000 || as.GID != -1 || as.Mode != 0) {
					t.Fatalf("As=%+v", as)
				}
			} else if len(b.openReqs) != 0 {
				t.Fatal("denial dispatched")
			}
		})
	}
}

type disconnectUpload struct{ cancel context.CancelFunc }

func (r disconnectUpload) Read(p []byte) (int, error) {
	r.cancel()
	return copy(p, "partial"), io.ErrUnexpectedEOF
}

func TestUploadDisconnectDiscards(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	readAudit := withAudit(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := uploadRequest("/api/fs/upload?dir=/dest&name=a", c, csrf, disconnectUpload{cancel}).WithContext(ctx)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if len(b.finalReqs) != 1 || !b.finalReqs[0].Discard {
		t.Fatalf("finalize: %+v", b.finalReqs)
	}
	events := readAudit()
	if len(events) != 2 || events[0].Phase != "intent" || events[1].Result != "aborted" || events[1].Bytes != 7 {
		t.Fatalf("audit: %+v", events)
	}
}

func TestUploadErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{os.ErrExist, "exists", 409}, {syscall.EBUSY, "conflict", 409}, {fsx.ErrChanged, "changed", 409}, {fsx.ErrNoSpace, "no_space", 507},
	} {
		for _, atOpen := range []bool{true, false} {
			t.Run(tc.code+"/"+map[bool]string{true: "open", false: "finalize"}[atOpen], func(t *testing.T) {
				s, b, c, csrf := uploadFixture(t)
				readAudit := withAudit(t, s)
				if atOpen {
					b.openErr = tc.err
				} else {
					b.finalErr = tc.err
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a", c, csrf, strings.NewReader("a")))
				if w.Code != tc.status || !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
					t.Fatalf("%d %s", w.Code, w.Body)
				}
				events := readAudit()
				if len(events) != 2 || events[1].Result != "error" || events[1].Code != tc.code {
					t.Fatalf("audit: %+v", events)
				}
			})
		}
	}
}

func TestUploadValidationAndAuth(t *testing.T) {
	for _, query := range []string{"name=..", "name=a/b", "name=a&size=-1", "name=a&size=9223372036854775808", "name=a&mtime=bad", "name=a&conflict=no"} {
		s, b, c, csrf := uploadFixture(t)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&"+query, c, csrf, unreadUpload{t}))
		if w.Code != 400 || len(b.openReqs) != 0 {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body)
		}
	}
	s, b, c, csrf := uploadFixture(t)
	for _, tc := range []struct {
		method, csrf, origin, site string
		status                     int
	}{
		{"GET", csrf, "http://example.com", "", 405}, {"POST", "bad", "http://example.com", "", 403},
		{"POST", csrf, "http://evil.example", "", 403}, {"POST", csrf, "http://example.com", "cross-site", 403},
	} {
		// A GET carrying a body is refused before routing now (bodiedRead), and
		// what this row is about is the method check, so it sends none.
		var body io.Reader = unreadUpload{t}
		if tc.method == http.MethodGet {
			body = nil
		}
		r := uploadRequest("/api/fs/upload?dir=/dest&name=a", c, tc.csrf, body)
		r.Method = tc.method
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	s.guard.SetReadOnly(true)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a", c, csrf, unreadUpload{t}))
	if w.Code != 403 || !strings.Contains(w.Body.String(), "read_only") || len(b.openReqs) != 0 {
		t.Fatal(w.Body)
	}
	s, _ = fixture(t, false)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a", nil, "", unreadUpload{t}))
	if w.Code != 401 || !isMutationRoute("/api/fs/upload") {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
}

func TestUploadByteSafeDirectoryAndProtectedName(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	// The base64 value wins over the display spelling, as on the other routes.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/bad&dirB64=L2Rlc3Q&name=a", c, csrf, strings.NewReader("a")))
	if w.Code != 201 || string(b.openReqs[0].Dir) != "/real" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=.zfs", c, csrf, unreadUpload{t}))
	if w.Code != 403 || len(b.openReqs) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUploadConnectionCloseOnEarlyRefusal(t *testing.T) {
	// Early errors must set Connection: close to prevent Chrome from retrying
	// POST requests when the body hasn't been fully consumed. Each refusal case
	// below returns a non-2xx status before io.CopyBuffer reads any body bytes.
	for _, tc := range []struct {
		name    string
		request func(*http.Request)
		wantErr string
		status  int
	}{
		{"validation: bad name", func(r *http.Request) {
			r.URL.RawQuery = "dir=/dest&name=.."
		}, "bad_request", 400},
		{"validation: invalid conflict", func(r *http.Request) {
			r.URL.RawQuery = "dir=/dest&name=a&conflict=maybe"
		}, "bad_request", 400},
		{"validation: negative size", func(r *http.Request) {
			r.URL.RawQuery = "dir=/dest&name=a&size=-1"
		}, "bad_request", 400},
		{"multipart: no file", func(r *http.Request) {
			r.URL.RawQuery = "dir=/dest&name=a"
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			_ = mw.WriteField("ignored", "value")
			_ = mw.Close()
			r.Body = io.NopCloser(&body)
			r.Header.Set("Content-Type", mw.FormDataContentType())
		}, "bad_request", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, c, csrf := uploadFixture(t)
			r := uploadRequest("/api/fs/upload", c, csrf, unreadUpload{t})
			tc.request(r)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), `"code":"`+tc.wantErr+`"`) {
				t.Fatalf("%d %s, want %d %s", w.Code, w.Body, tc.status, tc.wantErr)
			}
			if w.Header().Get("Connection") != "close" {
				t.Errorf("early refusal %s: Connection header = %q, want close", tc.name, w.Header().Get("Connection"))
			}
		})
	}
	// 201 success must NOT set Connection: close to preserve keep-alive
	s, _, c, csrf := uploadFixture(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=ok", c, csrf, strings.NewReader("data")))
	if w.Code != 201 {
		t.Fatalf("success: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Connection") == "close" {
		t.Error("201 success: Connection header should not be close (keep-alive preferred)")
	}
}

func TestUploadUnauthenticatedSendsPrompt401WithClose(t *testing.T) {
	// An unauthenticated POST to /api/fs/upload with a large body should get
	// a prompt 401 with Connection: close, not wait for the entire body.
	// This test uses raw TCP connections to verify the Connection: close header
	// is actually sent by the server (http.Client filters out hop-by-hop headers).
	s, _, _, _ := uploadFixture(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go http.Serve(listener, s.Handler())

	// Connect directly with raw TCP to see the actual headers
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send unauthenticated POST request
	fmt.Fprintf(conn, "POST /api/fs/upload?dir=/dest&name=test HTTP/1.1\r\n")
	fmt.Fprintf(conn, "Host: localhost\r\n")
	fmt.Fprintf(conn, "Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(conn, "Content-Length: %d\r\n", 10<<20) // 10 MiB
	fmt.Fprintf(conn, "\r\n")

	// Read response headers without sending full body
	reader := bufio.NewReader(conn)
	var statusLine string
	var connectionHeaderFound bool
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		if strings.HasPrefix(line, "HTTP/") {
			statusLine = line
		}
		if strings.HasPrefix(line, "Connection:") || strings.HasPrefix(line, "connection:") {
			connectionHeaderFound = strings.Contains(strings.ToLower(line), "close")
		}
	}

	// Verify the response has 401 status and Connection: close
	if !strings.Contains(statusLine, "401") {
		t.Errorf("status line %q, want 401", statusLine)
	}
	if !connectionHeaderFound {
		t.Errorf("Connection: close header not found in response")
	}
}

func TestUploadRefusalWrapper(t *testing.T) {
	// Verify that uploadRefusal correctly sets Connection: close for error codes
	resp := httptest.NewRecorder()
	wrapped := uploadRefusal{resp}

	// Test with 401 (should set Connection: close)
	wrapped.WriteHeader(401)

	if conn := resp.Header().Get("Connection"); conn != "close" {
		t.Errorf("401: Connection header %q, want 'close'", conn)
	}

	// Test with 200 (should NOT set Connection: close)
	resp2 := httptest.NewRecorder()
	wrapped2 := uploadRefusal{resp2}
	wrapped2.WriteHeader(200)

	if conn := resp2.Header().Get("Connection"); conn != "" {
		t.Errorf("200: Connection header %q, want empty", conn)
	}
}

// readDeadlineWriter records the read deadlines http.ResponseController sets on
// it, which is the only way to see them from a handler's side.
type readDeadlineWriter struct {
	http.ResponseWriter
	set []time.Time
}

func (w *readDeadlineWriter) SetReadDeadline(t time.Time) error {
	w.set = append(w.set, t)
	return nil
}

// eofWithBytes returns everything it has in one Read, together with io.EOF —
// exactly what net/http's body reader does when Content-Length is exhausted and
// the buffer is big enough to take the rest, which for a 1 MiB body into the
// 1 MiB copy buffer is the ordinary case.
type eofWithBytes struct{ data []byte }

func (r *eofWithBytes) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// TestUploadStallWindowDoesNotOutlastTheBody is round-13 P2. The stall window
// exists for a client that stops sending. It was also measuring OUR work: the
// read that ends the body re-armed it, and the HTTP server's own background read
// of the connection then ran into it — so an upload that had arrived in full
// came back 408 whenever Finalize (a rename and an fsync, on a busy volume) took
// longer than the window.
func TestUploadStallWindowDoesNotOutlastTheBody(t *testing.T) {
	// The deadline lives on a connection, so this half needs a real socket: a
	// ResponseRecorder has none and would turn the whole mechanism off.
	s, b, c, csrf := uploadFixture(t)
	s.uploads.window = 200 * time.Millisecond
	b.finalDelay = 3 * s.uploads.window
	server := httptest.NewServer(s.Handler())
	defer server.Close()

	payload := bytes.Repeat([]byte("u"), 1<<20) // one whole copy buffer
	req, err := http.NewRequest("POST", server.URL+"/api/fs/upload?dir=/dest&name=slow.bin&conflict=skip", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)
	req.Header.Set("X-QFM-CSRF", csrf)
	req.Header.Set("Origin", server.URL)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("the request never completed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a complete upload was cancelled during finalize: %d %s", resp.StatusCode, body)
	}
	// Finalized for real, and never discarded: the whole point is that the file
	// the user sent is the file that lands.
	if len(b.finalReqs) != 1 || b.finalReqs[0].Discard || string(b.finalReqs[0].Final) != "slow.bin" {
		t.Fatalf("finalize: %+v", b.finalReqs)
	}
	if got, err := os.ReadFile(b.file); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("stream mismatch: %v, %d bytes", err, len(got))
	}

	// And the rule underneath it: a read that hands back bytes AND io.EOF is the
	// end of the body, not traffic, so it must not re-arm anything.
	rec := &readDeadlineWriter{ResponseWriter: httptest.NewRecorder()}
	deadline := &uploadDeadline{rc: http.NewResponseController(rec), window: time.Minute}
	deadline.arm(0)
	reader := &uploadReader{
		downloadReader: downloadReader{ctx: t.Context(), reader: &eofWithBytes{data: make([]byte, uploadExtendEvery*2)}},
		deadline:       deadline,
	}
	// One read, which returns two megabytes and io.EOF together. Two megabytes
	// is past uploadExtendEvery, so a read that counted would certainly re-arm.
	buf := make([]byte, uploadExtendEvery*2)
	if n, err := reader.Read(buf); n != len(buf) || err != io.EOF {
		t.Fatalf("fixture read: %d %v", n, err)
	}
	if len(rec.set) != 1 {
		t.Fatalf("the final read re-armed the window: %v", rec.set)
	}
	// Clearing is what releases the connection for the finalize that follows.
	deadline.clear()
	if len(rec.set) != 2 || !rec.set[1].IsZero() {
		t.Fatalf("clear did not drop the deadline: %v", rec.set)
	}
}

// TestUploadBindsOpenWriteToTheAuthorizedDirectory is round-13 P1. Everything
// before the body authorizes a PATHNAME, and the worker does not open the
// destination until the file part's headers arrive — a gap the client controls.
// Rename the authorized directory away, drop a symlink into the install tree in
// its place, then send the body, and the write lands somewhere the guard never
// saw. The open is bound to the inode that was cleared instead.
func TestUploadBindsOpenWriteToTheAuthorizedDirectory(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	fj := &fakeJobs{fsid: map[string]wproto.FSIdentityResp{"/real": {Dev: 7, Ino: 42, Dir: true}}}
	s.SetJobs(fj, s.jobMgr)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, csrf, strings.NewReader("payload")))
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(b.openReqs) != 1 {
		t.Fatalf("open: %+v", b.openReqs)
	}
	// The identity travels with the open, and it is the RESOLVED directory's —
	// the one the guard cleared, not the name the client typed.
	got := b.openReqs[0].DirIdentity
	if got == nil {
		t.Fatal("OpenWrite was not bound to a directory identity")
	}
	want := wproto.FSIdentityResp{Dev: 7, Ino: 42, Dir: true}
	if *got != want {
		t.Fatalf("DirIdentity = %+v, want %+v", *got, want)
	}
	if !got.SameInode(want) {
		t.Fatalf("SameInode disagrees with itself: %+v", got)
	}
	// A different inode on the same device is a different directory, however
	// alike the two look otherwise.
	if got.SameInode(wproto.FSIdentityResp{Dev: 7, Ino: 43, Dir: true}) {
		t.Fatal("SameInode matched a different inode")
	}
}

// TestUploadRefusedWhenTheDirectoryChanged is the other end of the same fix: the
// worker answers "changed" when the directory it opens is not the one that was
// cleared, and that must reach the user as the conflict it is — not a 500 — with
// the part-written upload discarded and the audit pair closed.
func TestUploadRefusedWhenTheDirectoryChanged(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	s.SetJobs(&fakeJobs{fsid: map[string]wproto.FSIdentityResp{"/real": {Dev: 7, Ino: 42, Dir: true}}}, s.jobMgr)
	readAudit := withAudit(t, s)
	b.openErr = fsx.ErrChanged

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, csrf, strings.NewReader("payload")))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"code":"changed"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Same code, same status, different sentence: this "changed" is the
	// destination folder being swapped before anything was written, not the
	// file's own bytes changing under a completed upload.
	if !strings.Contains(w.Body.String(), "The destination folder changed before the upload could start.") {
		t.Fatalf("wording: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "could be published") {
		t.Fatalf("the finalize wording leaked into the open path: %s", w.Body)
	}
	// The upload never began, so there is nothing to finalize or discard, and
	// the audit still closes the pair it opened.
	if len(b.finalReqs) != 0 {
		t.Fatalf("finalize after a refused open: %+v", b.finalReqs)
	}
	events := readAudit()
	if len(events) != 2 || events[0].Phase != "intent" || events[1].Result != "error" || events[1].Code != "changed" {
		t.Fatalf("audit: %+v", events)
	}
}

// TestUploadRefusedWhenTheDirectoryCannotBeIdentified: if the directory we
// resolved a moment ago cannot be identified now, the upload cannot be bound to
// it — and going ahead unbound is the very thing the binding exists to prevent.
func TestUploadRefusedWhenTheDirectoryCannotBeIdentified(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	s.SetJobs(&fakeJobs{fsidErr: fs.ErrNotExist}, s.jobMgr)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, csrf, unreadUpload{t}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(b.openReqs) != 0 {
		t.Fatalf("an unbindable upload reached the worker: %+v", b.openReqs)
	}
}

// TestUploadWithheldMultipartTailDoesNotHangTheSlot is round-14 P1. EOF from the
// file part is not EOF from the body: the closing boundary and any trailing
// fields are still to come, and a client can simply stop there. With the stall
// deadline already cleared for Finalize, net/http's drain of that unread tail
// runs at the first response write — inside the handler, with no deadline — so
// the 201 and the upload slot hung for as long as the client stayed quiet.
//
// Two details make it reproduce rather than merely look plausible: the response
// has to be long enough to overflow net/http's response buffer (hence the long
// destination path), and the tail has to be DECLARED in Content-Length so the
// server waits for it.
func TestUploadWithheldMultipartTailDoesNotHangTheSlot(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	s.uploads.window = 300 * time.Millisecond
	// A destination deep enough that the success JSON exceeds the 2 KiB
	// response buffer and net/http must flush — which is what triggers the drain.
	deep := "/dest"
	for range 12 {
		deep += "/" + strings.Repeat("d", 200)
	}
	s.mutator.(*uploadBackend).resolveStub.aliases[deep] = "/real"
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// The file part is sent COMPLETE, delimiter and all, so it reaches EOF and
	// the handler moves on. What is withheld is the next part's headers and the
	// closing boundary — a tail Content-Length has promised and which never
	// comes. (Withholding the file part's own delimiter would only stall the
	// part read, which the stall window already handles.)
	const boundary = "withheld"
	part := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\npayload\r\n--" + boundary + "\r\n"
	tail := "Content-Disposition: form-data; name=\"trailing\"\r\n\r\nv\r\n--" + boundary + "--\r\n"

	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	head := fmt.Sprintf("POST /api/fs/upload?dir=%s&name=a.bin&conflict=skip HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nOrigin: %s\r\nX-QFM-CSRF: %s\r\nContent-Type: multipart/form-data; boundary=%s\r\nContent-Length: %d\r\n\r\n",
		url.QueryEscape(deep), u.Host, c.String(), server.URL, csrf, boundary, len(part)+len(tail))
	if _, err := io.WriteString(conn, head+part); err != nil {
		t.Fatal(err)
	}

	// The answer must arrive without the tail ever being sent.
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the response never came: the handler is still draining a tail that will not arrive: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	// The file is complete; only the connection is forfeit.
	if !resp.Close {
		t.Fatal("the connection was kept, so net/http would drain the tail after all")
	}
	if got, err := os.ReadFile(b.file); err != nil || string(got) != "payload" {
		t.Fatalf("the file is not the one that was sent: %q %v", got, err)
	}
	if len(b.finalReqs) != 1 || b.finalReqs[0].Discard {
		t.Fatalf("finalize: %+v", b.finalReqs)
	}

	// And the slot goes back, which is the thing that was hanging.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.uploads.mu.Lock()
		total := s.uploads.total
		s.uploads.mu.Unlock()
		if total == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the upload kept its slot")
}

// TestUploadDispatchesResolvedSpellings pins the two requests an upload makes:
// the identity it binds to and the directory it writes into are both the
// spelling the guard cleared, never the one the client typed.
func TestUploadDispatchesResolvedSpellings(t *testing.T) {
	s, b, c, csrf := uploadFixture(t)
	fj := &fakeJobs{}
	s.SetJobs(fj, s.jobMgr)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, uploadRequest("/api/fs/upload?dir=/dest&name=a.bin&conflict=skip", c, csrf, strings.NewReader("payload")))
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// FSIdentity: asked about the resolved directory, and about nothing else.
	fj.mu.Lock()
	asked := append([]string(nil), fj.fsidPaths...)
	fj.mu.Unlock()
	if len(asked) != 1 || asked[0] != "/real" {
		t.Fatalf("FSIdentity was asked about %q, want [/real]", asked)
	}
	// OpenWrite: the same resolved directory.
	if len(b.openReqs) != 1 || string(b.openReqs[0].Dir) != "/real" {
		t.Fatalf("OpenWriteReq carried the user's spelling: %q", b.openReqs[0].Dir)
	}
	// And the answer maps back to the user's vocabulary, never the worker's.
	if !strings.Contains(w.Body.String(), `"path":"/dest/a.bin"`) || strings.Contains(w.Body.String(), "/real") {
		t.Fatalf("the reply leaked the resolved spelling: %s", w.Body)
	}
}
