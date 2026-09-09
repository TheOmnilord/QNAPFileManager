package worker

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// dial starts a worker on one end of a net.Pipe and hands back the other end
// plus the loop's exit status. InProcess is set so the test process's umask
// and GC target are left alone.
func dial(t *testing.T, jail string) (wproto.Transport, <-chan error) {
	t.Helper()
	return dialWith(t, jail, Options{})
}

// dialWith is dial with the worker's own options, for the tests that need a
// handler they control.
func dialWith(t *testing.T, jail string, o Options) (wproto.Transport, <-chan error) {
	t.Helper()
	ours, theirs := net.Pipe()
	done := make(chan error, 1)
	finished := make(chan struct{})
	o.Version = "test"
	o.Log = log.New(io.Discard, "", 0)
	o.InProcess = true
	go func() {
		defer close(finished)
		err := Run(context.Background(), theirs, o)
		theirs.Close()
		done <- err
	}()
	tr := wproto.NewTransport(ours)
	t.Cleanup(func() {
		tr.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("the worker loop did not stop")
		}
	})
	_ = jail
	return tr, done
}

func req(t *testing.T, tr wproto.Transport, id uint64, op wproto.Op, body any) wproto.Frame {
	t.Helper()
	f, err := wproto.NewReq(id, op, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(f, nil); err != nil {
		t.Fatal(err)
	}
	got, files, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		file.Close()
	}
	if got.ID != id {
		t.Fatalf("reply id = %d, want %d", got.ID, id)
	}
	return got
}

func fixture(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	if err := os.WriteFile(filepath.Join(base, "a.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestHelloThenServe(t *testing.T) {
	base := fixture(t)
	tr, done := dial(t, base)

	hello := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{
		JailRoot: base,
		Umask:    0o022,
		Limits:   wproto.Limits{ListMax: 10},
	})
	if hello.Kind != wproto.KindOK {
		t.Fatalf("hello reply = %+v", hello)
	}
	var hr wproto.HelloResp
	if err := hello.Unmarshal(&hr); err != nil {
		t.Fatal(err)
	}
	if hr.PID != os.Getpid() || hr.Version != "test" {
		t.Errorf("hello = %+v", hr)
	}
	if hr.UID != os.Getuid() || hr.GID != os.Getgid() {
		t.Errorf("the worker must report what the kernel made it: %+v", hr)
	}

	if f := req(t, tr, 2, wproto.OpPing, nil); f.Kind != wproto.KindOK {
		t.Fatalf("ping = %+v", f)
	}

	f := req(t, tr, 3, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	if f.Kind != wproto.KindOK {
		t.Fatalf("list = %+v", f.Err)
	}
	var lr wproto.ListResp
	if err := f.Unmarshal(&lr); err != nil {
		t.Fatal(err)
	}
	if lr.Listing.Total != 2 {
		t.Fatalf("listing = %+v", lr.Listing)
	}

	f = req(t, tr, 4, wproto.OpStat, wproto.StatReq{Path: []byte("/a.txt")})
	var sr wproto.StatResp
	if err := f.Unmarshal(&sr); err != nil {
		t.Fatal(err)
	}
	if sr.Entry.Size != 3 || sr.Entry.Name != "a.txt" {
		t.Errorf("stat = %+v", sr.Entry)
	}

	// A missing path comes back as a classified error frame, not a broken
	// connection.
	f = req(t, tr, 5, wproto.OpStat, wproto.StatReq{Path: []byte("/nope")})
	if f.Kind != wproto.KindErr || f.Err.Code != "not_found" {
		t.Fatalf("stat of a missing file = %+v", f)
	}
	if string(f.Err.Path) != "/nope" {
		t.Errorf("the error must name the path: %+v", f.Err)
	}

	// A transport that cannot pass descriptors says so rather than pretending.
	f = req(t, tr, 6, wproto.OpOpenRead, wproto.OpenReadReq{Path: []byte("/a.txt")})
	if f.Kind != wproto.KindErr || f.Err.Code != "unsupported" {
		t.Fatalf("openread over a pipe = %+v", f)
	}

	// An op this worker does not implement is "unsupported", never silence.
	f = req(t, tr, 7, wproto.OpMkdir, wproto.MkdirReq{Dir: []byte("/"), Name: []byte("x")})
	if f.Kind != wproto.KindErr || f.Err.Code != "unsupported" {
		t.Fatalf("mkdir = %+v", f)
	}

	// bye is acknowledged and ends the loop cleanly.
	if f := req(t, tr, 8, wproto.OpBye, nil); f.Kind != wproto.KindOK {
		t.Fatalf("bye = %+v", f)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bye must exit cleanly, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bye did not end the loop")
	}
}

func TestTheFirstFrameMustBeHello(t *testing.T) {
	tr, done := dial(t, "")
	f, err := wproto.NewReq(1, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(f, nil); err != nil {
		t.Fatal(err)
	}
	reply, _, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if reply.Kind != wproto.KindErr {
		t.Fatalf("reply = %+v", reply)
	}
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, wproto.ErrProtocol) {
			t.Fatalf("err = %v, want a protocol error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker kept serving without a hello")
	}
}

func TestASecondHelloIsRefused(t *testing.T) {
	base := fixture(t)
	tr, _ := dial(t, base)
	if f := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base}); f.Kind != wproto.KindOK {
		t.Fatal("the first hello must succeed")
	}
	f := req(t, tr, 2, wproto.OpHello, wproto.HelloReq{JailRoot: "/"})
	if f.Kind != wproto.KindErr {
		t.Fatalf("a second hello = %+v", f)
	}
	// The jail must not have moved.
	l := req(t, tr, 3, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	var lr wproto.ListResp
	if err := l.Unmarshal(&lr); err != nil {
		t.Fatal(err)
	}
	if lr.Listing.Total != 2 {
		t.Fatalf("the jail changed: %+v", lr.Listing)
	}
}

func TestTheWorkerEnforcesTheListCap(t *testing.T) {
	base := fixture(t)
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(base, string(rune('m'+i))+".txt"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tr, _ := dial(t, base)
	req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base, Limits: wproto.Limits{ListMax: 3}})

	// The request asks for more than the front-end's cap; the worker applies
	// its own limit rather than trusting the request.
	f := req(t, tr, 2, wproto.OpList, wproto.ListReq{Dir: []byte("/"), Opts: fsx.ListOptions{Limit: 1000}})
	var lr wproto.ListResp
	if err := f.Unmarshal(&lr); err != nil {
		t.Fatal(err)
	}
	if len(lr.Listing.Entries) != 3 || !lr.Listing.Truncated {
		t.Fatalf("listing = %d entries, truncated=%v, want 3 and true", len(lr.Listing.Entries), lr.Listing.Truncated)
	}
	if lr.Listing.Total != 7 {
		t.Fatalf("total = %d, want 7", lr.Listing.Total)
	}
}

// TestOpCancelStopsARunningHandler is the worker half of cancellation
// propagation. A request deadline used to unregister the caller and nothing
// else: the handler kept running under the process context, holding one of the
// worker's 64 slots — and, for a fifo or a directory on a wedged mount, a
// syscall nothing in this process could interrupt.
func TestOpCancelStopsARunningHandler(t *testing.T) {
	base := fixture(t)
	started := make(chan struct{})
	tr, _ := dialWith(t, base, Options{
		dispatch: func(ctx context.Context, f wproto.Frame) (any, error) {
			close(started)
			<-ctx.Done() // only a cancellation ends this handler
			return nil, ctx.Err()
		},
	})
	if f := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base}); f.Kind != wproto.KindOK {
		t.Fatalf("hello = %+v", f)
	}

	slow, err := wproto.NewReq(2, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(slow, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started")
	}

	cancel, err := wproto.NewReq(3, wproto.OpCancel, wproto.CancelReq{ReqID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(cancel, nil); err != nil {
		t.Fatal(err)
	}

	// The acknowledgement and the cancelled request's own error frame race, so
	// read until the one that matters arrives.
	deadline := time.After(10 * time.Second)
	for {
		type read struct {
			f   wproto.Frame
			err error
		}
		got := make(chan read, 1)
		go func() {
			f, files, err := tr.Read()
			for _, file := range files {
				file.Close()
			}
			got <- read{f, err}
		}()
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatalf("read: %v", r.err)
			}
			if r.f.ID != 2 {
				continue
			}
			if r.f.Kind != wproto.KindErr || r.f.Err.Code != "cancelled" {
				t.Fatalf("the cancelled request came back as %+v", r.f)
			}
			return
		case <-deadline:
			t.Fatal("the cancel frame did not stop the handler")
		}
	}
}

// TestTheConnectionEndingStopsRunningHandlers: serve waits for every handler
// before it returns, so a worker whose front-end had gone used to sit out the
// listing it was in the middle of — with nobody left to give it to.
func TestTheConnectionEndingStopsRunningHandlers(t *testing.T) {
	base := fixture(t)
	started := make(chan struct{})
	tr, done := dialWith(t, base, Options{
		dispatch: func(ctx context.Context, f wproto.Frame) (any, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if f := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base}); f.Kind != wproto.KindOK {
		t.Fatalf("hello = %+v", f)
	}
	slow, err := wproto.NewReq(2, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(slow, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started")
	}

	// The front-end goes away mid-request.
	_ = tr.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker waited for a handler whose reply had nowhere to go")
	}
}

// TestAFailedWriteEndsTheWorker: a write that fails part-way leaves a frame the
// peer can never finish reading, and every reply after it would be read as the
// remainder of that one. The worker used to log the failure and carry on
// writing into the desynchronised stream.
func TestAFailedWriteEndsTheWorker(t *testing.T) {
	base := fixture(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	conn := &failingConn{in: pr, failAt: 2, closed: make(chan struct{})}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), conn, Options{
			Version:   "test",
			Log:       log.New(io.Discard, "", 0),
			InProcess: true,
		})
	}()

	// The hello reply is the first write and succeeds; the ping's reply is the
	// second and does not.
	sendFrame(t, pw, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base})
	sendFrame(t, pw, 2, wproto.OpPing, nil)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a failed write must end the worker with an error, not silently")
		}
		if !strings.Contains(err.Error(), "reply") {
			t.Errorf("err = %v, want the write failure", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker kept serving after a half-written frame")
	}
	select {
	case <-conn.closed:
	default:
		t.Error("the transport must be closed so the parent sees worker_gone and respawns")
	}
}

// failingConn is a transport whose writes stop working part-way through the
// session, the way a socket does when the peer is gone or the send buffer
// cannot be drained. Reads come from a pipe the test feeds.
type failingConn struct {
	in     *io.PipeReader
	failAt int64
	writes atomic.Int64
	once   sync.Once
	closed chan struct{}
}

func (c *failingConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *failingConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) >= c.failAt {
		return 0, errors.New("the connection went away mid-frame")
	}
	return len(p), nil
}

func (c *failingConn) Close() error {
	c.once.Do(func() {
		c.in.CloseWithError(io.ErrClosedPipe)
		close(c.closed)
	})
	return nil
}

func sendFrame(t *testing.T, w io.Writer, id uint64, op wproto.Op, body any) {
	t.Helper()
	f, err := wproto.NewReq(id, op, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := wproto.Encode(w, f); err != nil {
		t.Fatal(err)
	}
}

func TestANonRequestFrameIsAProtocolError(t *testing.T) {
	base := fixture(t)
	tr, _ := dial(t, base)
	req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base})

	if err := tr.Write(wproto.Frame{ID: 2, Kind: wproto.KindOK}, nil); err != nil {
		t.Fatal(err)
	}
	f, _, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != wproto.KindErr {
		t.Fatalf("reply = %+v", f)
	}
	// The connection survives it.
	if f := req(t, tr, 3, wproto.OpPing, nil); f.Kind != wproto.KindOK {
		t.Fatalf("ping after a bad frame = %+v", f)
	}
}
