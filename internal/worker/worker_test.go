package worker

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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
	ours, theirs := net.Pipe()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		err := Run(context.Background(), theirs, Options{
			Version:   "test",
			Log:       log.New(io.Discard, "", 0),
			InProcess: true,
		})
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
