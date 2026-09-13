package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/wproto"
)

// The M2-C worker tests that need a transport which really passes descriptors:
// a Unix socketpair, the same shape spawnProcess hands a worker. net.Pipe
// cannot carry an fd at all, so upload and archive could otherwise only ever be
// tested through their refusal.

// dialFD starts a worker on one end of a socketpair and returns the other,
// wrapped in the transport the NAS uses.
func dialFD(t *testing.T, o Options) (wproto.Transport, func()) {
	t.Helper()
	ours, theirs := socketPair(t)
	o.Version = "test"
	o.Log = log.New(io.Discard, "", 0)
	o.InProcess = true

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = Run(context.Background(), theirs, o)
		theirs.Close()
	}()
	tr := wproto.NewTransport(ours)
	if !tr.PassesFDs() {
		t.Fatal("a socketpair must get the fd-passing transport, or these tests prove nothing")
	}
	stop := func() {
		tr.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("the worker loop did not stop")
		}
	}
	t.Cleanup(stop)
	return tr, stop
}

// socketPair is the transport production actually uses: an anonymous Unix
// socketpair, the same shape the pool hands a spawned worker on fd 3.
func socketPair(t *testing.T) (ours, theirs *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	out := make([]*net.UnixConn, 0, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("worker-test-%d", i))
		c, cerr := net.FileConn(f)
		f.Close() // FileConn duplicates it
		if cerr != nil {
			t.Fatalf("FileConn: %v", cerr)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			t.Fatalf("the socket came back as %T", c)
		}
		t.Cleanup(func() { uc.Close() })
		out = append(out, uc)
	}
	return out[0], out[1]
}

// reqFD is req() for a reply that carries a descriptor: the files are handed
// back rather than closed.
func reqFD(t *testing.T, tr wproto.Transport, id uint64, op wproto.Op, body any) (wproto.Frame, []*os.File) {
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
	if got.ID != id {
		t.Fatalf("reply id = %d, want %d", got.ID, id)
	}
	return got, files
}

// TestUploadRoundTripThroughTheWorker is contract §1.2–1.3 end to end: the
// worker creates the file as the user, the caller streams into the descriptor
// it was handed, and Finalize publishes it and describes what landed.
func TestUploadRoundTripThroughTheWorker(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 30, wproto.OpOpenWrite, wproto.OpenWriteReq{
		Dir: []byte("/a"), Name: []byte("up.txt"), Size: 5,
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("openwrite = %+v", f.Err)
	}
	if len(files) != 1 {
		t.Fatalf("%d descriptors arrived, want 1", len(files))
	}
	if f.NFD != 1 {
		t.Errorf("NFD = %d, want 1", f.NFD)
	}
	var ow wproto.OpenWriteResp
	if err := f.Unmarshal(&ow); err != nil {
		t.Fatal(err)
	}
	if len(ow.Tmp) != 16 {
		t.Fatalf("the handle is %q; it must be sixteen hex digits and never a path", ow.Tmp)
	}
	if strings.ContainsAny(string(ow.Tmp), "/\\") {
		t.Fatalf("the handle looks like a path: %q", ow.Tmp)
	}
	// Nothing is named in the destination while the body is in flight.
	if _, err := os.Stat(filepath.Join(base, "a", "up.txt")); !os.IsNotExist(err) {
		t.Errorf("the name exists before Finalize: %v", err)
	}

	if _, err := files[0].Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	files[0].Close()

	fin := req(t, tr, 31, wproto.OpFinalize, wproto.FinalizeReq{Tmp: ow.Tmp, Final: []byte("up.txt")})
	if fin.Kind != wproto.KindOK {
		t.Fatalf("finalize = %+v", fin.Err)
	}
	var fr wproto.FinalizeResp
	if err := fin.Unmarshal(&fr); err != nil {
		t.Fatal(err)
	}
	if string(fr.Path) != "/a/up.txt" || fr.Entry.Size != 5 {
		t.Fatalf("resp = %+v", fr)
	}
	b, err := os.ReadFile(filepath.Join(base, "a", "up.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("the published file is %q (%v)", b, err)
	}
	// The handle is consumed: a second Finalize can never publish it again.
	again := req(t, tr, 32, wproto.OpFinalize, wproto.FinalizeReq{Tmp: ow.Tmp, Final: []byte("other.txt")})
	if again.Kind != wproto.KindErr || again.Err.Code != "not_found" {
		t.Fatalf("a second finalize = %+v", again)
	}
}

// TestUnfinishedUploadIsClosedWhenTheSessionEnds is the other half of "a handle
// is per session": a browser that was closed mid-upload must not leave a
// `.qfm-upload-*.part` in somebody's folder.
func TestUnfinishedUploadIsClosedWhenTheSessionEnds(t *testing.T) {
	base := jobTree(t)
	tr, stop := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 40, wproto.OpOpenWrite, wproto.OpenWriteReq{Dir: []byte("/a"), Name: []byte("gone.txt")})
	if f.Kind != wproto.KindOK {
		t.Fatalf("openwrite = %+v", f.Err)
	}
	files[0].Write([]byte("half"))
	files[0].Close()

	stop() // the front-end went away
	for _, name := range dirEntries(t, filepath.Join(base, "a")) {
		if strings.HasPrefix(name, ".qfm-upload-") || name == "gone.txt" {
			t.Fatalf("the session ended with %q left behind", name)
		}
	}
}

// TestExpiredUploadHandleIsReaped is contract §1.3's ten minutes, driven by the
// clock rather than waited out.
func TestExpiredUploadHandleIsReaped(t *testing.T) {
	base := jobTree(t)
	// The clock is the SESSION's, handed in at construction, so the test can
	// move it without writing a variable a worker goroutine reads.
	start := time.Now()
	var advanced atomic.Bool
	clock := func() time.Time {
		if advanced.Load() {
			return start.Add(uploadIdleTimeout + time.Minute)
		}
		return start
	}
	tr, _ := dialFD(t, Options{now: clock})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 50, wproto.OpOpenWrite, wproto.OpenWriteReq{Dir: []byte("/a"), Name: []byte("slow.txt")})
	if f.Kind != wproto.KindOK {
		t.Fatalf("openwrite = %+v", f.Err)
	}
	var ow wproto.OpenWriteResp
	if err := f.Unmarshal(&ow); err != nil {
		t.Fatal(err)
	}
	files[0].Close()

	// Eleven minutes later, and any upload operation sweeps first.
	advanced.Store(true)
	fin := req(t, tr, 51, wproto.OpFinalize, wproto.FinalizeReq{Tmp: ow.Tmp, Final: []byte("slow.txt")})
	if fin.Kind != wproto.KindErr || fin.Err.Code != "not_found" {
		t.Fatalf("finalize of an expired handle = %+v", fin)
	}
	if _, err := os.Stat(filepath.Join(base, "a", "slow.txt")); !os.IsNotExist(err) {
		t.Errorf("an expired upload published something: %v", err)
	}
}

// TestArchiveRoundTripThroughTheWorker is §2.2's shape: OK immediately, the
// pipe's read end on the frame, and the archive arriving through it.
func TestArchiveRoundTripThroughTheWorker(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 60, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a")}, Format: "zip",
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("archive = %+v", f.Err)
	}
	if len(files) != 1 || f.NFD != 1 {
		t.Fatalf("%d descriptors arrived (NFD %d), want 1", len(files), f.NFD)
	}
	var ar wproto.ArchiveResp
	if err := f.Unmarshal(&ar); err != nil {
		t.Fatal(err)
	}
	if string(ar.Name) != "a.zip" {
		t.Errorf("name = %q", ar.Name)
	}

	body, err := io.ReadAll(files[0])
	files[0].Close()
	if err != nil {
		t.Fatalf("reading the archive from the pipe: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("the archive did not read back: %v", err)
	}
	got := map[string]bool{}
	for _, m := range zr.File {
		got[m.Name] = true
	}
	for _, want := range []string{"a/", "a/one.txt", "a/sub/", "a/sub/two.txt"} {
		if !got[want] {
			t.Fatalf("%q missing from %v", want, got)
		}
	}
	if got["ERROR.txt"] {
		t.Error("a clean archive has no ERROR.txt")
	}
}

// TestArchiveRefusesBeforeThePipe: a root the user cannot reach is an error
// frame, never a zip whose only member is a complaint.
func TestArchiveRefusesBeforeThePipe(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 61, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a"), []byte("/nope")}, Format: "zip",
	})
	for _, file := range files {
		file.Close()
	}
	if f.Kind != wproto.KindErr || f.Err.Code != "not_found" {
		t.Fatalf("archive of a missing root = %+v", f)
	}
	if len(files) != 0 {
		t.Fatalf("a refused archive must pass no descriptor, got %d", len(files))
	}
}

// TestArchiveReaderGoingAwayDoesNotBreakTheWorker: closing the read end is how
// a cancelled download stops the walk, and the session must carry on serving.
func TestArchiveReaderGoingAwayDoesNotBreakTheWorker(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 62, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a")}, Format: "tgz",
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("archive = %+v", f.Err)
	}
	files[0].Close()

	if p := req(t, tr, 63, wproto.OpPing, nil); p.Kind != wproto.KindOK {
		t.Fatalf("the worker stopped serving after a cancelled download: %+v", p)
	}
}

// TestArchiveProducersAreBoundedPerSession is M2-C review round 1, finding 2:
// an OpArchive hands over a pipe and returns, so the request semaphore bounds
// none of them. Past the session's own bound the answer is queue_full, and a
// slot that comes back is usable again.
func TestArchiveProducersAreBoundedPerSession(t *testing.T) {
	base := jobTree(t)
	// A member big enough that the archive cannot fit in a pipe's buffer, and
	// named so the zip STORES it rather than deflating it — otherwise a
	// megabyte of zeros would compress to nothing and every producer would
	// finish instantly, leaving this test asserting a bound it never reached.
	if err := os.WriteFile(filepath.Join(base, "a", "big.jpg"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	// Each producer is held open by not reading its pipe: a pipe's buffer fills
	// and the walk blocks in the write, which is exactly the state a client
	// downloading slowly leaves it in.
	held := make([]*os.File, 0, maxArchiveStreams)
	for i := 0; i < maxArchiveStreams; i++ {
		f, files := reqFD(t, tr, uint64(70+i), wproto.OpArchive, wproto.ArchiveReq{
			Paths: [][]byte{[]byte("/a")}, Format: "zip",
		})
		if f.Kind != wproto.KindOK {
			t.Fatalf("archive %d = %+v", i, f.Err)
		}
		held = append(held, files[0])
	}
	t.Cleanup(func() {
		for _, f := range held {
			f.Close()
		}
	})

	over, files := reqFD(t, tr, 80, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a")}, Format: "zip",
	})
	for _, f := range files {
		f.Close()
	}
	if over.Kind != wproto.KindErr || over.Err.Code != "queue_full" {
		t.Fatalf("the %dth archive = %+v, want queue_full", maxArchiveStreams+1, over)
	}
	if len(files) != 0 {
		t.Fatalf("a refused archive must pass no descriptor, got %d", len(files))
	}

	// A finished download gives its slot back. Draining one producer to
	// completion is what a real client does.
	if _, err := io.ReadAll(held[0]); err != nil {
		t.Fatalf("draining the first archive: %v", err)
	}
	held[0].Close()

	// The producer releases its slot as it exits, which races this request by
	// nature; a bounded retry is the honest way to observe "it came back".
	var last wproto.Frame
	for i := 0; i < 50; i++ {
		f, fds := reqFD(t, tr, uint64(90+i), wproto.OpArchive, wproto.ArchiveReq{
			Paths: [][]byte{[]byte("/a")}, Format: "zip",
		})
		last = f
		if f.Kind == wproto.KindOK {
			for _, fd := range fds {
				fd.Close()
			}
			return
		}
		for _, fd := range fds {
			fd.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the slot never came back: %+v", last)
}

// waitArchive asks for a producer's verdict until it has one. The producer runs
// on its own goroutine by design, so "ask until Done" is what a front-end does
// too — bounded, because a producer that never finishes is the failure.
func waitArchive(t *testing.T, tr wproto.Transport, id string, base uint64) wproto.ArchiveStatusResp {
	t.Helper()
	for i := 0; i < 200; i++ {
		f := req(t, tr, base+uint64(i), wproto.OpArchiveStatus, wproto.ArchiveStatusReq{ID: id})
		if f.Kind != wproto.KindOK {
			t.Fatalf("archivestatus = %+v", f.Err)
		}
		var resp wproto.ArchiveStatusResp
		if err := f.Unmarshal(&resp); err != nil {
			t.Fatal(err)
		}
		if resp.Done {
			return resp
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the producer never finished")
	return wproto.ArchiveStatusResp{}
}

// TestArchiveStatusReportsACleanRun is adversarial finding 6: a clean EOF on the
// pipe is what a truncated archive and a complete one both look like, so the
// verdict has to come from the worker rather than from the stream.
func TestArchiveStatusReportsACleanRun(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 200, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a")}, Format: "zip",
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("archive = %+v", f.Err)
	}
	var ar wproto.ArchiveResp
	if err := f.Unmarshal(&ar); err != nil {
		t.Fatal(err)
	}
	if ar.ID == "" {
		t.Fatal("the reply must carry an id for the outcome to be asked about")
	}
	body, err := io.ReadAll(files[0])
	files[0].Close()
	if err != nil {
		t.Fatal(err)
	}
	resp := waitArchive(t, tr, ar.ID, 210)
	if resp.Truncated || resp.Error != "" {
		t.Fatalf("a complete archive reported %+v", resp)
	}
	if resp.Bytes != int64(len(body)) {
		t.Errorf("Bytes = %d, want %d", resp.Bytes, len(body))
	}
}

// TestArchiveStatusIsReadyTheInstantTheStreamEnds is round 2's finding, and it
// asks the question with NO retry at all: the verdict must already be there
// when the read end reports EOF.
//
// It is by construction rather than by timing. The worker holds the only write
// end, so EOF cannot be observed until it closes it — and it closes it strictly
// after the outcome is in the table, under that table's lock. A front-end that
// asks the moment io.ReadAll returns therefore cannot be told "still
// producing", and must never be told "no record", which is what it used to
// audit as an unknown outcome.
//
// Several rounds, because a window this narrow is exactly the kind a single
// pass can step over by luck.
func TestArchiveStatusIsReadyTheInstantTheStreamEnds(t *testing.T) {
	base := jobTree(t)
	// Big enough that the producer is still writing when the reader starts, so
	// EOF really is the moment the producer finished rather than a buffer that
	// was full before anybody read it.
	if err := os.WriteFile(filepath.Join(base, "a", "big.jpg"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	id := uint64(600)
	for round := 0; round < 5; round++ {
		f, files := reqFD(t, tr, id, wproto.OpArchive, wproto.ArchiveReq{
			Paths: [][]byte{[]byte("/a")}, Format: "zip",
		})
		id++
		if f.Kind != wproto.KindOK {
			t.Fatalf("archive = %+v", f.Err)
		}
		var ar wproto.ArchiveResp
		if err := f.Unmarshal(&ar); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(files[0]) // returns at EOF, not before
		files[0].Close()
		if err != nil {
			t.Fatal(err)
		}

		st := req(t, tr, id, wproto.OpArchiveStatus, wproto.ArchiveStatusReq{ID: ar.ID})
		id++
		if st.Kind != wproto.KindOK {
			t.Fatalf("round %d: the verdict must exist by the time the stream ends: %+v", round, st.Err)
		}
		var resp wproto.ArchiveStatusResp
		if err := st.Unmarshal(&resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Done {
			t.Fatalf("round %d: status = %+v; EOF and \"still producing\" cannot both be true", round, resp)
		}
		if resp.Truncated || resp.Error != "" {
			t.Fatalf("round %d: a complete archive reported %+v", round, resp)
		}
		if resp.Bytes != int64(len(body)) {
			t.Fatalf("round %d: Bytes = %d, want %d", round, resp.Bytes, len(body))
		}
	}
}

// TestArchiveStatusReportsAReaderThatWentAway: the client cancelled, so what
// they have is not a whole archive — and the audit must say so rather than "ok".
func TestArchiveStatusReportsAReaderThatWentAway(t *testing.T) {
	base := jobTree(t)
	// Big enough that closing the read end interrupts a producer that is still
	// writing, rather than one that finished into the pipe's buffer.
	if err := os.WriteFile(filepath.Join(base, "a", "big.jpg"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f, files := reqFD(t, tr, 300, wproto.OpArchive, wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/a")}, Format: "zip",
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("archive = %+v", f.Err)
	}
	var ar wproto.ArchiveResp
	if err := f.Unmarshal(&ar); err != nil {
		t.Fatal(err)
	}
	files[0].Close() // the browser went away

	resp := waitArchive(t, tr, ar.ID, 310)
	if !resp.Truncated || resp.Error == "" {
		t.Fatalf("a download the client abandoned reported %+v, want truncated", resp)
	}
}

// TestArchiveStatusReportsAFatalRun is the mapping itself, over the one fatal
// outcome a test can produce on demand: the item bound (fsops has the run that
// produces it). What matters here is that the worker carries "truncated"
// through to the frame rather than flattening it into a byte count.
func TestArchiveStatusReportsAFatalRun(t *testing.T) {
	s := &session{opts: Options{}, archives: map[string]*archiveRecord{}}
	s.archives["abc"] = &archiveRecord{started: time.Now()}
	s.endArchive("abc", fsops.ArchiveResult{
		Bytes:     12,
		Truncated: true,
		Reason:    "fsops: the archive reached its item limit: it stopped after 2 entries",
	})
	rec := s.archives["abc"]
	if !rec.done || !rec.resp.Done {
		t.Fatalf("record = %+v", rec)
	}
	if !rec.resp.Truncated || rec.resp.Bytes != 12 || !strings.Contains(rec.resp.Error, "item limit") {
		t.Fatalf("resp = %+v", rec.resp)
	}
}

// TestArchiveStatusOfAnUnknownIdIsNotFound: an id this worker has no record of
// must not be answered with a guess. "Complete" for an archive nobody can
// account for is exactly the lie this operation exists to prevent.
func TestArchiveStatusOfAnUnknownIdIsNotFound(t *testing.T) {
	base := jobTree(t)
	tr, _ := dialFD(t, Options{})
	helloIn(t, tr, base)

	f := req(t, tr, 500, wproto.OpArchiveStatus, wproto.ArchiveStatusReq{ID: "deadbeefdeadbeef"})
	if f.Kind != wproto.KindErr || f.Err.Code != "not_found" {
		t.Fatalf("status of an unknown archive = %+v", f)
	}
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(des))
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}
