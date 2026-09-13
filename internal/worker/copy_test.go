package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// The M2-B half of the job spine: a copy and a move through the real worker
// loop, and the plain OpFSIdentity request the move pre-flight asks before it
// shows a confirm dialog.

// copyTree builds a jail with a tree to move and somewhere to move it to:
//
//	/a/one.txt      3 bytes
//	/a/sub/two.txt  6 bytes
//	/dst/
func copyTree(t *testing.T) string {
	t.Helper()
	base := jobTree(t)
	if err := os.Mkdir(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func copyBody(t *testing.T, dst string, conflict string, srcs ...string) wproto.CopyReq {
	t.Helper()
	req := wproto.CopyReq{DstDir: []byte(dst), Opts: wproto.CopyOptions{Conflict: conflict}}
	for _, s := range srcs {
		req.Src = append(req.Src, []byte(s))
	}
	return req
}

// TestJobCopyRunsThroughTheWorker: the dispatch, the progress and the terminal
// result, on one request id like every other job.
func TestJobCopyRunsThroughTheWorker(t *testing.T) {
	base := copyTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 61, wproto.OpJob, wproto.JobReq{
		JobID: "copy-1",
		Kind:  wproto.JobCopy,
		Body:  mustJSON(t, copyBody(t, "/dst", "", "/a")),
	})
	s := readJob(t, tr, 61)
	res := s.result(t)
	if res.Files != 2 || res.Dirs != 2 || res.Bytes != 9 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want 2 files, 2 dirs, 9 bytes", res)
	}
	if res.Warnings != 0 {
		t.Fatalf("warnings on a healthy copy: %+v", res.Warns)
	}
	if len(s.progs) == 0 {
		t.Fatal("a copy must report progress while it runs")
	}
	if b, err := os.ReadFile(filepath.Join(base, "dst", "a", "sub", "two.txt")); err != nil || string(b) != "twotwo" {
		t.Fatalf("the copied file is %q (%v)", b, err)
	}
	if _, err := os.Stat(filepath.Join(base, "a", "one.txt")); err != nil {
		t.Errorf("a copy removed its source: %v", err)
	}
}

// TestJobMoveRunsThroughTheWorker: the same body, the other kind, and the
// source is gone afterwards. On one filesystem this is a rename, so the counts
// come from the pre-scan rather than from a walk that never happened.
func TestJobMoveRunsThroughTheWorker(t *testing.T) {
	base := copyTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 62, wproto.OpJob, wproto.JobReq{
		JobID: "move-1",
		Kind:  wproto.JobMove,
		Body:  mustJSON(t, copyBody(t, "/dst", "", "/a")),
	})
	s := readJob(t, tr, 62)
	res := s.result(t)
	if res.Files != 2 || res.Dirs != 2 || res.Skipped != 0 || res.Warnings != 0 {
		t.Fatalf("result = %+v (%+v), want the whole tree moved", res, res.Warns)
	}
	if _, err := os.Stat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Errorf("the source survived the move: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(base, "dst", "a", "one.txt")); err != nil || string(b) != "one" {
		t.Fatalf("the moved file is %q (%v)", b, err)
	}
}

// TestJobCopyRefusesAnUnusableConflictPolicy: the engine's own refusal reaches
// the caller as an err frame, not as a job that quietly did nothing.
func TestJobCopyRefusesAnUnusableConflictPolicy(t *testing.T) {
	base := copyTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 63, wproto.OpJob, wproto.JobReq{
		JobID: "copy-bad",
		Kind:  wproto.JobCopy,
		Body:  mustJSON(t, copyBody(t, "/dst", "ask", "/a")),
	})
	s := readJob(t, tr, 63)
	if s.term.Kind != wproto.KindErr {
		t.Fatalf("terminal = %+v, want an error frame", s.term)
	}
	if s.term.Err == nil || s.term.Err.Code != "bad_request" {
		t.Fatalf("error = %+v, want bad_request", s.term.Err)
	}
}

// TestCancellingACopyDrainsToThePartialResult (F7): the terminal of a cancelled
// copy is an OK frame carrying what it managed to do, and what it managed to do
// is still on the disk.
func TestCancellingACopyDrainsToThePartialResult(t *testing.T) {
	const files = 400
	base := manyFiles(t, files)
	if err := os.Mkdir(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 64, wproto.OpJob, wproto.JobReq{
		JobID: "copy-cancel",
		Kind:  wproto.JobCopy,
		Body:  mustJSON(t, copyBody(t, "/dst", "", "/many")),
	})
	// The first frame of the stream proves the job is running before the
	// cancellation is sent, so this cannot race an empty job table.
	f, files0, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files0 {
		file.Close()
	}
	if f.ID != 64 || f.Kind != wproto.KindProg {
		t.Fatalf("first frame = %+v, want progress for the job", f)
	}
	send(t, tr, 65, wproto.OpCancel, wproto.CancelReq{JobID: "copy-cancel"})

	s := readJob(t, tr, 64)
	res := s.result(t)
	if !res.Cancelled {
		t.Fatalf("terminal result = %+v, want Cancelled set", res)
	}
	if !strings.Contains(res.Detail, "cancelled after") {
		t.Errorf("detail = %q, want the partial counts", res.Detail)
	}
	if _, err := os.Stat(filepath.Join(base, "many", "f0000.txt")); err != nil {
		t.Errorf("a cancelled COPY removed part of its source: %v", err)
	}
}

// TestCancellingAMoveLeavesBothCopies is the rule that makes a move safe to
// stop: whatever was copied stays, and nothing is deleted (contract §1.1).
func TestCancellingAMoveLeavesBothCopies(t *testing.T) {
	const files = 400
	base := manyFiles(t, files)
	if err := os.Mkdir(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 66, wproto.OpJob, wproto.JobReq{
		JobID: "move-cancel",
		Kind:  wproto.JobMove,
		Body:  mustJSON(t, copyBody(t, "/dst", "", "/many")),
	})
	f, files0, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files0 {
		file.Close()
	}
	if f.ID != 66 {
		t.Fatalf("first frame = %+v", f)
	}
	send(t, tr, 67, wproto.OpCancel, wproto.CancelReq{JobID: "move-cancel"})

	s := readJob(t, tr, 66)
	res := s.result(t)
	if !res.Cancelled {
		t.Fatalf("terminal result = %+v, want Cancelled set", res)
	}
	// A same-filesystem move is one rename, so it may well have finished before
	// the cancellation landed. What must never be true is that the source is
	// gone AND the destination is not there.
	_, srcErr := os.Stat(filepath.Join(base, "many"))
	_, dstErr := os.Stat(filepath.Join(base, "dst", "many"))
	if srcErr != nil && dstErr != nil {
		t.Fatalf("a cancelled move lost the data: source %v, destination %v", srcErr, dstErr)
	}
}

// TestOpFSIdentityAnswersFromTheWorker is the move pre-flight's round trip
// (contract §1.2): a plain request, not a job, because the confirm dialog needs
// the answer before anything starts.
func TestOpFSIdentityAnswersFromTheWorker(t *testing.T) {
	base := copyTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	f := req(t, tr, 70, wproto.OpFSIdentity, wproto.FSIdentityReq{Path: []byte("/a")})
	if f.Kind != wproto.KindOK {
		t.Fatalf("fsid = %+v", f.Err)
	}
	var dir wproto.FSIdentityResp
	if err := f.Unmarshal(&dir); err != nil {
		t.Fatal(err)
	}
	if !dir.Dir {
		t.Errorf("/a: Dir = false, want true")
	}

	f = req(t, tr, 71, wproto.OpFSIdentity, wproto.FSIdentityReq{Path: []byte("/dst")})
	if f.Kind != wproto.KindOK {
		t.Fatalf("fsid = %+v", f.Err)
	}
	var dst wproto.FSIdentityResp
	if err := f.Unmarshal(&dst); err != nil {
		t.Fatal(err)
	}
	if !dir.Same(dst) {
		t.Errorf("two directories of one jail report two filesystems: %+v vs %+v", dir, dst)
	}

	// A path that is not there is the worker's error, not an invented identity
	// the front-end would then compare against something real.
	f = req(t, tr, 72, wproto.OpFSIdentity, wproto.FSIdentityReq{Path: []byte("/nope")})
	if f.Kind != wproto.KindErr {
		t.Fatalf("fsid of a missing path = %+v, want an error frame", f)
	}
	if f.Err == nil || f.Err.Code != "not_found" {
		t.Fatalf("error = %+v, want not_found", f.Err)
	}

}
