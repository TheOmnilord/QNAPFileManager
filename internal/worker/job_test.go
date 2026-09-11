package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// send writes one request frame without waiting for anything. A job is not a
// request-response: prog and warn frames arrive on the same id before the
// terminal one, so the tests here read the stream themselves rather than
// through req().
func send(t *testing.T, tr wproto.Transport, id uint64, op wproto.Op, body any) {
	t.Helper()
	f, err := wproto.NewReq(id, op, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(f, nil); err != nil {
		t.Fatal(err)
	}
}

// mustJSON marshals a job body the way the front-end's jobs.Manager does: the
// JobReq carries the operation's own request type as a raw message.
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jobStream is everything one job sent back.
type jobStream struct {
	progs []wproto.Prog
	warns []wproto.Warn
	term  wproto.Frame
}

// readJob drains frames until the terminal one for id arrives. Frames for other
// ids — a cancellation's own acknowledgement — are skipped, which is the whole
// point of every frame carrying the id it belongs to.
func readJob(t *testing.T, tr wproto.Transport, id uint64) jobStream {
	t.Helper()
	var out jobStream
	for i := 0; i < 100000; i++ {
		f, files, err := tr.Read()
		if err != nil {
			t.Fatalf("reading the job stream: %v", err)
		}
		for _, file := range files {
			file.Close()
		}
		if f.ID != id {
			continue
		}
		switch f.Kind {
		case wproto.KindProg:
			var p wproto.Prog
			if err := f.Unmarshal(&p); err != nil {
				t.Fatal(err)
			}
			out.progs = append(out.progs, p)
		case wproto.KindWarn:
			var w wproto.Warn
			if err := f.Unmarshal(&w); err != nil {
				t.Fatal(err)
			}
			out.warns = append(out.warns, w)
		default:
			out.term = f
			return out
		}
	}
	t.Fatal("the job never produced a terminal frame")
	return out
}

func (s jobStream) result(t *testing.T) wproto.JobResult {
	t.Helper()
	if s.term.Kind != wproto.KindOK {
		t.Fatalf("terminal frame = %+v, want ok", s.term.Err)
	}
	var res wproto.JobResult
	if err := s.term.Unmarshal(&res); err != nil {
		t.Fatal(err)
	}
	return res
}

// jobTree builds a tree under the worker's jail:
//
//	/a/one.txt      3 bytes
//	/a/sub/two.txt  6 bytes
func jobTree(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	if err := os.MkdirAll(filepath.Join(base, "a", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "a", "one.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "a", "sub", "two.txt"), []byte("twotwo"), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}

func helloIn(t *testing.T, tr wproto.Transport, jail string) {
	t.Helper()
	if f := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: jail, Umask: 0o022}); f.Kind != wproto.KindOK {
		t.Fatalf("hello = %+v", f)
	}
}

// TestJobDeleteReportsProgressAndResult: one long-lived RPC, progress and the
// terminal result all on the request's own id.
func TestJobDeleteReportsProgressAndResult(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 7, wproto.OpJob, wproto.JobReq{
		JobID: "job-1",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/a")}, Recursive: true}),
	})
	s := readJob(t, tr, 7)
	res := s.result(t)
	if res.Files != 2 || res.Dirs != 2 || res.Bytes != 9 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want 2 files, 2 dirs, 9 bytes", res)
	}
	if len(s.progs) == 0 {
		t.Fatal("a job must report progress while it runs")
	}
	if _, err := os.Stat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Errorf("the tree survived the delete: %v", err)
	}
}

// TestJobWarningsAreSentAndFoldedIntoTheResult is the backstop that makes a
// dropped warn frame harmless: the terminal result carries the count and the
// warnings themselves.
func TestJobWarningsAreSentAndFoldedIntoTheResult(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 8, wproto.OpJob, wproto.JobReq{
		JobID: "job-2",
		Kind:  wproto.JobDelete,
		Body: mustJSON(t, wproto.DeleteReq{
			Paths:     [][]byte{[]byte("/nope"), []byte("/a/one.txt")},
			Recursive: true,
		}),
	})
	s := readJob(t, tr, 8)
	res := s.result(t)
	if res.Files != 1 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want one removed and one skipped", res)
	}
	if len(s.warns) != 1 || s.warns[0].Code != "not_found" || string(s.warns[0].Path) != "/nope" {
		t.Fatalf("warn frames = %+v, want one not_found for /nope", s.warns)
	}
	if res.Warnings != 1 || len(res.Warns) != 1 || res.Warns[0].Code != "not_found" {
		t.Fatalf("result warnings = %+v, want the warning folded in", res)
	}
}

// TestJobProgressIsCoalesced pins identity plan §2.5: at most ten progress
// frames a second (or one per 8 MiB), so a million-file delete does not flood
// the socket.
func TestJobProgressIsCoalesced(t *testing.T) {
	const files = 400
	base := manyFiles(t, files)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	start := time.Now()
	send(t, tr, 9, wproto.OpJob, wproto.JobReq{
		JobID: "job-3",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/many")}, Recursive: true}),
	})
	s := readJob(t, tr, 9)
	elapsed := time.Since(start)
	res := s.result(t)
	if res.Files != files {
		t.Fatalf("result = %+v, want %d files", res, files)
	}
	// Two phases, so two "first" frames go out at once; everything after that
	// is bounded by the interval, plus the one final flush of whatever the
	// coalescing was still holding when the job ended.
	allowed := 2 + int(elapsed/progInterval) + 2
	if len(s.progs) > allowed {
		t.Fatalf("%d progress frames for %d items in %v; the coalescing allows %d",
			len(s.progs), files, elapsed, allowed)
	}
	if len(s.progs) == 0 {
		t.Fatal("no progress at all")
	}
}

// TestTheLastProgressStateIsFlushedBeforeTheTerminal: the coalescing holds back
// updates, and a job short enough to finish inside one interval would otherwise
// leave a UI showing the first frame's counts for ever while the terminal
// result said something else. The held state goes out before the terminal frame
// and never after it — a progress frame behind the terminal would be a reply
// for a request id the front-end has already retired.
func TestTheLastProgressStateIsFlushedBeforeTheTerminal(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 51, wproto.OpJob, wproto.JobReq{
		JobID: "job-flush",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/a")}, Recursive: true}),
	})
	s := readJob(t, tr, 51)
	res := s.result(t)
	if len(s.progs) == 0 {
		t.Fatal("no progress at all")
	}
	last := s.progs[len(s.progs)-1]
	if last.Phase != wproto.PhaseWorking {
		t.Fatalf("last progress = %+v, want the working phase", last)
	}
	// Delete counts files and directories together in its progress.
	if want := res.Files + res.Dirs; last.Files != want {
		t.Fatalf("last progress reported %d of the %d items the terminal result accounts for", last.Files, want)
	}
}

// TestJobCancelByJobIDStopsARunningDelete.
//
// The synchronisation is the protocol itself rather than a sleep: the in-process
// transport is an unbuffered pipe, so the job's first progress frame blocks
// until the test reads it — which proves the job is running and registered
// under its JobID. The cancellation is sent at that point, and the terminal
// frame reports the partial work rather than a completed delete.
func TestJobCancelByJobIDStopsARunningDelete(t *testing.T) {
	base := manyFiles(t, 2000)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 11, wproto.OpJob, wproto.JobReq{
		JobID: "job-4",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/many")}, Recursive: true}),
	})
	// The first frame of the stream: the job is running, blocked writing it.
	f, files0, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files0 {
		file.Close()
	}
	if f.ID != 11 || f.Kind != wproto.KindProg {
		t.Fatalf("first frame = %+v, want progress for the job", f)
	}
	send(t, tr, 12, wproto.OpCancel, wproto.CancelReq{JobID: "job-4"})

	s := readJob(t, tr, 11)
	// F7: the terminal of a cancelled job is an OK frame carrying the partial
	// JobResult with Cancelled set — an err frame has nowhere to put the counts
	// or the warnings.
	res := s.result(t)
	if !res.Cancelled {
		t.Fatalf("terminal result = %+v, want Cancelled set", res)
	}
	if !strings.Contains(res.Detail, "cancelled after") {
		t.Errorf("detail = %q, want the partial counts", res.Detail)
	}
	left, err := os.ReadDir(filepath.Join(base, "many"))
	if err != nil {
		t.Fatalf("the cancelled delete removed the directory itself: %v", err)
	}
	if len(left) == 0 {
		t.Fatal("the cancelled delete emptied the directory anyway")
	}
}

// manyFiles builds a directory of n one-byte files under a fresh jail and
// returns the jail root.
func manyFiles(t *testing.T, n int) string {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	if err := os.Mkdir(filepath.Join(base, "many"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(base, "many", fmt.Sprintf("f%04d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

// TestJobCancelArrivingRightBehindTheJobIsHonoured is F5.
//
// The registration happens on the read loop, before the handler goroutine
// exists, so an OpCancel sent immediately after the OpJob cannot find an empty
// table. The transport is an unbuffered pipe, so writing the OpJob frame
// returns only once the loop has read it: the cancellation that follows is
// therefore processed by the very next iteration of the same loop, and a
// registration made anywhere later would have missed it — leaving a destructive
// job running under a context nobody had cancelled while the front-end had
// already been told it stopped.
func TestJobCancelArrivingRightBehindTheJobIsHonoured(t *testing.T) {
	const files = 500
	base := manyFiles(t, files)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 31, wproto.OpJob, wproto.JobReq{
		JobID: "job-racer",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/many")}, Recursive: true}),
	})
	send(t, tr, 32, wproto.OpCancel, wproto.CancelReq{JobID: "job-racer"})

	res := readJob(t, tr, 31).result(t)
	if !res.Cancelled {
		t.Fatalf("result = %+v, want a cancelled job: the cancellation was accepted but the job ran anyway", res)
	}
	left, err := os.ReadDir(filepath.Join(base, "many"))
	if err != nil {
		t.Fatalf("the cancelled delete removed the directory itself: %v", err)
	}
	if len(left) == 0 {
		t.Fatal("the cancelled delete emptied the directory anyway")
	}
}

// TestDuplicateJobIDIsRefusedAndTheFirstStaysCancellable is F9.
//
// Overwriting the registration put two live jobs under one name: a cancellation
// then stopped whichever happened to be in the map, and the first to finish
// deleted the other's entry, so a running destructive job could no longer be
// stopped at all. The second submission is refused with "conflict" instead, and
// the first is still the one the id names.
func TestDuplicateJobIDIsRefusedAndTheFirstStaysCancellable(t *testing.T) {
	const files = 3000
	base := manyFiles(t, files)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 41, wproto.OpJob, wproto.JobReq{
		JobID: "job-dup",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/many")}, Recursive: true}),
	})
	// The first frame of the stream proves the job is running and registered:
	// the pipe is unbuffered, so the worker is blocked writing it.
	f, files0, err := tr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files0 {
		file.Close()
	}
	if f.ID != 41 || f.Kind != wproto.KindProg {
		t.Fatalf("first frame = %+v, want progress for the job", f)
	}

	send(t, tr, 42, wproto.OpJob, wproto.JobReq{
		JobID: "job-dup",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte("/many")}, Recursive: true}),
	})
	dup := readJob(t, tr, 42)
	if dup.term.Kind != wproto.KindErr {
		t.Fatalf("the duplicate job id was accepted: %+v", dup.term)
	}
	if dup.term.Err.Code != "conflict" {
		t.Fatalf("duplicate job id = %+v, want the conflict code", dup.term.Err)
	}

	// And the id still names the FIRST job, which is what makes it stoppable.
	send(t, tr, 43, wproto.OpCancel, wproto.CancelReq{JobID: "job-dup"})
	res := readJob(t, tr, 41).result(t)
	if !res.Cancelled {
		t.Fatalf("result = %+v, want the first job cancelled", res)
	}
	left, err := os.ReadDir(filepath.Join(base, "many"))
	if err != nil || len(left) == 0 {
		t.Fatalf("the cancelled delete emptied the directory anyway (%d left, %v)", len(left), err)
	}

	// The name is unregistered before the terminal frame goes out, so a
	// front-end that reuses the id the instant it sees the outcome is not
	// refused.
	send(t, tr, 44, wproto.OpJob, wproto.JobReq{
		JobID: "job-dup",
		Kind:  wproto.JobSize,
		Body:  mustJSON(t, wproto.SizeReq{Paths: [][]byte{[]byte("/many")}}),
	})
	again := readJob(t, tr, 44)
	if again.term.Kind != wproto.KindOK {
		t.Fatalf("reusing the id of a finished job = %+v, want it accepted", again.term.Err)
	}
}

// TestJobUnknownKindIsUnsupported keeps the job vocabulary closed.
func TestJobUnknownKindIsUnsupported(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 13, wproto.OpJob, wproto.JobReq{JobID: "job-5", Kind: "encrypt-everything"})
	s := readJob(t, tr, 13)
	if s.term.Kind != wproto.KindErr || s.term.Err.Code != "unsupported" {
		t.Fatalf("terminal frame = %+v, want unsupported", s.term)
	}
}

// TestJobSizeMeasuresWithoutChangingAnything.
func TestJobSizeMeasuresWithoutChangingAnything(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 14, wproto.OpJob, wproto.JobReq{
		JobID: "job-6",
		Kind:  wproto.JobSize,
		Body:  mustJSON(t, wproto.SizeReq{Paths: [][]byte{[]byte("/a")}}),
	})
	res := readJob(t, tr, 14).result(t)
	if res.Files != 2 || res.Dirs != 2 || res.Bytes != 9 {
		t.Fatalf("result = %+v, want 2 files, 2 dirs, 9 bytes", res)
	}
	if _, err := os.Stat(filepath.Join(base, "a", "one.txt")); err != nil {
		t.Fatalf("a size job changed the tree: %v", err)
	}
}

// TestTrashJobAndTrashListRoundTrip drives the trash over the wire: a delete
// with Trash set moves the item into .@qfm_trash, OpTrashList shows it, and a
// trash-restore job puts it back.
//
// The worker is unjailed here, because the mount table speaks host paths: the
// synthetic table declares the test's own temporary directory to be an ext4
// storage mount, which is how the hero and QTS trash layouts are exercised on a
// dev box (PLAN.md decision 15).
func TestTrashJobAndTrashListRoundTrip(t *testing.T) {
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	vol := filepath.VolumeName(base)
	if vol != "" {
		cwd, err := os.Getwd()
		if err != nil || !strings.EqualFold(filepath.VolumeName(cwd), vol) {
			t.Skipf("the temporary directory is on %s and the process is not", vol)
		}
	}
	api := path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(base, vol)), "/"))

	// The trash directory as the root front-end would have made it.
	trash := filepath.Join(base, ".@qfm_trash")
	if err := os.Mkdir(trash, 0o777); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(trash, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "doc.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	line := fmt.Sprintf("36 1 8:1 / %s rw,relatime - ext4 /dev/sda1 rw\n", strings.ReplaceAll(api, " ", `\040`))
	plat, err := platform.FromMountinfo(strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := dialWith(t, "", Options{Platform: plat})
	helloIn(t, tr, "")

	send(t, tr, 21, wproto.OpJob, wproto.JobReq{
		JobID: "trash-1",
		Kind:  wproto.JobDelete,
		Body:  mustJSON(t, wproto.DeleteReq{Paths: [][]byte{[]byte(api + "/doc.txt")}, Trash: true}),
	})
	res := readJob(t, tr, 21).result(t)
	if res.Files != 1 || res.Skipped != 0 || res.Warnings != 0 {
		t.Fatalf("result = %+v, want the file trashed", res)
	}
	if _, err := os.Stat(filepath.Join(base, "doc.txt")); !os.IsNotExist(err) {
		t.Fatalf("the file is still at its original path: %v", err)
	}

	listed := req(t, tr, 22, wproto.OpTrashList, wproto.TrashListReq{})
	if listed.Kind != wproto.KindOK {
		t.Fatalf("trashlist = %+v", listed.Err)
	}
	var resp wproto.TrashListResp
	if err := listed.Unmarshal(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 || string(resp.Items[0].OrigPath) != api+"/doc.txt" {
		t.Fatalf("trash list = %+v", resp.Items)
	}

	send(t, tr, 23, wproto.OpJob, wproto.JobReq{
		JobID: "trash-2",
		Kind:  wproto.JobTrashRestore,
		Body:  mustJSON(t, wproto.TrashRestoreReq{IDs: []string{resp.Items[0].ID}}),
	})
	res = readJob(t, tr, 23).result(t)
	if res.Files != 1 || res.Warnings != 0 {
		t.Fatalf("restore result = %+v", res)
	}
	if got, err := os.ReadFile(filepath.Join(base, "doc.txt")); err != nil || string(got) != "hello" {
		t.Fatalf("the restored file = %q, %v", got, err)
	}
}
