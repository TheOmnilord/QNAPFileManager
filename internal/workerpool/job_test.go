package workerpool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The job tests run against a worker that never was: a goroutine on the other
// end of a net.Pipe speaking the real frame codec. It is written here rather
// than driven through internal/worker because the worker's own job handler is
// being built in parallel — and because a scripted worker is the only way to
// produce the three things that matter to this side and are hard to provoke in
// a real one: a flood of progress frames, a cancellation answered with partial
// counts, and a process that dies in the middle.

type jobScript struct {
	// progs and warns are emitted, in that order, before the job finishes.
	progs, warns int
	// filesTotal is the denominator reported in each progress frame.
	filesTotal int64
	// result is the terminal ok body when the job runs to completion.
	result wproto.JobResult
	// hold, when set, makes the job wait after its frames until the test opens
	// it (or cancels the job).
	hold chan struct{}
	// cancelReply picks what a cancelled job answers with: "err" (the worker's
	// own cancelled error, carrying its partial counts in the detail) or "ok"
	// (a JobResult whose counters are the partial ones).
	cancelReply string
	// crashAfter closes the connection after this many progress frames, which
	// is what a segfaulting worker looks like from the pool's side. 0 disables.
	crashAfter int
	// trash is what OpTrashList answers.
	trash wproto.TrashListResp
}

type fakeWorker struct {
	t      *testing.T
	who    backend.Principal
	peer   wproto.Transport
	script jobScript

	// cancels carries every OpCancel body the worker saw.
	cancels chan wproto.CancelReq
	// wrote is closed once a job has written its terminal frame.
	wrote chan struct{}
	// jobs counts the OpJob frames that arrived.
	jobs atomic.Int64

	mu      sync.Mutex
	running map[string]chan struct{}
}

func newFakeWorker(t *testing.T, who backend.Principal, script jobScript) (*client, *fakeWorker) {
	t.Helper()
	ours, theirs := net.Pipe()
	c := newClient(who)
	c.tr = wproto.NewTransport(ours)
	c.pid = 7777
	terminates(c, theirs)

	w := &fakeWorker{
		t:       t,
		who:     who,
		peer:    wproto.NewTransport(theirs),
		script:  script,
		cancels: make(chan wproto.CancelReq, 8),
		wrote:   make(chan struct{}),
		running: map[string]chan struct{}{},
	}
	go w.serve()
	return c, w
}

// jobPool is a pool whose workers are fakeWorkers. The first one is made on
// the first acquire, so a test pings before it reads from made.
func jobPool(t *testing.T, script jobScript) (*Pool, <-chan *fakeWorker, *clock, *atomic.Int64) {
	t.Helper()
	made := make(chan *fakeWorker, 4)
	var spawns atomic.Int64
	p, clk := testPool(t, func(o *Options) {
		o.newWorker = func(who backend.Principal) (*client, error) {
			spawns.Add(1)
			c, w := newFakeWorker(t, who, script)
			made <- w
			return c, nil
		}
	})
	return p, made, clk, &spawns
}

func (w *fakeWorker) serve() {
	for {
		f, files, err := w.peer.Read()
		closeAll(files)
		if err != nil {
			return
		}
		switch f.Op {
		case wproto.OpHello:
			w.ok(f.ID, wproto.HelloResp{PID: 7777, UID: w.who.UID, GID: w.who.GID})
		case wproto.OpPing, wproto.OpBye:
			w.ok(f.ID, nil)
		case wproto.OpTrashList:
			w.ok(f.ID, w.script.trash)
		case wproto.OpCancel:
			var req wproto.CancelReq
			if err := f.Unmarshal(&req); err == nil {
				select {
				case w.cancels <- req:
				default:
				}
				w.stop(req.JobID)
			}
			w.ok(f.ID, nil)
		case wproto.OpJob:
			var req wproto.JobReq
			if err := f.Unmarshal(&req); err != nil {
				w.errFrame(f.ID, err)
				continue
			}
			w.jobs.Add(1)
			go w.runJob(f.ID, req)
		default:
			w.errFrame(f.ID, fmt.Errorf("%s: %w", f.Op, fsx.ErrUnsupported))
		}
	}
}

// runJob is the scripted job: progress, then warnings, then either a wait or a
// terminal frame. It runs on its own goroutine, which is what the real worker
// does too (identity plan §2.8: a running job does not block this user's List).
func (w *fakeWorker) runJob(id uint64, req wproto.JobReq) {
	cancelled := make(chan struct{})
	w.mu.Lock()
	w.running[req.JobID] = cancelled
	w.mu.Unlock()

	total := w.script.filesTotal
	if total == 0 {
		total = int64(w.script.progs)
	}
	for i := 0; i < w.script.progs; i++ {
		if w.script.crashAfter > 0 && i >= w.script.crashAfter {
			_ = w.peer.Close() // the process died mid-job
			return
		}
		f, err := wproto.NewProg(id, wproto.Prog{
			Files:      int64(i + 1),
			FilesTotal: total,
			Current:    []byte(fmt.Sprintf("/share/Public/f%d", i)),
			Phase:      wproto.PhaseWorking,
		})
		if err != nil || w.peer.Write(f, nil) != nil {
			return
		}
	}
	for i := 0; i < w.script.warns; i++ {
		f, err := wproto.NewWarn(id, wproto.Warn{
			Path:    []byte(fmt.Sprintf("/share/Public/w%d", i)),
			Code:    "permission",
			Message: "EACCES",
			Errno:   13,
		})
		if err != nil || w.peer.Write(f, nil) != nil {
			return
		}
	}

	if w.script.hold != nil {
		select {
		case <-w.script.hold:
		case <-cancelled:
			w.finishCancelled(id)
			return
		}
	}
	ok, err := wproto.NewOK(id, w.script.result)
	if err != nil {
		return
	}
	if w.peer.Write(ok, nil) == nil {
		w.finished()
	}
}

// finishCancelled is the worker's own account of a cancellation: what it
// managed to do before it stopped. Partial work is not rolled back, so this is
// the number the caller has to be told.
func (w *fakeWorker) finishCancelled(id uint64) {
	partial := wproto.JobResult{Files: 412, Warnings: w.script.warns, Detail: "cancelled after 412 of 8003 files"}
	var f wproto.Frame
	if w.script.cancelReply == "ok" {
		var err error
		f, err = wproto.NewOK(id, partial)
		if err != nil {
			return
		}
	} else {
		f = wproto.NewErr(id, fmt.Errorf("cancelled after 412 of 8003 files: %w", context.Canceled), nil)
	}
	if w.peer.Write(f, nil) == nil {
		w.finished()
	}
}

func (w *fakeWorker) finished() {
	select {
	case <-w.wrote:
	default:
		close(w.wrote)
	}
}

func (w *fakeWorker) stop(jobID string) {
	w.mu.Lock()
	ch, ok := w.running[jobID]
	delete(w.running, jobID)
	w.mu.Unlock()
	if ok {
		close(ch)
	}
}

func (w *fakeWorker) ok(id uint64, body any) {
	f, err := wproto.NewOK(id, body)
	if err != nil {
		return
	}
	_ = w.peer.Write(f, nil)
}

func (w *fakeWorker) errFrame(id uint64, cause error) {
	_ = w.peer.Write(wproto.NewErr(id, cause, nil), nil)
}

// spawnWorker brings a fake worker up and hands it back.
func spawnWorker(t *testing.T, p *Pool, made <-chan *fakeWorker, who backend.Principal) *fakeWorker {
	t.Helper()
	if err := p.Ping(context.Background(), who); err != nil {
		t.Fatalf("ping: %v", err)
	}
	select {
	case w := <-made:
		return w
	case <-time.After(testWait):
		t.Fatal("no worker was made")
		return nil
	}
}

type jobOutcome struct {
	res wproto.JobResult
	err error
}

// runJobAsync starts a job and returns the channel its outcome arrives on.
func runJobAsync(p *Pool, ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) <-chan jobOutcome {
	out := make(chan jobOutcome, 1)
	go func() {
		res, err := p.Job(ctx, who, req, onProg, onWarn)
		out <- jobOutcome{res: res, err: err}
	}()
	return out
}

func awaitJob(t *testing.T, out <-chan jobOutcome) jobOutcome {
	t.Helper()
	select {
	case o := <-out:
		return o
	case <-time.After(testWait):
		t.Fatal("the job never returned")
		return jobOutcome{}
	}
}

func deleteJob(id string) wproto.JobReq {
	body, _ := wproto.NewReq(0, wproto.OpJob, wproto.DeleteReq{Paths: [][]byte{[]byte("/share/Public/x")}, Recursive: true})
	return wproto.JobReq{JobID: id, Kind: wproto.JobDelete, Body: body.Body}
}

// TestJobStreamsProgressAndWarningsThenTheResult is the shape of the whole
// contract: one RPC, in-band progress and warnings in the order the worker
// sent them, and a terminal JobResult that closes it.
func TestJobStreamsProgressAndWarningsThenTheResult(t *testing.T) {
	want := wproto.JobResult{Files: 5, Bytes: 1234, Dirs: 2, Warnings: 3, Detail: "deleted 5 items"}
	p, made, _, _ := jobPool(t, jobScript{progs: 5, warns: 3, filesTotal: 5, result: want})
	who := alice()
	spawnWorker(t, p, made, who)

	var (
		progs []wproto.Prog
		warns []wproto.Warn
	)
	res, err := p.Job(context.Background(), who, deleteJob("abc0123456789def"),
		func(pr wproto.Prog) { progs = append(progs, pr) },
		func(w wproto.Warn) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("result = %+v, want %+v", res, want)
	}
	if len(progs) != 5 {
		t.Fatalf("%d progress frames, want 5", len(progs))
	}
	for i, pr := range progs {
		if pr.Files != int64(i+1) || pr.FilesTotal != 5 || pr.Phase != wproto.PhaseWorking {
			t.Fatalf("progress %d out of order or malformed: %+v", i, pr)
		}
		if string(pr.Current) != fmt.Sprintf("/share/Public/f%d", i) {
			t.Fatalf("progress %d current = %q", i, pr.Current)
		}
	}
	if len(warns) != 3 {
		t.Fatalf("%d warnings, want 3", len(warns))
	}
	if warns[0].Code != "permission" || warns[0].Errno != 13 || string(warns[0].Path) != "/share/Public/w0" {
		t.Fatalf("warning = %+v", warns[0])
	}

	// Nil callbacks are the documented case for a job nobody is watching.
	if _, err := p.Job(context.Background(), who, deleteJob("0123456789abcdef"), nil, nil); err != nil {
		t.Fatalf("job with no callbacks: %v", err)
	}
}

// TestASlowCallbackLosesProgressButNeverTheResult: deliver drops a frame when
// the caller is not reading, which is acceptable for a superseded Prog and for
// a Warn (the JobResult folds the count back in) and never acceptable for the
// terminal frame — a dropped terminal would leave the caller waiting for a
// reply that had already come and gone.
func TestASlowCallbackLosesProgressButNeverTheResult(t *testing.T) {
	const sent = jobFrames * 2
	want := wproto.JobResult{Files: sent, Warnings: 50, Detail: "done"}
	p, made, _, _ := jobPool(t, jobScript{progs: sent, warns: 50, result: want})
	who := alice()
	w := spawnWorker(t, p, made, who)

	release := make(chan struct{})
	var seen atomic.Int64
	out := runJobAsync(p, context.Background(), who, deleteJob("slowcaller000001"),
		func(wproto.Prog) {
			if seen.Add(1) == 1 {
				// The first callback blocks until the worker has written
				// everything, so the buffer overflows for certain.
				<-release
			}
		}, nil)

	select {
	case <-w.wrote:
	case <-time.After(testWait):
		t.Fatal("the worker never finished writing its frames")
	}
	close(release)

	got := awaitJob(t, out)
	if got.err != nil {
		t.Fatalf("job: %v", got.err)
	}
	if !reflect.DeepEqual(got.res, want) {
		t.Fatalf("result = %+v, want %+v", got.res, want)
	}
	if n := seen.Load(); n > sent {
		t.Fatalf("%d progress frames delivered, more than the %d sent", n, sent)
	}
	// The backstop is what makes the dropped frames harmless: the count is in
	// the result whatever the socket did.
	if got.res.Warnings != 50 {
		t.Fatalf("result warnings = %d, want the worker's total of 50", got.res.Warnings)
	}
}

// TestCancellingAJobTellsTheWorkerAndWaitsForItsOutcome: dropping this end
// stops nobody. The worker is told, by job id, and the call keeps draining
// until the worker says what it managed to do — so the caller gets the real
// partial counts rather than a bare "cancelled".
func TestCancellingAJobTellsTheWorkerAndWaitsForItsOutcome(t *testing.T) {
	for _, reply := range []string{"err", "ok"} {
		t.Run("worker answers with "+reply, func(t *testing.T) {
			hold := make(chan struct{})
			defer close(hold)
			p, made, _, _ := jobPool(t, jobScript{progs: 2, filesTotal: 8003, hold: hold, cancelReply: reply})
			who := alice()
			w := spawnWorker(t, p, made, who)

			first := make(chan struct{})
			var once sync.Once
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := runJobAsync(p, ctx, who, deleteJob("cancelme00000001"),
				func(wproto.Prog) { once.Do(func() { close(first) }) }, nil)

			select {
			case <-first:
			case <-time.After(testWait):
				t.Fatal("the job never reported progress")
			}
			cancel()

			select {
			case req := <-w.cancels:
				if req.JobID != "cancelme00000001" {
					t.Fatalf("cancel carried job id %q", req.JobID)
				}
				if req.ReqID != 0 {
					t.Fatalf("a job cancellation must carry the job id, not the request id: %+v", req)
				}
			case <-time.After(testWait):
				t.Fatal("the worker was never told to cancel")
			}

			got := awaitJob(t, out)
			if !errors.Is(got.err, context.Canceled) {
				t.Fatalf("err = %v, want a cancellation", got.err)
			}
			if code := fsx.Code(got.err); code != "cancelled" {
				t.Fatalf("fsx.Code = %q, want cancelled", code)
			}
			switch reply {
			case "err":
				if !strings.Contains(got.err.Error(), "412 of 8003") {
					t.Fatalf("err = %v, want the worker's partial counts", got.err)
				}
			case "ok":
				if got.res.Files != 412 || !strings.Contains(got.res.Detail, "412 of 8003") {
					t.Fatalf("result = %+v, want the worker's partial counts", got.res)
				}
			}
		})
	}
}

// TestAWorkerThatDiesMidJobIsWorkerGone: the job is lost and the partial work
// it did stands. Saying so is the contract; pretending it was rolled back
// would be worse.
func TestAWorkerThatDiesMidJobIsWorkerGone(t *testing.T) {
	p, made, _, _ := jobPool(t, jobScript{progs: 10, crashAfter: 2})
	who := alice()
	spawnWorker(t, p, made, who)

	res, err := p.Job(context.Background(), who, deleteJob("dyingworker00001"), nil, nil)
	if !errors.Is(err, fsx.ErrWorkerGone) {
		t.Fatalf("err = %v, want ErrWorkerGone", err)
	}
	if code := fsx.Code(err); code != "worker_gone" {
		t.Fatalf("fsx.Code = %q, want worker_gone", code)
	}
	if !reflect.DeepEqual(res, wproto.JobResult{}) {
		t.Fatalf("result = %+v, want the zero result", res)
	}
}

// TestARunningJobIsNeverReaped is PLAN.md decision 5: the idle reaper must not
// fire under a job, however long it runs without another request.
func TestARunningJobIsNeverReaped(t *testing.T) {
	hold := make(chan struct{})
	p, made, clk, _ := jobPool(t, jobScript{progs: 1, hold: hold, result: wproto.JobResult{Files: 1}})
	who := alice()
	spawnWorker(t, p, made, who)
	c := p.workerForTest(t, who.Key())

	first := make(chan struct{})
	var once sync.Once
	out := runJobAsync(p, context.Background(), who, deleteJob("longjob000000001"),
		func(wproto.Prog) { once.Do(func() { close(first) }) }, nil)
	select {
	case <-first:
	case <-time.After(testWait):
		t.Fatal("the job never started")
	}

	if !c.busy() {
		t.Fatal("a running job must keep its worker in flight")
	}
	if s := p.Stats(); len(s) != 1 || s[0].InFlight < 1 {
		t.Fatalf("stats = %+v, want the job counted in flight", s)
	}
	// Hours of a job with no other request must not look idle.
	clk.advance(time.Hour)
	p.reapIdle()
	if c.idleSince(clk.now(), time.Minute) {
		t.Fatal("a worker with a job in flight reported itself idle")
	}
	p.mu.Lock()
	_, still := p.workers[who.Key()]
	p.mu.Unlock()
	if !still {
		t.Fatal("the worker running a job was reaped")
	}

	close(hold)
	got := awaitJob(t, out)
	if got.err != nil || got.res.Files != 1 {
		t.Fatalf("job = %+v, %v", got.res, got.err)
	}
	// And once it is done the worker is idle again, so the reaper may have it.
	if c.busy() {
		t.Fatal("the worker is still in flight after the job finished")
	}
}

// TestAJobClosesADescriptorItNeverAskedFor: a job passes no fds, and one that
// arrives anyway must not be left open in the root front-end for the life of
// the daemon.
func TestAJobClosesADescriptorItNeverAskedFor(t *testing.T) {
	p, _ := testPool(t, nil)
	c := newClient(alice())
	tr := newFakeTransport()
	c.tr = tr
	terminates(c, tr)
	go c.readLoop(p.opts.Logger)
	t.Cleanup(func() { _ = tr.Close() })

	stray := tempFile(t, "stray")
	out := make(chan jobOutcome, 1)
	go func() {
		res, err := p.runJob(context.Background(), c, deleteJob("fdleaktest000001"), nil, nil)
		out <- jobOutcome{res: res, err: err}
	}()

	// Wait for the job frame so the reply can echo its id.
	var id uint64
	deadline := time.Now().Add(testWait)
	for time.Now().Before(deadline) {
		if w := tr.written(); len(w) > 0 {
			id = w[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == 0 {
		t.Fatal("the job frame was never written")
	}

	prog, err := wproto.NewProg(id, wproto.Prog{Files: 1, Phase: wproto.PhaseWorking})
	if err != nil {
		t.Fatal(err)
	}
	prog.NFD = 1
	tr.in <- result{f: prog, files: []*os.File{stray}}
	ok, err := wproto.NewOK(id, wproto.JobResult{Files: 1})
	if err != nil {
		t.Fatal(err)
	}
	tr.in <- result{f: ok}

	got := awaitJob(t, out)
	if got.err != nil || got.res.Files != 1 {
		t.Fatalf("job = %+v, %v", got.res, got.err)
	}
	if !isClosed(stray) {
		t.Fatal("a descriptor that arrived on a job frame was left open in the root front-end")
	}
}

// TestCancelJobUsesTheLiveWorkerOrNothing: spawning a process to tell it to
// stop work it never started would be absurd, and the job cannot have outlived
// the worker that ran it.
func TestCancelJobUsesTheLiveWorkerOrNothing(t *testing.T) {
	p, made, _, spawns := jobPool(t, jobScript{})
	who := alice()

	if err := p.CancelJob(context.Background(), who, "nosuchjob0000001"); err != nil {
		t.Fatalf("cancelling with no worker = %v, want nil", err)
	}
	if n := spawns.Load(); n != 0 {
		t.Fatalf("%d workers were spawned to cancel a job; want none", n)
	}

	w := spawnWorker(t, p, made, who)
	if err := p.CancelJob(context.Background(), who, "livejob000000001"); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	select {
	case req := <-w.cancels:
		if req.JobID != "livejob000000001" || req.ReqID != 0 {
			t.Fatalf("cancel frame = %+v", req)
		}
	case <-time.After(testWait):
		t.Fatal("the live worker was never told")
	}
	if n := spawns.Load(); n != 1 {
		t.Fatalf("%d workers were spawned, want the one that was already there", n)
	}

	// An empty id is a caller bug, not a broadcast cancellation.
	if err := p.CancelJob(context.Background(), who, ""); !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("err = %v, want a bad-request refusal", err)
	}
}

// TestJobRefusesAnIncompleteRequest: a job with no id could never be cancelled.
func TestJobRefusesAnIncompleteRequest(t *testing.T) {
	p, made, _, _ := jobPool(t, jobScript{})
	who := alice()
	spawnWorker(t, p, made, who)

	if _, err := p.Job(context.Background(), who, wproto.JobReq{Kind: wproto.JobDelete}, nil, nil); !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("err = %v, want a bad-request refusal for a job with no id", err)
	}
	if _, err := p.Job(context.Background(), who, wproto.JobReq{JobID: "nokind0000000001"}, nil, nil); !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("err = %v, want a bad-request refusal for a job with no kind", err)
	}
}

// TestTrashListIsAPlainCall: the trash panel opens without a job round-trip,
// and a non-UTF-8 name survives it (the reason every path on the wire is
// []byte).
func TestTrashListIsAPlainCall(t *testing.T) {
	raw := []byte("/share/Public/\xff\xfe")
	p, made, _, _ := jobPool(t, jobScript{trash: wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1757600000-0a1b2c3d", Name: []byte("\xff\xfe"), OrigPath: raw, Type: "file", Size: 12, DeletedAt: 1757600000, Trash: []byte("/share/CACHEDEV1_DATA/.@qfm_trash")},
	}}})
	who := alice()
	spawnWorker(t, p, made, who)

	resp, err := p.TrashList(context.Background(), who)
	if err != nil {
		t.Fatalf("trashlist: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("%d items, want 1", len(resp.Items))
	}
	item := resp.Items[0]
	if string(item.OrigPath) != string(raw) || item.ID != "1757600000-0a1b2c3d" || item.Size != 12 {
		t.Fatalf("item = %+v", item)
	}
}

// TestJobsSatisfyTheBackendInterface keeps the pool usable through the
// interface internal/web codes against, all three of them.
func TestJobsSatisfyTheBackendInterface(t *testing.T) {
	p, made, _, _ := jobPool(t, jobScript{progs: 1, result: wproto.JobResult{Files: 1}})
	who := alice()
	spawnWorker(t, p, made, who)

	var jobs backend.Jobs = p
	res, err := jobs.Job(context.Background(), who, deleteJob("viaiface00000001"), nil, nil)
	if err != nil || res.Files != 1 {
		t.Fatalf("job through the interface = %+v, %v", res, err)
	}
	if err := jobs.CancelJob(context.Background(), who, "viaiface00000001"); err != nil {
		t.Fatalf("cancel through the interface: %v", err)
	}
	if _, err := jobs.TrashList(context.Background(), who); err != nil {
		t.Fatalf("trash list through the interface: %v", err)
	}
}
