package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/wproto"
)

// fakeJobs is a backend.Jobs that behaves like the worker RPC without a worker:
// it records what it was asked, emits the progress and warning frames a caller
// configured, and — when blocked — honours the job's context so a cancellation
// test exercises the real path (partial counts, no rollback).
type fakeJobs struct {
	mu        sync.Mutex
	reqs      []wproto.JobReq
	cancelled []string
	result    wproto.JobResult
	// resultFor, when set, answers PER REQUEST instead of from result: a walker
	// that honours the entry budget it was handed, which is what a bounded
	// pre-scan needs in order to be tested at all (Astra M3 round-2 finding 8).
	resultFor func(wproto.JobReq) (wproto.JobResult, error)
	partial   wproto.JobResult // returned alongside ctx.Err() when cancelled
	err       error
	prog      []wproto.Prog
	warns     []wproto.Warn
	block     chan struct{} // when non-nil, Job waits for this or for ctx
	started   chan struct{} // closed by the first Job call
	trash     wproto.TrashListResp
	trashErr  error
	fsid      map[string]wproto.FSIdentityResp // per-path identity for the move pre-flight
	fsidPaths []string                         // every path FSIdentity was asked about, in order
	fsidErr   error
}

func (f *fakeJobs) Job(ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	prog, warns, block, started := f.prog, f.warns, f.block, f.started
	result, partial, err := f.result, f.partial, f.err
	resultFor := f.resultFor
	f.mu.Unlock()
	if resultFor != nil {
		result, err = resultFor(req)
	}
	if started != nil {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	for _, p := range prog {
		if onProg != nil {
			onProg(p)
		}
	}
	for _, w := range warns {
		if onWarn != nil {
			onWarn(w)
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			// What the pool does: keep the worker's own partial result and report
			// the cancellation alongside it.
			return partial, ctx.Err()
		}
	}
	return result, err
}

func (f *fakeJobs) CancelJob(_ context.Context, _ backend.Principal, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id)
	return nil
}

func (f *fakeJobs) TrashList(_ context.Context, _ backend.Principal) (wproto.TrashListResp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.trash, f.trashErr
}

// FSIdentity answers from the fsid map when the test configured one, else says
// every path is on one filesystem (Dev 1) — the same-device case, so the move
// pre-flight predicts nothing unless a test asks it to.
func (f *fakeJobs) FSIdentity(_ context.Context, _ backend.Principal, path string) (wproto.FSIdentityResp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Recorded so a test can pin WHICH spelling the worker was asked about: the
	// guard clears a resolved path, and every request must carry that one.
	f.fsidPaths = append(f.fsidPaths, path)
	if f.fsidErr != nil {
		return wproto.FSIdentityResp{}, f.fsidErr
	}
	if id, ok := f.fsid[path]; ok {
		return id, nil
	}
	return wproto.FSIdentityResp{Dev: 1, Dir: true}, nil
}

func (f *fakeJobs) requests() []wproto.JobReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wproto.JobReq(nil), f.reqs...)
}

// jobsFixture is the M1 fixture plus a wired job spine and a trash seam that
// reports a directory without touching the host's mount table (Windows and CI
// alike have no /share/CACHEDEV1_DATA).
func jobsFixture(t *testing.T, limits jobs.Limits) (*Server, *fakeBackend, *fakeJobs) {
	t.Helper()
	s, b := fixture(t, true)
	s.guard.SetReadOnly(false)
	fj := &fakeJobs{result: wproto.JobResult{Files: 3, Bytes: 30}}
	mgr := jobs.New(limits)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Close(ctx)
	})
	s.SetJobs(fj, mgr)
	created := map[string]bool{}
	var mu sync.Mutex
	s.ensureTrash = func(_ *platform.Platform, osPath string) (string, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		dir := filepath.ToSlash(filepath.Join(b.dir, trashroot.DirName))
		if created[dir] {
			return dir, false, nil
		}
		created[dir] = true
		return dir, true, nil
	}
	return s, b, fj
}

// withAudit points the server at a fresh audit file and returns a reader that
// closes the logger (flushing the async drain) and tails it.
func withAudit(t *testing.T, s *Server) func() []audit.Event {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auditor = logger
	s.AuditPath = path
	closed := false
	// Windows cannot remove an open file, so the logger is closed even when a
	// test fails before it reads.
	t.Cleanup(func() {
		if !closed {
			_ = logger.Close()
			closed = true
		}
	})
	return func() []audit.Event {
		// A job's RESULT line is written by the manager's completion hook (W2),
		// which runs just AFTER the job's state becomes terminal — so observing
		// the terminal state is not by itself proof the line has been written.
		// Draining the manager is: Close waits for every job goroutine, and the
		// hook is deferred inside it. Closing twice is harmless (the fixture's
		// own cleanup does it too).
		if s.jobMgr != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.jobMgr.Close(ctx); err != nil {
				t.Errorf("draining the job manager: %v", err)
			}
			cancel()
		}
		if !closed {
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
		}
		events, err := logger.Tail(200)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
}

type confirmEnvelope struct {
	Error struct {
		Code, Message, Path string
	} `json:"error"`
	Confirm struct {
		Token string `json:"token"`
		// Grade is M3's explicit confirmation grade (ui-ux §4.2): absent (0)
		// on every pre-M3 route, 1 for an acknowledgement, 2 for the typed
		// phrase. It travels beside the token because the guard's token
		// machinery is grade-blind.
		Grade   int           `json:"grade"`
		Summary guard.Summary `json:"summary"`
	} `json:"confirm"`
}

func challenge(t *testing.T, s *Server, c *http.Cookie, csrf, route, body string) confirmEnvelope {
	t.Helper()
	resp := post(s, route, c, csrf, body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("%s: want 409 confirm_required, got %d %s", route, resp.StatusCode, readBody(resp))
	}
	var env confirmEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "confirm_required" || env.Confirm.Token == "" {
		t.Fatalf("%s: %+v", route, env)
	}
	return env
}

type jobEnvelope struct {
	Job jobs.Job `json:"job"`
}

func acceptedJob(t *testing.T, resp *http.Response) jobs.Job {
	t.Helper()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d %s", resp.StatusCode, readBody(resp))
	}
	var env jobEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Job.ID == "" {
		t.Fatal("no job id in the 202")
	}
	return env.Job
}

// awaitTerminal waits for a job to leave the live states, so a test can read
// the record of what it did without sleeping blindly.
func awaitTerminal(t *testing.T, s *Server, id string) jobs.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j, ok := s.jobMgr.Get(id); ok && j.State.Terminal() {
			return j
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return jobs.Job{}
}

// withToken re-posts the IDENTICAL body plus the redeemed token, which is what
// the client does and what the token's binding requires.
func withToken(body, token string) string {
	return strings.TrimSuffix(strings.TrimSpace(body), "}") + fmt.Sprintf(`,"confirm":%q}`, token)
}

func decodeDelete(t *testing.T, req wproto.JobReq) wproto.DeleteReq {
	t.Helper()
	var body wproto.DeleteReq
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// --- the ladder --------------------------------------------------------------

func TestJobDeleteTrashModeIsGradeOneAndNeedsAToken(t *testing.T) {
	s, b, fj := jobsFixture(t, jobs.Limits{})
	if err := os.Mkdir(filepath.Join(b.dir, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/folder"}],"mode":"trash","crossMounts":false}`
	// Both modes demand a redeemed token (decision 10), so the first POST is a
	// challenge even for a reversible move to trash.
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	for _, warning := range env.Confirm.Summary.Warnings {
		if warning == permanentWarning {
			t.Fatalf("a move to Trash must not be presented as permanent: %+v", env.Confirm.Summary)
		}
	}
	if env.Confirm.Summary.Files != 1 {
		t.Fatalf("summary %+v", env.Confirm.Summary)
	}
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/folder"}],"mode":"trash","crossMounts":false,"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	reqs := fj.requests()
	if len(reqs) != 1 || reqs[0].Kind != wproto.JobDelete || reqs[0].JobID != job.ID {
		t.Fatalf("worker requests %+v", reqs)
	}
	req := decodeDelete(t, reqs[0])
	if !req.Trash || !req.Recursive || req.CrossMounts || len(req.Paths) != 1 || string(req.Paths[0]) != "/folder" {
		t.Fatalf("delete request %+v", req)
	}
}

func TestJobDeletePermanentCarriesTheGradeTwoWarning(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	found := false
	for _, warning := range env.Confirm.Summary.Warnings {
		if warning == permanentWarning {
			found = true
		}
	}
	if !found {
		t.Fatalf("permanent delete summary lacks the warning: %+v", env.Confirm.Summary)
	}
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"permanent","confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	if req := decodeDelete(t, fj.requests()[0]); req.Trash {
		t.Fatal("a permanent delete must not be dispatched as a trash move")
	}
}

func TestJobDeleteTokenIsBoundToItsMode(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`)
	// The same token, presented for a permanent delete of the same path, must not
	// redeem: the token binds the mode, so a grade-1 confirmation can never
	// authorise the irreversible operation.
	resp := post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"permanent","confirm":%q}`, env.Confirm.Token))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("cross-mode redemption: %d %s", resp.StatusCode, readBody(resp))
	}
}

func TestJobDeleteRejectsAForgedToken(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/delete", c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"trash","confirm":"not-a-token"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("forged token: %d %s", resp.StatusCode, readBody(resp))
	}
	if len(fj.requests()) != 0 {
		t.Fatal("a forged token reached the worker")
	}
}

func TestJobDeleteGuardRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, path, code string
		setup            func(*Server, *fakeBackend)
	}{
		{name: "protected", path: "/bin", code: "protected"},
		{
			name: "mount point", path: "/share/vol", code: "protected",
			setup: func(s *Server, b *fakeBackend) {
				if err := os.MkdirAll(filepath.Join(b.dir, "share"), 0o755); err != nil {
					t.Fatal(err)
				}
				s.guard.SetMountPointChecker(func(p string) bool { return p == "/share/vol" })
			},
		},
		{
			name: "read-only", path: "/a.txt", code: "read_only",
			setup: func(s *Server, _ *fakeBackend) { s.guard.SetReadOnly(true) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, fj := jobsFixture(t, jobs.Limits{})
			if tc.setup != nil {
				tc.setup(s, b)
			}
			c, csrf := sessionCookie(t, s)
			for _, mode := range []string{"trash", "permanent"} {
				resp := post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":%q}],"mode":%q}`, tc.path, mode))
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("%s %s: %d %s", tc.name, mode, resp.StatusCode, readBody(resp))
				}
				var e apiEnvelope
				json.NewDecoder(resp.Body).Decode(&e)
				if e.Error.Code != tc.code {
					t.Fatalf("%s %s: code %q", tc.name, mode, e.Error.Code)
				}
			}
			if len(fj.requests()) != 0 {
				t.Fatal("a refused delete reached the worker")
			}
		})
	}
}

// A refusal on ANY root refuses the whole job: a job reports one outcome, so a
// partially-guarded selection must never be dispatched.
func TestJobDeleteRefusesTheWholeSelectionForOneBadRoot(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/delete", c, csrf, `{"paths":[{"path":"/a.txt"},{"path":"/bin"}],"mode":"trash"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mixed selection: %d %s", resp.StatusCode, readBody(resp))
	}
	if len(fj.requests()) != 0 {
		t.Fatal("a refused selection reached the worker")
	}
}

func TestJobDeleteWarnPathSummaryCarriesItsReason(t *testing.T) {
	s, b, _ := jobsFixture(t, jobs.Limits{})
	if err := os.MkdirAll(filepath.Join(b.dir, "etc", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/etc/config/thing"}],"mode":"trash"}`)
	if len(env.Confirm.Summary.Warnings) == 0 {
		t.Fatal("a warn-class path must explain itself in the summary")
	}
	for _, warning := range env.Confirm.Summary.Warnings {
		if strings.Contains(warning, "/etc/config") {
			t.Fatalf("the summary must stay path-free: %q", warning)
		}
	}
}

// --- trash roots -------------------------------------------------------------

func TestJobDeleteNoTrashIsA409AfterTheTokenIsSpent(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	s.ensureTrash = func(_ *platform.Platform, osPath string) (string, bool, error) {
		return "", false, fmt.Errorf("%s: %w", osPath, trashroot.ErrNoTrash)
	}
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`)
	resp := post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"trash","confirm":%q}`, env.Confirm.Token))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("no trash: %d %s", resp.StatusCode, readBody(resp))
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "no_trash" {
		t.Fatalf("code %q", e.Error.Code)
	}
	if len(fj.requests()) != 0 {
		t.Fatal("nothing may be dispatched when there is no trash")
	}
	// The client re-asks as a permanent delete, which is a fresh token and does
	// not touch the trash root at all.
	env2 := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"permanent","confirm":%q}`, env2.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
}

func TestTrashRootCreationIsAuditedOnce(t *testing.T) {
	s, b, _ := jobsFixture(t, jobs.Limits{})
	read := withAudit(t, s)
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/one"},{"path":"/two"}],"mode":"trash"}`
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	created := 0
	for _, ev := range read() {
		if ev.Op == "trash-root" {
			created++
			if !strings.Contains(ev.Detail, trashroot.DirName) {
				t.Fatalf("the trash-root milestone must name the directory it made: %q", ev.Detail)
			}
		}
	}
	if created != 1 {
		t.Fatalf("trash-root audit lines: %d, want exactly one for the one directory created", created)
	}
}

// --- audit -------------------------------------------------------------------

func TestJobDeleteAuditsIntentAndResult(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.result = wproto.JobResult{Files: 4, Bytes: 400}
	read := withAudit(t, s)
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"permanent","confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	var intent, result *audit.Event
	for i, ev := range read() {
		if ev.Op != "delete" {
			continue
		}
		switch {
		case ev.Phase == "intent":
			intent = &[]audit.Event{ev}[0]
		case ev.Phase == "result" && ev.Result == "ok":
			result = &[]audit.Event{ev}[0]
		}
		_ = i
	}
	if intent == nil || result == nil {
		t.Fatalf("missing phases: intent=%v result=%v", intent != nil, result != nil)
	}
	if intent.Actor != "dev" || !strings.Contains(intent.Detail, "permanent") {
		t.Fatalf("intent %+v", *intent)
	}
	// The result records what the WORKER did, not what was requested.
	if result.Job != job.ID || result.Files != 4 || result.Bytes != 400 {
		t.Fatalf("result %+v", *result)
	}
}

func TestJobMilestoneClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		force        bool
		result       string
		files, bytes int64
		want         bool
	}{
		{name: "permanent delete is always a milestone", force: true, result: "ok", files: 1, want: true},
		{name: "a small trash move is not", result: "ok", files: 3, bytes: 30, want: false},
		{name: "a hundred files is", result: "ok", files: 100, want: true},
		{name: "a gigabyte is", result: "ok", bytes: 1 << 30, want: true},
		{name: "just under either threshold is not", result: "ok", files: 99, bytes: (1 << 30) - 1, want: false},
		// W1: a job the guard refused when it started is a security record.
		{name: "a denial always is", result: "denied", want: true},
	} {
		if got := jobMilestone(tc.force, tc.result, tc.files, tc.bytes); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestJobOutcomeVocabulary(t *testing.T) {
	if result, _ := jobFinishOutcome(jobs.Job{State: jobs.StateDone, Files: 2}, 0, 0); result != "ok" {
		t.Errorf("clean job: %q", result)
	}
	if result, _ := jobFinishOutcome(jobs.Job{State: jobs.StateDone, Files: 2}, 3, 0); result != "partial" {
		t.Errorf("per-item failures: %q", result)
	}
	// R3-S1: the reconciled totals decide, so a job that streamed no warn frame
	// at all is still partial when its terminal result skipped items.
	if result, _ := jobFinishOutcome(jobs.Job{State: jobs.StateDone, Files: 2}, 0, 1); result != "partial" {
		t.Errorf("skipped items: %q", result)
	}
	if result, code := jobFinishOutcome(jobs.Job{State: jobs.StateCancelled, Files: 2}, 0, 0); result != "cancelled" || code != "cancelled" {
		t.Errorf("cancelled: %q %q", result, code)
	}
	if result, code := jobFinishOutcome(jobs.Job{State: jobs.StateFailed, ErrCode: "internal"}, 0, 0); result != "error" || code != "internal" {
		t.Errorf("failure: %q %q", result, code)
	}
	// A guard refusal at start (W1) is a denial in the trail, not an error.
	for _, code := range []string{"read_only", "protected"} {
		if result, got := jobFinishOutcome(jobs.Job{State: jobs.StateFailed, ErrCode: code}, 0, 0); result != "denied" || got != code {
			t.Errorf("guard refusal %q: %q %q", code, result, got)
		}
	}
}

func TestCancelledJobRecordsPartialCounts(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	fj.partial = wproto.JobResult{Files: 7, Bytes: 70}
	read := withAudit(t, s)
	c, csrf := sessionCookie(t, s)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/a.txt"}],"mode":"permanent","confirm":%q}`, env.Confirm.Token)))
	select {
	case <-fj.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never reached the worker")
	}
	resp := post(s, "/api/jobs/"+job.ID+"/cancel", c, csrf, `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel: %d %s", resp.StatusCode, readBody(resp))
	}
	final := awaitTerminal(t, s, job.ID)
	if final.State != jobs.StateCancelled || !final.Partial || final.Note == "" {
		t.Fatalf("cancelled job %+v", final)
	}
	if got := fj.cancelled; len(got) != 1 || got[0] != job.ID {
		t.Fatalf("the worker was not told to stop: %v", got)
	}
	var cancelled *audit.Event
	for _, ev := range read() {
		if ev.Op == "delete" && ev.Phase == "result" && ev.Result == "cancelled" {
			e := ev
			cancelled = &e
		}
	}
	if cancelled == nil {
		t.Fatal("no cancelled result line")
	}
	// The partial counts the worker reported before it stopped, and a note that
	// says the work was not rolled back (design §3).
	if cancelled.Files != 7 || cancelled.Bytes != 70 || !strings.Contains(cancelled.Detail, "partial work remains") {
		t.Fatalf("cancelled line %+v", *cancelled)
	}
	close(fj.block)
}

// --- list, ownership, cancellation ------------------------------------------

// otherSession injects a second identity so ownership can be tested; the
// fixture pins one principal for every cookie it issues.
func otherSession(s *Server, id, user string, uid int, admin bool) (*http.Cookie, string) {
	sess := &session{
		id: id, csrf: "csrf-" + id, admin: admin,
		who:     backend.Principal{User: user, UID: uid, GID: uid, Groups: []int{uid}},
		expires: time.Now().Add(time.Hour), checked: time.Now(),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return &http.Cookie{Name: "qfm_sid", Value: id}, sess.csrf
}

func TestJobsListIsNewestFirstAndScopedToItsOwner(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	var ids []string
	for _, name := range []string{"a.txt", "b #.txt"} {
		body := fmt.Sprintf(`{"paths":[{"path":"/%s"}],"mode":"permanent"}`, name)
		env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
		job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token)))
		ids = append(ids, job.ID)
	}
	for _, id := range ids {
		awaitTerminal(t, s, id)
	}
	var listed struct {
		Jobs []jobs.Job `json:"jobs"`
	}
	w := request(s, "GET", "/api/jobs", c, nil)
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Jobs) != 2 || listed.Jobs[0].ID != ids[1] || listed.Jobs[1].ID != ids[0] {
		t.Fatalf("newest first: %+v", listed.Jobs)
	}

	// A different user sees none of it, and cannot look one up or cancel it: the
	// answer is the same not_found a job that never existed would get.
	other, otherCSRF := otherSession(s, "other-sid", "other", 1001, false)
	w = request(s, "GET", "/api/jobs", other, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Jobs) != 0 {
		t.Fatalf("another user saw %d jobs", len(listed.Jobs))
	}
	if w := request(s, "GET", "/api/jobs/"+ids[0], other, nil); w.Code != http.StatusNotFound {
		t.Fatalf("foreign job lookup: %d %s", w.Code, w.Body)
	}
	if resp := post(s, "/api/jobs/"+ids[0]+"/cancel", other, otherCSRF, `{}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign job cancel: %d %s", resp.StatusCode, readBody(resp))
	}
	// An administrator does see it — somebody has to be able to.
	admin, _ := otherSession(s, "admin-sid", "root", 0, true)
	w = request(s, "GET", "/api/jobs", admin, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Jobs) != 2 {
		t.Fatalf("admin saw %d jobs", len(listed.Jobs))
	}
	// And the owner's own lookup works.
	if w := request(s, "GET", "/api/jobs/"+ids[0], c, nil); w.Code != 200 {
		t.Fatalf("own job lookup: %d %s", w.Code, w.Body)
	}
}

func TestJobRoutePathForms(t *testing.T) {
	id, action, ok := jobPath("/api/jobs/0123456789abcdef")
	if !ok || action != "" || id != "0123456789abcdef" {
		t.Fatalf("job form: %q %q %v", id, action, ok)
	}
	if id, action, ok := jobPath("/api/jobs/0123456789abcdef/cancel"); !ok || action != "cancel" || id != "0123456789abcdef" {
		t.Fatalf("cancel form: %q %q %v", id, action, ok)
	}
	// The literal routes must never be read as job ids, and a malformed id is
	// not a route at all.
	for _, p := range []string{"/api/jobs/delete", "/api/jobs/size", "/api/jobs/", "/api/jobs/NOTHEX0123456789", "/api/jobs/0123456789abcdef/other", "/api/jobs/0123456789abcde"} {
		if _, _, ok := jobPath(p); ok {
			t.Errorf("%s must not parse as a job id", p)
		}
	}
	if methods, ok := routeFor("/api/jobs/delete"); !ok || methods[0] != "POST" {
		t.Fatalf("literal route: %v %v", methods, ok)
	}
	if methods, ok := routeFor("/api/jobs/0123456789abcdef"); !ok || methods[0] != "GET" {
		t.Fatalf("job route: %v %v", methods, ok)
	}
}

func TestUnknownJobIsNotFound(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	c, _ := sessionCookie(t, s)
	if w := request(s, "GET", "/api/jobs/0123456789abcdef", c, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown job: %d %s", w.Code, w.Body)
	}
}

func TestQueueFullIs429(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1, QueueDepth: 1})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	defer close(fj.block)
	c, csrf := sessionCookie(t, s)
	submit := func(name string) *http.Response {
		body := fmt.Sprintf(`{"paths":[{"path":"/%s"}],"mode":"permanent"}`, name)
		env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
		return post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token))
	}
	first := acceptedJob(t, submit("a.txt"))
	select {
	case <-fj.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first job never started")
	}
	// It is running, so it has left the queue; the next fills the single queue
	// slot and the one after that is refused rather than silently backing up.
	awaitState(t, s, first.ID, jobs.StateRunning)
	acceptedJob(t, submit("binary"))
	resp := submit("b #.txt")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("queue full: %d %s", resp.StatusCode, readBody(resp))
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "queue_full" {
		t.Fatalf("code %q", e.Error.Code)
	}
}

func awaitState(t *testing.T, s *Server, id string, want jobs.State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j, ok := s.jobMgr.Get(id); ok && j.State == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %s", id, want)
}

// --- size --------------------------------------------------------------------

func TestJobSizeNeedsNoTokenAndHonoursTheTraverseGuard(t *testing.T) {
	s, b, fj := jobsFixture(t, jobs.Limits{})
	fj.result = wproto.JobResult{Files: 9, Dirs: 2, Bytes: 900}
	// The daemon's own logs are traverse-denied, and measuring them would be a
	// way to read the audit trail's shape.
	s.guard = guard.New("/install", false)
	s.guard.SetReadOnly(false)
	if err := os.MkdirAll(filepath.Join(b.dir, "install", "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, csrf := sessionCookie(t, s)
	if resp := post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/install/logs"}]}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("protected size: %d %s", resp.StatusCode, readBody(resp))
	}
	job := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}],"crossMounts":true}`))
	final := awaitTerminal(t, s, job.ID)
	if final.State != jobs.StateDone {
		t.Fatalf("size job %+v", final)
	}
	var view jobResultView
	if err := json.Unmarshal(final.Result, &view); err != nil {
		t.Fatal(err)
	}
	if view.Files != 9 || view.Dirs != 2 || view.Bytes != 900 {
		t.Fatalf("size result %+v", view)
	}
	var req wproto.SizeReq
	if err := json.Unmarshal(fj.requests()[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if !req.CrossMounts || len(req.Paths) != 1 {
		t.Fatalf("size request %+v", req)
	}
}

// Read-only mode is about writes; measuring a folder is a read and stays
// available (the guard's writeOps rule, exercised end to end).
func TestJobSizeWorksInReadOnlyMode(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	s.guard.SetReadOnly(true)
	c, csrf := sessionCookie(t, s)
	acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
}

// --- progress and warnings ---------------------------------------------------

func TestJobProgressAndWarningsReachTheManager(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.prog = []wproto.Prog{{Files: 2, FilesTotal: 4, Bytes: 20, BytesTotal: 40, Current: []byte("/a.txt"), Phase: "working"}}
	fj.warns = []wproto.Warn{{Path: []byte("/locked"), Code: "permission", Message: "Permission denied"}}
	fj.result = wproto.JobResult{Files: 3, Bytes: 30, Warnings: 1}
	c, csrf := sessionCookie(t, s)
	acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
	list := s.jobMgr.List()
	if len(list) != 1 {
		t.Fatalf("jobs %+v", list)
	}
	final := awaitTerminal(t, s, list[0].ID)
	if final.Files != 2 || final.FilesTotal != 4 || final.Bytes != 20 || final.Current != "/a.txt" || final.Phase != "working" {
		t.Fatalf("progress not recorded: %+v", final)
	}
	if final.WarningCount != 1 || len(final.Warnings) != 1 || !strings.Contains(final.Warnings[0], "/locked") {
		t.Fatalf("warnings not recorded: %+v", final.Warnings)
	}
}

// --- trash routes ------------------------------------------------------------

func trashFixture(t *testing.T) (*Server, *fakeJobs, *http.Cookie, string) {
	t.Helper()
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.trash = wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1700000000-abcdef01", Name: []byte("notes.txt"), OrigPath: []byte("/notes.txt"), Type: "file", Size: 12, DeletedAt: 1700000000, Trash: []byte("/.@qfm_trash")},
		{ID: "1700000001-abcdef02", Name: []byte("bad\xffname"), OrigPath: []byte("/bad\xffname"), Type: "file", Size: 3, DeletedAt: 1700000001, Trash: []byte("/.@qfm_trash")},
	}}
	c, csrf := sessionCookie(t, s)
	return s, fj, c, csrf
}

func TestTrashListIsByteSafe(t *testing.T) {
	s, _, c, _ := trashFixture(t)
	w := request(s, "GET", "/api/trash", c, nil)
	if w.Code != 200 {
		t.Fatalf("trash list: %d %s", w.Code, w.Body)
	}
	var listed struct {
		Items   []trashItem `json:"items"`
		DirName string      `json:"dirName"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.DirName != trashroot.DirName || len(listed.Items) != 2 {
		t.Fatalf("listing %+v", listed)
	}
	if listed.Items[0].NameB64 != "" {
		t.Fatal("a valid UTF-8 name must not carry a base64 companion")
	}
	want := base64.RawURLEncoding.EncodeToString([]byte("bad\xffname"))
	if listed.Items[1].NameB64 != want || listed.Items[1].OrigPathB64 == "" {
		t.Fatalf("non-UTF-8 item %+v", listed.Items[1])
	}
}

func TestTrashRestoreGuardsTheOriginalLocation(t *testing.T) {
	s, fj, c, csrf := trashFixture(t)
	read := withAudit(t, s)
	job := acceptedJob(t, post(s, "/api/trash/restore", c, csrf, `{"ids":["1700000000-abcdef01"]}`))
	awaitTerminal(t, s, job.ID)
	var req wproto.TrashRestoreReq
	if err := json.Unmarshal(fj.requests()[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.IDs) != 1 || req.IDs[0] != "1700000000-abcdef01" {
		t.Fatalf("restore request %+v", req)
	}
	var intent, result bool
	for _, ev := range read() {
		if ev.Op == "trash-restore" {
			intent = intent || ev.Phase == "intent"
			result = result || (ev.Phase == "result" && ev.Result == "ok")
		}
	}
	if !intent || !result {
		t.Fatalf("restore audit: intent=%v result=%v", intent, result)
	}
}

func TestTrashRestoreRefusals(t *testing.T) {
	s, fj, c, csrf := trashFixture(t)
	// An item whose original home is protected must not be written back into it.
	// The daemon's own install tree denies every write op, so it is the clearest
	// example: /bin only denies delete and rename, not creating inside it.
	s.guard = guard.New("/install", false)
	s.guard.SetReadOnly(false)
	fj.trash.Items = append(fj.trash.Items, wproto.TrashItem{ID: "1700000002-abcdef03", Name: []byte("sh"), OrigPath: []byte("/install/bin/qfm"), Type: "file"})
	if resp := post(s, "/api/trash/restore", c, csrf, `{"ids":["1700000002-abcdef03"]}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("protected restore: %d %s", resp.StatusCode, readBody(resp))
	}
	// An unknown id, an id shaped like a path, and an empty list.
	if resp := post(s, "/api/trash/restore", c, csrf, `{"ids":["1700000009-ffffffff"]}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: %d", resp.StatusCode)
	}
	if resp := post(s, "/api/trash/restore", c, csrf, `{"ids":["../../etc"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("path-shaped id: %d", resp.StatusCode)
	}
	if resp := post(s, "/api/trash/restore", c, csrf, `{"ids":[]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty list: %d", resp.StatusCode)
	}
	// And read-only mode refuses it outright.
	s.guard.SetReadOnly(true)
	if resp := post(s, "/api/trash/restore", c, csrf, `{"ids":["1700000000-abcdef01"]}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only restore: %d", resp.StatusCode)
	}
	if len(fj.requests()) != 0 {
		t.Fatal("a refused restore reached the worker")
	}
}

// --- Undo --------------------------------------------------------------------

// jobResult reads the result view a finished job published.
func jobResult(t *testing.T, job jobs.Job) jobResultView {
	t.Helper()
	var view jobResultView
	if len(job.Result) == 0 {
		t.Fatalf("job %s published no result", job.ID)
	}
	if err := json.Unmarshal(job.Result, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// runTrashDelete posts one delete-to-trash through the confirmation ladder and
// returns the finished job.
func runTrashDelete(t *testing.T, s *Server, c *http.Cookie, csrf, path string) jobs.Job {
	t.Helper()
	body := fmt.Sprintf(`{"paths":[{"path":%q}],"mode":"trash"}`, path)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token)))
	return awaitTerminal(t, s, job.ID)
}

// TestUndoUsesTheWorkersOwnTrashIDs: the worker names the entries its trash
// delete created, and those ids — not a match against the trash listing — are
// what the job's result carries and what the Undo restore then asks for.
//
// The listing here deliberately holds an entry for the same original path with a
// DIFFERENT id, which is exactly the case the old heuristic got wrong: delete
// the same name twice and "their own item, same origPath, trashed since this job
// started" names both.
func TestUndoUsesTheWorkersOwnTrashIDs(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.result = wproto.JobResult{Files: 1, Bytes: 5, TrashIDs: []string{"1700000100-11111111"}}
	fj.trash = wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1700000100-11111111", Name: []byte("a.txt"), OrigPath: []byte("/a.txt"), Type: "file", DeletedAt: time.Now().Unix()},
		{ID: "1700000099-22222222", Name: []byte("a.txt"), OrigPath: []byte("/a.txt"), Type: "file", DeletedAt: time.Now().Unix()},
	}}
	c, csrf := sessionCookie(t, s)
	final := runTrashDelete(t, s, c, csrf, "/a.txt")
	view := jobResult(t, final)
	if len(view.TrashIDs) != 1 || view.TrashIDs[0] != "1700000100-11111111" {
		t.Fatalf("result trashIds = %v, want exactly the worker's own id", view.TrashIDs)
	}

	// The Undo: the client posts the ids it found on the job result, and what
	// reaches the worker must be exactly those.
	ids, err := json.Marshal(map[string]any{"ids": view.TrashIDs})
	if err != nil {
		t.Fatal(err)
	}
	restore := acceptedJob(t, post(s, "/api/trash/restore", c, csrf, string(ids)))
	awaitTerminal(t, s, restore.ID)
	reqs := fj.requests()
	var got wproto.TrashRestoreReq
	if err := json.Unmarshal(reqs[len(reqs)-1].Body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IDs) != 1 || got.IDs[0] != view.TrashIDs[0] {
		t.Fatalf("restore request %+v, want exactly the job's trash ids %v", got, view.TrashIDs)
	}
}

// TestUndoFallsBackToTheListingForAnOlderWorker: a worker that reports no ids
// at all is the one case the origPath/time heuristic is still for.
func TestUndoFallsBackToTheListingForAnOlderWorker(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.result = wproto.JobResult{Files: 1, Bytes: 5}
	fj.trash = wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1700000100-33333333", Name: []byte("a.txt"), OrigPath: []byte("/a.txt"), Type: "file", DeletedAt: time.Now().Unix()},
		{ID: "1700000101-44444444", Name: []byte("b.txt"), OrigPath: []byte("/b.txt"), Type: "file", DeletedAt: time.Now().Unix()},
	}}
	c, csrf := sessionCookie(t, s)
	view := jobResult(t, runTrashDelete(t, s, c, csrf, "/a.txt"))
	if len(view.TrashIDs) != 1 || view.TrashIDs[0] != "1700000100-33333333" {
		t.Fatalf("result trashIds = %v, want the listing fallback to name the deleted root's entry", view.TrashIDs)
	}
}

// A permanent delete has nothing to undo, and must not go looking.
func TestPermanentDeleteReportsNoTrashIDs(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.result = wproto.JobResult{Files: 1, Bytes: 5, TrashIDs: []string{"1700000100-55555555"}}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	job := acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token)))
	if ids := jobResult(t, awaitTerminal(t, s, job.ID)).TrashIDs; len(ids) != 0 {
		t.Fatalf("a permanent delete reported trash ids %v", ids)
	}
}

func TestTrashEmptyIsGradeTwoAndAudited(t *testing.T) {
	s, fj, c, csrf := trashFixture(t)
	read := withAudit(t, s)
	env := challenge(t, s, c, csrf, "/api/trash/empty", `{}`)
	found := false
	for _, warning := range env.Confirm.Summary.Warnings {
		if warning == permanentWarning {
			found = true
		}
	}
	if !found || env.Confirm.Summary.Files != 2 {
		t.Fatalf("empty summary %+v", env.Confirm.Summary)
	}
	job := acceptedJob(t, post(s, "/api/trash/empty", c, csrf, fmt.Sprintf(`{"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	if reqs := fj.requests(); len(reqs) != 1 || reqs[0].Kind != wproto.JobTrashEmpty {
		t.Fatalf("worker requests %+v", reqs)
	}
	var intent, result bool
	for _, ev := range read() {
		if ev.Op == "trash-empty" {
			intent = intent || ev.Phase == "intent"
			result = result || (ev.Phase == "result" && ev.Result == "ok")
		}
	}
	if !intent || !result {
		t.Fatalf("empty audit: intent=%v result=%v", intent, result)
	}
	// Read-only mode refuses it even with a token in hand.
	s.guard.SetReadOnly(true)
	if resp := post(s, "/api/trash/empty", c, csrf, `{}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only empty: %d", resp.StatusCode)
	}
}

// TestTrashEmptySummaryLeavesOutWhatItCannotMeasure: the worker reports a size
// of -1 for an item whose size it does not know — a folder whose tree was too
// large to count inside the scan's bound, or one trashed by a build that only
// ever recorded the directory inode's own size. Adding that to the total would
// subtract a byte from it, and dropping it silently would state a total that is
// not one, so it is left out of the sum and said out loud in the summary.
func TestTrashEmptySummaryLeavesOutWhatItCannotMeasure(t *testing.T) {
	s, _, c, csrf := trashFixture(t)
	env := challenge(t, s, c, csrf, "/api/trash/empty", `{}`)
	// The fixture's two items are 12 and 3 bytes, both known.
	if env.Confirm.Summary.Files != 2 || env.Confirm.Summary.Bytes != 15 {
		t.Fatalf("summary with every size known = %+v", env.Confirm.Summary)
	}
	for _, warning := range env.Confirm.Summary.Warnings {
		if strings.Contains(warning, "not known") {
			t.Fatalf("nothing is unmeasured here, yet the summary says %q", warning)
		}
	}

	s2, fj2, c2, csrf2 := trashFixture(t)
	fj2.trash = wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1700000000-abcdef01", Name: []byte("notes.txt"), OrigPath: []byte("/notes.txt"), Type: "file", Size: 12, Files: 1, DeletedAt: 1700000000},
		{ID: "1700000001-abcdef02", Name: []byte("photos"), OrigPath: []byte("/photos"), Type: "dir", Size: -1, Files: -1, DeletedAt: 1700000001},
	}}
	read2 := withAudit(t, s2)
	env = challenge(t, s2, c2, csrf2, "/api/trash/empty", `{}`)
	summary := env.Confirm.Summary
	if summary.Files != 2 || summary.Bytes != 12 {
		t.Fatalf("summary = %+v, want both items counted and only the known bytes summed", summary)
	}
	var said, permanent bool
	for _, warning := range summary.Warnings {
		said = said || strings.Contains(warning, "The size of 1 item(s) is not known")
		permanent = permanent || warning == permanentWarning
	}
	if !said || !permanent {
		t.Fatalf("warnings = %v, want the permanent sentence and the unknown-size one", summary.Warnings)
	}
	// And the durable record states the same total: a -1 must never reach it.
	job := acceptedJob(t, post(s2, "/api/trash/empty", c2, csrf2, fmt.Sprintf(`{"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s2, job.ID)
	found := false
	for _, ev := range read2() {
		if ev.Op == "trash-empty" && ev.Phase == "intent" {
			found = true
			if !strings.Contains(ev.Detail, "2 item(s), 12 byte(s)") {
				t.Fatalf("intent detail = %q, want the item count and the summed bytes", ev.Detail)
			}
		}
	}
	if !found {
		t.Fatal("the empty wrote no intent line")
	}
}

// TestTrashEmptySummaryCannotOverflow: each item's size fits in an int64 and
// their sum need not — two measured five-exabyte trees are enough. A wrapped
// total is NEGATIVE, and it would reach the confirmation dialog, the mutation
// record and the audit line as a fact, so the sum stops at what is
// representable and says that it did.
func TestTrashEmptySummaryCannotOverflow(t *testing.T) {
	s, fj, c, csrf := trashFixture(t)
	const huge = int64(5) << 60 // 5 EiB, and two of them do not fit
	fj.trash = wproto.TrashListResp{Items: []wproto.TrashItem{
		{ID: "1700000000-abcdef01", Name: []byte("one"), OrigPath: []byte("/one"), Type: "dir", Size: huge, Files: 3, DeletedAt: 1700000000},
		{ID: "1700000001-abcdef02", Name: []byte("two"), OrigPath: []byte("/two"), Type: "dir", Size: huge, Files: 3, DeletedAt: 1700000001},
	}}
	read := withAudit(t, s)
	env := challenge(t, s, c, csrf, "/api/trash/empty", `{}`)
	summary := env.Confirm.Summary
	if summary.Bytes < 0 {
		t.Fatalf("the summary total wrapped: %+v", summary)
	}
	if summary.Bytes != huge || summary.Files != 2 {
		t.Fatalf("summary = %+v, want both items counted and the total stopped at what fits", summary)
	}
	said := false
	for _, warning := range summary.Warnings {
		said = said || strings.Contains(warning, "more than can be counted")
	}
	if !said {
		t.Fatalf("warnings = %v, want the total declared a minimum", summary.Warnings)
	}
	// The durable record gets the same non-negative total.
	job := acceptedJob(t, post(s, "/api/trash/empty", c, csrf, fmt.Sprintf(`{"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	for _, ev := range read() {
		if ev.Op == "trash-empty" && ev.Phase == "intent" && !strings.Contains(ev.Detail, fmt.Sprintf("%d byte(s)", huge)) {
			t.Fatalf("intent detail = %q, want the summed bytes that fit", ev.Detail)
		}
	}
}

func TestTrashEmptyRejectsAnotherOperationsToken(t *testing.T) {
	s, _, c, csrf := trashFixture(t)
	env := challenge(t, s, c, csrf, "/api/jobs/delete", `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	if resp := post(s, "/api/trash/empty", c, csrf, fmt.Sprintf(`{"confirm":%q}`, env.Confirm.Token)); resp.StatusCode != http.StatusConflict {
		t.Fatalf("a delete token must not empty the trash: %d %s", resp.StatusCode, readBody(resp))
	}
}

// --- contracts ---------------------------------------------------------------

// The permanent-delete sentence is a contract between the two halves: the
// client promotes its dialog to grade 2 when it sees this exact string in a
// summary (actions.js PERMANENT_WARNING, asserted in actions_test.mjs).
func TestPermanentWarningIsPinnedToTheClient(t *testing.T) {
	const want = "This delete is permanent and cannot be undone."
	if permanentWarning != want {
		t.Fatalf("server text %q", permanentWarning)
	}
	js, err := assets.ReadFile("static/js/actions.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "PERMANENT_WARNING='"+want+"'") {
		t.Fatal("actions.js no longer carries the same sentence")
	}
}

// --- wiring ------------------------------------------------------------------

func TestJobRoutesRefuseWhenTheSpineIsNotWired(t *testing.T) {
	s, _ := fixture(t, true)
	s.guard.SetReadOnly(false)
	c, csrf := sessionCookie(t, s)
	if w := request(s, "GET", "/api/jobs", c, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("unwired list: %d %s", w.Code, w.Body)
	}
	if resp := post(s, "/api/jobs/delete", c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("unwired delete: %d", resp.StatusCode)
	}
}

func TestJobRoutesRequireCSRF(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	c, _ := sessionCookie(t, s)
	for _, route := range []string{"/api/jobs/delete", "/api/jobs/size", "/api/trash/restore", "/api/trash/empty"} {
		resp := post(s, route, c, "", `{}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s without a CSRF token: %d", route, resp.StatusCode)
		}
	}
}
