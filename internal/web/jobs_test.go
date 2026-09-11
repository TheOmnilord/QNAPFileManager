package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	partial   wproto.JobResult // returned alongside ctx.Err() when cancelled
	err       error
	prog      []wproto.Prog
	warns     []wproto.Warn
	block     chan struct{} // when non-nil, Job waits for this or for ctx
	started   chan struct{} // closed by the first Job call
	trash     wproto.TrashListResp
	trashErr  error
}

func (f *fakeJobs) Job(ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	prog, warns, block, started := f.prog, f.warns, f.block, f.started
	result, partial, err := f.result, f.partial, f.err
	f.mu.Unlock()
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
		Token   string        `json:"token"`
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
		name  string
		force bool
		res   wproto.JobResult
		want  bool
	}{
		{name: "permanent delete is always a milestone", force: true, res: wproto.JobResult{Files: 1}, want: true},
		{name: "a small trash move is not", res: wproto.JobResult{Files: 3, Bytes: 30}, want: false},
		{name: "a hundred files is", res: wproto.JobResult{Files: 100}, want: true},
		{name: "a gigabyte is", res: wproto.JobResult{Bytes: 1 << 30}, want: true},
		{name: "just under either threshold is not", res: wproto.JobResult{Files: 99, Bytes: (1 << 30) - 1}, want: false},
	} {
		if got := jobMilestone(tc.force, tc.res); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestJobOutcomeVocabulary(t *testing.T) {
	if result, _ := jobOutcome(wproto.JobResult{Files: 2}, nil); result != "ok" {
		t.Errorf("clean job: %q", result)
	}
	if result, _ := jobOutcome(wproto.JobResult{Files: 2, Warnings: 3}, nil); result != "partial" {
		t.Errorf("per-item failures: %q", result)
	}
	if result, code := jobOutcome(wproto.JobResult{Files: 2}, context.Canceled); result != "cancelled" || code != "cancelled" {
		t.Errorf("cancelled: %q %q", result, code)
	}
	if result, _ := jobOutcome(wproto.JobResult{}, errors.New("boom")); result != "error" {
		t.Errorf("failure: %q", result)
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
