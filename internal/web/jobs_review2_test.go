package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/wproto"
)

// The M2-A round-2 web/jobs findings, one test group per finding:
//
//	W1 the guard is re-run when a queued job STARTS
//	W2 a job that never ran still gets a terminal audit line
//	W3 a cancelled job keeps its partial result
//	W4 nothing a job publishes carries a resolved spelling or raw worker text
//	W5 no_trash names the requested spelling
//	W6 trash.enabled=false is honoured everywhere
//	W7 the durable trail names the targets and correlates by job id

// submitDelete posts one delete through the confirmation ladder and returns the
// accepted job.
func submitDelete(t *testing.T, s *Server, c *http.Cookie, csrf, body string) jobs.Job {
	t.Helper()
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	return acceptedJob(t, post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token)))
}

// eventsFor returns the audit events recorded against one job id.
func eventsFor(events []audit.Event, id string) []audit.Event {
	var out []audit.Event
	for _, ev := range events {
		if ev.Job == id {
			out = append(out, ev)
		}
	}
	return out
}

// --- W1: the guard is re-checked when the job starts --------------------------

// TestQueuedDeleteIsRefusedWhenReadOnlyIsTurnedOn is finding W1: a confirmed
// delete can sit in the queue behind a full concurrency class while an
// administrator turns read-only ON. The submit-time verdict is then stale, so
// the job re-checks before it dispatches — and a refusal ends it without the
// worker ever being asked to delete anything.
func TestQueuedDeleteIsRefusedWhenReadOnlyIsTurnedOn(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1, QueueDepth: 4})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	read := withAudit(t, s)
	c, csrf := sessionCookie(t, s)

	// One job occupies the single metadata slot.
	first := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	select {
	case <-fj.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first job never reached the worker")
	}
	awaitState(t, s, first.ID, jobs.StateRunning)

	// The second is confirmed and accepted, but queued behind it.
	queued := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/b #.txt"}],"mode":"permanent"}`)
	awaitState(t, s, queued.ID, jobs.StateQueued)

	// The administrator turns read-only on while it waits, then the slot frees.
	s.guard.SetReadOnly(true)
	close(fj.block)

	final := awaitTerminal(t, s, queued.ID)
	if final.State != jobs.StateFailed || final.ErrCode != "read_only" {
		t.Fatalf("queued delete after a read-only toggle: state=%s code=%q err=%q", final.State, final.ErrCode, final.Err)
	}
	// Nothing was dispatched for it: only the first job ever reached the worker.
	for _, req := range fj.requests() {
		if req.JobID == queued.ID {
			t.Fatal("a job refused by the start-of-job guard re-check still reached the worker")
		}
	}
	var denied *audit.Event
	for _, ev := range eventsFor(read(), queued.ID) {
		if ev.Phase == "result" && ev.Result == "denied" {
			e := ev
			denied = &e
		}
	}
	if denied == nil {
		t.Fatal("no denied result line for the refused job")
	}
	if denied.Code != "read_only" || denied.Op != "delete" {
		t.Fatalf("denial %+v", *denied)
	}
}

// A protected rule that starts matching while the job waits refuses it too, and
// a warn-class path does not: its confirmation token was redeemed at submit.
func TestStartOfJobGuardRecheckVocabulary(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	// A warn-class path (the guard's /etc/config rule) must not fail the job:
	// the confirmation token that covered it was redeemed at submit.
	if err := s.recheckGuard(guardCheck{op: guard.OpDelete, paths: []string{"/etc/config/smb.conf"}}); err != nil {
		t.Fatalf("a warn-class path refused a confirmed job: %v", err)
	}
	// A deny-class path does.
	err := s.recheckGuard(guardCheck{op: guard.OpDelete, paths: []string{"/bin"}})
	if err == nil {
		t.Fatal("a protected path passed the re-check")
	}
	var coder jobs.ErrCoder
	if !errors.As(err, &coder) || coder.ErrorCode() != "protected" {
		t.Fatalf("protected refusal: %v", err)
	}
	if strings.Contains(err.Error(), "/bin") {
		t.Fatalf("the published message names the path: %q", err.Error())
	}
}

// The other two destructive jobs re-check as well: a restore and an empty that
// were queued when read-only went on are refused before they dispatch.
func TestQueuedTrashJobsAreRefusedWhenReadOnlyIsTurnedOn(t *testing.T) {
	for _, tc := range []struct{ name, route, body string }{
		{name: "restore", route: "/api/trash/restore", body: `{"ids":["1700000000-abcdef01"]}`},
		{name: "empty", route: "/api/trash/empty", body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fj, c, csrf := trashFixture(t)
			s.jobMgr = nil
			mgr := jobs.New(jobs.Limits{Metadata: 1, QueueDepth: 4})
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = mgr.Close(ctx)
			})
			s.SetJobs(fj, mgr)
			fj.block = make(chan struct{})
			fj.started = make(chan struct{})

			// Hold the single metadata slot with a delete.
			first := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
			select {
			case <-fj.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the first job never reached the worker")
			}
			awaitState(t, s, first.ID, jobs.StateRunning)

			body := tc.body
			if tc.name == "empty" {
				env := challenge(t, s, c, csrf, tc.route, body)
				body = fmt.Sprintf(`{"confirm":%q}`, env.Confirm.Token)
			}
			queued := acceptedJob(t, post(s, tc.route, c, csrf, body))
			awaitState(t, s, queued.ID, jobs.StateQueued)
			s.guard.SetReadOnly(true)
			close(fj.block)

			final := awaitTerminal(t, s, queued.ID)
			if final.State != jobs.StateFailed || final.ErrCode != "read_only" {
				t.Fatalf("%s queued past a read-only toggle: state=%s code=%q", tc.name, final.State, final.ErrCode)
			}
			for _, req := range fj.requests() {
				if req.JobID == queued.ID {
					t.Fatalf("the refused %s still reached the worker", tc.name)
				}
			}
		})
	}
}

// --- W2: a terminal audit line for a job that never ran -----------------------

// TestCancelledQueuedJobIsStillAudited is finding W2: a job cancelled while it
// is still queued finishes without its work function ever running, so the
// result line has to come from the manager's completion hook — otherwise a
// durable delete INTENT stands forever with nothing beside it.
func TestCancelledQueuedJobIsStillAudited(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1, QueueDepth: 4})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	read := withAudit(t, s)
	c, csrf := sessionCookie(t, s)

	first := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	select {
	case <-fj.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first job never reached the worker")
	}
	awaitState(t, s, first.ID, jobs.StateRunning)

	queued := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/b #.txt"}],"mode":"permanent"}`)
	awaitState(t, s, queued.ID, jobs.StateQueued)
	if resp := post(s, "/api/jobs/"+queued.ID+"/cancel", c, csrf, `{}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel: %d %s", resp.StatusCode, readBody(resp))
	}
	final := awaitTerminal(t, s, queued.ID)
	if final.State != jobs.StateCancelled || final.Partial {
		t.Fatalf("a job cancelled in the queue: state=%s partial=%v", final.State, final.Partial)
	}
	close(fj.block)

	var result *audit.Event
	for _, ev := range eventsFor(read(), queued.ID) {
		if ev.Phase == "result" {
			e := ev
			result = &e
		}
	}
	if result == nil {
		t.Fatal("a job cancelled before it ran left no result line")
	}
	if result.Result != "cancelled" || !strings.Contains(result.Detail, "cancelled before it started") {
		t.Fatalf("result %+v", *result)
	}
	// And exactly one: the hook fires once per job, never twice.
	lines := 0
	for _, ev := range eventsFor(read(), queued.ID) {
		if ev.Phase == "result" {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("result lines for one job: %d", lines)
	}
}

// --- W3: a cancelled job keeps its partial result ------------------------------

// TestCancelledTrashDeletePublishesItsPartialResult is finding W3: Pool.Job
// returns a partial JobResult ALONGSIDE context.Canceled, and that view — the
// counts, the warnings and the trash ids the worker managed to create — is what
// the API and the Undo need. Returning nil with the error threw it away.
func TestCancelledTrashDeletePublishesItsPartialResult(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	fj.partial = wproto.JobResult{Files: 2, Bytes: 20, Warnings: 1, TrashIDs: []string{"1700000100-aaaaaaaa"}}
	c, csrf := sessionCookie(t, s)

	job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`)
	select {
	case <-fj.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never reached the worker")
	}
	if resp := post(s, "/api/jobs/"+job.ID+"/cancel", c, csrf, `{}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel: %d %s", resp.StatusCode, readBody(resp))
	}
	final := awaitTerminal(t, s, job.ID)
	close(fj.block)
	if final.State != jobs.StateCancelled {
		t.Fatalf("state %s", final.State)
	}
	view := jobResult(t, final)
	if view.Files != 2 || view.Bytes != 20 {
		t.Fatalf("the partial counts were dropped: %+v", view)
	}
	if len(view.TrashIDs) != 1 || view.TrashIDs[0] != "1700000100-aaaaaaaa" {
		t.Fatalf("a cancelled trash delete must still name what it moved: %+v", view.TrashIDs)
	}
}

// --- W4: no resolved spelling, no raw worker text -----------------------------

// TestJobPublishesOnlyTheRequestedSpelling is finding W4. The job dispatches
// against the RESOLVED root (PLAN.md §2.0), so the worker's warnings, its
// current path and its error all name a target the caller never asked about.
// Everything published maps back to the requested root, and the messages are
// derived from the error code rather than copied from the worker.
func TestJobPublishesOnlyTheRequestedSpelling(t *testing.T) {
	s, b, fj := jobsFixture(t, jobs.Limits{})
	s.mutator = &resolveStub{fakeBackend: b, aliases: map[string]string{"/alias": "/real"}}
	fj.prog = []wproto.Prog{{Files: 1, FilesTotal: 2, Current: []byte("/real/doc/inner/file"), Phase: "working"}}
	fj.warns = []wproto.Warn{{Path: []byte("/real/doc/locked"), Code: "permission", Message: "unlinkat /real/doc/locked: permission denied"}}
	fj.err = fmt.Errorf("unlinkat /real/doc: %w", fs.ErrPermission)
	c, csrf := sessionCookie(t, s)

	job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/alias/doc"}],"mode":"permanent"}`)
	final := awaitTerminal(t, s, job.ID)

	if final.Current != "/alias/doc/inner/file" {
		t.Fatalf("current path %q, want it mapped back under the requested alias", final.Current)
	}
	if len(final.Warnings) != 1 || !strings.Contains(final.Warnings[0], "/alias/doc/locked") {
		t.Fatalf("warning %q, want the requested spelling", final.Warnings)
	}
	if strings.Contains(final.Warnings[0], "unlinkat") {
		t.Fatalf("the worker's own text was published: %q", final.Warnings[0])
	}
	if final.ErrCode != "permission" || final.Err != "Permission denied." {
		t.Fatalf("job error %q (%s), want a code-derived message", final.Err, final.ErrCode)
	}
	// Nothing the client can read may name the resolved root.
	w := request(s, "GET", "/api/jobs/"+job.ID, c, nil)
	if w.Code != 200 {
		t.Fatalf("job lookup: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "/real") {
		t.Fatalf("the resolved spelling reached the client: %s", w.Body)
	}
}

// A path the worker reports that lies under NO root of this job is answered with
// the job's own requested root rather than published verbatim.
func TestJobPathMappingRules(t *testing.T) {
	jr := mappedRoots([]string{"/alias/doc", "/alias/doc/deep"}, []string{"/real/doc", "/real/doc/deep"})
	for _, tc := range []struct{ in, want string }{
		{"/real/doc", "/alias/doc"},
		{"/real/doc/inner", "/alias/doc/inner"},
		{"/real/doc/deep/x", "/alias/doc/deep/x"}, // the closest root wins
		{"/elsewhere/x", "/alias/doc"},            // under no known root
		{"", ""},
	} {
		if got := jr.mapPath(tc.in); got != tc.want {
			t.Errorf("mapPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A root of "/" maps the whole tree without doubling the separator.
	if got := mappedRoots([]string{"/"}, []string{"/"}).mapPath("/x/y"); got != "/x/y" {
		t.Errorf(`mapPath under "/" = %q`, got)
	}
	// With no roots at all (emptying the trash) nothing is published.
	if got := (jobRoots{}).mapPath("/anything"); got != "" {
		t.Errorf("mapPath with no roots = %q, want nothing published", got)
	}
}

// --- W5: no_trash names the requested spelling --------------------------------

func TestNoTrashReportsTheRequestedSpelling(t *testing.T) {
	s, b, _ := jobsFixture(t, jobs.Limits{})
	s.mutator = &resolveStub{fakeBackend: b, aliases: map[string]string{"/alias": "/real"}}
	s.ensureTrash = func(_ *platform.Platform, osPath string) (string, bool, error) {
		return "", false, fmt.Errorf("%s: %w", osPath, trashroot.ErrNoTrash)
	}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/alias/doc"}],"mode":"trash"}`
	env := challenge(t, s, c, csrf, "/api/jobs/delete", body)
	resp := post(s, "/api/jobs/delete", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("no trash: %d", resp.StatusCode)
	}
	raw := readBody(resp)
	var e apiEnvelope
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	if e.Error.Code != "no_trash" || e.Error.Path != "/alias/doc" {
		t.Fatalf("no_trash answer %+v", e.Error)
	}
	if strings.Contains(raw, "/real") {
		t.Fatalf("the resolved spelling reached the client: %s", raw)
	}
}

// --- W6: trash.enabled=false --------------------------------------------------

// TestTrashDisabledRefusesBeforeAnythingIsCreated is finding W6: with the NAS
// switch off, a default-mode delete used to call trashroot.Ensure anyway —
// creating root-owned 1777 directories — and then dispatch a trash job. It now
// answers 409 no_trash before any Ensure, so the client re-asks at grade 2.
func TestTrashDisabledRefusesBeforeAnythingIsCreated(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	s.cfg.Trash.Enabled = false
	ensured := false
	s.ensureTrash = func(_ *platform.Platform, _ string) (string, bool, error) {
		ensured = true
		return "/never", true, nil
	}
	c, csrf := sessionCookie(t, s)

	// R3-WA1: the refusal comes on the FIRST POST, before a trash-mode token is
	// ever issued. It used to arrive only on the redemption, so the user
	// confirmed a move to Trash and was then asked to confirm all over again.
	body := `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`
	resp := post(s, "/api/jobs/delete", c, csrf, body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("trash delete with trash disabled: %d %s", resp.StatusCode, readBody(resp))
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "no_trash" || !strings.Contains(e.Error.Message, "disabled") {
		t.Fatalf("answer %+v", e.Error)
	}
	if ensured {
		t.Fatal("a trash directory was prepared even though trash is disabled")
	}
	if len(fj.requests()) != 0 {
		t.Fatal("a trash delete was dispatched even though trash is disabled")
	}

	// The panel and its two actions say so plainly rather than failing oddly.
	if w := request(s, "GET", "/api/trash", c, nil); w.Code != http.StatusConflict {
		t.Fatalf("trash list: %d %s", w.Code, w.Body)
	}
	for _, route := range []string{"/api/trash/restore", "/api/trash/empty"} {
		resp := post(s, route, c, csrf, `{"ids":["1700000000-abcdef01"]}`)
		if route == "/api/trash/empty" {
			resp = post(s, route, c, csrf, `{}`)
		}
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("%s with trash disabled: %d %s", route, resp.StatusCode, readBody(resp))
		}
		var te apiEnvelope
		json.NewDecoder(resp.Body).Decode(&te)
		if te.Error.Code != "no_trash" {
			t.Fatalf("%s code %q", route, te.Error.Code)
		}
	}

	// A permanent delete is unaffected: that is the re-ask the client makes.
	job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	awaitTerminal(t, s, job.ID)
	if len(fj.requests()) != 1 {
		t.Fatalf("worker requests %+v", fj.requests())
	}
}

// --- W7: durable targets and one correlation id --------------------------------

// TestDeleteIntentNamesItsTargetsAndCorrelates is finding W7: the intent line
// carried no paths and the result line no targets, so concurrent deletes could
// not be paired and, after retention or a restart, the trail could not say what
// had been deleted. The id is now chosen before the intent is written, and both
// phases carry it.
func TestDeleteIntentNamesItsTargetsAndCorrelates(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	read := withAudit(t, s)
	c, csrf := sessionCookie(t, s)
	job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"},{"path":"/b #.txt"}],"mode":"permanent"}`)
	awaitTerminal(t, s, job.ID)

	var intent, result *audit.Event
	for _, ev := range read() {
		if ev.Op != "delete" {
			continue
		}
		e := ev
		switch e.Phase {
		case "intent":
			intent = &e
		case "result":
			// A permanent delete writes an async "denied/confirm_required"
			// challenge line for the first (token-less) POST before the redeemed
			// POST runs. That async line and the job's own durable result line have
			// no fixed order in the log (they raced visibly on the Windows CI job),
			// so skip the challenge and keep only the real terminal result.
			if e.Result != "denied" {
				result = &e
			}
		}
	}
	if intent == nil || result == nil {
		t.Fatalf("phases: intent=%v result=%v", intent != nil, result != nil)
	}
	if intent.Path != "/a.txt" {
		t.Fatalf("the intent must name its first target: %q", intent.Path)
	}
	for _, want := range []string{"job " + job.ID, "2 root(s)", "/a.txt", "/b #.txt", "permanent"} {
		if !strings.Contains(intent.Detail, want) {
			t.Fatalf("intent detail %q lacks %q", intent.Detail, want)
		}
	}
	// The result is the same job, and says so, so two concurrent deletes of
	// different things can be told apart in the trail.
	if result.Job != job.ID || !strings.Contains(result.Detail, "job "+job.ID) || result.Path != "/a.txt" {
		t.Fatalf("result %+v", *result)
	}
}

func TestJobIntentDetailIsCappedAndByteSafe(t *testing.T) {
	paths := make([]string, 25)
	for i := range paths {
		paths[i] = fmt.Sprintf("/item-%02d", i)
	}
	detail := jobIntentDetail("0123456789abcdef", "permanent", paths)
	if !strings.Contains(detail, "25 root(s)") || !strings.Contains(detail, "and 5 more") {
		t.Fatalf("cap: %q", detail)
	}
	if strings.Contains(detail, "/item-20") {
		t.Fatalf("past the cap a path is counted, not named: %q", detail)
	}
	// A non-UTF-8 root survives as base64 instead of being mangled to U+FFFD.
	if got := jobIntentDetail("0123456789abcdef", "trash", []string{"/bad\xffname"}); !strings.Contains(got, "b64:") {
		t.Fatalf("byte-safe naming: %q", got)
	}
}

// The job id the client is handed is the one the audit trail names, and it has
// the shape the /api/jobs/<id> routes accept.
func TestSubmittedJobUsesTheAuditedID(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)
	job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
	awaitTerminal(t, s, job.ID)
	if !validJobID(job.ID) {
		t.Fatalf("job id %q is not addressable by the job routes", job.ID)
	}
	reqs := fj.requests()
	if len(reqs) != 1 || reqs[0].JobID != job.ID {
		t.Fatalf("the worker was given a different id: %+v", reqs)
	}
}
