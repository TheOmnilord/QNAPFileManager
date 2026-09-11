package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

// The M2-A round-3 web/jobs findings, one test group per finding:
//
//	R3-S1  the audit outcome is classified from the RECONCILED counts
//	R3-S2  a refused submission names the id its intent already used
//	R3-WA1 trash.enabled=false is refused before a trash token is issued

// --- R3-S1: outcome from the terminal result, not the frame counter -----------

// TestSkippedItemsAreNeverAuditedOK is finding R3-S1.
//
// The completion hook classified "ok" against "partial" from Job.WarningCount,
// which counts the warn FRAMES that actually arrived. The terminal JobResult is
// the authority — the worker summarises there, and a frame can be dropped — so a
// destructive job that skipped items could be recorded as a clean success, which
// is the one thing the durable record of a delete must never say.
func TestSkippedItemsAreNeverAuditedOK(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result wproto.JobResult
		want   string
		says   string
	}{
		{
			name:   "warnings without a single warn frame",
			result: wproto.JobResult{Files: 2, Bytes: 20, Warnings: 3},
			want:   "partial",
			says:   "3 warning(s)",
		},
		{
			name:   "skipped items without a single warn frame",
			result: wproto.JobResult{Files: 2, Bytes: 20, Skipped: 4},
			want:   "partial",
			says:   "4 skipped",
		},
		{
			name:   "nothing skipped, nothing warned",
			result: wproto.JobResult{Files: 2, Bytes: 20},
			want:   "ok",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, fj := jobsFixture(t, jobs.Limits{})
			// The whole point: the worker sends NO warn frames, so the manager's
			// live counter stays at zero and only the terminal result knows.
			fj.warns = nil
			fj.result = tc.result
			read := withAudit(t, s)
			c, csrf := sessionCookie(t, s)

			job := submitDelete(t, s, c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"permanent"}`)
			awaitTerminal(t, s, job.ID)
			if j, _ := s.jobMgr.Get(job.ID); j.WarningCount != 0 {
				t.Fatalf("the fixture streamed %d warn frames; this test is about the case where none arrive", j.WarningCount)
			}

			result := resultLine(t, read(), job.ID)
			if result.Result != tc.want {
				t.Fatalf("result line %q, want %q: %+v", result.Result, tc.want, result)
			}
			if tc.says != "" && !strings.Contains(result.Detail, tc.says) {
				t.Errorf("detail %q does not say %q", result.Detail, tc.says)
			}
		})
	}
}

// resultLine returns the one durable result event recorded for a job id.
func resultLine(t *testing.T, events []audit.Event, id string) audit.Event {
	t.Helper()
	for _, ev := range eventsFor(events, id) {
		if ev.Phase == "result" {
			return ev
		}
	}
	t.Fatalf("no result line for job %s in %+v", id, events)
	return audit.Event{}
}

// --- R3-S2: a refused submission carries the minted id ------------------------

// TestRejectedSubmissionPairsWithItsIntent is finding R3-S2.
//
// The job id is chosen before the durable intent line (W7), so an intent saying
// "job <id>" could stand with a result line that named no job at all whenever
// Submit refused the work (a full queue, a closing manager). Nothing could pair
// the two, which is exactly what a durable trail of destructive intent is for.
func TestRejectedSubmissionPairsWithItsIntent(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1, QueueDepth: 1})
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	defer close(fj.block)
	read := withAudit(t, s)
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
	awaitState(t, s, first.ID, jobs.StateRunning)
	acceptedJob(t, submit("binary"))
	// The third fills nothing: the queue is full and the manager refuses it.
	resp := submit("refused.txt")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("queue full: %d %s", resp.StatusCode, readBody(resp))
	}

	// The refused submission's intent and its result must name the SAME id.
	var intent, result audit.Event
	for _, ev := range read() {
		if ev.Op != "delete" || !strings.Contains(ev.Detail, "/refused.txt") && ev.Code != "queue_full" {
			continue
		}
		switch {
		case ev.Phase == "intent" && strings.Contains(ev.Detail, "/refused.txt"):
			intent = ev
		case ev.Phase == "result" && ev.Code == "queue_full":
			result = ev
		}
	}
	if intent.Detail == "" {
		t.Fatal("the refused submission wrote no intent line")
	}
	id := jobIDIn(t, intent.Detail)
	if want := "job " + id; !strings.Contains(result.Detail, want) {
		t.Fatalf("the queue_full result line %q does not carry %q, so it cannot be paired with its intent", result.Detail, want)
	}
	if result.Result != "error" {
		t.Errorf("result %q, want error", result.Result)
	}
}

// jobIDIn pulls the correlation id out of a "job <id>: ..." audit detail.
func jobIDIn(t *testing.T, detail string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(detail, "job ")
	if !ok {
		t.Fatalf("detail %q does not begin with a job id", detail)
	}
	id, _, _ := strings.Cut(rest, ":")
	if !validJobID(id) {
		t.Fatalf("detail %q carries %q, which is not a job id", detail, id)
	}
	return id
}

// --- R3-WA1: no_trash before the token ----------------------------------------

// TestTrashDisabledIsRefusedBeforeATokenIsIssued is finding R3-WA1: with the
// NAS-wide switch off, the very FIRST POST in trash mode answers no_trash, and
// no confirmation token is minted for a mode the daemon will never run. The old
// order issued the token, took the user's confirmation, and only then discovered
// there is no Trash — two dialogs and a spent single-use token for one decision.
func TestTrashDisabledIsRefusedBeforeATokenIsIssued(t *testing.T) {
	s, _, _ := jobsFixture(t, jobs.Limits{})
	s.cfg.Trash.Enabled = false
	c, csrf := sessionCookie(t, s)

	resp := post(s, "/api/jobs/delete", c, csrf, `{"paths":[{"path":"/a.txt"}],"mode":"trash"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("first trash POST: %d %s", resp.StatusCode, readBody(resp))
	}
	var env confirmEnvelope
	body := readBody(resp)
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "no_trash" {
		t.Fatalf("first trash POST answered %q, want no_trash: %s", env.Error.Code, body)
	}
	if env.Confirm.Token != "" {
		t.Fatalf("a trash-mode confirmation token was issued although Trash is disabled: %s", body)
	}
}

// TestTrashDisabledDoesNotPreEmptTheGuard pins R3-WA1's ordering rule: a
// protected root, or a daemon in read-only mode, refuses for its OWN reason
// first. "There is no Trash" must never be the answer to a delete that was not
// going to be allowed in any mode — the client would re-ask as a PERMANENT
// delete of a path that is protected against every kind of delete.
func TestTrashDisabledDoesNotPreEmptTheGuard(t *testing.T) {
	for _, tc := range []struct {
		name, path, want string
		setup            func(*Server)
	}{
		{name: "protected path", path: "/bin", want: "protected"},
		{
			name: "read-only mode", path: "/a.txt", want: "read_only",
			setup: func(s *Server) { s.guard.SetReadOnly(true) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, _ := jobsFixture(t, jobs.Limits{})
			s.cfg.Trash.Enabled = false
			if err := os.MkdirAll(filepath.Join(b.dir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(s)
			}
			c, csrf := sessionCookie(t, s)

			resp := post(s, "/api/jobs/delete", c, csrf, fmt.Sprintf(`{"paths":[{"path":%q}],"mode":"trash"}`, tc.path))
			var e apiEnvelope
			body := readBody(resp)
			if err := json.Unmarshal([]byte(body), &e); err != nil {
				t.Fatal(err)
			}
			if e.Error.Code != tc.want {
				t.Fatalf("answered %q, want %q: %s", e.Error.Code, tc.want, body)
			}
		})
	}
}
