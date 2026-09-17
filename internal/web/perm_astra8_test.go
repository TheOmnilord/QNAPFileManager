package web

import (
	"context"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

// The route half of the gpt-6-astra M3 round-8 review: finding 4. Rounds 6 and 7
// bound the ACL verdict into the confirmation token — first as the folded rung,
// then as a per-dataset digest — so a token minted on one set of facts cannot be
// redeemed once they have moved. What neither round bound is the gap AFTER the
// redemption: a token binds submission, and a job does not start when it is
// submitted. With the four metadata slots occupied it waits in the queue, and a
// `zfs set aclmode=discard` between the 202 and the dispatch lands entirely
// before the first mutation — early enough for the destructive sentence to have
// been shown, and late enough that the queued callback, which re-checked the
// guard and nothing else, never asked.
//
// These tests stage exactly that: the challenge is answered and redeemed while
// the dataset is `passthrough`, the job is parked behind a held slot, the facts
// move, and the slot is released. What must come out of it is a FAILED job and no
// worker call at all — an ACL that has been destroyed cannot be put back, so the
// refusal has to happen on this side of the dispatch.
//
// The slot is taken only AFTER the challenge, deliberately: a recursive job's
// pre-scan takes the same metadata slot the job will (round-1 finding 10), so
// holding it earlier would park the measurement instead. The redemption reads its
// count back off the token (peekScan) and walks nothing, which is what makes the
// staging possible at all.

// permQueueFixture is permFixture with ONE metadata slot, so a single held
// admission is enough to park everything behind it.
func permQueueFixture(t *testing.T) (*Server, *fakeBackend, *fakeJobs) {
	t.Helper()
	s, b, fj := jobsFixture(t, jobs.Limits{Metadata: 1})
	s.Root = fsx.Root{}
	return s, b, fj
}

// holdMetadataSlot occupies the only metadata slot and returns its release.
func holdMetadataSlot(t *testing.T, s *Server) func() {
	t.Helper()
	release, err := s.jobMgr.Admit(context.Background(), jobs.ClassMetadata)
	if err != nil {
		t.Fatalf("holding the metadata slot: %v", err)
	}
	return release
}

// TestAQueuedChmodDoesNotDispatchOnceTheACLFactsMove is finding 4 as reported.
// The dialog said the mode is set and the other entries are kept; by the time the
// job reaches a slot that sentence is false, and the confirmation that carried it
// may not authorise the change the new facts describe.
func TestAQueuedChmodDoesNotDispatchOnceTheACLFactsMove(t *testing.T) {
	s, b, fj := permQueueFixture(t)
	events := withAudit(t, s)
	const root = "/share/ZFS530_DATA/Public"
	s.platform = heroPlatform(t, "passthrough")
	mkAPIDir(t, b, root)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + root + `"}],"files":{"mask":511,"value":493},"recursive":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Token == "" {
		t.Fatalf("no token in the challenge: %v", env.Confirm.Summary.Warnings)
	}
	if joined := strings.Join(env.Confirm.Summary.Warnings, " | "); !strings.Contains(joined, "Other entries are kept") {
		t.Fatalf("the challenge must be the passthrough sentence: %q", joined)
	}

	// The slot is taken now, so the confirmed job is accepted and then parked.
	release := holdMetadataSlot(t, s)
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)))
	if n := countChmodJobs(fj); n != 0 {
		t.Fatalf("%d chmod(s) already dispatched: the job was meant to be queued", n)
	}

	// `zfs set aclmode=discard` while it waits. Nothing has been mutated yet, so
	// this is a change the user could still have been asked about.
	s.platform = heroPlatform(t, "discard")
	release()

	done := awaitTerminal(t, s, job.ID)
	if done.State != jobs.StateFailed {
		t.Fatalf("job state %q, want failed: a queued job may not dispatch on a superseded sentence", done.State)
	}
	if done.ErrCode != "confirm_required" {
		t.Fatalf("error code %q, want confirm_required", done.ErrCode)
	}
	if !strings.Contains(done.Err, "ACL facts changed while this was waiting") {
		t.Fatalf("published error %q must say what happened and what to do", done.Err)
	}
	if strings.ContainsAny(done.Err, "/\\") {
		t.Fatalf("the published error must stay path-free: %q", done.Err)
	}
	if n := countChmodJobs(fj); n != 0 {
		t.Fatalf("%d chmod(s) reached the worker: a destroyed ACL cannot be restored", n)
	}

	// And the durable trail closes the intent: a denial, with the code on it.
	var denied bool
	for _, e := range events() {
		if e.Job == job.ID && e.Phase == "result" {
			denied = e.Result == "denied" && e.Code == "confirm_required"
		}
	}
	if !denied {
		t.Fatal("the refused job left no denied result line beside its intent")
	}
}

// TestAQueuedChmodStillDispatchesWhenTheACLFactsHold is the cost the re-check may
// not have. A binding that re-grades at dispatch is sensitive by design, and one
// that failed a job whose facts never moved would turn every queued permissions
// change into a coin toss — which teaches the typed phrase as a formality, the
// failure mode the ladder exists to avoid.
func TestAQueuedChmodStillDispatchesWhenTheACLFactsHold(t *testing.T) {
	s, b, fj := permQueueFixture(t)
	const root = "/share/ZFS530_DATA/Public"
	s.platform = heroPlatform(t, "passthrough")
	mkAPIDir(t, b, root)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + root + `"}],"files":{"mask":511,"value":493},"recursive":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Token == "" {
		t.Fatalf("no token in the challenge: %v", env.Confirm.Summary.Warnings)
	}
	release := holdMetadataSlot(t, s)
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)))

	// The table is re-probed rather than changed: the same facts, read again, are
	// the same verdict — the digest sorts precisely so a walk order cannot make
	// them look different.
	s.platform = heroPlatform(t, "passthrough")
	release()

	done := awaitTerminal(t, s, job.ID)
	if done.State != jobs.StateDone {
		t.Fatalf("job state %q (%s), want done on facts that did not move", done.State, done.Err)
	}
	if n := countChmodJobs(fj); n != 1 {
		t.Fatalf("%d chmod(s) reached the worker, want 1", n)
	}
}

// TestAQueuedChownIsNotRegradedAtDispatch: a chown's ladder never asks the mount
// table about an ACL, so its verdict is the zero one at submit and must stay the
// zero one at dispatch however the datasets move. Without that the re-check would
// refuse ownership changes over a fact their dialog never mentioned.
func TestAQueuedChownIsNotRegradedAtDispatch(t *testing.T) {
	s, b, fj := permQueueFixture(t)
	const root = "/share/ZFS530_DATA/Public"
	s.platform = heroPlatform(t, "passthrough")
	mkAPIDir(t, b, root)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + root + `"}],"uid":1000,"recursive":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chown", c, csrf, body))
	if env.Confirm.Token == "" {
		t.Fatalf("no token in the challenge: %v", env.Confirm.Summary.Warnings)
	}
	release := holdMetadataSlot(t, s)
	job := acceptedJob(t, post(s, "/api/jobs/chown", c, csrf, withToken(body, env.Confirm.Token)))
	s.platform = heroPlatform(t, "discard")
	release()

	if done := awaitTerminal(t, s, job.ID); done.State != jobs.StateDone {
		t.Fatalf("chown state %q (%s): an aclmode is not a fact a chown was graded on", done.State, done.Err)
	}
	n := 0
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobChown {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d chown(s) reached the worker, want 1", n)
	}
}
