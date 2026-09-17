package web

import (
	"fmt"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// The route half of the gpt-6-astra M3 round-6 review (docs/reviews/
// m3-astra-round6.md): finding 3. A confirmation token lives sixty seconds and a
// probed mount fact is trusted for a minute of its own, so the two windows overlap
// by construction — probe `passthrough` at t=0, `zfs set aclmode=discard`, take the
// L1 token at t=59, re-post it at t=61. The redemption re-grades and computes the
// L2 typed phrase, and then accepted the earlier token anyway, because the token's
// descriptor bound the op, the mode bits and the roots and nothing at all about
// the ACL. The dialog the user acknowledged promised that the other entries would
// be kept; the change that ran destroyed them.
//
// The tests below move the FACTS rather than the clock. Replacing the injected
// platform between the challenge and the re-post is the same event from the
// route's point of view as the expiry mask flipping under it (Astra r6 #2), and it
// is the one this package can stage: it is the re-grade that has to refuse the
// stale confirmation, whatever made the facts move.

const heroChildDataset = "zpool1/zfs530_data/Public"

// discardOnly answers `discard` for one dataset and `passthrough` for the rest,
// which is the hero pool shape the crossing rung exists for: one dataset per share
// and often per sub-folder, each with its own aclmode.
func discardOnly(dataset string) func(string) string {
	return func(got string) string {
		if got == dataset {
			return "discard"
		}
		return "passthrough"
	}
}

// heroAt points BOTH halves of the sync ladder at one aclmode: the daemon's
// injected mount table and the worker's own cached row, which entryACLFacts folds
// to the worse of the two (Astra r5 #5). Moving only one of them would be a test
// of that fold rather than of the token, and the event being staged here — a `zfs
// set` that both sides eventually see, or a minute passing over the daemon's copy
// — moves what both of them say.
func heroAt(t *testing.T, s *Server, b *fakeBackend, aclmode string) {
	t.Helper()
	s.platform = heroPlatform(t, aclmode)
	b.propsACL = wproto.ACLInfo{Aclmode: aclmode}
}

// countChmodJobs counts the chmod work actually submitted to the worker, as
// opposed to the size walks a challenge runs to measure a recursion.
func countChmodJobs(fj *fakeJobs) int {
	n := 0
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobChmod {
			n++
		}
	}
	return n
}

// --- the sync route ------------------------------------------------------------

// TestAnL1ConfirmationCannotBeSpentOnceTheGradeIsL2 is the finding. The dialog the
// user saw said the mode is set and the other entries are kept; by the time the
// token comes back that sentence is false, and the token may not be what carries
// it past the re-grade.
func TestAnL1ConfirmationCannotBeSpentOnceTheGradeIsL2(t *testing.T) {
	s, b, _ := permFixture(t)
	heroAt(t, s, b, "passthrough")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)

	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeConfirm {
		t.Fatalf("grade %d, want the L1 passthrough challenge: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " | "), "passthrough") {
		t.Fatalf("warnings %v, want the passthrough reassurance; this test proves nothing", env.Confirm.Summary.Warnings)
	}

	// `zfs set aclmode=discard`, or simply a minute passing over a fact that was
	// already discard — either way the re-grade is the destructive rung now.
	heroAt(t, s, b, "discard")

	resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want a fresh challenge: the confirmation was given for a sentence that is no longer true", resp.StatusCode)
	}
	again := decodeConfirm(t, resp)
	if again.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2 on the re-challenge: %v", again.Confirm.Grade, again.Confirm.Summary.Warnings)
	}
	if !strings.Contains(strings.Join(again.Confirm.Summary.Warnings, " | "), "DESTROY") {
		t.Fatalf("the new challenge must say what the change now does: %v", again.Confirm.Summary.Warnings)
	}
	if len(b.chmodReqs) != 0 {
		t.Fatalf("%d chmod(s) dispatched: the refusal has to happen BEFORE the worker is called, because a confirmation cannot be demanded after the change", len(b.chmodReqs))
	}

	// And the new token, minted for the sentence that is true, does redeem — the
	// user is challenged again, not locked out.
	if ok := post(s, "/api/fs/chmod", c, csrf, withToken(body, again.Confirm.Token)); ok.StatusCode != 200 {
		t.Fatalf("status %d on the current challenge's token: %s", ok.StatusCode, readBody(ok))
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d, want the one the user confirmed on the current facts", len(b.chmodReqs))
	}
}

// TestAConfirmationOnUnchangedFactsStillRedeems is the cost the binding may not
// have. Nothing moved between the challenge and the re-post, so the descriptor is
// rebuilt identically and the ordinary confirm-and-repost flow is untouched.
func TestAConfirmationOnUnchangedFactsStillRedeems(t *testing.T) {
	s, b, _ := permFixture(t)
	heroAt(t, s, b, "passthrough")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)

	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want the change to go through on facts that did not move: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d, want 1", len(b.chmodReqs))
	}
}

// TestASofterRegradeAlsoInvalidatesTheToken is the other direction, and it is not
// symmetric decoration: the descriptor is an equality, not a floor. A token minted
// for an L2 typed phrase describes a change the user was told would destroy an ACL,
// and the same descriptor has to stop describing the operation once the facts say
// otherwise — the alternative is a rule that has to reason about which way a grade
// may drift, which is the kind of rule that is wrong in the third case nobody
// thought of.
func TestASofterRegradeAlsoInvalidatesTheToken(t *testing.T) {
	s, b, _ := permFixture(t)
	heroAt(t, s, b, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)

	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	heroAt(t, s, b, "passthrough")
	resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want a fresh challenge", resp.StatusCode)
	}
	if again := decodeConfirm(t, resp); again.Confirm.Grade != gradeConfirm {
		t.Fatalf("grade %d, want the L1 the current facts call for", again.Confirm.Grade)
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("nothing may be dispatched on a descriptor that no longer matches")
	}
}

// TestTwoL1SentencesAreNotInterchangeable is why the verdict carries the aclmode
// and not just the grade. `passthrough` says the other entries are kept and
// `groupmask` says they are silently reduced to the group bits of the new mode:
// both are L1, neither discards, and they are different promises. A descriptor of
// grade alone would let one be acknowledged and the other performed.
func TestTwoL1SentencesAreNotInterchangeable(t *testing.T) {
	s, b, _ := permFixture(t)
	heroAt(t, s, b, "passthrough")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)

	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	heroAt(t, s, b, "groupmask")
	resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d: an L1 token was spent on a different L1 sentence", resp.StatusCode)
	}
	if !strings.Contains(strings.Join(decodeConfirm(t, resp).Confirm.Summary.Warnings, " | "), "groupmask") {
		t.Fatal("the re-challenge must carry the sentence that is now true")
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("nothing may be dispatched on the superseded sentence")
	}
}

// --- the job route, including the crossing rung ---------------------------------

// TestAJobConfirmationCannotSurviveADiscardingChild is the same finding over the
// ladder that folds every dataset a crossing walk can reach. The root is
// passthrough throughout; what changes is a CHILD dataset one directory down,
// which is exactly the case the collapsed L2 sentence was added for (round 4) and
// exactly the one a root-bound descriptor cannot see.
func TestAJobConfirmationCannotSurviveADiscardingChild(t *testing.T) {
	s, b, fj := permFixture(t)
	const parent = "/share/ZFS530_DATA"
	s.platform = heroPlatformPerDataset(t, nil, func(string) string { return "passthrough" })
	mkAPIDir(t, b, parent)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + parent + `"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeConfirm {
		t.Fatalf("grade %d, want L1 while every dataset is passthrough: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}

	// One child dataset is set to discard. The roots the token binds are unchanged,
	// the mode bits are unchanged, and the change now destroys ACLs.
	s.platform = heroPlatformPerDataset(t, nil, discardOnly(heroChildDataset))

	resp := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want a fresh challenge: the crossing rung moved under the confirmation", resp.StatusCode)
	}
	again := decodeConfirm(t, resp)
	if again.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", again.Confirm.Grade, again.Confirm.Summary.Warnings)
	}
	if joined := strings.Join(again.Confirm.Summary.Warnings, " | "); !strings.Contains(joined, heroChildDataset) {
		t.Fatalf("the discarding child must be named on the re-challenge: %q", joined)
	}
	if n := countChmodJobs(fj); n != 0 {
		t.Fatalf("%d job(s) submitted: a permissions job cannot be undone, so the refusal belongs before the submission", n)
	}

	// The current challenge's token is accepted, and the job runs.
	if ok := post(s, "/api/jobs/chmod", c, csrf, withToken(body, again.Confirm.Token)); ok.StatusCode != 202 {
		t.Fatalf("status %d on the current challenge's token: %s", ok.StatusCode, readBody(ok))
	}
}

// TestAJobConfirmationOnUnchangedFactsStillRedeems is the job route's half of the
// cost the binding may not have.
func TestAJobConfirmationOnUnchangedFactsStillRedeems(t *testing.T) {
	s, b, _ := permFixture(t)
	const parent = "/share/ZFS530_DATA"
	s.platform = heroPlatformPerDataset(t, nil, discardOnly(heroChildDataset))
	mkAPIDir(t, b, parent)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + parent + `"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	if resp := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)); resp.StatusCode != 202 {
		t.Fatalf("status %d, want the job accepted on facts that did not move: %s", resp.StatusCode, readBody(resp))
	}
}

// TestAChownConfirmationIsUnaffected: a chown's ladder never reads an aclmode, so
// its verdict is the zero one and its descriptor is what it always was. The
// binding may not make an operation that has no ACL consequence sensitive to one.
func TestAChownConfirmationIsUnaffected(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "passthrough")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"uid":1000,"gid":1000}`, p)

	env := decodeConfirm(t, post(s, "/api/fs/chown", c, csrf, body))
	// The aclmode moves; a chown was never graded on it and its token stands.
	s.platform = heroPlatform(t, "discard")
	if resp := post(s, "/api/fs/chown", c, csrf, withToken(body, env.Confirm.Token)); resp.StatusCode != 200 {
		t.Fatalf("status %d, want the chown to go through: %s", resp.StatusCode, readBody(resp))
	}
}

// --- the verdict itself ----------------------------------------------------------

// TestTheACLVerdictRecordsOnlyRungsThatWereStated pins the fold. A fact that
// produced no sentence contributes no aclmode, because there was nothing for one
// to have been built on — otherwise a tmpfs under a job's root would put a "?" in
// the descriptor and make the token sensitive to a mount nobody was told about.
func TestTheACLVerdictRecordsOnlyRungsThatWereStated(t *testing.T) {
	var v aclVerdict
	if got := v.part(); got != "acl=0/false/" {
		t.Fatalf("the zero verdict is %q, want an empty one", got)
	}
	v.fold(aclFacts{aclmode: "passthrough"}, gradeNone, false)
	if got := v.part(); got != "acl=0/false/" {
		t.Fatalf("part %q: a rung that stated nothing must contribute nothing", got)
	}
	v.fold(aclFacts{aclmode: "passthrough"}, gradeConfirm, false)
	if got := v.part(); got != "acl=1/false/passthrough" {
		t.Fatalf("part %q, want the stated L1 rung", got)
	}
	// A second dataset saying the same thing is the same rung; an unreadable
	// aclmode is its own, because it is what carries the L2 suffix.
	v.fold(aclFacts{aclmode: "passthrough"}, gradeConfirm, false)
	v.fold(aclFacts{aclmode: ""}, gradeTyped, true)
	if got := v.part(); got != "acl=2/true/?+passthrough" {
		t.Fatalf("part %q, want the worst grade, the discard flag and both rungs, sorted", got)
	}
}
