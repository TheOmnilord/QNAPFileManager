package web

import (
	"strings"
	"testing"
)

// The route half of the gpt-6-astra M3 round-7 review (docs/reviews/
// m3-astra-round7.md): finding 1. Round 6 bound the ACL verdict into the
// confirmation token, but bound it as the DEDUPLICATED SET of aclmode rungs —
// and a set says how many kinds of consequence there were, never which dataset
// had which. A crossing job reaches many datasets at once, so the set is the one
// shape that hides the change that matters: with the root on `passthrough`,
// child A on `discard` and child B on `passthrough`, the descriptor read
// `discard+passthrough`, and it still read `discard+passthrough` after B flipped
// to `discard`, because A had been contributing that spelling all along. The
// stale token verified, the job ran, and B's ACL was destroyed on an L2 sentence
// that named only A.
//
// The fix is a digest of the per-dataset consequence table, so these tests move
// ONE dataset's rung and leave the folded grade, the discard flag and the set of
// modes exactly as they were. As in round 6 the facts move rather than the clock:
// replacing the injected platform between the challenge and the re-post is the
// same event, from the route's point of view, as an expiry mask flipping under it.

// heroChildDatasetB is a second dataset under the same share as heroChildDataset
// — the golden hero mountinfo nests both under /share/ZFS530_DATA — so a crossing
// walk grades two children whose rungs can be moved independently.
const heroChildDatasetB = "zpool1/zfs530_data/Media"

// discardingOnly answers `discard` for the named datasets and `passthrough` for
// every other, which is discardOnly generalised to the two-child case.
func discardingOnly(datasets ...string) func(string) string {
	return func(got string) string {
		for _, d := range datasets {
			if got == d {
				return "discard"
			}
		}
		return "passthrough"
	}
}

// TestACrossingConfirmationCannotSurviveASecondChildDiscarding is finding 1
// exactly as it was reported. The mode bits, the roots, the folded grade (L2),
// the discard flag (true) and the set of aclmode rungs (`discard` and
// `passthrough`) are all unchanged across the flip; the only thing that moved is
// WHICH datasets discard — and with it the sentence the user would have to
// acknowledge, which now has to name B.
func TestACrossingConfirmationCannotSurviveASecondChildDiscarding(t *testing.T) {
	s, b, fj := permFixture(t)
	const parent = "/share/ZFS530_DATA"
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDataset))
	mkAPIDir(t, b, parent)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + parent + `"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2 while one child discards: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	if joined := strings.Join(env.Confirm.Summary.Warnings, " | "); strings.Contains(joined, heroChildDatasetB) {
		t.Fatalf("the first sentence must not name the passthrough child: %q", joined)
	}

	// The second child is set to discard. Everything the round-6 descriptor
	// carried is still true of the new ladder; the table underneath it is not.
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDataset, heroChildDatasetB))

	resp := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want a fresh challenge: a second dataset now loses its ACL", resp.StatusCode)
	}
	again := decodeConfirm(t, resp)
	if again.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", again.Confirm.Grade, again.Confirm.Summary.Warnings)
	}
	joined := strings.Join(again.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, heroChildDatasetB) || !strings.Contains(joined, heroChildDataset) {
		t.Fatalf("the re-challenge must name both discarding datasets: %q", joined)
	}
	if n := countChmodJobs(fj); n != 0 {
		t.Fatalf("%d job(s) submitted: a destroyed ACL cannot be restored, so the refusal belongs before the submission", n)
	}

	// The current challenge's token is accepted, and the job runs: the binding
	// refuses a superseded sentence, not the user.
	if ok := post(s, "/api/jobs/chmod", c, csrf, withToken(body, again.Confirm.Token)); ok.StatusCode != 202 {
		t.Fatalf("status %d on the current challenge's token: %s", ok.StatusCode, readBody(ok))
	}
}

// TestACrossingConfirmationCannotSurviveSwappedRungs is the same finding with the
// set held identical by construction: one child discards before and one child
// discards after, and they are different children. A descriptor built from the
// modes alone is byte-for-byte the same on both sides of the swap, so this is the
// case that can only be caught by binding the dataset to its rung.
func TestACrossingConfirmationCannotSurviveSwappedRungs(t *testing.T) {
	s, b, fj := permFixture(t)
	const parent = "/share/ZFS530_DATA"
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDataset))
	mkAPIDir(t, b, parent)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + parent + `"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}

	// A goes back to passthrough and B discards instead: same grade, same discard
	// flag, same pair of rungs, a different dataset losing its ACL.
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDatasetB))

	resp := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want a fresh challenge: the acknowledged sentence named the wrong dataset", resp.StatusCode)
	}
	again := decodeConfirm(t, resp)
	joined := strings.Join(again.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, heroChildDatasetB) {
		t.Fatalf("the re-challenge must name the dataset that now discards: %q", joined)
	}
	if strings.Contains(joined, heroChildDataset) {
		t.Fatalf("it must not still name the one that no longer does: %q", joined)
	}
	if n := countChmodJobs(fj); n != 0 {
		t.Fatalf("%d job(s) submitted on the superseded sentence", n)
	}
}

// TestACrossingConfirmationOnAnUnmovedTableStillRedeems is the cost the binding
// may not have. A digest over every dataset a crossing walk reaches is sensitive
// by design, and a descriptor that is sensitive to something that did not move
// would re-challenge the user on every second attempt — which teaches the typed
// phrase as a formality, which is the failure mode the ladder exists to avoid.
func TestACrossingConfirmationOnAnUnmovedTableStillRedeems(t *testing.T) {
	s, b, _ := permFixture(t)
	const parent = "/share/ZFS530_DATA"
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDataset, heroChildDatasetB))
	mkAPIDir(t, b, parent)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"` + parent + `"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`

	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	// The same platform re-probed: the walk order of a mount table is not a fact
	// about the change, and the digest sorts precisely so it cannot become one.
	s.platform = heroPlatformPerDataset(t, nil, discardingOnly(heroChildDatasetB, heroChildDataset))
	if resp := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)); resp.StatusCode != 202 {
		t.Fatalf("status %d, want the job accepted on a table that did not move: %s", resp.StatusCode, readBody(resp))
	}
}
