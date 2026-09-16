package web

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The route half of the gpt-6-astra M3 round-2 review (docs/reviews/
// m3-astra-round2.md): findings 1, 6 and 8. Findings 1 and 6 are one bug seen
// from two sides — the precondition the sync chmod sends was built out of the
// ladder's GRADE rather than out of what the worker reported, so a chmod the
// user confirmed was refused as `changed` for an object nothing had touched.

// --- finding 1: the expectation is an observation, not a grade -------------------

// TestChmodExpectsTheObservedStateNotTheGrade. The daemon's table knows this
// mount is NFSv4; the worker, running as a user who cannot read the dataset
// root's attribute, answers `none`. Round 1 taught the route to discard that
// reading rather than let it downgrade the warning — and then to send the
// discarded pessimistic value as the precondition, which the worker cannot
// match, because when it re-probes it will see exactly what it saw before.
//
// So: L2 is still demanded (the grade is unchanged), and the chmod carries the
// state the WORKER saw.
func TestChmodExpectsTheObservedStateNotTheGrade(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNone, State: fsx.ACLNone}
	b.propsIdentity = wproto.FSIdentityResp{Dev: 66305, Ino: 4242}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.state != fsx.ACLUnknown {
		t.Fatalf("graded state %q, want the pessimistic one", facts.state)
	}

	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)
	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: a discarded worker reading is still graded pessimistically", env.Confirm.Grade)
	}
	if resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token)); resp.StatusCode != 200 {
		t.Fatalf("confirmed chmod %d: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 || b.chmodReqs[0].Expect == nil {
		t.Fatalf("dispatched %+v", b.chmodReqs)
	}
	if got := b.chmodReqs[0].Expect.State; got != fsx.ACLNone {
		t.Fatalf("expected state %q, want the OBSERVED %q — the worker cannot prove a grade it never reported",
			got, fsx.ACLNone)
	}
	if id := b.chmodReqs[0].Expect.Identity; id.Dev != 66305 || id.Ino != 4242 {
		t.Fatalf("identity %+v, want the object Props described", id)
	}
}

// TestChmodWithNothingObservedProvesTheIdentityOnly: a worker that could not
// read the attribute at all reports no state. The route grades that as unknown
// — it must — and sends an EMPTY expectation state, which means "prove the
// identity only". Sending `unknown` instead is the round-1 regression: the
// worker re-probes, sees nothing again, and refuses a chmod that was confirmed.
func TestChmodWithNothingObservedProvesTheIdentityOnly(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsIdentity = wproto.FSIdentityResp{Dev: 66305, Ino: 909}

	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)
	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if resp := post(s, "/api/fs/chmod", c, csrf, withToken(body, env.Confirm.Token)); resp.StatusCode != 200 {
		t.Fatalf("confirmed chmod %d: %s", resp.StatusCode, readBody(resp))
	}
	expect := b.chmodReqs[0].Expect
	if expect == nil {
		t.Fatal("the identity is still worth proving when the state is not known")
	}
	if expect.State != "" {
		t.Fatalf("expected state %q, want empty: nothing was observed", expect.State)
	}
	if expect.Identity.Ino != 909 {
		t.Fatalf("identity %+v", expect.Identity)
	}
}

// --- finding 6: an object with no inode to prove ---------------------------------

// TestChmodAfterPropsSucceedsWithoutAnInode is the dev loop, off Linux (§14):
// there is no inode to report, so Props answers the zero identity. The route
// neither drops the expectation on that account — the ACL half is still worth
// proving where there is one — nor invents an identity, which would be a proof
// of nothing. The worker, seeing no inode on either side, proves the state
// alone; this is the route's end of that arrangement, and it runs on this box.
func TestChmodAfterPropsSucceedsWithoutAnInode(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNone, State: fsx.ACLNone}
	// The fake's identity stays zero: no mount id, no device, no inode, which is
	// what props_other.go reports where there are none.

	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":511,"value":493}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d", len(b.chmodReqs))
	}
	expect := b.chmodReqs[0].Expect
	if expect == nil {
		t.Fatal("the expectation was suppressed because the identity was zero (Astra r2 #6)")
	}
	if expect.State != fsx.ACLNone {
		t.Fatalf("expected state %q, want the observed one", expect.State)
	}
	if expect.Identity != (wproto.FSIdentityResp{}) {
		t.Fatalf("identity %+v, want the zero one Props reported — nothing may be fabricated", expect.Identity)
	}
}

// --- finding 8: the scan budget is the selection's, not each root's ---------------

// TestPermScanBudgetIsTheRemainingAllowance. Every root used to be handed a
// fresh 500 000-entry budget, so the bound that exists to stop an unconfirmed
// POST from walking a NAS was multiplied by the number of paths in the body —
// and the sum came back as a MEASURED count, which the ladder reads as small
// enough not to warn about.
func TestPermScanBudgetIsTheRemainingAllowance(t *testing.T) {
	s, _, fj := permFixture(t)
	// A walker that honours the budget it was handed: 400 000 entries under it,
	// capped when the budget is smaller than that.
	fj.resultFor = func(req wproto.JobReq) (wproto.JobResult, error) {
		var sent wproto.SizeReq
		if err := json.Unmarshal(req.Body, &sent); err != nil {
			return wproto.JobResult{}, err
		}
		if sent.MaxEntries < 400_000 {
			return wproto.JobResult{Files: sent.MaxEntries, Capped: true}, nil
		}
		return wproto.JobResult{Files: 400_000}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	roots := []string{"/data/one", "/data/two"}
	if got := s.permScan(ctx, backend.Principal{}, roots, false); got != -1 {
		t.Fatalf("permScan = %d, want -1: two roots of 400 000 exceed the bound", got)
	}
	var budgets []int64
	for _, req := range fj.requests() {
		if req.Kind != wproto.JobSize {
			continue
		}
		var sent wproto.SizeReq
		if err := json.Unmarshal(req.Body, &sent); err != nil {
			t.Fatal(err)
		}
		budgets = append(budgets, sent.MaxEntries)
	}
	if len(budgets) != 2 {
		t.Fatalf("size walks %v, want two", budgets)
	}
	if budgets[0] != modeScanMaxEntries {
		t.Fatalf("first budget %d, want the whole allowance %d", budgets[0], modeScanMaxEntries)
	}
	if budgets[1] != modeScanMaxEntries-400_000 {
		t.Fatalf("second budget %d, want what the first root left (%d)", budgets[1], modeScanMaxEntries-400_000)
	}
}

// TestPermScanStopsWhenTheAllowanceIsSpent: a root that arrives with nothing
// left is the capped case itself, and is not walked at all.
func TestPermScanStopsWhenTheAllowanceIsSpent(t *testing.T) {
	s, _, fj := permFixture(t)
	fj.result = wproto.JobResult{Files: modeScanMaxEntries}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if got := s.permScan(ctx, backend.Principal{}, []string{"/data/one", "/data/two"}, false); got != -1 {
		t.Fatalf("permScan = %d, want -1", got)
	}
	if n := countSizeJobs(fj); n != 1 {
		t.Fatalf("%d walks, want 1 — the second root had no allowance to walk with", n)
	}
}
