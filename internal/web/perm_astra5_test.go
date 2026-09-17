package web

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The route half of the gpt-6-astra M3 round-5 review (docs/reviews/
// m3-astra-round5.md): findings 1 and 5, plus the route's end of finding 2. All
// three are the same mistake in three places — a fact that two caches happen to
// agree on is not thereby a fact about the filesystem the chmod will land on.

// TestAMismatchIsTheDestructiveRungEvenWhenBothCachesAgree is round-5 finding 1.
// Round 4 made a demonstrated mount mismatch set `unknown`, which moves the grade
// onto §7's nfs4/unknown branch — but that branch still reads the aclmode, and
// when BOTH tables say `passthrough` there is nothing for worstAclmode to
// disagree about. The dialog was then the L1 sentence that ends "Other entries are
// kept", for a change landing on a mount neither table describes. The mismatch
// itself has to discard the aclmode.
func TestAMismatchIsTheDestructiveRungEvenWhenBothCachesAgree(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "passthrough")
	const p = passthroughParentAPI + "/new/file.txt"
	mkAPIFile(t, b, p, "x")
	// The worker's descriptor is on a dataset mounted since the daemon's last
	// refresh; its own cached row for that dataset says passthrough too.
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI + "/new", Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4,
		Aclmode: "passthrough",
		Dataset: "zpool1/new",
	}

	facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if !facts.unknown {
		t.Fatalf("facts %+v: the mismatch itself was not registered", facts)
	}
	if facts.aclmode != "" {
		t.Fatalf("aclmode %q: two agreeing caches described a mount neither of them is about", facts.aclmode)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want the L2 discard rung: %q", grade, discards, notice)
	}
	if !strings.Contains(notice, "could not be read") {
		t.Fatalf("the unknown-aclmode suffix must say why: %q", notice)
	}
	for _, want := range []string{"zpool1/zfs530_data/Public", "zpool1/new"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("the L2 sentence must name both candidate datasets (%q missing): %q", want, notice)
		}
	}
	// The observation still travels untouched — grading pessimistically and
	// expecting pessimistically stay two different things (round-2 #1).
	if expect == nil || expect.State != fsx.ACLNFS4 {
		t.Fatalf("precondition %+v, want the observed state", expect)
	}

	// End to end: the typed phrase, and not one word promising the ACL survives.
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)
	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	for _, w := range env.Confirm.Summary.Warnings {
		if strings.Contains(w, "Other entries are kept") {
			t.Fatalf("the dialog promised the other entries survive: %q", w)
		}
	}
}

// TestTwoKnownModesThatDisagreeAreUnknown is round-5 finding 5. The two sides
// agree about the mount here — nothing is stale about the identity — but the
// daemon's cached `passthrough` meets a worker that refreshed after `zfs set
// aclmode=groupmask`. Both modes grade L1, and round 4 read that as "nothing to
// fold, keep the daemon's": the dialog then promised that named entries are kept
// while the kernel was about to reduce them to the mode's group bits. Two L1
// sentences are not interchangeable, and neither cache is the proved one.
func TestTwoKnownModesThatDisagreeAreUnknown(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "passthrough")
	const p = passthroughParentAPI + "/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI, Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4,
		Aclmode: "groupmask",
		Dataset: "zpool1/zfs530_data/Public",
	}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.aclmode != "" {
		t.Fatalf("aclmode %q: one of two contradicting modes was stated as the answer", facts.aclmode)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2 while the mode is in dispute: %q", grade, discards, notice)
	}
	if strings.Contains(notice, "Other entries are kept") || strings.Contains(notice, "group bits") {
		t.Fatalf("a disputed mode may not be described as either of the two: %q", notice)
	}

	// And the agreeing case is untouched: the same mode on both sides is the mode
	// the ladder states, which is every ordinary lookup on a healthy table.
	b.propsACL.Aclmode = "passthrough"
	agreed, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if agreed.aclmode != "passthrough" {
		t.Fatalf("aclmode %q: two identical answers are not a disagreement", agreed.aclmode)
	}
	if grade, _, discards := chmodACLNotice(agreed); grade != gradeConfirm || discards {
		t.Fatalf("grade %d discards %v, want the L1 passthrough notice when the two sides say the same thing", grade, discards)
	}
}

// TestAnAclmodeTheTableWillNotStateGradesL2 is the route's end of round-5 finding
// 2. The platform now MASKS a probed aclmode that has passed its freshness bound,
// so a lookup answers "" — unknown — until the re-probe publishes, instead of
// handing out the fact it has just declared too old to trust. What the route has
// to do with that answer is what it does with every unreadable aclmode: the L2
// typed phrase with the suffix that says it could not be read.
//
// The masking itself is proved on the platform's own seams, where a pass can be
// held in the gate and a cached answer aged (probe_freshness_astra5_test.go);
// here the table is simply one whose `zfs get` never answers, which is the same
// shape arriving from the other direction.
func TestAnAclmodeTheTableWillNotStateGradesL2(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "")
	const p = passthroughParentAPI + "/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI, Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNFS4, State: fsx.ACLNFS4, Dataset: "zpool1/zfs530_data/Public"}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.aclmode != "" || facts.backend != platform.ACLNFS4 {
		t.Fatalf("facts %+v, want the backend kept and the aclmode unstated", facts)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2: %q", grade, discards, notice)
	}
	if !strings.Contains(notice, "could not be read") {
		t.Fatalf("the suffix must say the aclmode is the thing nobody could state: %q", notice)
	}
}
