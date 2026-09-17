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

// The route half of the gpt-6-astra M3 round-4 review (docs/reviews/
// m3-astra-round4.md): findings 1, 4 and 5, which are three ways of reaching the
// same hole. Round 3 taught entryACLFacts to distrust a worker that names another
// mount; what it did NOT do is distrust the daemon's own row when that happens,
// and it checked the agreement against a fact (the descriptor's mount id) that
// travels separately from the fact it was protecting (the worker's cached
// aclmode). Each of the three shapes below ends with a chmod that destroys an
// NFSv4 ACL behind a dialog that promised it would survive.

// mismatchTable is the daemon's table for the reverse-staleness cases: a plain
// hero pool with NO row for the child dataset the worker can already see. The
// child is what the daemon's next refresh will add; until it does, every lookup
// for a path inside it lands on the passthrough parent.
const passthroughParentAPI = "/share/ZFS530_DATA/Public"

// TestAFresherWorkerMountIsGradedPessimisticallyToo is round-4 finding 1, the
// reverse of round 3's direction. The worker's platform refreshed first, so IT
// holds the row for the newly mounted `zpool1/new` (aclmode=discard) while the
// daemon still places the path on `Public` (aclmode=passthrough). Round 3 threw
// the worker's real reading away as "elsewhere" and kept the daemon's stale one,
// which graded L1 and promised that the other entries survive — and the worker's
// unchanged re-reading then satisfied the precondition, so the chmod went through.
func TestAFresherWorkerMountIsGradedPessimisticallyToo(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "passthrough")
	const p = passthroughParentAPI + "/new/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI + "/new", Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4,
		Aclmode: "discard",
		Dataset: "zpool1/new",
	}

	facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.aclmode != "" {
		t.Fatalf("aclmode %q: the daemon's contradicted row was kept as if it were still true", facts.aclmode)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want the L2 discard rung: %q", grade, discards, notice)
	}
	if !strings.Contains(notice, "could not be read") {
		t.Fatalf("an aclmode nobody can state must say so: %q", notice)
	}
	// Both candidates are named: the sentence may not reassure the user about a
	// dataset the change may well not land on.
	for _, want := range []string{"zpool1/zfs530_data/Public", "zpool1/new"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("the L2 sentence must name both candidate datasets (%q missing): %q", want, notice)
		}
	}
	// The observation still travels exactly as the worker reported it (round-2 #1).
	if expect == nil || expect.State != fsx.ACLNFS4 {
		t.Fatalf("precondition %+v, want the observed state", expect)
	}

	// And end to end: the typed phrase, not the passthrough reassurance.
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

// TestTheRoundThreeDirectionIsStillGradedPessimistically: the forward case from
// round 3 — the DAEMON holds the newer row — must still be L2. The rule is
// symmetric now, so the grade has to come out the same way from either end.
func TestTheRoundThreeDirectionIsStillGradedPessimistically(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = passthroughParentAPI + "/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: "/share", Domain: "dev:0:23"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4Trivial,
		Aclmode: "passthrough",
		Dataset: "zpool1/somewhere_else",
	}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.state != fsx.ACLUnknown {
		t.Fatalf("state %q: a reading taken on another mount was graded as this object's", facts.state)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2 in this direction as well: %q", grade, discards, notice)
	}
}

// TestAgreementOnAProbedRowStillAcceptsTheWorkersReading is the behaviour the
// pessimism may not cost. When the two sides agree about the mount and the
// daemon has probed it, the worker's per-object state is believed — a trivial
// NFSv4 ACL is nothing the mode does not already describe, and the chmod stays
// ordinary.
func TestAgreementOnAProbedRowStillAcceptsTheWorkersReading(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = passthroughParentAPI + "/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI, Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4Trivial,
		Aclmode: "discard",
		Dataset: "zpool1/zfs530_data/Public",
	}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.state != fsx.ACLNFS4Trivial || facts.unknown || facts.altDataset != "" {
		t.Fatalf("facts %+v, want the worker's reading on the row it agrees about", facts)
	}
	if grade, _, discards := chmodACLNotice(facts); grade != gradeNone || discards {
		t.Fatalf("grade %d discards %v, want no rung for a trivial ACL", grade, discards)
	}
}

// TestASubstitutedDatasetCannotSoftenTheGrade is round-4 finding 4. The identity
// the agreement check believes comes from the inode the worker has just opened;
// the aclmode that arrives beside it comes from the worker's CACHED row. Unmount
// `Public` (discard), mount another dataset at the same point (passthrough in the
// worker's cache), refresh the daemon and not the worker: same mount point, same
// domain, a mount id read from the live inode — the check passes, and the cached
// passthrough replaced the daemon's discard. The worker's aclmode may never
// soften the grade, agreement or not.
func TestASubstitutedDatasetCannotSoftenTheGrade(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = passthroughParentAPI + "/file.txt"
	mkAPIFile(t, b, p, "x")
	// Everything the agreement check compares matches; only the cached half is old.
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: passthroughParentAPI, Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4,
		Aclmode: "passthrough",
		Dataset: "zpool1/zfs530_data/Public_old",
	}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.aclmode == "passthrough" {
		t.Fatalf("facts %+v: a cached aclmode softened the daemon's discard row", facts)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2: %q", grade, discards, notice)
	}
	if !strings.Contains(notice, "zpool1/zfs530_data/Public_old") {
		t.Fatalf("the second candidate dataset must be named too: %q", notice)
	}
}

// TestADemonstratedMismatchRaisesTheFloorOverAPosixRow is round-4 finding 5. The
// daemon's row is a probed POSIX one — the cached parent — and an NFSv4 dataset
// under aclmode=discard has been mounted beneath it. The worker is stale in the
// same way, so its POSIX probe answers `none` twice: once for the grade and once
// for the precondition. Nothing but the mount identification betrays the
// mismatch, and it has to raise the floor by itself — on this injected table that
// is the mount point, on a live one the descriptor's mount id as well — whatever
// backend the stale row carries.
func TestADemonstratedMismatchRaisesTheFloorOverAPosixRow(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatformPerDataset(t,
		func(string) string { return platform.ACLPosix },
		func(string) string { return "passthrough" })
	const p = "/share/CACHEDEV1_DATA/Public/new/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "ext4", Mount: "/share/CACHEDEV1_DATA/Public/new", Domain: "dev:0:33"}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLPosix, State: fsx.ACLNone}

	facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if !facts.unknown {
		t.Fatalf("facts %+v: a demonstrated mismatch left the path graded on the stale row", facts)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2 over a mismatch on a posix row: %q", grade, discards, notice)
	}
	if !strings.Contains(notice, "could not be read") {
		t.Fatalf("the unknown-aclmode suffix must be there: %q", notice)
	}
	if expect == nil || expect.State != fsx.ACLNone {
		t.Fatalf("precondition %+v, want the observed state carried anyway", expect)
	}
}

// TestWorstAclmodeIsTheTableItself states the fold once, away from the fixtures:
// "discard" and "not read" are the two that destroy, and either of them on either
// side wins. Everything else keeps the other entries and grades L1, so two such
// answers leave the daemon's row alone.
func TestWorstAclmodeIsTheTableItself(t *testing.T) {
	for _, tc := range []struct {
		daemon, worker, want string
	}{
		{"passthrough", "discard", ""},
		{"discard", "passthrough", ""},
		{"passthrough", "", ""},
		{"", "passthrough", ""},
		{"discard", "discard", ""},
		{"passthrough", "restricted", "passthrough"},
		{"restricted", "groupmask", "restricted"},
		{"groupmask", "groupmask", "groupmask"},
	} {
		if got := worstAclmode(tc.daemon, tc.worker); got != tc.want {
			t.Fatalf("worstAclmode(%q, %q) = %q, want %q", tc.daemon, tc.worker, got, tc.want)
		}
	}
}
