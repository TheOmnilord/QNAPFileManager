package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The route half of the gpt-6-astra M3 round-1 review (docs/reviews/
// m3-astra-round1.md): findings 1, 2, 4, 5, 6, 9, 10 and 11. Each of them is a
// decision the ROUTE makes before the kernel is involved, which is the half of
// M3 that is testable on a dev box at all (contract §14), so each gets a test
// that fails against the reviewed commit.

// unprobedHero is the golden hero mount table as it looks the moment a dataset
// appears: parsed, so the mount is known and its FSCaps say Storage, but never
// probed — so ACLBackend is "". That is exactly the state Platform.Refresh used
// to leave a NEW mount in, and it is the state the ladder has to read
// pessimistically (finding 1).
func unprobedHero(t *testing.T) *platform.Platform {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "platform", "testdata", "hero_mountinfo.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := platform.FromMountinfo(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// --- finding 1: an unprobed storage mount is not a mount without ACLs ---------

// TestUnprobedStorageMountIsGradedPessimistically is the table half of finding
// 1. A dataset mounted after the daemon probed answers ACLBackend "", and an
// empty backend used to fall out of the switch as "no warning at all" — on a
// pool whose aclmode is discard, that is silence in front of the one change
// that destroys an ACL irrecoverably.
func TestUnprobedStorageMountIsGradedPessimistically(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts aclFacts
		want  int
	}{
		{"unprobed storage mount", aclFacts{storage: true, state: fsx.ACLUnknown}, gradeTyped},
		{"a path the table cannot place", aclFacts{unknown: true, state: fsx.ACLUnknown}, gradeTyped},
		{"unprobed, but the object has no ACL", aclFacts{storage: true, state: fsx.ACLNone}, gradeNone},
		{"unprobed and trivial", aclFacts{storage: true, state: fsx.ACLNFS4Trivial}, gradeNone},
		{"not storage at all", aclFacts{state: fsx.ACLUnknown}, gradeNone},
		{"probed and answered none", aclFacts{storage: true, backend: platform.ACLNone, state: fsx.ACLUnknown}, gradeNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grade, notice, discards := chmodACLNotice(tc.facts)
			if grade != tc.want {
				t.Fatalf("grade %d, want %d (notice %q)", grade, tc.want, notice)
			}
			if tc.want != gradeTyped {
				return
			}
			if !discards {
				t.Fatal("a pessimistic L2 is a discard: it is what makes the change a milestone")
			}
			if !strings.Contains(notice, "DESTROY") || !strings.Contains(notice, "could not be read") {
				t.Fatalf("the L2 sentence must say what is destroyed and that the aclmode is unknown: %q", notice)
			}
		})
	}
}

// TestJobOverAnUnprobedDatasetDemandsTheTypedPhrase drives the same finding
// through the route, with the real mount table in the state a fresh mount
// leaves it in.
func TestJobOverAnUnprobedDatasetDemandsTheTypedPhrase(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = unprobedHero(t)
	const root = "/share/ZFS530_DATA/Public"
	mkAPIDir(t, b, root)
	c, csrf := sessionCookie(t, s)
	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
		`{"paths":[{"path":"`+root+`"}],"files":{"mask":511,"value":493},"recursive":true}`))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
	joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, "DESTROY") || !strings.Contains(joined, "could not be read") {
		t.Fatalf("warnings %q", joined)
	}
}

// --- finding 2: the mount lookup is literal --------------------------------------

// TestMountFactsUseTheLiteralLookup is finding 2. Platform.For normalises before
// it matches: a backslash becomes a separator and the result is Cleaned. On
// Linux a backslash is an ordinary character in a filename, so a file called
// `danger\..\..\Media` inside the Public dataset was graded on the MEDIA
// dataset — passthrough, "other entries are kept" — while the chmod changed an
// inode on Public, where aclmode is discard.
//
// The dev box keeps the lenient key on purpose (mountkey_other.go: the tables
// here are synthetic and the paths are Windows spellings), so the assertion is
// about the kernel's rule and runs where that rule applies.
func TestMountFactsUseTheLiteralLookup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("literalMountKey is byte-exact only on Linux, where a backslash is a filename character")
	}
	s, _, _ := permFixture(t)
	s.platform = heroPlatformPerDataset(t, nil, func(dataset string) string {
		if dataset == "zpool1/zfs530_data/Public" {
			return "discard"
		}
		return "passthrough"
	})
	const literal = `/share/ZFS530_DATA/Public/danger\..\..\Media`
	facts := s.mountFacts(literal)
	if facts.dataset != "zpool1/zfs530_data/Public" {
		t.Fatalf("dataset %q: the name was re-graded onto a sibling mount", facts.dataset)
	}
	if facts.aclmode != "discard" {
		t.Fatalf("aclmode %q, want the dataset the bytes are on", facts.aclmode)
	}
	facts.state = fsx.ACLNFS4
	if grade, _, _ := chmodACLNotice(facts); grade != gradeTyped {
		t.Fatalf("grade %d: a discard dataset reached through a backslash name is still a discard dataset", grade)
	}
}

// --- finding 4: the chmod carries the precondition it was graded on --------------

// TestChmodSendsTheGradedPrecondition: Props probes the ACL by pathname in a
// round trip of its own, and the chmod is a second one. Between them the name
// can be re-pointed at a different object, and the ACL the user was warned about
// is then not the ACL that is destroyed. What was graded travels with the
// change, and the worker refuses `changed` when it has moved.
func TestChmodSendsTheGradedPrecondition(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.aclState = map[string]string{p: fsx.ACLNFS4}
	b.propsIdentity = wproto.FSIdentityResp{Dev: 66305, Ino: 4242, HasBtime: true, Btime: 1758000000000000000}
	c, csrf := sessionCookie(t, s)
	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)))
	if resp := post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":%q,"mask":511,"value":493,"confirm":%q}`, p, env.Confirm.Token)); resp.StatusCode != 200 {
		t.Fatalf("confirmed chmod %d: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d", len(b.chmodReqs))
	}
	expect := b.chmodReqs[0].Expect
	if expect == nil {
		t.Fatal("the chmod carried no precondition: the ladder's grade would be unenforceable")
	}
	if expect.State != fsx.ACLNFS4 {
		t.Fatalf("expected state %q, want the state the ladder graded", expect.State)
	}
	if expect.Identity.Dev != 66305 || expect.Identity.Ino != 4242 {
		t.Fatalf("expected identity %+v, want the object Props described", expect.Identity)
	}
}

// TestChmodSendsNoPreconditionWhenNothingWasLearned: a precondition built from a
// probe that failed would refuse every change rather than the changed ones, so
// there is none — the route promises only what it knows.
func TestChmodSendsNoPreconditionWhenNothingWasLearned(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	b.propsErr = fsx.ErrUnsupported
	c, csrf := sessionCookie(t, s)
	if resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":511,"value":493}`); resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 || b.chmodReqs[0].Expect != nil {
		t.Fatalf("precondition %+v, want none", b.chmodReqs[0].Expect)
	}
}

// TestChmodPreconditionRefusalIsChanged: the worker's answer when the object or
// its ACL state moved is the existing `changed` code, surfaced unchanged — 409,
// and the client re-asks with a fresh grade.
func TestChmodPreconditionRefusalIsChanged(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	b.chmodErr = fsx.ErrChanged
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":511,"value":493}`)
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, readBody(resp))
	}
	if body := readBody(resp); !strings.Contains(body, `"code":"changed"`) {
		t.Fatalf("body %s", body)
	}
}

// --- finding 5: the worker's backend never downgrades the daemon's ---------------

// TestWorkerBackendNeverDowngrades: a worker runs AS THE USER, and a user who
// cannot read the dataset root's attribute gets "none" out of its own detection.
// Letting that overwrite a known nfs4 deleted the discard warning for exactly
// the sessions least able to check for themselves.
func TestWorkerBackendNeverDowngrades(t *testing.T) {
	const p = "/share/ZFS530_DATA/Public/file.txt"
	for _, tc := range []struct {
		name         string
		worker       wproto.ACLInfo
		wantBackend  string
		wantState    string
		wantExpect   string
		wantDiscards bool
	}{
		{
			name:        "a worker none is ignored and the state stays unknown",
			worker:      wproto.ACLInfo{Backend: platform.ACLNone, State: fsx.ACLNone},
			wantBackend: platform.ACLNFS4,
			wantState:   fsx.ACLUnknown,
			// Discarded for GRADING, still what the worker will see when it
			// re-probes (Astra r2 #1): expecting the pessimistic grade here made
			// the worker refuse `changed` on an object that never moved.
			wantExpect:   fsx.ACLNone,
			wantDiscards: true,
		},
		{
			name:        "a worker that says nothing leaves both halves alone",
			worker:      wproto.ACLInfo{State: fsx.ACLNFS4Trivial},
			wantBackend: platform.ACLNFS4,
			wantState:   fsx.ACLNFS4Trivial,
			wantExpect:  fsx.ACLNFS4Trivial,
		},
		{
			name:         "a worker that agrees is believed",
			worker:       wproto.ACLInfo{Backend: platform.ACLNFS4, State: fsx.ACLNFS4},
			wantBackend:  platform.ACLNFS4,
			wantState:    fsx.ACLNFS4,
			wantExpect:   fsx.ACLNFS4,
			wantDiscards: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b, _ := permFixture(t)
			s.platform = heroPlatform(t, "discard")
			mkAPIFile(t, b, p, "x")
			b.propsACL = tc.worker
			facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
			if facts.backend != tc.wantBackend {
				t.Fatalf("backend %q, want %q", facts.backend, tc.wantBackend)
			}
			if facts.state != tc.wantState {
				t.Fatalf("state %q, want %q", facts.state, tc.wantState)
			}
			if expect == nil || expect.State != tc.wantExpect {
				t.Fatalf("the precondition must carry the state the worker OBSERVED (%q): %+v", tc.wantExpect, expect)
			}
			if _, _, discards := chmodACLNotice(facts); discards != tc.wantDiscards {
				t.Fatalf("discards %v, want %v", discards, tc.wantDiscards)
			}
		})
	}
	// The rank itself, stated once: "we did not look" is more pessimistic than
	// "there is nothing there", and both are less pessimistic than a backend a
	// chmod can destroy.
	if !(aclBackendRank(platform.ACLNFS4) > aclBackendRank(platform.ACLPosix) &&
		aclBackendRank(platform.ACLPosix) > aclBackendRank("") &&
		aclBackendRank("") > aclBackendRank(platform.ACLNone)) {
		t.Fatal("aclBackendRank is not nfs4 > posix > unprobed > none")
	}
}

// TestWorkerBackendMayUpgrade: the daemon's table can be the stale half — a
// mount it probed as posix that is now a dataset — and the worker holds the
// descriptor. An UPGRADE is taken, together with the state read on it.
func TestWorkerBackendMayUpgrade(t *testing.T) {
	s, b, _ := permFixture(t)
	const p = "/share/CACHEDEV1_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	s.platform = heroPlatformPerDataset(t, func(string) string { return platform.ACLPosix }, func(string) string { return "" })
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNFS4, State: fsx.ACLNFS4, Aclmode: "discard", Dataset: "zpool1/late"}
	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.backend != platform.ACLNFS4 || facts.state != fsx.ACLNFS4 {
		t.Fatalf("facts %+v, want the worker's more pessimistic reading", facts)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards || !strings.Contains(notice, "zpool1/late") {
		t.Fatalf("grade %d discards %v notice %q", grade, discards, notice)
	}
}

// --- finding 6: a recursive job is checked for what it CONTAINS ------------------

// TestRecursiveJobRefusesAnAncestorOfTheInstallation is the adversarial half of
// the review. The guard was checked on the roots alone, so a recursive chmod of
// /share/CACHEDEV1_DATA/.qpkg walked into this daemon's own configuration,
// credentials and audit trail — the very files that are refused outright when
// they are named. Containment is the static, INV-1-safe answer the transfer and
// upload routes already use.
func TestRecursiveJobRefusesAnAncestorOfTheInstallation(t *testing.T) {
	const ancestor = "/data/qpkg"
	const install = "/data/qpkg/QNAPFileManager"
	for _, route := range []string{"/api/jobs/chmod", "/api/jobs/chown"} {
		t.Run(route, func(t *testing.T) {
			s, b, fj := permFixture(t)
			s.guard = guard.New(install, false)
			mkAPIDir(t, b, install)
			c, csrf := sessionCookie(t, s)
			body := `{"paths":[{"path":"` + ancestor + `"}],"files":{"mask":511,"value":493},"recursive":true}`
			if route == "/api/jobs/chown" {
				body = `{"paths":[{"path":"` + ancestor + `"}],"uid":1003,"recursive":true}`
			}
			resp := post(s, route, c, csrf, body)
			if resp.StatusCode != 403 {
				t.Fatalf("status %d, want 403: %s", resp.StatusCode, readBody(resp))
			}
			if got := readBody(resp); !strings.Contains(got, `"code":"protected"`) {
				t.Fatalf("body %s", got)
			}
			if len(fj.requests()) != 0 {
				t.Fatal("nothing may be dispatched, not even a pre-scan")
			}
			// Naming the installation directly is refused the same way, which is
			// the equivalence the finding is about.
			direct := strings.Replace(body, ancestor, install, 1)
			if resp := post(s, route, c, csrf, direct); resp.StatusCode != 403 {
				t.Fatalf("naming it directly: %d %s", resp.StatusCode, readBody(resp))
			}
		})
	}
}

// TestNonRecursiveJobOverAnAncestorIsOrdinary: containment is about what the
// WALK reaches. A non-recursive change acts on the named entry alone, so it is
// not promoted — the refusal must not become a ban on touching any folder that
// happens to have something protected somewhere beneath it.
func TestNonRecursiveJobOverAnAncestorIsOrdinary(t *testing.T) {
	s, b, _ := permFixture(t)
	s.guard = guard.New("/data/qpkg/QNAPFileManager", false)
	mkAPIDir(t, b, "/data/qpkg/QNAPFileManager")
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/qpkg"}],"files":{"mask":511,"value":493}}`)
	if resp.StatusCode != 202 {
		t.Fatalf("status %d, want 202: %s", resp.StatusCode, readBody(resp))
	}
}

// --- finding 9: an uninspected POSIX ACL is not a harmless one -------------------

// TestPosixJobWarnsOnTheMask: a chmod JOB hands the ladder ACLUnknown, because
// it cannot probe a tree it has not walked. On a POSIX share that used to mean
// no rung at all, while the identical change through the sync route — which
// does probe — asked for the acknowledgement.
func TestPosixJobWarnsOnTheMask(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatformPerDataset(t, func(string) string { return platform.ACLPosix }, func(string) string { return "" })
	const root = "/share/ZFS530_DATA/Public"
	mkAPIDir(t, b, root)
	c, csrf := sessionCookie(t, s)
	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
		`{"paths":[{"path":"`+root+`"}],"files":{"mask":511,"value":493},"recursive":true}`))
	joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, aclPosixMaskNotice) {
		t.Fatalf("the mask notice is missing: %q", joined)
	}
	if env.Confirm.Grade < gradeConfirm {
		t.Fatalf("grade %d, want at least L1", env.Confirm.Grade)
	}
}

// --- finding 10: the pre-scan is admitted and bounded ----------------------------

// TestPermScanTakesAMetadataSlot: the pre-scan is a full tree walk with a job's
// cost and none of a job's limits. It now takes the same ClassMetadata slot the
// job it measures for will take, so a handful of unconfirmed POSTs cannot put an
// unbounded number of walks on a NAS that deliberately allows four.
func TestPermScanTakesAMetadataSlot(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1})
	s.Root = fsx.Root{}
	fj.result = wproto.JobResult{Files: 5}

	held, err := s.jobMgr.Admit(context.Background(), jobs.ClassMetadata)
	if err != nil {
		t.Fatal(err)
	}
	// The only slot is taken, so a scan whose budget runs out while it waits
	// measures nothing — and starts no walk.
	tight, cancel := context.WithTimeout(context.Background(), permScanReserve+300*time.Millisecond)
	defer cancel()
	if got := s.permScan(tight, backend.Principal{}, []string{"/data/tree"}, false); got != -1 {
		t.Fatalf("permScan = %d, want -1 while the pool is full", got)
	}
	if n := countSizeJobs(fj); n != 0 {
		t.Fatalf("%d walks started without a slot", n)
	}
	held()

	roomy, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	if got := s.permScan(roomy, backend.Principal{}, []string{"/data/tree"}, false); got != 5 {
		t.Fatalf("permScan = %d, want 5 once a slot is free", got)
	}
	// And the slot is given back: a second scan does not deadlock behind the
	// first one's release.
	if got := s.permScan(roomy, backend.Principal{}, []string{"/data/tree"}, false); got != 5 {
		t.Fatalf("permScan = %d on the second pass", got)
	}
}

// TestConcurrentPermScansAreBoundedByTheSlots: two scans, one slot, and the
// second one does not walk until the first has finished.
func TestConcurrentPermScansAreBoundedByTheSlots(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1})
	s.Root = fsx.Root{}
	fj.block = make(chan struct{})
	fj.started = make(chan struct{})
	fj.result = wproto.JobResult{Files: 5}

	var wg sync.WaitGroup
	wg.Add(2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			s.permScan(ctx, backend.Principal{}, []string{"/data/tree"}, false)
		}()
	}
	<-fj.started // the first scan is inside the worker call, holding the slot
	time.Sleep(50 * time.Millisecond)
	if n := countSizeJobs(fj); n != 1 {
		t.Fatalf("%d concurrent walks, want 1 — the slot is not bounding them", n)
	}
	close(fj.block)
	wg.Wait()
	if n := countSizeJobs(fj); n != 2 {
		t.Fatalf("the second scan never ran: %d walks", n)
	}
}

// TestPermScanBoundsTheWalkAndReadsCapped: the walk carries the contract's entry
// budget, and a walk that hit it is not a count — it is "unknown", which the
// ladder reads as large.
func TestPermScanBoundsTheWalkAndReadsCapped(t *testing.T) {
	s, _, fj := permFixture(t)
	fj.result = wproto.JobResult{Files: 500000, Dirs: 12, Capped: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if got := s.permScan(ctx, backend.Principal{}, []string{"/data/tree"}, false); got != -1 {
		t.Fatalf("permScan = %d, want -1 for a capped walk", got)
	}
	reqs := fj.requests()
	if len(reqs) != 1 {
		t.Fatalf("size jobs %d", len(reqs))
	}
	var sent wproto.SizeReq
	if err := json.Unmarshal(reqs[0].Body, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.MaxEntries != modeScanMaxEntries {
		t.Fatalf("MaxEntries %d, want %d", sent.MaxEntries, modeScanMaxEntries)
	}
}

// --- finding 11: a capped scan is an outcome the ledger keeps --------------------

// TestCappedScanIsRememberedAndNotRescanned. An unmeasurable recursion reported
// Files: 0, which the issued-cost ledger discarded as "nothing measured" — so
// the CONFIRMED re-post walked the tree again. That is the one walk guaranteed
// to fail twice: it is the tree whose walk had just proved too big to finish,
// inside a token with sixty seconds to live.
func TestCappedScanIsRememberedAndNotRescanned(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	fj.result = wproto.JobResult{Files: 500000, Capped: true}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true}`
	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2 for an unmeasurable recursion", env.Confirm.Grade)
	}
	if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " | "), "unknown number of items") {
		t.Fatalf("warnings %v", env.Confirm.Summary.Warnings)
	}
	// What the dialog is shown is unchanged: nothing was counted, so the count
	// is zero rather than a number nobody established.
	if env.Confirm.Summary.Files != 0 {
		t.Fatalf("summary files %d, want 0", env.Confirm.Summary.Files)
	}
	scans := countSizeJobs(fj)
	if scans == 0 {
		t.Fatal("the challenge must have tried to measure")
	}
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	if got := countSizeJobs(fj); got != scans {
		t.Fatalf("the redemption re-scanned the tree it could not measure: %d walks, want %d", got, scans)
	}
}

// TestCappedOutcomeSurvivesTheLedger is the guard-side half, stated where the
// ledger lives: a capped summary is remembered although its totals are zero, and
// peekScan hands it back as -1.
func TestCappedOutcomeSurvivesTheLedger(t *testing.T) {
	s, _, _ := permFixture(t)
	spec := perm.ModeSpec{Mask: 0o777, Value: 0o755}
	parts := permTokenParts(tokenKindJob, "chmod", spec, perm.ModeSpec{}, -1, -1, true, false, aclVerdict{}, []string{"/data/tree"})
	token, _ := s.guard.Issue("chmod", guard.Summary{Files: 0, Capped: true}, parts, true)
	got, ok := s.peekScan(token, "chmod", parts)
	if !ok || got != -1 {
		t.Fatalf("peekScan = %d, %v — a capped outcome must come back as unknown", got, ok)
	}
	// A summary that measured nothing and was not capped is still not worth
	// remembering: the re-post measures again.
	empty, _ := s.guard.Issue("chmod", guard.Summary{}, parts, true)
	if _, ok := s.peekScan(empty, "chmod", parts); ok {
		t.Fatal("an unrecorded cost must read as measure-it-yourself")
	}
}
