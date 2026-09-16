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

// The route half of the gpt-6-astra M3 round-3 review (docs/reviews/
// m3-astra-round3.md): finding 8. The daemon's refresh is asynchronous by design
// (round-2 #7), so for a few seconds after a dataset is mounted the daemon has a
// row for it with an EMPTY backend while a worker that started earlier still
// answers out of the enclosing share. The worker then probes the new inode for
// the POSIX attribute — the question its share's backend calls for — gets
// ENOTSUP, and reports `posix` with state `none`. That outranks "not probed", so
// the L2 floor over an unlooked-at storage mount disappeared; and because the
// worker's re-probe gives the same wrong answer, the precondition matched and the
// chmod went through on a dataset whose ACLs it may have destroyed.

// unprobedTable is a mount table the daemon has PARSED and not yet probed, which
// is the state every newly appeared storage mount is in until the background pass
// reaches it.
func unprobedTable(t *testing.T, lines string) *platform.Platform {
	t.Helper()
	p, err := platform.FromMountinfo(strings.NewReader(lines))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const newDatasetTable = "25 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n" +
	"30 25 8:3 / /share rw,relatime - ext4 /dev/sda3 rw\n" +
	"70 30 0:70 / /share/pool/new rw,relatime - zfs zpool1/new rw\n"

// TestAnUnprobedMountKeepsItsFloorAgainstAWorkerOnAnotherMount is the finding.
// The daemon has the new dataset and has not probed it; the worker is still on
// /share and says posix/none. The floor is the whole warning for a mount nobody
// has looked at, and a reading from a different filesystem may not take it away.
func TestAnUnprobedMountKeepsItsFloorAgainstAWorkerOnAnotherMount(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = unprobedTable(t, newDatasetTable)
	const p = "/share/pool/new/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "ext4", Mount: "/share", Domain: "dev:8:3"}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLPosix, State: fsx.ACLNone}

	facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.backend != "" {
		t.Fatalf("backend %q: the worker's answer for the enclosing share was folded onto the dataset", facts.backend)
	}
	if facts.state != fsx.ACLUnknown {
		t.Fatalf("state %q, want unknown: nothing has read this object's ACL on the filesystem it is on", facts.state)
	}
	grade, notice, discards := chmodACLNotice(facts)
	if grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want the L2 floor over an unprobed storage mount: %q", grade, discards, notice)
	}
	// The observation still travels: the worker will see exactly what it saw, and
	// expecting anything else refuses a chmod for an object that never moved
	// (round-2 #1).
	if expect == nil || expect.State != fsx.ACLNone {
		t.Fatalf("precondition %+v, want the observed state", expect)
	}

	// And end to end: the dialog is the typed one, not a silent chmod.
	c, csrf := sessionCookie(t, s)
	body := fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)
	env := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, body))
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
	}
}

// TestAnUnprobedMountKeepsItsFloorEvenWhenTheMountMatches: the floor is up
// because nobody has probed the row, and a row nobody has probed is a row the
// worker's claim cannot be checked against. Naming the same mount point is not
// itself evidence about the backend — the daemon's own probe is what lifts this,
// a few seconds later, and until then the pessimistic reading stands.
func TestAnUnprobedMountKeepsItsFloorEvenWhenTheMountMatches(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = unprobedTable(t, newDatasetTable)
	const p = "/share/pool/new/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: "/share/pool/new", Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLPosix, State: fsx.ACLNone}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.backend != "" || facts.state != fsx.ACLUnknown {
		t.Fatalf("facts %+v, want the daemon's unprobed row kept", facts)
	}
	if grade, _, discards := chmodACLNotice(facts); grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want L2", grade, discards)
	}
}

// TestWorkerFactsAreTakenWhenTheMountMatches is the other side: on a row the
// daemon HAS probed, a worker that is demonstrably on that mount is believed, and
// its per-object reading is what the grade uses. A trivial NFSv4 ACL is nothing
// the mode does not already describe, so the chmod is ordinary — which is the
// behaviour the mismatch rule must not cost.
func TestWorkerFactsAreTakenWhenTheMountMatches(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: "/share/ZFS530_DATA/Public", Domain: "zfs:zpool1"}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNFS4, State: fsx.ACLNFS4Trivial}

	facts, _ := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.backend != platform.ACLNFS4 || facts.state != fsx.ACLNFS4Trivial {
		t.Fatalf("facts %+v, want the worker's reading on the mount it agrees about", facts)
	}
	if grade, _, discards := chmodACLNotice(facts); grade != gradeNone || discards {
		t.Fatalf("grade %d discards %v, want no rung for a trivial ACL", grade, discards)
	}
}

// TestWorkerFactsFromAnotherMountAreNotFoldedIn: the same worker answer, reported
// for the enclosing share instead. A probed daemon row is not overwritten by a
// reading of a different filesystem — neither the state nor the aclmode, which
// between them are the difference between "this is fine" and "this DESTROYS the
// ACL".
func TestWorkerFactsFromAnotherMountAreNotFoldedIn(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: "/share", Domain: "dev:0:23"}
	b.propsACL = wproto.ACLInfo{
		Backend: platform.ACLNFS4,
		State:   fsx.ACLNFS4Trivial,
		Aclmode: "passthrough",
		Dataset: "zpool1/somewhere_else",
	}

	facts, expect := s.entryACLFacts(context.Background(), backend.Principal{}, p)
	if facts.state != fsx.ACLUnknown {
		t.Fatalf("state %q: a reading taken on another mount was graded as this object's", facts.state)
	}
	if facts.aclmode != "discard" || facts.dataset == "zpool1/somewhere_else" {
		t.Fatalf("facts %+v, want the daemon's own row for this dataset", facts)
	}
	if grade, _, discards := chmodACLNotice(facts); grade != gradeTyped || !discards {
		t.Fatalf("grade %d discards %v, want the discard warning kept", grade, discards)
	}
	if expect == nil || expect.State != fsx.ACLNFS4Trivial {
		t.Fatalf("precondition %+v, want the state the worker reported", expect)
	}
}
