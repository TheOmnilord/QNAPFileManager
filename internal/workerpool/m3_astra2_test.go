package workerpool

// Astra M3 round 2, finding 1, end to end: Props then Chmod, through a real
// worker, with the precondition built exactly the way internal/web's
// entryACLFacts builds it.
//
// Round 1 added the precondition and only the fake mutator's request was ever
// inspected, so nobody noticed that the route sent the LADDER'S GRADE where the
// worker re-proves an OBSERVATION. On a mount the daemon cannot place — every
// dev box, and any mount that appeared since the last probe — the grade is
// `unknown`, the worker re-probes and sees nothing, and a chmod the user had
// just confirmed came back `changed`. The whole trip is what proves it: the two
// round trips are the bug.

import (
	"context"
	"testing"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// observedExpectation is the route's rule (internal/web/routes_perm.go,
// entryACLFacts): the state the worker reported, never the state the ladder
// graded on, plus the identity of the object it was read from — zero included,
// because off Linux there is no inode to report and inventing one proves
// nothing.
func observedExpectation(resp wproto.PropsResp) *wproto.ACLExpect {
	state := resp.ACL.State
	if state == "" {
		state = resp.Entry.ACL
	}
	return &wproto.ACLExpect{State: state, Identity: resp.Identity}
}

func TestPropsThenChmodWithTheObservedPrecondition(t *testing.T) {
	p, _ := m3Pool(t)
	var b backend.Backend = p
	ctx := context.Background()
	const path = "/share/tree/one.txt"

	props, err := b.Props(ctx, alice(), wproto.PropsReq{Path: []byte(path)})
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	expect := observedExpectation(props)

	resp, err := p.Chmod(ctx, alice(), wproto.ChmodReq{
		Path:   []byte(path),
		Spec:   perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
		Expect: expect,
	})
	if err != nil {
		t.Fatalf("a chmod carrying what Props reported (state %q, inode %d) was refused: %v",
			expect.State, expect.Identity.Ino, err)
	}
	if resp.Entry.Name != "one.txt" {
		t.Fatalf("entry = %+v", resp.Entry)
	}
}

// TestChmodWithNoObservedStateProvesTheIdentity: the empty state is the dev
// box's ordinary answer and it is not a claim that the object has no ACL — it
// means "nothing was observed, prove the identity only". It must not be turned
// into `unknown` anywhere along the way, because nothing ever reports that.
func TestChmodWithNoObservedStateProvesTheIdentity(t *testing.T) {
	p, _ := m3Pool(t)
	ctx := context.Background()
	const path = "/share/tree/sub/two.txt"

	props, err := p.Props(ctx, alice(), wproto.PropsReq{Path: []byte(path)})
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if _, err := p.Chmod(ctx, alice(), wproto.ChmodReq{
		Path:   []byte(path),
		Spec:   perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Expect: &wproto.ACLExpect{Identity: props.Identity},
	}); err != nil {
		t.Fatalf("an expectation with no state was refused: %v", err)
	}
}
