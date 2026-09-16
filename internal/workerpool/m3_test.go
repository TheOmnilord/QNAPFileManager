package workerpool

// M3 through a worker: the three plain ops and the two job kinds, each making
// the whole trip the NAS makes — the pool encodes the request, the worker
// decodes it, fsops does the syscall, and the reply comes back through the
// frame codec. What is under test here is the plumbing, not the kernel: the
// permission semantics live in internal/fsops's Linux tests and in the CI root
// job (INV-2).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// m3Pool is testPool over a tree deep enough for a recursive job: the engine
// refuses a recursive root at depth 1, so "/dir" — testTree's own — would be
// refused for a reason that has nothing to do with what these tests are about.
func m3Pool(t *testing.T) (*Pool, string) {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	if err := os.MkdirAll(filepath.Join(base, "share", "tree", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"share/tree/one.txt", "share/tree/sub/two.txt"} {
		if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(rel)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := testPool(t, func(o *Options) { o.Root = r })
	return p, base
}

func jobBodyOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestChmodRoundTripsThroughAWorker: the spec goes over as a mask and a value,
// and what comes back is the pre-call entry, the post-call entry and the diff
// between what was asked and what the kernel did.
func TestChmodRoundTripsThroughAWorker(t *testing.T) {
	p, _ := m3Pool(t)
	ctx := context.Background()

	resp, err := p.Chmod(ctx, alice(), wproto.ChmodReq{
		Path: []byte("/share/tree/one.txt"),
		Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
	})
	if err != nil {
		t.Fatalf("Chmod = %v", err)
	}
	if resp.Before.Name != "one.txt" || resp.Entry.Name != "one.txt" {
		t.Fatalf("before/after = %q/%q", resp.Before.Name, resp.Entry.Name)
	}
	if len(resp.Before.Mode) != 4 || len(resp.Entry.Mode) != 4 {
		t.Fatalf("modes did not survive the wire: %q -> %q", resp.Before.Mode, resp.Entry.Mode)
	}
	// The Windows dev box stores almost none of a Unix mode (§14), so the exact
	// bits are the Linux jobs' assertion. What must hold everywhere is that the
	// worker reported a BEFORE at all — it is the only side that could — and
	// that the diff is consistent with the two entries it sent.
	wantMode := perm.ModeSpec{Mask: 0o7777, Value: 0o0640}.Apply(perm.EntryMode(resp.Before))
	hasModeDiff := false
	for _, d := range resp.Diffs {
		if d.Field == perm.FieldMode {
			hasModeDiff = true
		}
	}
	if got := perm.EntryMode(resp.Entry); (got != wantMode) != hasModeDiff {
		t.Fatalf("the diff disagrees with the entries: want %s, got %s, diffs %+v",
			perm.Octal(wantMode), perm.Octal(got), resp.Diffs)
	}
}

// TestChmodOfASymlinkIsUnsupportedThroughTheWorker: the refusal survives the
// wire as "unsupported" rather than arriving as a 500 (the code-coverage rule
// in action).
func TestChmodOfASymlinkIsUnsupportedThroughTheWorker(t *testing.T) {
	p, base := m3Pool(t)
	if err := os.Symlink(filepath.Join(base, "share", "tree", "one.txt"),
		filepath.Join(base, "share", "tree", "link")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	_, err := p.Chmod(context.Background(), alice(), wproto.ChmodReq{
		Path: []byte("/share/tree/link"),
		Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
	})
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("Chmod of a symlink = %v, want unsupported", err)
	}
}

// TestChownFollowIsRefused is §1.4 at the worker's own door: there is exactly
// one chown semantics in M3, and the flag that would have introduced a second
// is answered rather than implemented.
func TestChownFollowIsRefused(t *testing.T) {
	p, _ := m3Pool(t)
	_, err := p.Chown(context.Background(), alice(), wproto.ChownReq{
		Path: []byte("/share/tree/one.txt"), UID: -1, GID: -1, Follow: true,
	})
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("Chown with follow = %v, want unsupported", err)
	}
}

// TestPropsRoundTripsThroughAWorker: one canonical walk inside the worker, and
// the whole answer in one reply.
func TestPropsRoundTripsThroughAWorker(t *testing.T) {
	p, _ := m3Pool(t)
	var b backend.Backend = p

	resp, err := b.Props(context.Background(), alice(), wproto.PropsReq{Path: []byte("/share/tree/one.txt")})
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if resp.Entry.Name != "one.txt" || resp.Entry.Type != "file" || resp.Entry.Size != 1 {
		t.Fatalf("entry = %+v", resp.Entry)
	}
	if resp.Target != nil {
		t.Fatalf("a plain file has no target: %+v", resp.Target)
	}
	// The backend is one of the table's words. "" is among them since Astra
	// round 1 (#2, #5): it means the literal mount lookup could not place the
	// path — the dev box's empty mount table, here — and the ROUTE grades that
	// pessimistically; the worker no longer promotes "could not tell" to none.
	switch resp.ACL.Backend {
	case "", platform.ACLNone, platform.ACLPosix, platform.ACLNFS4:
	default:
		t.Fatalf("ACLInfo.Backend = %q, not a word of the platform table", resp.ACL.Backend)
	}
	if resp.Identity.Dir {
		t.Fatal("the identity describes a directory for a regular file")
	}
}

// TestPropsOfAMissingPathIsNotFound proves the error vocabulary survives this
// route too.
func TestPropsOfAMissingPathIsNotFound(t *testing.T) {
	p, _ := m3Pool(t)
	_, err := p.Props(context.Background(), alice(), wproto.PropsReq{Path: []byte("/share/tree/nope")})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Props of a missing path = %v, want not_found", err)
	}
}

// TestChmodJobRoundTripsThroughAWorker: JobChmod dispatches, the two specs
// arrive intact, and the terminal result carries the counts.
func TestChmodJobRoundTripsThroughAWorker(t *testing.T) {
	p, _ := m3Pool(t)
	res, err := p.Job(context.Background(), alice(), wproto.JobReq{
		JobID: "chmod-0000000001",
		Kind:  wproto.JobChmod,
		Body: jobBodyOf(t, wproto.ChmodJobReq{
			Paths:     [][]byte{[]byte("/share/tree")},
			Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
			Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
			Recursive: true,
		}),
	}, nil, nil)
	if err != nil {
		t.Fatalf("JobChmod = %v", err)
	}
	if res.Files != 2 || res.Dirs != 2 {
		t.Fatalf("result = %+v, want 2 files and 2 dirs", res)
	}
	if res.Bytes != 0 {
		t.Fatalf("Bytes = %d; a mode change moves none", res.Bytes)
	}
	if !strings.Contains(res.Detail, "changed 4 of 4 items") {
		t.Fatalf("Detail = %q, want the pre-scan's denominator in it", res.Detail)
	}
}

// TestChmodJobRefusesARecursiveSpecialBitSet: the refusal is the engine's, so it
// cannot be routed around by talking to the worker directly, and it arrives as
// bad_request rather than as a 500.
func TestChmodJobRefusesARecursiveSpecialBitSet(t *testing.T) {
	p, _ := m3Pool(t)
	_, err := p.Job(context.Background(), alice(), wproto.JobReq{
		JobID: "chmod-0000000002",
		Kind:  wproto.JobChmod,
		Body: jobBodyOf(t, wproto.ChmodJobReq{
			Paths:     [][]byte{[]byte("/share/tree")},
			Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o4755},
			Recursive: true,
		}),
	}, nil, nil)
	if !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("a recursive setuid = %v, want bad_request", err)
	}
}

// TestChmodJobRefusesADepth1Root: the one hard refusal M3 adds, through the
// worker.
func TestChmodJobRefusesADepth1Root(t *testing.T) {
	p, _ := m3Pool(t)
	_, err := p.Job(context.Background(), alice(), wproto.JobReq{
		JobID: "chmod-0000000003",
		Kind:  wproto.JobChmod,
		Body: jobBodyOf(t, wproto.ChmodJobReq{
			Paths:     [][]byte{[]byte("/share")},
			Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0755},
			Recursive: true,
		}),
	}, nil, nil)
	if !errors.Is(err, fsx.ErrProtected) {
		t.Fatalf("a recursive chmod of a depth-1 path = %v, want protected", err)
	}
}

// TestChownJobDispatches proves JobChown reaches the engine. What the kernel
// then does is the Linux root job's business — off Linux every entry comes back
// "unsupported", which is itself the §14 degradation being exercised.
func TestChownJobDispatches(t *testing.T) {
	p, _ := m3Pool(t)
	var warns []wproto.Warn
	res, err := p.Job(context.Background(), alice(), wproto.JobReq{
		JobID: "chown-0000000001",
		Kind:  wproto.JobChown,
		Body: jobBodyOf(t, wproto.ChownJobReq{
			Paths:     [][]byte{[]byte("/share/tree")},
			UID:       -1,
			GID:       -1,
			Recursive: true,
		}),
	}, nil, func(w wproto.Warn) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("JobChown = %v", err)
	}
	changed := res.Files + res.Dirs
	if changed == 0 && res.Skipped != 4 {
		t.Fatalf("neither changed nor cleanly skipped: %+v (warnings %d)", res, len(warns))
	}
	if changed != 0 && changed != 4 {
		t.Fatalf("result = %+v, want all four entries or none", res)
	}
	if !strings.Contains(res.Detail, "re-owned") {
		t.Fatalf("Detail = %q", res.Detail)
	}
}

// The cancel-to-partial path is not re-tested here. It is the job spine's, not
// M3's: internal/fsops proves a cancelled ChmodTree returns the partial counts
// with context.Canceled (TestChmodTreeCancelLeavesPartialWork), and this package
// already proves the spine turns that into an OK frame carrying the partial
// JobResult and hands the caller context.Canceled (F7). Racing a cancellation
// against an in-process worker over a four-entry tree would test the scheduler.
