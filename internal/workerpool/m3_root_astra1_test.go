package workerpool

// M3's permission semantics through REAL spawned workers, as distinct uids.
//
// m3_test.go makes the same round trips with InProcess: true, which proves the
// plumbing and nothing at all about credentials — an in-process worker runs as
// whoever runs the test, so alice()'s uid is never applied and the kernel is
// never actually asked (Astra M3 round 1, finding 15). These tests are the
// other half: the kernel IS asked, by a worker that really is the fixture user,
// and what is asserted is what the APP reported about the answer — the error
// vocabulary, the per-item outcome, the diff and the partial-success sentence.
// Never the kernel's internals, and never a prediction of its verdict (INV-2).
//
// They need root to create fixture users, so they run in the CI test-linux-root
// job and requireLinuxRoot skips them everywhere else.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// rootVol adds one level of depth to a fixture tree. A recursive job refuses a
// root at depth 1 — that is a share — so "/vol/..." is the shallowest spelling
// these tests can use without being refused for a reason none of them is about.
func rootVol(t *testing.T, base string) string {
	t.Helper()
	vol := filepath.Join(base, "vol")
	if err := os.MkdirAll(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	return vol
}

// ownedFile writes a fixture file and gives it away. Only root can hand a file
// to another user, which is exactly why these tests need root: the point is to
// present the worker with something it does NOT own.
func ownedFile(t *testing.T, path string, mode os.FileMode, uid, gid int) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode goes through the umask; the fixture's starting mode is
	// load bearing in every one of these tests, so it is set explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

// ownedDir is ownedFile for a directory.
func ownedDir(t *testing.T, path string, mode os.FileMode, uid, gid int) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

// fixtureGID resolves a fixture group created by fixtureUser.
func fixtureGID(t *testing.T, name string) int {
	t.Helper()
	gid, ok := idmap.Open("", "").GroupGID(name)
	if !ok {
		t.Skipf("the fixture group %s is not in /etc/group", name)
	}
	return gid
}

func hasGroup(groups []int, gid int) bool {
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

// diffFor finds one field of a ModeResp's diff.
func diffFor(diffs []perm.Diff, field string) (perm.Diff, bool) {
	for _, d := range diffs {
		if d.Field == field {
			return d, true
		}
	}
	return perm.Diff{}, false
}

// TestRootChmodByANonOwnerIsRefused: alice may not change the mode of bob's
// file, and the two routes report that refusal in the two different shapes the
// contract gives them — an error on the synchronous call, a per-ITEM outcome on
// the job, where the job itself succeeds and says it changed nothing.
func TestRootChmodByANonOwnerIsRefused(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	bob := fixtureUser(t, "qfmbob", "qfmother")
	if alice.UID == bob.UID {
		t.Skip("the two fixture users resolved to one uid")
	}

	vol := rootVol(t, base)
	theirs := filepath.Join(vol, "theirs.txt")
	ownedFile(t, theirs, 0o644, bob.UID, bob.GID)

	p := rootPool(t, base, exe)
	ctx := context.Background()
	who := principalOf(alice)

	_, err := p.Chmod(ctx, who, wproto.ChmodReq{
		Path: []byte("/vol/theirs.txt"),
		Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
	})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("alice chmod of bob's 0644 file = %v, want a permission error", err)
	}
	if code := fsx.Code(err); code != "permission" {
		t.Errorf("code = %q, want %q", code, "permission")
	}

	var warns []wproto.Warn
	res, err := p.Job(ctx, who, wproto.JobReq{
		JobID: "chmod-0000000101",
		Kind:  wproto.JobChmod,
		Body: jobBodyOf(t, wproto.ChmodJobReq{
			Paths: [][]byte{[]byte("/vol/theirs.txt")},
			Files: perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		}),
	}, nil, func(w wproto.Warn) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("the job itself must succeed and report the refusal per item: %v", err)
	}
	if done := res.Files + res.Dirs; done != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want nothing changed and one item skipped", res)
	}
	if !strings.Contains(res.Detail, "changed 0 of 1 items") ||
		!strings.Contains(res.Detail, "1 refused by the kernel") {
		t.Fatalf("Detail = %q, want the refusal counted as the kernel's", res.Detail)
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warns)
	}
	if got := string(warns[0].Path); got != "/vol/theirs.txt" {
		t.Errorf("the warning names %q", got)
	}
	if warns[0].Code != "permission" {
		t.Errorf("warning code = %q, want permission", warns[0].Code)
	}

	// Nothing happened to the file, and the app is what says so: a Props of the
	// same path still reports the mode it started with.
	pr, err := p.Props(ctx, who, wproto.PropsReq{Path: []byte("/vol/theirs.txt")})
	if err != nil {
		t.Fatalf("Props after the refusal: %v", err)
	}
	if got := perm.EntryMode(pr.Entry); got != 0o0644 {
		t.Errorf("the refused chmod left the mode at %s, want 0644", perm.Octal(got))
	}
}

// TestRootChgrpFollowsGroupMembership is the rule a non-root chown(2) enforces
// and this app only predicts (perm.CapsFor's ChgrpTo): the owner may give a
// file to a group they belong to, and to no other. Both halves go through the
// same call as the same user, so the difference in the answer is the kernel's
// and nothing else.
func TestRootChgrpFollowsGroupMembership(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	_ = fixtureUser(t, "qfmbob", "qfmother")

	team := fixtureGID(t, "qfmteam")
	other := fixtureGID(t, "qfmother")
	if !hasGroup(alice.Groups, team) {
		t.Skipf("the fixture user is not in qfmteam (groups %v)", alice.Groups)
	}
	if hasGroup(alice.Groups, other) {
		t.Skipf("the fixture user is in qfmother (groups %v), so there is no non-member group to test", alice.Groups)
	}

	vol := rootVol(t, base)
	p := rootPool(t, base, exe)
	ctx := context.Background()
	who := principalOf(alice)

	for _, tc := range []struct {
		name   string
		file   string
		gid    int
		member bool
	}{
		{"a group she belongs to", "member.txt", team, true},
		{"a group she does not belong to", "stranger.txt", other, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osPath := filepath.Join(vol, tc.file)
			ownedFile(t, osPath, 0o644, alice.UID, alice.GID)

			resp, err := p.Chown(ctx, who, wproto.ChownReq{
				Path: []byte("/vol/" + tc.file), UID: -1, GID: tc.gid,
			})
			if !tc.member {
				if !errors.Is(err, fs.ErrPermission) {
					t.Fatalf("chgrp to a non-member group = %v, want a permission error", err)
				}
				if code := fsx.Code(err); code != "permission" {
					t.Errorf("code = %q, want %q", code, "permission")
				}
				pr, perr := p.Props(ctx, who, wproto.PropsReq{Path: []byte("/vol/" + tc.file)})
				if perr != nil {
					t.Fatalf("Props after the refusal: %v", perr)
				}
				if pr.Entry.GID != alice.GID {
					t.Errorf("the refused chgrp left the group at %d, want the original %d", pr.Entry.GID, alice.GID)
				}
				return
			}
			if err != nil {
				t.Fatalf("chgrp to a member group = %v, want success", err)
			}
			if resp.Before.GID != alice.GID {
				t.Errorf("Before.GID = %d, want %d", resp.Before.GID, alice.GID)
			}
			if resp.Entry.GID != tc.gid {
				t.Fatalf("Entry.GID = %d, want %d", resp.Entry.GID, tc.gid)
			}
			// A change the kernel made exactly as asked has nothing to report.
			if d, ok := diffFor(resp.Diffs, perm.FieldGID); ok {
				t.Errorf("a successful chgrp reported a gid diff: %+v", d)
			}
		})
	}
}

// TestRootSetgidIsDroppedSilentlyAndTheDiffSaysSo is the silent case identity
// plan §3.1 names first: chmod(2) turns S_ISGID off, WITHOUT an error, when the
// caller is not privileged and the file's group is not one of theirs. The call
// succeeds, the bit is gone, and the only thing that tells the user is the
// diff the worker computed from two stats of one descriptor.
func TestRootSetgidIsDroppedSilentlyAndTheDiffSaysSo(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	_ = fixtureUser(t, "qfmbob", "qfmother")

	other := fixtureGID(t, "qfmother")
	if hasGroup(alice.Groups, other) {
		t.Skipf("the fixture user is in qfmother (groups %v); the kernel would keep the bit", alice.Groups)
	}

	vol := rootVol(t, base)
	// Hers to chmod, but in a group that is not hers: the two conditions the
	// silent drop needs.
	osPath := filepath.Join(vol, "foreign-group.txt")
	ownedFile(t, osPath, 0o644, alice.UID, other)

	p := rootPool(t, base, exe)
	resp, err := p.Chmod(context.Background(), principalOf(alice), wproto.ChmodReq{
		Path: []byte("/vol/foreign-group.txt"),
		Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o2644},
	})
	if err != nil {
		t.Fatalf("the chmod itself must SUCCEED; the bit is dropped silently: %v", err)
	}
	if got := perm.EntryMode(resp.Entry); got&perm.Setgid != 0 {
		t.Fatalf("mode after = %s; this kernel kept setgid, so there is nothing to report",
			perm.Octal(got))
	}
	d, ok := diffFor(resp.Diffs, perm.FieldSetgid)
	if !ok {
		t.Fatalf("no setgid diff in %+v; a bit the kernel took away is the whole reason the diff exists", resp.Diffs)
	}
	if d.Want != "on" || d.Got != "off" {
		t.Errorf("setgid diff = %+v, want on -> off", d)
	}
	// And the whole-mode field, because a mode change was asked for.
	if d, ok := diffFor(resp.Diffs, perm.FieldMode); !ok {
		t.Errorf("no mode diff in %+v", resp.Diffs)
	} else if d.Want != "2644" || d.Got != "0644" {
		t.Errorf("mode diff = %+v, want 2644 -> 0644", d)
	}
}

// TestRootRecursiveChmodOverAMixedTreeIsPartialSuccess is PLAN.md decision 12
// against the kernel: a tree with somebody else's files in it comes back as a
// SUCCESSFUL job that changed some of the items, skipped the rest, and says how
// many of those skips were refusals rather than policy.
func TestRootRecursiveChmodOverAMixedTreeIsPartialSuccess(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	bob := fixtureUser(t, "qfmbob", "qfmother")
	if alice.UID == bob.UID {
		t.Skip("the two fixture users resolved to one uid")
	}

	vol := rootVol(t, base)
	// Six entries: two directories and two files that are alice's, and two
	// files inside them that are bob's. She can enumerate everything — the
	// directories are hers — and change only her own four.
	mixed := filepath.Join(vol, "mixed")
	ownedDir(t, mixed, 0o755, alice.UID, alice.GID)
	ownedDir(t, filepath.Join(mixed, "sub"), 0o755, alice.UID, alice.GID)
	ownedFile(t, filepath.Join(mixed, "mine.txt"), 0o644, alice.UID, alice.GID)
	ownedFile(t, filepath.Join(mixed, "sub", "mine.txt"), 0o644, alice.UID, alice.GID)
	ownedFile(t, filepath.Join(mixed, "theirs.txt"), 0o644, bob.UID, bob.GID)
	ownedFile(t, filepath.Join(mixed, "sub", "theirs.txt"), 0o644, bob.UID, bob.GID)

	p := rootPool(t, base, exe)
	var warns []wproto.Warn
	res, err := p.Job(context.Background(), principalOf(alice), wproto.JobReq{
		JobID: "chmod-0000000102",
		Kind:  wproto.JobChmod,
		Body: jobBodyOf(t, wproto.ChmodJobReq{
			Paths:     [][]byte{[]byte("/vol/mixed")},
			Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
			Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
			Recursive: true,
		}),
	}, nil, func(w wproto.Warn) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("a partially refused recursive chmod must still be a successful job: %v", err)
	}
	if res.Files != 2 || res.Dirs != 2 || res.Skipped != 2 {
		t.Fatalf("result = %+v, want 2 files and 2 dirs changed and 2 skipped", res)
	}
	if !strings.Contains(res.Detail, "changed 4 of 6 items") {
		t.Fatalf("Detail = %q, want the pre-scan's denominator and the partial count", res.Detail)
	}
	if !strings.Contains(res.Detail, "2 refused by the kernel") {
		t.Fatalf("Detail = %q, want both skips attributed to the kernel", res.Detail)
	}
	if len(warns) != 2 {
		t.Fatalf("warnings = %+v, want one per foreign item", warns)
	}
	named := map[string]bool{}
	for _, w := range warns {
		named[string(w.Path)] = true
		if w.Code != "permission" {
			t.Errorf("warning %+v: code = %q, want permission", w, w.Code)
		}
	}
	for _, want := range []string{"/vol/mixed/theirs.txt", "/vol/mixed/sub/theirs.txt"} {
		if !named[want] {
			t.Errorf("no warning names %s; got %v", want, named)
		}
	}
}
