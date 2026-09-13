package fsops

// The M3 rules that are decided WITHOUT the kernel: the refusals a chmod or a
// chown makes before a syscall, and the shape of the job's result. They run on
// every platform, which is the point — the permission semantics themselves are
// the kernel's and live in the Linux and root jobs (INV-2).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// collect gathers a job's warnings so a test can read them back.
func collect(warns *[]wproto.Warn) Emit {
	return Emit{Warn: func(w wproto.Warn) { *warns = append(*warns, w) }}
}

func codes(warns []wproto.Warn) []string {
	out := make([]string, 0, len(warns))
	for _, w := range warns {
		out = append(out, w.Code)
	}
	return out
}

// TestChmodRefusesASymlinkLeaf is contract §1.4: Linux has no lchmod, so a
// symlink is never the subject of a chmod and is never reached through. The
// route's follow:true resolves the link and re-guards the TARGET as a path of
// its own, so a link that arrives at the engine is a refusal whatever anybody
// asked for.
func TestChmodRefusesASymlinkLeaf(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "x")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	_, err := Chmod(context.Background(), r, nil, "/link", perm.ModeSpec{Mask: 0o7777, Value: 0o0600})
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("Chmod of a symlink = %v, want unsupported", err)
	}
	// And the target is untouched: a refusal that had quietly followed the link
	// would show up here.
	fi, serr := os.Lstat(filepath.Join(base, "real.txt"))
	if serr != nil {
		t.Fatal(serr)
	}
	if perm.Bits(fi.Mode())&0o600 != 0o600 || fi.Mode().Perm() == 0o600 {
		// 0644 was written; a chmod to 0600 would have removed the group and
		// other read bits.
		t.Fatalf("the symlink's target was changed: %v", fi.Mode())
	}
}

// TestChmodRefusesTheRootOfTheTree: the jail base has no parent descriptor to
// address it through, and nobody means to chmod the root of a filesystem.
func TestChmodRefusesTheRootOfTheTree(t *testing.T) {
	r := newRoot(t, tempDir(t))
	_, err := Chmod(context.Background(), r, nil, "/", perm.ModeSpec{Mask: 0o7777, Value: 0o0755})
	if !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("Chmod of / = %v, want bad_request", err)
	}
}

// TestChmodTreeRefusesARecursiveSpecialBitSet is §1.3. Setting setuid across a
// tree is the single most effective way to make a NAS exploitable, and it is
// refused for every session — this is not a confirmation.
func TestChmodTreeRefusesARecursiveSpecialBitSet(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()

	for _, mode := range []uint32{0o4755, 0o2755, 0o1777} {
		spec := perm.ModeSpec{Mask: 0o7777, Value: mode}
		t.Run("files "+perm.Octal(mode), func(t *testing.T) {
			_, err := ChmodTree(ctx, r, nil, []string{"/a/sub"}, ChmodOptions{Files: spec, Recursive: true}, Emit{})
			if !errors.Is(err, fsx.ErrBadName) {
				t.Fatalf("ChmodTree = %v, want bad_request", err)
			}
		})
		t.Run("dirs "+perm.Octal(mode), func(t *testing.T) {
			_, err := ChmodTree(ctx, r, nil, []string{"/a/sub"}, ChmodOptions{Dirs: spec, Recursive: true}, Emit{})
			if !errors.Is(err, fsx.ErrBadName) {
				t.Fatalf("ChmodTree = %v, want bad_request", err)
			}
		})
	}
}

// TestChmodTreeAllowsARecursiveSpecialBitClear is the other half of §1.3, and
// the reason the rule is about SETTING rather than about the bits: clearing
// setuid across a tree is the cleanup that actually gets needed.
func TestChmodTreeAllowsARecursiveSpecialBitClear(t *testing.T) {
	r, _ := fixture(t)
	spec := perm.ModeSpec{Mask: perm.SpecialBits, Value: 0}
	if _, err := ChmodTree(context.Background(), r, nil, []string{"/a/sub"},
		ChmodOptions{Files: spec, Dirs: spec, Recursive: true}, Emit{}); err != nil {
		t.Fatalf("clearing the special bits recursively = %v, want it allowed", err)
	}
}

// TestChmodTreeRefusesADepth1Root is §4.5, the one hard refusal M3 adds: there
// is no recursive chmod of "/" or of "/share" that anybody means, and it applies
// to every session including root.
func TestChmodTreeRefusesADepth1Root(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/Public/deep")
	r := newRoot(t, base)
	ctx := context.Background()
	spec := perm.ModeSpec{Mask: 0o7777, Value: 0o0755}

	for _, p := range []string{"/", "/share"} {
		t.Run(p, func(t *testing.T) {
			_, err := ChmodTree(ctx, r, nil, []string{p}, ChmodOptions{Dirs: spec, Recursive: true}, Emit{})
			if !errors.Is(err, fsx.ErrProtected) {
				t.Fatalf("recursive ChmodTree(%q) = %v, want protected", p, err)
			}
			_, err = ChownTree(ctx, r, nil, []string{p}, ChownOptions{UID: -1, GID: -1, Recursive: true}, Emit{})
			if !errors.Is(err, fsx.ErrProtected) {
				t.Fatalf("recursive ChownTree(%q) = %v, want protected", p, err)
			}
		})
	}
	// Depth two is the ordinary case and must not be caught by the same rule.
	if _, err := ChmodTree(ctx, r, nil, []string{"/share/Public"},
		ChmodOptions{Dirs: spec, Recursive: true}, Emit{}); err != nil {
		t.Fatalf("recursive ChmodTree(/share/Public) = %v, want it allowed", err)
	}
	// And a NON-recursive change of a depth-1 path is not this rule's business:
	// it changes one directory, not a filesystem.
	if _, err := ChmodTree(ctx, r, nil, []string{"/share"}, ChmodOptions{Dirs: spec}, Emit{}); err != nil {
		t.Fatalf("non-recursive ChmodTree(/share) = %v, want it allowed", err)
	}
}

// TestChmodTreeRefusesNeverWriteRoots is F10 applied to a SELECTED path: the
// walker only ever sees components it reaches by recursion, so a job rooted AT
// .zfs or @Recycle was never shown the component at all.
func TestChmodTreeRefusesNeverWriteRoots(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/Public/.zfs/snapshot")
	mkdir(t, base, "share/Public/@Recycle")
	r := newRoot(t, base)
	spec := perm.ModeSpec{Mask: 0o7777, Value: 0o0700}

	for _, p := range []string{"/share/Public/.zfs/snapshot", "/share/Public/@Recycle"} {
		t.Run(p, func(t *testing.T) {
			var warns []wproto.Warn
			res, err := ChmodTree(context.Background(), r, nil, []string{p},
				ChmodOptions{Dirs: spec, Files: spec}, collect(&warns))
			if err != nil {
				t.Fatalf("ChmodTree = %v", err)
			}
			if res.Dirs != 0 || res.Files != 0 || res.Skipped != 1 {
				t.Fatalf("result = %+v, want nothing changed and one skip", res)
			}
			if len(warns) != 1 || warns[0].Code != "protected" {
				t.Fatalf("warnings = %v", codes(warns))
			}
		})
	}
}

// TestRecursiveJobRefusesASymlinkRoot is the other round-2 P2: chmod already
// skipped a link root as unsupported, but chown lchowned it and reported
// "re-owned 1 of 1 items" — a recursive success over exactly one inode, which is
// a false success. Both verbs refuse it now.
func TestRecursiveJobRefusesASymlinkRoot(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "share/real/sub")
	write(t, base, "share/real/one.txt", "1")
	if err := os.Symlink(filepath.Join(base, "share", "real"), filepath.Join(base, "share", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	for _, c := range []struct {
		name string
		run  func(emit Emit) (wproto.JobResult, error)
	}{
		{"chmod", func(emit Emit) (wproto.JobResult, error) {
			return ChmodTree(ctx, r, nil, []string{"/share/link"}, ChmodOptions{
				Files: perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, Recursive: true}, emit)
		}},
		{"chown", func(emit Emit) (wproto.JobResult, error) {
			return ChownTree(ctx, r, nil, []string{"/share/link"}, ChownOptions{
				UID: -1, GID: -1, Recursive: true}, emit)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var warns []wproto.Warn
			res, err := c.run(collect(&warns))
			if err != nil {
				t.Fatalf("%s = %v", c.name, err)
			}
			if res.Files != 0 || res.Dirs != 0 {
				t.Fatalf("a recursive %s of a symlink reported work done: %+v", c.name, res)
			}
			if res.Skipped != 1 {
				t.Fatalf("Skipped = %d, want 1", res.Skipped)
			}
			if len(warns) != 1 || warns[0].Code != "unsupported" {
				t.Fatalf("warnings = %+v, want one unsupported", warns)
			}
		})
	}

	// A NON-recursive chown of a link keeps its lchown semantics (§1.4): the
	// link itself is the object, and that is not a false success.
	res, err := ChownTree(ctx, r, nil, []string{"/share/link"}, ChownOptions{UID: -1, GID: -1}, Emit{})
	if err != nil {
		t.Fatalf("non-recursive chown of a link = %v", err)
	}
	if res.Files+res.Dirs == 0 && res.Skipped == 1 {
		t.Skip("this platform has no chown at all; the Linux jobs exercise it")
	}
	if res.Files != 1 {
		t.Fatalf("non-recursive chown of a link = %+v, want the link counted", res)
	}
}

// TestChmodTreeCountsAZeroMaskAsSkipped is §1.2 and §4.3 together: "apply to
// folders only" is a zero mask on the files half, and the entries it leaves
// alone are skipped by POLICY — counted, so that changed plus skipped adds up to
// the pre-scan's total, and warned about by nothing, because nothing failed.
func TestChmodTreeCountsAZeroMaskAsSkipped(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree/sub")
	write(t, base, "share/tree/one.txt", "1")
	write(t, base, "share/tree/sub/two.txt", "2")
	r := newRoot(t, base)

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"},
		ChmodOptions{Dirs: perm.ModeSpec{Mask: 0o7777, Value: 0o0755}, Recursive: true}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Dirs != 2 {
		t.Fatalf("Dirs = %d, want 2 (/tree and /tree/sub)", res.Dirs)
	}
	if res.Files != 0 {
		t.Fatalf("Files = %d, want 0 — the files half had a zero mask", res.Files)
	}
	if res.Skipped != 2 {
		t.Fatalf("Skipped = %d, want 2 (the two files, by policy)", res.Skipped)
	}
	// A policy skip warns about nothing, because nothing failed. (The dev box
	// may warn "unchanged" about the DIRECTORIES, whose mode bits Windows does
	// not really store — that is §14's fiction, not this rule.)
	for _, w := range warns {
		if strings.HasSuffix(string(w.Path), ".txt") {
			t.Fatalf("a file skipped by a zero mask warned: %+v", w)
		}
	}
	if res.Bytes != 0 {
		t.Fatalf("Bytes = %d; a mode change moves none and reporting a number would be a lie", res.Bytes)
	}
	if !strings.Contains(res.Detail, "changed 2 of 4 items; 2 skipped") {
		t.Fatalf("Detail = %q", res.Detail)
	}
}

// TestChownTreeRefusesFollow has no engine half — Follow is refused by the
// worker before fsops is called — so what is pinned here is the other half of
// the same rule: a chown of a symlink changes the LINK and never its target.
// The mode-changing mirror of it is TestChmodRefusesASymlinkLeaf.
func TestChownTreeNeverFollowsALink(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "x")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// -1/-1 asks for no change at all, so this runs unprivileged everywhere and
	// still proves the engine addressed the link rather than refusing it the way
	// chmod does.
	var warns []wproto.Warn
	res, err := ChownTree(context.Background(), r, nil, []string{"/link"},
		ChownOptions{UID: -1, GID: -1}, collect(&warns))
	if err != nil {
		t.Fatalf("ChownTree of a symlink = %v", err)
	}
	if len(warns) == 1 && warns[0].Code == "unsupported" {
		t.Skip("this platform has no chown at all; the Linux jobs exercise it")
	}
	if res.Files != 1 {
		t.Fatalf("result = %+v, want the link itself counted", res)
	}
}

// TestPropsDescribesTheEntry is the shape of the properties reply on any box:
// one entry, no target unless asked, and an identity that names the object.
func TestPropsDescribesTheEntry(t *testing.T) {
	r, _ := fixture(t)
	resp, err := Props(context.Background(), r, nil, "/a/one.txt", "")
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if resp.Entry.Name != "one.txt" || resp.Entry.Type != "file" || resp.Entry.Size != 3 {
		t.Fatalf("entry = %+v", resp.Entry)
	}
	if resp.Target != nil {
		t.Fatalf("a plain file has no link target, got %+v", resp.Target)
	}
	if resp.ACL.Backend == "" {
		t.Fatal("ACLInfo.Backend must always say something, even when it is none")
	}
}

// TestPropsFollowsALinkAndToleratesADanglingOne is §8.1: Follow fills Target,
// and a dangling link leaves it nil rather than failing the whole dialog — which
// is exactly the case somebody opens the dialog to diagnose.
func TestPropsFollowsALinkAndToleratesADanglingOne(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "hello")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "good")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "gone.txt"), filepath.Join(base, "dangling")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	// The target comes from the CALLER's already-guarded spelling, never from a
	// resolution made here (round-3 review).
	good, err := Props(ctx, r, nil, "/good", "/real.txt")
	if err != nil {
		t.Fatalf("Props(/good) = %v", err)
	}
	if !good.Entry.IsSymlink {
		t.Fatalf("the entry must describe the LINK: %+v", good.Entry)
	}
	if good.Target == nil || good.Target.Size != 5 {
		t.Fatalf("target = %+v, want the 5-byte file", good.Target)
	}
	if good.Target.Path != "/real.txt" || good.Entry.LinkResolved != "/real.txt" {
		t.Fatalf("the target must be described at the spelling the caller guarded: %+v", good.Target)
	}
	if good.Entry.TargetType != "file" {
		t.Fatalf("TargetType = %q, want file", good.Entry.TargetType)
	}

	// A dangling link: the route has no resolved spelling to send for one, so
	// there is no target — and the link itself is still fully described, which
	// is exactly what somebody opened the dialog to find out.
	bad, err := Props(ctx, r, nil, "/dangling", "")
	if err != nil {
		t.Fatalf("Props(/dangling) = %v, want the link described rather than an error", err)
	}
	if bad.Target != nil {
		t.Fatalf("a dangling link has no target, got %+v", bad.Target)
	}
	if bad.Entry.LinkTarget == "" {
		t.Fatal("a dangling link must still report where it points")
	}
}

// TestPropsDescribesNoTargetWithoutOne is the round-3 rule stated on its own: a
// worker that resolved the link itself described whatever it pointed at NOW,
// which is not what the route guarded. With no Target there is simply no target,
// however live and however followable the link is.
func TestPropsDescribesNoTargetWithoutOne(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "hello")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "good")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	resp, err := Props(context.Background(), r, nil, "/good", "")
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if resp.Target != nil {
		t.Fatalf("a link with no guarded target was followed anyway: %+v", resp.Target)
	}
	if !resp.Entry.IsSymlink || resp.Entry.LinkTarget == "" {
		t.Fatalf("the link itself must still be described: %+v", resp.Entry)
	}
}

// TestPropsToleratesATargetThatWentAway: a target removed between the route's
// resolution and the worker's walk is not evidence of an attack, just a race.
// The link is still described and there is simply no target.
func TestPropsToleratesATargetThatWentAway(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "hello")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	if err := os.Remove(filepath.Join(base, "real.txt")); err != nil {
		t.Fatal(err)
	}

	resp, err := Props(context.Background(), r, nil, "/link", "/real.txt")
	if err != nil {
		t.Fatalf("Props = %v, want the link described rather than an error", err)
	}
	if resp.Target != nil {
		t.Fatalf("target = %+v, want none", resp.Target)
	}
	if resp.Entry.LinkTarget == "" {
		t.Fatal("the link itself must still be described")
	}
}

// TestListLeavesACLUnprobedUnlessAsked: the badge costs one lgetxattr per entry,
// so an ordinary listing must not pay for it, and an unprobed entry must read as
// "we did not look" rather than as "there is no ACL".
func TestListLeavesACLUnprobedUnlessAsked(t *testing.T) {
	r, _ := fixture(t)
	l, err := List(context.Background(), r, nil, "/a", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if e.ACL != "" || e.HasACL {
			t.Fatalf("%s was probed without being asked: acl=%q hasAcl=%v", e.Name, e.ACL, e.HasACL)
		}
	}
	// And asking with no platform knowledge probes nothing either: there is no
	// mount to say whether it has an ACL backend at all.
	l, err = List(context.Background(), r, nil, "/a", fsx.ListOptions{ACLProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if e.ACL != "" {
			t.Fatalf("%s was probed with no mount table: acl=%q", e.Name, e.ACL)
		}
	}
}
