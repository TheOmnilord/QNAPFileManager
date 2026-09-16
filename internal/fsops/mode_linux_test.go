package fsops

// The M3 engine against a real kernel, unprivileged: the descriptor discipline,
// the two fallbacks, the canonical walk's refusal, and the recursive job's
// counts. Nothing here needs root — every file is one this process owns — which
// is what makes them the ordinary Linux CI job's rather than the root job's.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// modeOf reads the 07777 of a path with a plain lstat, which is the check every
// test here makes against the engine's own answer.
func modeOf(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return perm.Bits(fi.Mode())
}

// heldIn opens a directory and one entry inside it the way the engine does, so
// a test can drive chmodHeld and chownHeld directly.
func heldIn(t *testing.T, r fsx.Root, dirAPI, name string) (*dirRef, *itemRef) {
	t.Helper()
	d, _, err := canonicalDir(r, dirAPI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.close() })
	ref, err := itemRefIn(d, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.close)
	return d, ref
}

// TestChmodAppliesAndReportsNoDiff is the ordinary case: the spec is applied to
// the mode the descriptor reported, the post-call stat comes from that same
// descriptor, and there is nothing to warn about.
func TestChmodAppliesAndReportsNoDiff(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	if err := os.Chmod(filepath.Join(base, "f.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	resp, err := Chmod(context.Background(), r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, nil)
	if err != nil {
		t.Fatalf("Chmod = %v", err)
	}
	if resp.Before.Mode != "0644" {
		t.Fatalf("Before.Mode = %q, want 0644", resp.Before.Mode)
	}
	if resp.Entry.Mode != "0600" {
		t.Fatalf("Entry.Mode = %q, want 0600", resp.Entry.Mode)
	}
	if len(resp.Diffs) != 0 {
		t.Fatalf("Diffs = %+v, want none", resp.Diffs)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got != 0o600 {
		t.Fatalf("the file on disk is %s", perm.Octal(got))
	}
}

// TestChmodAppliesOnlyTheMaskedBits is §1.1 through the engine rather than in
// the arithmetic: a spec that touches one bit leaves everything else exactly as
// the DESCRIPTOR reported it, without the caller having to know the mode.
func TestChmodAppliesOnlyTheMaskedBits(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	if err := os.Chmod(filepath.Join(base, "f.txt"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// "tick the group-write box" and nothing else.
	if _, err := Chmod(context.Background(), r, nil, "/f.txt", perm.ModeSpec{Mask: 0o020, Value: 0o020}, nil); err != nil {
		t.Fatalf("Chmod = %v", err)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got != 0o660 {
		t.Fatalf("mode = %s, want 0660", perm.Octal(got))
	}
}

// TestChmodRefusesASymlinkComponent is the canonical walk (§2.2): a symlink
// among the components of an already-resolved path is not a path to follow, it
// is evidence that the tree changed after it was authorized.
func TestChmodRefusesASymlinkComponent(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "real")
	write(t, base, "real/f.txt", "x")
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	_, err := Chmod(context.Background(), r, nil, "/link/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, nil)
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("Chmod through a symlink component = %v, want changed", err)
	}
	if got := modeOf(t, filepath.Join(base, "real", "f.txt")); got == 0o600 {
		t.Fatal("the refusal still changed the file behind the link")
	}
	// The same path spelled canonically is fine: the refusal is about the
	// symlink, not about the file.
	if _, err := Chmod(context.Background(), r, nil, "/real/f.txt",
		perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, nil); err != nil {
		t.Fatalf("Chmod of the canonical spelling = %v", err)
	}
}

// TestChmodFallsBackToFchmodWithoutProc drives the branch a container without
// /proc takes (§2.3). The seam is the only way to reach it: /proc is mounted on
// every box this runs on, and un-mounting it is not something a test may do.
func TestChmodFallsBackToFchmodWithoutProc(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	if err := os.Chmod(filepath.Join(base, "f.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	noProcFD = true
	t.Cleanup(func() { noProcFD = false })

	resp, err := Chmod(context.Background(), r, nil, "/f.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0640}, nil)
	if err != nil {
		t.Fatalf("Chmod without /proc = %v", err)
	}
	if resp.Entry.Mode != "0640" {
		t.Fatalf("Entry.Mode = %q", resp.Entry.Mode)
	}
	if got := modeOf(t, filepath.Join(base, "f.txt")); got != 0o640 {
		t.Fatalf("mode = %s", perm.Octal(got))
	}
}

// TestChmodWithoutProcSurfacesTheKernelsRefusal is the third rung of §2.3, and
// the round-2 P3: with no /proc, the re-open of a 0200 file comes back EACCES —
// the kernel's verdict on this caller — and it must reach the user AS a
// permission refusal (403).
//
// It used to be flattened to fsx.ErrUnsupported, which the front end renders as
// "that kind of item cannot be changed" (415). That is not what happened, and
// inventing a reason the kernel did not give is the wrong half of INV-2. The
// contract's §2.3 sentence named "unsupported" for this case; the code now says
// what the kernel said instead, and that reading is the one being kept.
func TestChmodWithoutProcSurfacesTheKernelsRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open anything, so this rung cannot be reached (CAP_DAC_OVERRIDE)")
	}
	base := tempDir(t)
	write(t, base, "wo.txt", "x")
	if err := os.Chmod(filepath.Join(base, "wo.txt"), 0o200); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	noProcFD = true
	t.Cleanup(func() { noProcFD = false })

	_, err := Chmod(context.Background(), r, nil, "/wo.txt", perm.ModeSpec{Mask: 0o7777, Value: 0o0644}, nil)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Chmod = %v, want the kernel's own permission refusal", err)
	}
	if errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("the kernel's refusal was flattened to unsupported: %v", err)
	}
}

// TestReopenProvedClassifiesTheOpen pins the split the case above turns on:
// unsupported is for an object with no readable descriptor to be had, and
// everything else is the kernel's answer, unchanged.
func TestReopenProvedClassifiesTheOpen(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "x")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// A symlink: O_NOFOLLOW means Linux will never open it, for anybody. That is
	// "no readable route", and it is how a chown's ladder learns to fall to its
	// last rung.
	parent, ref := heldIn(t, r, "/", "link")
	if _, err := reopenProved(parent, "link", ref); !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("reopenProved of a symlink = %v, want unsupported", err)
	}

	// A name that is not there at all: the caller still holds the object, so
	// the name going away is the tree having changed under it (round 3), not
	// unsupported and not a fresh not_found.
	if _, err := reopenProved(parent, "gone", ref); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("reopenProved of a missing name = %v, want changed", err)
	}
}

// TestRecursiveJobSkipsAHardlinkAsRoot is the round-2 P2 on hardlinks.
//
// A hardlink is the inode itself under a second name, and the mode belongs to
// the inode — so anybody who can create a file in a share can link one of the
// daemon's own files into it and wait for an administrator's "apply 0777 to this
// folder and everything in it". A root worker therefore skips a multiply-linked
// non-directory the RECURSION reached; a non-root worker does not, because the
// kernel already refuses an inode that user does not own (INV-2).
func TestRecursiveJobSkipsAHardlinkAsRoot(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree")
	write(t, base, "secret.conf", "the daemon's own file")
	write(t, base, "share/tree/ordinary.txt", "x")
	if err := os.Chmod(filepath.Join(base, "secret.conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(base, "secret.conf"),
		filepath.Join(base, "share", "tree", "planted")); err != nil {
		t.Skipf("this filesystem has no hard links: %v", err)
	}
	r := newRoot(t, base)

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0777},
		Recursive: true,
	}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	planted := modeOf(t, filepath.Join(base, "secret.conf"))

	if !rootWorker() {
		// Unprivileged: the rule does not apply, and the kernel is what decides.
		// The link is this user's own file, so it is changed like any other.
		if res.Files != 2 {
			t.Fatalf("a non-root job = %+v, want both files changed", res)
		}
		if planted != 0o777 {
			t.Fatalf("the linked inode is %s; a non-root job must not invent a refusal", perm.Octal(planted))
		}
		return
	}
	if res.Files != 1 || res.Dirs != 1 {
		t.Fatalf("a root job = %+v, want the ordinary file and the directory only", res)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want the hardlink", res.Skipped)
	}
	if planted == 0o777 {
		t.Fatal("a root recursive chmod reached an inode named from outside the tree")
	}
	found := false
	for _, w := range warns {
		if w.Code == "unsupported" && strings.Contains(w.Message, "hard-linked elsewhere") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the skip was not explained: %+v", warns)
	}
}

// TestNamingAHardlinkDirectlyStillWorks is the other half of the rule, and the
// reason the warning says what it says: the guard SAW the path the user named,
// so naming it is exactly what makes the change legitimate. Only entries the
// recursion reached are refused.
func TestNamingAHardlinkDirectlyStillWorks(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree")
	write(t, base, "target.txt", "x")
	if err := os.Link(filepath.Join(base, "target.txt"),
		filepath.Join(base, "share", "tree", "named")); err != nil {
		t.Skipf("this filesystem has no hard links: %v", err)
	}
	r := newRoot(t, base)

	// The single-item route: no job, no recursion, no rule.
	if _, err := Chmod(context.Background(), r, nil, "/share/tree/named",
		perm.ModeSpec{Mask: 0o7777, Value: 0o0640}, nil); err != nil {
		t.Fatalf("Chmod of a named hardlink = %v", err)
	}
	if got := modeOf(t, filepath.Join(base, "target.txt")); got != 0o640 {
		t.Fatalf("mode = %s, want 0640", perm.Octal(got))
	}

	// And the job route, when the hardlink IS the selected path.
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree/named"},
		ChmodOptions{Files: perm.ModeSpec{Mask: 0o7777, Value: 0o0600}}, Emit{})
	if err != nil {
		t.Fatalf("ChmodTree of a named hardlink = %v", err)
	}
	if res.Files != 1 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want the named hardlink changed", res)
	}
}

// TestChownAddressesTheDescriptor proves the AT_EMPTY_PATH form works on the
// held O_PATH descriptor. -1/-1 asks for no change, so it runs unprivileged —
// what is under test is that the call reaches the inode at all, not what the
// kernel would allow a non-root process to do with it (that is the root job's).
func TestChownAddressesTheDescriptor(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)

	resp, err := Chown(context.Background(), r, nil, "/f.txt", -1, -1)
	if err != nil {
		t.Fatalf("Chown = %v", err)
	}
	if resp.Before.UID != os.Getuid() || resp.Entry.UID != os.Getuid() {
		t.Fatalf("before/after uid = %d/%d, want %d", resp.Before.UID, resp.Entry.UID, os.Getuid())
	}
	if len(resp.Diffs) != 0 {
		t.Fatalf("Diffs = %+v; -1/-1 asks for nothing and can differ from nothing", resp.Diffs)
	}
}

// TestChownChangesTheLinkAndNotItsTarget is §1.4: chown is always lchown.
func TestChownChangesTheLinkAndNotItsTarget(t *testing.T) {
	base := tempDir(t)
	write(t, base, "real.txt", "x")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	resp, err := Chown(context.Background(), r, nil, "/link", -1, -1)
	if err != nil {
		t.Fatalf("Chown of a symlink = %v", err)
	}
	if !resp.Entry.IsSymlink {
		t.Fatalf("the entry describes %q, not the link itself", resp.Entry.Type)
	}
	if resp.Entry.LinkTarget == "" {
		t.Fatal("the reply must carry the link's own target so the row can be redrawn")
	}
}

// substitute replaces a name with a different inode while a descriptor for the
// original is still held — the rename an attacker with write access to the
// parent makes in the window between a check and the syscall that acts on it.
func substitute(t *testing.T, base, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(base, filepath.FromSlash(rel))); err != nil {
		t.Fatal(err)
	}
	write(t, base, rel, "a different file")
}

// TestChownWithoutEmptyPathUsesTheHeldDescriptor is rung 1 of
// chownWithoutEmptyPath and the fix for the round-1 P3: with AT_EMPTY_PATH gone,
// the chown goes through /proc/self/fd/N on the descriptor that is already held,
// so no directory is consulted at all.
//
// The name is substituted first, and the assertion is that this changes NOTHING:
// a route that looked the name up would either refuse with "changed" or — the
// bug — chown the substitute. Succeeding on a name that now points elsewhere is
// what proves the name was never used.
func TestChownWithoutEmptyPathUsesTheHeldDescriptor(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "original")
	r := newRoot(t, base)
	parent, ref := heldIn(t, r, "/", "f.txt")

	noEmptyPath = true
	t.Cleanup(func() { noEmptyPath = false })

	substitute(t, base, "f.txt")
	fi, err := chownHeld(parent, "f.txt", ref, -1, -1)
	if err != nil {
		t.Fatalf("the /proc route consulted the name it should not have: %v", err)
	}
	// And the object it reported on is the one that was held, not the one the
	// name now leads to.
	if fi.Size() != int64(len("original")) {
		t.Fatalf("the post-call stat describes the substitute (%d bytes)", fi.Size())
	}
}

// TestChownFallbackFchownsTheProvedDescriptor is rung 2: no AT_EMPTY_PATH and no
// /proc either, so the entry is re-opened through the held parent, proved, and
// fchown'ed through THAT descriptor — the proof and the act on one open file,
// with no lookup in between.
func TestChownFallbackFchownsTheProvedDescriptor(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "original")
	r := newRoot(t, base)
	parent, ref := heldIn(t, r, "/", "f.txt")

	noEmptyPath, noProcFD = true, true
	t.Cleanup(func() { noEmptyPath, noProcFD = false, false })

	// The name still refers to the held object: the re-open proves it and acts.
	if _, err := chownHeld(parent, "f.txt", ref, -1, -1); err != nil {
		t.Fatalf("the proved re-open refused an unchanged name: %v", err)
	}

	// Substituted: the proof fails on the descriptor that was opened, so nothing
	// is chowned and the caller is told the tree changed.
	substitute(t, base, "f.txt")
	if _, err := chownHeld(parent, "f.txt", ref, -1, -1); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("the proved re-open = %v, want changed", err)
	}
}

// TestChownNamedFallbackProvesIdentity is rung 3, the residual: a symlink cannot
// be opened at all, so with neither AT_EMPTY_PATH nor /proc there is no
// descriptor left to act through and the named call is all there is. It still
// re-proves first, so the ordinary substitution is refused — what it cannot
// close is the window between that proof and the syscall, which is why the rung
// is documented as a residual rather than as a guarantee.
func TestChownNamedFallbackProvesIdentity(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "real.txt", "original")
	if err := os.Symlink(filepath.Join(base, "real.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	parent, ref := heldIn(t, r, "/", "link")

	noEmptyPath, noProcFD = true, true
	t.Cleanup(func() { noEmptyPath, noProcFD = false, false })

	if _, err := chownHeld(parent, "link", ref, -1, -1); err != nil {
		t.Fatalf("the named fallback refused an unchanged link: %v", err)
	}
	// The link's target must be untouched by any of this: chown is lchown on
	// every rung, and the one rung that could have followed (/proc) is never
	// taken for a symlink.
	if fi, serr := os.Lstat(filepath.Join(base, "real.txt")); serr != nil || fi.Size() != int64(len("original")) {
		t.Fatalf("the link's target was disturbed: %v %v", fi, serr)
	}

	if err := os.Remove(filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	write(t, base, "link", "not a link any more")
	if _, err := chownHeld(parent, "link", ref, -1, -1); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("the named fallback = %v, want changed", err)
	}
}

// TestAReopenedNameThatWentAwayIsChanged is the round-3 P3, over all three
// re-open paths at once.
//
// A name renamed away while this process still HOLDS the object it named comes
// back ENOENT, and a raw ENOENT tells the user "this path no longer exists"
// about a file the worker demonstrably has open. §2.2 already has the word for
// what actually happened — the tree changed after it was authorized — and these
// three are the places that have to say it. A genuine not-found belongs to the
// FIRST canonical walk, which holds nothing yet, and that is checked here too.
func TestAReopenedNameThatWentAwayIsChanged(t *testing.T) {
	for _, c := range []struct {
		name string
		// setup builds an entry called "victim" and hands back the held pair.
		setup func(t *testing.T, base string, r fsx.Root) (*dirRef, *itemRef)
		// act is the re-open under test, after the name has been renamed away.
		act func(parent *dirRef, ref *itemRef) error
	}{
		{
			name: "reopenProved",
			setup: func(t *testing.T, base string, r fsx.Root) (*dirRef, *itemRef) {
				write(t, base, "victim", "x")
				return heldIn(t, r, "/", "victim")
			},
			act: func(parent *dirRef, ref *itemRef) error {
				_, err := reopenProved(parent, "victim", ref)
				return err
			},
		},
		{
			name: "reopenDir",
			setup: func(t *testing.T, base string, r fsx.Root) (*dirRef, *itemRef) {
				mkdir(t, base, "victim")
				return heldIn(t, r, "/", "victim")
			},
			act: func(parent *dirRef, ref *itemRef) error {
				_, err := reopenDir(parent, "victim", ref)
				return err
			},
		},
		{
			name: "sameAsHeld",
			setup: func(t *testing.T, base string, r fsx.Root) (*dirRef, *itemRef) {
				write(t, base, "victim", "x")
				return heldIn(t, r, "/", "victim")
			},
			act: func(parent *dirRef, ref *itemRef) error {
				return sameAsHeld(parent, "victim", ref)
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := tempDir(t)
			r := newRoot(t, base)
			parent, ref := c.setup(t, base, r)

			if err := os.Rename(filepath.Join(base, "victim"), filepath.Join(base, "moved")); err != nil {
				t.Fatal(err)
			}
			err := c.act(parent, ref)
			if !errors.Is(err, fsx.ErrChanged) {
				t.Fatalf("%s after a rename = %v, want changed", c.name, err)
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%s reported not_found for an inode it is holding: %v", c.name, err)
			}
		})
	}

	// The first canonical walk is untouched: it holds nothing, so a path that is
	// really not there is really not_found.
	base := tempDir(t)
	r := newRoot(t, base)
	if _, err := Chmod(context.Background(), r, nil, "/nope",
		perm.ModeSpec{Mask: 0o7777, Value: 0o0644}, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Chmod of a path that was never there = %v, want not_found", err)
	}
}

// TestChownFallbackSaysChangedWhenTheNameWentAway is the same rule reached
// through the ladder rather than through a helper: with no AT_EMPTY_PATH and no
// /proc, the fallback re-opens a name that is gone, and the caller is told the
// tree changed rather than that the file it is holding does not exist.
func TestChownFallbackSaysChangedWhenTheNameWentAway(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "original")
	r := newRoot(t, base)
	parent, ref := heldIn(t, r, "/", "f.txt")

	noEmptyPath, noProcFD = true, true
	t.Cleanup(func() { noEmptyPath, noProcFD = false, false })

	if err := os.Rename(filepath.Join(base, "f.txt"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	_, err := chownHeld(parent, "f.txt", ref, -1, -1)
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("chownHeld after a rename = %v, want changed", err)
	}
}

// TestReopenDirProvesIdentity is the same rule for the recursive job's root: the
// directory the walk enumerates is the directory that was authorized, or the job
// refuses.
func TestReopenDirProvesIdentity(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree")
	r := newRoot(t, base)
	parent, ref := heldIn(t, r, "/", "tree")

	d, err := reopenDir(parent, "tree", ref)
	if err != nil {
		t.Fatalf("reopenDir of the same directory = %v", err)
	}
	d.close()

	if err := os.Rename(filepath.Join(base, "tree"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	mkdir(t, base, "tree")
	if _, err := reopenDir(parent, "tree", ref); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("reopenDir of a substituted name = %v, want changed", err)
	}
}

// TestChmodTreeChangesAShareThatIsAMountPoint is the round-2 P2: on QuTS hero
// every share IS its own dataset mount, and a QTS share is a bind mount of one,
// so refusing a recursive change whose root is a mount point refused a recursive
// chmod of every share on the NAS — after a pre-scan that had counted the whole
// tree and a level-2 confirmation for a job that then did nothing.
//
// The refusal it inherited was delete's, whose reason is that unlinking a mount
// point empties the volume. A mode change unlinks nothing.
func TestChmodTreeChangesAShareThatIsAMountPoint(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/Public/sub")
	write(t, base, "share/Public/one.txt", "1")
	write(t, base, "share/Public/sub/two.txt", "2")
	r := newRoot(t, base)

	// A mount table that says the share IS the mount point, which is what the
	// engine used to refuse on.
	osShare, err := r.OS("/share/Public")
	if err != nil {
		t.Fatal(err)
	}
	plat := synthPlatform(t,
		synthMount{mountPoint: slashClean(base), fsType: "ext4"},
		synthMount{mountPoint: slashClean(osShare), fsType: "ext4", dev: "8:2"},
	)
	if !plat.IsMountPointByTable(osShare) {
		t.Fatalf("the fixture table does not call %q a mount point", osShare)
	}

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, plat, []string{"/share/Public"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
		Recursive: true,
	}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Dirs != 2 || res.Files != 2 {
		t.Fatalf("result = %+v, want the share and everything under it changed", res)
	}
	for _, w := range warns {
		if w.Code == "protected" {
			t.Fatalf("the share was refused for being a mount point: %+v", w)
		}
	}
}

// TestChmodTreeCountsAndSkips is §4.2 and §4.3 on a real tree: files and
// directories counted separately, symlinks skipped with an "unsupported"
// warning and never followed, bytes always zero.
func TestChmodTreeCountsAndSkips(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree/sub")
	write(t, base, "share/tree/one.txt", "1")
	write(t, base, "share/tree/sub/two.txt", "2")
	if err := os.Symlink(filepath.Join(base, "share", "tree", "one.txt"),
		filepath.Join(base, "share", "tree", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
		Recursive: true,
	}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Files != 2 || res.Dirs != 2 {
		t.Fatalf("result = %+v, want 2 files and 2 dirs", res)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1 (the symlink)", res.Skipped)
	}
	if res.Bytes != 0 {
		t.Fatalf("Bytes = %d; a mode change moves none", res.Bytes)
	}
	if len(warns) != 1 || warns[0].Code != "unsupported" ||
		!strings.HasSuffix(string(warns[0].Path), "/link") {
		t.Fatalf("warnings = %+v", warns)
	}
	if got := modeOf(t, filepath.Join(base, "share", "tree", "sub", "two.txt")); got != 0o640 {
		t.Fatalf("the nested file is %s, want 0640", perm.Octal(got))
	}
	if got := modeOf(t, filepath.Join(base, "share", "tree", "sub")); got != 0o750 {
		t.Fatalf("the nested directory is %s, want 0750", perm.Octal(got))
	}
	if got := modeOf(t, filepath.Join(base, "share", "tree")); got != 0o750 {
		t.Fatalf("the root is %s, want 0750", perm.Octal(got))
	}
	// The link's target keeps the mode the FILES spec gave it, which is the
	// proof that the walk skipped the link rather than reaching through it.
	if got := modeOf(t, filepath.Join(base, "share", "tree", "one.txt")); got != 0o640 {
		t.Fatalf("the link's target is %s", perm.Octal(got))
	}
}

// TestChmodTreeChangesDirectoriesAfterTheirChildren is the ordering §4 depends
// on: a directory whose search bit is being removed must be changed LAST, or the
// walk locks itself out of the tree it is in the middle of changing.
func TestChmodTreeChangesDirectoriesAfterTheirChildren(t *testing.T) {
	requireOwnPermissions(t)
	base := tempDir(t)
	mkdir(t, base, "share/tree/sub/deeper")
	write(t, base, "share/tree/sub/deeper/f.txt", "x")
	r := newRoot(t, base)

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, // no search bit at all
		Recursive: true,
	}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Dirs != 3 || res.Files != 1 {
		t.Fatalf("result = %+v, want every entry reached before the search bits went", res)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %+v, want none", warns)
	}
	// Put the tree back, top down, so the temp dir can be removed: restoring a
	// child needs search permission on the parent that was just restored.
	for _, p := range []string{"share/tree", "share/tree/sub", "share/tree/sub/deeper"} {
		if cerr := os.Chmod(filepath.Join(base, filepath.FromSlash(p)), 0o755); cerr != nil {
			t.Fatal(cerr)
		}
	}
}

// TestChmodTreeRefusesNeverWriteComponentsBelowTheRoot is F10 inside the
// recursion: the guard only ever sees a job's root paths, so .zfs and @Recycle
// are refused again here, per component, as the walk reaches them.
func TestChmodTreeRefusesNeverWriteComponentsBelowTheRoot(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/Public/.zfs/snapshot")
	mkdir(t, base, "share/Public/@Recycle/old")
	write(t, base, "share/Public/.zfs/snapshot/keep", "x")
	write(t, base, "share/Public/@Recycle/old/keep", "x")
	write(t, base, "share/Public/ordinary.txt", "x")
	if err := os.Chmod(filepath.Join(base, "share/Public/.zfs/snapshot/keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	var warns []wproto.Warn
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/Public"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0700},
		Recursive: true,
	}, collect(&warns))
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	// /share/Public and ordinary.txt only: neither protected directory is
	// entered, and neither is changed.
	if res.Dirs != 1 || res.Files != 1 {
		t.Fatalf("result = %+v, want only the root and the ordinary file", res)
	}
	if len(warns) != 2 {
		t.Fatalf("warnings = %+v, want one per refused component", warns)
	}
	for _, w := range warns {
		if w.Code != "protected" {
			t.Fatalf("warning = %+v, want protected", w)
		}
	}
	if got := modeOf(t, filepath.Join(base, "share/Public/.zfs/snapshot/keep")); got != 0o644 {
		t.Fatalf("a file inside .zfs was changed to %s", perm.Octal(got))
	}
}

// TestChmodTreeCancelLeavesPartialWork is §4.4: no rollback, and the counts that
// come back with the cancellation are the real ones.
func TestChmodTreeCancelLeavesPartialWork(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree")
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		write(t, base, "share/tree/"+n, "x")
	}
	r := newRoot(t, base)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	emit := Emit{Prog: func(p wproto.Prog) {
		if p.Phase == wproto.PhaseWorking {
			seen++
			if seen == 2 {
				cancel()
			}
		}
	}}
	res, err := ChmodTree(ctx, r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Recursive: true,
	}, emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ChmodTree = %v, want the cancellation", err)
	}
	if res.Files == 0 {
		t.Fatal("a cancelled job must still report what it managed to do")
	}
	if res.Files >= 6 {
		t.Fatalf("Files = %d; the cancellation did nothing", res.Files)
	}
	if !strings.Contains(res.Detail, "changed") {
		t.Fatalf("Detail = %q", res.Detail)
	}
}

// TestChmodTreePreScanBoundGoesIndeterminate: past the bound the denominator is
// -1 and the reason is said once, so the UI shows an indeterminate bar rather
// than a total that is quietly a floor.
func TestChmodTreePreScanBoundGoesIndeterminate(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree")
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		write(t, base, "share/tree/"+n, "x")
	}
	r := newRoot(t, base)

	prev := modeScanMaxEntries
	modeScanMaxEntries = 2
	t.Cleanup(func() { modeScanMaxEntries = prev })

	var warns []wproto.Warn
	var totals []int64
	emit := Emit{
		Warn: func(w wproto.Warn) { warns = append(warns, w) },
		Prog: func(p wproto.Prog) {
			if p.Phase == wproto.PhaseWorking {
				totals = append(totals, p.FilesTotal)
			}
		},
	}
	res, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0700},
		Recursive: true,
	}, emit)
	if err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if res.Files != 6 || res.Dirs != 1 {
		t.Fatalf("a capped SCAN must not stop the job: %+v", res)
	}
	if len(totals) == 0 || totals[0] != -1 {
		t.Fatalf("FilesTotal = %v, want -1 (indeterminate)", totals)
	}
	found := false
	for _, w := range warns {
		if w.Code == scanCappedCode {
			found = true
		}
	}
	if !found {
		t.Fatalf("the capped scan said nothing: %v", codes(warns))
	}
}

// TestChmodTreeReportsADiffAsAnUnchangedWarning: a per-entry difference between
// what was asked and what the kernel stored is folded into the job's warnings
// (§3.4). The seam here is the mode itself — asking for a bit the filesystem
// will not keep is not something a test can arrange portably — so the property
// is proved on the one case that IS arrangeable: the diff machinery is the same
// one the single-item reply uses, and that is covered in internal/perm.
func TestChmodTreeReportsNoSpuriousWarnings(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/tree")
	write(t, base, "share/tree/f.txt", "x")
	r := newRoot(t, base)

	var warns []wproto.Warn
	if _, err := ChmodTree(context.Background(), r, nil, []string{"/share/tree"}, ChmodOptions{
		Files:     perm.ModeSpec{Mask: 0o7777, Value: 0o0640},
		Dirs:      perm.ModeSpec{Mask: 0o7777, Value: 0o0750},
		Recursive: true,
	}, collect(&warns)); err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("a chmod the kernel obeyed must warn about nothing, got %+v", warns)
	}
}

// TestPropsTargetIsNotResolvedInTheWorker is the attack the round-3 finding
// names: the route guards the resolved target, and by the time the worker looks,
// the path it was told to describe passes through a symlink. A second resolution
// would have followed it and described an object the guard never saw; the
// canonical walk calls it what it is.
//
// It is Linux-only for the reason canonical_other.go gives: off Linux there is no
// O_PATH walk and os.Root follows a symlink that stays inside the tree, so the
// round-14 refusal is a Linux answer and the CI jobs are where it is made.
func TestPropsTargetIsNotResolvedInTheWorker(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "real")
	write(t, base, "real/f.txt", "hello")
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere", "f.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// A target spelling with a symlink among its components is evidence the tree
	// moved after it was guarded, and the dialog must not describe what is there
	// now instead.
	_, err := Props(context.Background(), r, nil, "/link", "/elsewhere/f.txt")
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("Props with an unresolved target = %v, want changed", err)
	}

	// The canonical spelling of the same file is described without complaint.
	resp, err := Props(context.Background(), r, nil, "/link", "/real/f.txt")
	if err != nil {
		t.Fatalf("Props with the canonical target = %v", err)
	}
	if resp.Target == nil || resp.Target.Path != "/real/f.txt" {
		t.Fatalf("target = %+v", resp.Target)
	}
}

// TestPropsReportsTheFilesystem: FSInfo's numbers come from fstatfs on the held
// descriptor, and the mount facts from the table the front end reads too.
func TestPropsReportsTheFilesystem(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)
	plat := synthPlatform(t, synthMount{mountPoint: "/", fsType: "ext4"})

	resp, err := Props(context.Background(), r, plat, "/f.txt", "")
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if resp.FS.FSType != "ext4" {
		t.Fatalf("FSType = %q", resp.FS.FSType)
	}
	if resp.FS.Total == 0 || resp.FS.Avail == 0 {
		t.Fatalf("fstatfs gave nothing: %+v", resp.FS)
	}
	if resp.FS.Avail > resp.FS.Total {
		t.Fatalf("avail %d > total %d", resp.FS.Avail, resp.FS.Total)
	}
	if resp.Identity.Ino == 0 {
		t.Fatal("the identity must name the object the walk held")
	}
}

// TestPropsReportsTheACLBackendAndAclmode: the dialog's ACL row is the mount
// table's answer plus this object's own probe. An ordinary file on a filesystem
// with a POSIX backend and no ACL set must read "none" — if it read "posix" the
// badge would be on every file on the NAS.
func TestPropsReportsTheACLBackendAndAclmode(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	r := newRoot(t, base)

	plat := synthPlatform(t, synthMount{mountPoint: "/", fsType: "ext4"})
	plat.SetXattrProbe(func(path, name string) (int, error) {
		if name == platform.XattrPosixACL {
			return 0, platform.ErrNoData
		}
		return 0, syscall.EOPNOTSUPP
	})
	plat.Probe()

	resp, err := Props(context.Background(), r, plat, "/f.txt", "")
	if err != nil {
		t.Fatalf("Props = %v", err)
	}
	if resp.ACL.Backend != platform.ACLPosix {
		t.Fatalf("ACL.Backend = %q, want posix", resp.ACL.Backend)
	}
	if resp.ACL.State != fsx.ACLNone {
		t.Fatalf("ACL.State = %q, want none — a plain file must not be badged", resp.ACL.State)
	}
	if resp.Entry.HasACL {
		t.Fatal("HasACL is set for a file with no ACL")
	}
}

// TestListProbesTheACLStateWhenAsked exercises the real lgetxattr against a
// mount the table says has a POSIX backend. Nothing here has an ACL, so every
// entry must come back "none" — which is the answer that proves the probe ran
// (an unprobed entry is "").
func TestListProbesTheACLStateWhenAsked(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a")
	write(t, base, "a/one.txt", "1")
	r := newRoot(t, base)

	plat := synthPlatform(t, synthMount{mountPoint: "/", fsType: "ext4"})
	plat.SetXattrProbe(func(path, name string) (int, error) {
		if name == platform.XattrPosixACL {
			return 0, platform.ErrNoData
		}
		return 0, syscall.EOPNOTSUPP
	})
	plat.Probe()

	l, err := List(context.Background(), r, plat, "/a", fsx.ListOptions{ACLProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	e, ok := find(l, "one.txt")
	if !ok {
		t.Fatal("one.txt is missing from the listing")
	}
	if e.ACL != fsx.ACLNone {
		t.Fatalf("ACL = %q, want none", e.ACL)
	}
	if e.HasACL {
		t.Fatal("HasACL must be false for a file with no ACL")
	}
	for _, n := range l.Notes {
		if n == fsx.ACLProbeCappedNote {
			t.Fatal("a two-entry listing cannot have hit the probe's bound")
		}
	}
}

// TestACLProbeStopsAtItsBounds is §6.2: past 2000 entries or 64 KiB the rest of
// the page is left unprobed and the listing says so. The counters are seeded
// rather than the directory filled, because the property under test is the
// bound, not the ability to create two thousand files.
func TestACLProbeStopsAtItsBounds(t *testing.T) {
	base := tempDir(t)
	write(t, base, "f.txt", "x")
	target := filepath.Join(base, "f.txt")

	t.Run("the entry bound", func(t *testing.T) {
		p := &aclProbe{backend: platform.ACLPosix, xattr: platform.XattrPosixACL,
			bud: &aclBudget{entries: fsx.ACLProbeMaxEntries}}
		if state, ok := p.probe(aclTarget{osPath: target}); ok {
			t.Fatalf("probe past the entry bound answered %q", state)
		}
		if !p.bud.capped {
			t.Fatal("the probe must record that it stopped at a bound")
		}
	})
	t.Run("the byte bound", func(t *testing.T) {
		p := &aclProbe{backend: platform.ACLNFS4, xattr: platform.XattrNFS4ACL,
			bud: &aclBudget{bytes: fsx.ACLProbeMaxBytes}}
		if _, ok := p.probe(aclTarget{osPath: target}); ok {
			t.Fatal("probe past the byte bound still answered")
		}
		if !p.bud.capped {
			t.Fatal("the probe must record that it stopped at a bound")
		}
	})
	t.Run("below the bounds it answers", func(t *testing.T) {
		p := &aclProbe{backend: platform.ACLPosix, xattr: platform.XattrPosixACL, bud: &aclBudget{}}
		state, ok := p.probe(aclTarget{osPath: target})
		if !ok {
			t.Fatal("a fresh probe must answer")
		}
		if state != fsx.ACLNone {
			t.Fatalf("state = %q, want none", state)
		}
		if p.bud.capped {
			t.Fatal("a probe that answered has not capped")
		}
	})
}
