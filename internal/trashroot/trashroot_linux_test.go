package trashroot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/platform"
)

// storageAt declares dir as an ext4 storage mount root, which is what makes it
// a trash root: the nearest enclosing Storage, non-network mount.
//
// The directory-creating half of this package's tests lives in this file
// because the sticky bit only exists on Linux (INV-2: never simulate the
// kernel). On Windows os.Chmod ignores os.ModeSticky and os.Lstat never
// reports it, so the assertion that matters could only be faked there.
func storageAt(t *testing.T, dir string) *platform.Platform {
	t.Helper()
	return mountinfo(t, storageLine(30, dir))
}

// tempMount is a temporary directory pretending to be a volume root. The
// symlinks are evaluated because /tmp is a symlink on some distributions and
// mountinfo paths are resolved.
//
// It also points the required owner (F3 — uid 0, because the root front-end is
// the only thing that creates the trash directory) at whoever this process is: a
// test running as an ordinary user can never produce a root-owned directory. On
// the CI root job the assignment changes nothing, the check runs either way, and
// TestEnsureRefusesADirectoryOwnedBySomebodyElse is what proves a mismatch is
// refused.
func tempMount(t *testing.T) string {
	t.Helper()
	expectOwner(t, os.Geteuid())
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return dir
}

// expectOwner points the trash directory's required owner at uid for one test.
func expectOwner(t *testing.T, uid int) {
	t.Helper()
	prev := wantOwner
	wantOwner = uid
	t.Cleanup(func() { wantOwner = prev })
}

// pinTempName fixes the random component of the unpublished directory's name
// for one test and reports how many times it was asked for (B3). The name is
// otherwise 16 hex digits, which is exactly what a test needs to be able to
// stand in front of.
func pinTempName(t *testing.T, name string) *int {
	t.Helper()
	calls := 0
	prev := newTempName
	newTempName = func() (string, error) {
		calls++
		return name, nil
	}
	t.Cleanup(func() { newTempName = prev })
	return &calls
}

// pinTempNameSeries hands out a DIFFERENT unpublished name on every call and
// records them, which is what a retry has to be judged by: publishing again
// under the same name would be repairing a name rather than publishing a new
// directory (R4-1).
func pinTempNameSeries(t *testing.T) *[]string {
	t.Helper()
	var used []string
	prev := newTempName
	newTempName = func() (string, error) {
		used = append(used, fmt.Sprintf("%s%016x", tempPrefix, len(used)+1))
		return used[len(used)-1], nil
	}
	t.Cleanup(func() { newTempName = prev })
	return &used
}

// pinNow skews the reference the freshness rule is measured against (R4-1): the
// nth reading of the clock is offset by the nth duration given and anything
// beyond the list is the real time. A negative offset is the stall or the
// backwards clock step the finding is about — the reference is read, the world
// moves on, and the directory the process then really does create looks far
// older than the reading, although nothing was substituted.
func pinNow(t *testing.T, skews ...time.Duration) {
	t.Helper()
	prev := now
	calls := 0
	now = func() time.Time {
		var d time.Duration
		if calls < len(skews) {
			d = skews[calls]
		}
		calls++
		return prev().Add(d)
	}
	t.Cleanup(func() { now = prev })
}

// pinLogf captures the package's logging hook for one test (R4-2).
func pinLogf(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	prev := Logf
	Logf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { Logf = prev })
	return &lines
}

// pinPublishRename replaces step (e) for one test (R3-BA2). It is the only
// instant at which a test can stand where the attacker does: after the temporary
// directory has been proved to be ours and before the publication fails.
func pinPublishRename(t *testing.T, fn func(dir *os.File, from, to string) error) {
	t.Helper()
	prev := publishRename
	publishRename = fn
	t.Cleanup(func() { publishRename = prev })
}

// leftovers lists what the mount root holds besides the published trash
// directory, so a test can assert that a refusal left no half-made directory
// behind (B3 step f).
func leftovers(t *testing.T, root string) []string {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if e.Name() != DirName {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestEnsurePublishesUnderATemporaryName is B3's happy path. The directory is
// created under an unpredictable name, proved and given its mode through its own
// descriptor, and only then renamed onto ".@qfm_trash" — so there is no instant
// at which the published name refers to a directory this process has not
// examined, and no instant at which something else could be standing at it while
// a root fchmod is aimed there.
func TestEnsurePublishesUnderATemporaryName(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	calls := pinTempName(t, tempPrefix+"0123456789abcdef")

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if err != nil || !created {
		t.Fatalf("Ensure = %q,%v,%v", dir, created, err)
	}
	if *calls != 1 {
		t.Errorf("the temporary name was asked for %d times, want once: the directory is published, not named into existence", *calls)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o777 || fi.Mode()&fs.ModeSticky == 0 {
		t.Fatalf("mode = %v, want a sticky 1777 directory", fi.Mode())
	}
	if owner, ok := ownerOf(fi); ok && owner != wantOwner {
		t.Errorf("owner = %d, want %d", owner, wantOwner)
	}
	if rest := leftovers(t, root); len(rest) != 0 {
		t.Errorf("the mount root still holds %v: the temporary directory was not consumed by the rename", rest)
	}
}

// TestEnsureRefusesAPlantedTemporaryName is the substitution B3 exists for, seen
// from the only place a test can stand: something is already at the name the
// publication is about to use. A directory that this process did not create is
// never opened, never chmodded to 1777 and never published — the whole attack
// was to get a root fchmod aimed at somebody else's directory.
func TestEnsureRefusesAPlantedTemporaryName(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	name := tempPrefix + "deadbeefdeadbeef"
	pinTempName(t, name)
	planted := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(planted, "victim"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o755); err != nil {
		t.Fatal(err)
	}

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrUnsafeTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", dir, created, err)
	}
	fi, err := os.Lstat(planted)
	if err != nil {
		t.Fatalf("the planted directory was removed: %v", err)
	}
	if fi.Mode().Perm() != 0o755 || fi.Mode()&fs.ModeSticky != 0 {
		t.Errorf("the planted directory is now %v: a root fchmod reached a directory this process did not create", fi.Mode())
	}
	if _, err := os.Lstat(filepath.Join(root, DirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("something was published as the trash directory: %v", err)
	}
}

// TestPrepareRefusesASubstitutedDirectory is step (c) on its own: the questions
// asked of the temporary directory's descriptor before a root fchmod is aimed at
// it. A directory that is not empty, whose permission bits are not the 0700 it
// was created with, or whose mtime is older than the mkdirat that supposedly
// made it, is not the directory this process just made — whatever its name says.
//
// The last two cases are R3-BA1's: each one passes EVERY check the round-2 shape
// made (a directory, right owner, 0700, link count exactly 2) and is refused only
// by a check added in round 3. "only regular files" is the hole in nlink == 2;
// "pre-existing" is any root-owned empty 0700 directory an attacker found lying
// around on the volume and renamed into place.
func TestPrepareRefusesASubstitutedDirectory(t *testing.T) {
	root := tempMount(t)
	rootFD, err := openDirNoFollow(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rootFD.Close()

	cases := []struct {
		name string
		perm fs.FileMode
		// want is errStale for the freshness-ONLY refusal and ErrUnsafeTrash for
		// every other one (R4-1), and identity says whether prepare hands the
		// refused directory's identity back — which it does exactly when its
		// caller is going to remove it and publish another.
		want     error
		identity bool
		place    func(t *testing.T, dir string)
	}{
		{"not empty", 0o700, ErrUnsafeTrash, false, func(t *testing.T, dir string) {
			// @Recycle, a share, anything worth substituting: it has children.
			if err := os.MkdirAll(filepath.Join(dir, "snapshot"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"not 0700", 0o777, ErrUnsafeTrash, false, func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"only regular files", 0o700, ErrUnsafeTrash, false, func(t *testing.T, dir string) {
			// R3-BA1: a directory holding nothing but files still has exactly two
			// links, so the retired nlink test called this empty. Reading it does
			// not.
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"pre-existing", 0o700, errStale, true, func(t *testing.T, dir string) {
			// R3-BA1: root-owned, 0700, genuinely empty — and made an hour ago, so
			// it cannot be the one the mkdirat a few syscalls back produced. A
			// rename does not refresh an inode's mtime, and an unprivileged
			// attacker cannot set the mtime of a root-owned directory.
			//
			// R4-1: this is the one refusal that is errStale rather than
			// ErrUnsafeTrash, because a directory that answers every other question
			// and only has the wrong timestamp is also what a stalled filesystem or
			// a stepped wall clock produces. It is still refused here; what changes
			// is that the caller may take it away and publish another.
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(dir, old, old); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name := "substituted-" + strings.ReplaceAll(c.name, " ", "-")
			dir := filepath.Join(root, name)
			c.place(t, dir)

			made, err := prepare(rootFD, name, dir, time.Now())
			if !errors.Is(err, c.want) {
				t.Fatalf("prepare = %v, want %v", err, c.want)
			}
			if c.want == errStale && errors.Is(err, ErrUnsafeTrash) {
				// R4-1: if the two were the same error Ensure could not tell a
				// retryable timing problem from a substitution, and would retry both.
				t.Errorf("a freshness-only refusal must not also be ErrUnsafeTrash: %v", err)
			}
			switch {
			case !c.identity && made != nil:
				// R3-BA2: a refused directory must not be handed back as an
				// identity the failure cleanup would then remove.
				t.Errorf("prepare returned an identity (%v) for a directory it refused", made.Name())
			case c.identity && made == nil:
				t.Error("prepare returned no identity for a stale directory, so the caller cannot clear it before retrying")
			}
			fi, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != c.perm || fi.Mode()&fs.ModeSticky != 0 {
				t.Errorf("mode = %v, want it left at %v: the substituted directory was given the trash mode", fi.Mode(), c.perm)
			}
		})
	}
}

// TestPrepareAcceptsTheDirectoryItJustMade is the other side of R3-BA1: the
// freshness and emptiness rules must not refuse the real thing. It also pins
// what prepare returns — the identity the cleanup re-checks.
func TestPrepareAcceptsTheDirectoryItJustMade(t *testing.T) {
	root := tempMount(t)
	rootFD, err := openDirNoFollow(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rootFD.Close()

	name := tempPrefix + "00ff00ff00ff00ff"
	createdAt := time.Now()
	if err := mkdirIn(rootFD, name, 0o700); err != nil {
		t.Fatal(err)
	}
	made, err := prepare(rootFD, name, filepath.Join(root, name), createdAt)
	if err != nil {
		t.Fatalf("prepare refused the directory it just made: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(made, fi) {
		t.Error("prepare returned the identity of something other than the directory at the name")
	}
	if fi.Mode().Perm() != 0o777 || fi.Mode()&fs.ModeSticky == 0 {
		t.Errorf("mode = %v, want 1777", fi.Mode())
	}
}

// TestEnsureRetriesATemporaryDirectoryThatIsOnlyStale is R4-1.
//
// The freshness rule compares WALL times: FileInfo.ModTime carries no monotonic
// reading, so a NAS that stalls for longer than tempMaxAge between the clock
// reading and the inode actually appearing — or a clock step in that window —
// makes a directory this process unmistakably did create look stale. Refusing
// outright turned that into a failed delete and left the temporary directory
// behind, although nothing had been substituted.
//
// It still fails closed: that directory is never used. What it does instead is
// take it away — it is root-owned, exactly 0700 and empty, and the identity is
// re-checked before the rmdir — and publish a NEW one under a NEW name against
// a fresh reading, which is the difference between a slow filesystem and an
// attack.
func TestEnsureRetriesATemporaryDirectoryThatIsOnlyStale(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	names := pinTempNameSeries(t)
	pinNow(t, -time.Hour)
	lines := pinLogf(t)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if err != nil || !created {
		t.Fatalf("Ensure = %q,%v,%v — a stalled clock must not fail a delete", dir, created, err)
	}
	if len(*names) != 2 {
		t.Fatalf("temporary names used = %v, want two: the stale attempt and the retry", *names)
	}
	if (*names)[0] == (*names)[1] {
		t.Errorf("the retry reused the temporary name %q: a retry publishes a new directory, it does not repair a name", (*names)[0])
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o777 || fi.Mode()&fs.ModeSticky == 0 {
		t.Errorf("mode = %v, want a sticky 1777 directory", fi.Mode())
	}
	if rest := leftovers(t, root); len(rest) != 0 {
		t.Errorf("the mount root still holds %v: the stale attempt was not cleaned up before the retry", rest)
	}
	if len(*lines) != 1 {
		t.Errorf("Logf lines = %v, want one: the retry is worth a line in the daemon log", *lines)
	}
}

// TestEnsureDoesNotRetryAProvenanceRefusal is the other half of R4-1: only the
// TIMESTAMP is retryable. A directory that fails any of the other three
// questions is a substitution as far as this package can tell, and a retry on
// the same volume would be a second root fchmod aimed at whatever the attacker
// can arrange next. One attempt, one refusal, nothing published.
func TestEnsureDoesNotRetryAProvenanceRefusal(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	names := pinTempNameSeries(t)
	// The directory Ensure creates really belongs to this process; saying the
	// front-end runs as somebody else is the same comparison the other way up,
	// and it is the only ownership mismatch a test without a second account can
	// make.
	expectOwner(t, os.Geteuid()+1)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrUnsafeTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", dir, created, err)
	}
	if len(*names) != 1 {
		t.Errorf("temporary names used = %v, want exactly one: a refusal that is not about the timestamp is final", *names)
	}
	if _, serr := os.Lstat(filepath.Join(root, DirName)); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("something was published as the trash directory: %v", serr)
	}
}

// TestEnsureLogsALeftoverWhenAnotherPublisherWins is R4-2.
//
// The two halves of this situation used to cancel each other out. The cleanup
// after a failed publication reports, in the error, that it could not prove the
// temporary directory was its own and left it behind (R3-BA2) — and when the
// failure is "somebody else published first", Ensure swallows that error,
// validates the winner and returns SUCCESS, so the sentence an operator needs in
// order to understand an abandoned .@qfm_trash.tmp-* on their volume was never
// written anywhere. It now goes to the daemon log before the retry.
func TestEnsureLogsALeftoverWhenAnotherPublisherWins(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	name := tempPrefix + "3333333333333333"
	pinTempName(t, name)
	lines := pinLogf(t)
	winner := filepath.Join(root, DirName)
	pinPublishRename(t, func(_ *os.File, from, _ string) error {
		// Another request publishes a perfectly good trash directory first...
		if err := os.Mkdir(winner, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(winner, 0o777|fs.ModeSticky); err != nil {
			t.Fatal(err)
		}
		// ...and in the same instant our own temporary directory is renamed aside
		// and something else takes its name, so the cleanup cannot prove what is
		// standing there is ours and must leave it alone.
		if err := os.Rename(filepath.Join(root, from), filepath.Join(root, "ours")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, from), 0o700); err != nil {
			t.Fatal(err)
		}
		return &fs.PathError{Op: "renameat", Path: DirName, Err: syscall.EEXIST}
	})

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if err != nil || created || dir != winner {
		t.Fatalf("Ensure = %q,%v,%v — want the winner's directory and no error", dir, created, err)
	}
	if len(*lines) != 1 {
		t.Fatalf("Logf lines = %v, want exactly one", *lines)
	}
	if line := (*lines)[0]; !strings.Contains(line, filepath.Join(root, name)) || !strings.Contains(line, "left in place") {
		t.Errorf("the logged line does not name the temporary directory that was left behind: %q", line)
	}
}

// TestFailedPublishRemovesOnlyItsOwnDirectory is R3-BA2.
//
// The deferred cleanup used to unlinkat(AT_REMOVEDIR) the temporary PATHNAME. An
// attacker who can rename at the mount root — which is the whole premise of B3 —
// could point that name at an unrelated empty directory between the provenance
// check and the failure, turning a refused publication into a root-mode rmdir of
// a directory of their choosing. The cleanup now removes only the inode
// provenance accepted, re-identified on a fresh O_NOFOLLOW open.
func TestFailedPublishRemovesOnlyItsOwnDirectory(t *testing.T) {
	fail := &fs.PathError{Op: "renameat", Path: DirName, Err: syscall.EIO}

	t.Run("its own temporary directory goes away", func(t *testing.T) {
		root := tempMount(t)
		plat := storageAt(t, root)
		name := tempPrefix + "1111111111111111"
		pinTempName(t, name)
		pinPublishRename(t, func(*os.File, string, string) error { return fail })

		if _, _, err := Ensure(plat, filepath.Join(root, "Public")); err == nil {
			t.Fatal("Ensure must report the failed publication")
		}
		if rest := leftovers(t, root); len(rest) != 0 {
			t.Errorf("the mount root still holds %v: our own temporary directory was not cleaned up", rest)
		}
	})

	t.Run("a substituted directory survives", func(t *testing.T) {
		root := tempMount(t)
		plat := storageAt(t, root)
		name := tempPrefix + "2222222222222222"
		pinTempName(t, name)
		victim := filepath.Join(root, "victim")
		pinPublishRename(t, func(_ *os.File, from, _ string) error {
			// The attacker's move, at the one instant it is worth anything: our
			// proved directory is renamed aside and an unrelated empty directory
			// takes its name, just before the publication fails.
			if err := os.Rename(filepath.Join(root, from), filepath.Join(root, "ours")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(victim, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(victim, filepath.Join(root, from)); err != nil {
				t.Fatal(err)
			}
			return fail
		})

		_, _, err := Ensure(plat, filepath.Join(root, "Public"))
		if err == nil {
			t.Fatal("Ensure must report the failed publication")
		}
		if _, serr := os.Lstat(filepath.Join(root, name)); serr != nil {
			t.Fatalf("the substituted directory was removed by the failure cleanup: %v", serr)
		}
		if !strings.Contains(err.Error(), "left in place") {
			t.Errorf("the error does not say a temporary directory may have been left behind: %v", err)
		}
	})
}

// TestEnsureDoesNotRepairAPlantedTrashDirectory: something that is already at
// the published name and is not a trash we may use is refused (ErrUnsafeTrash)
// and left EXACTLY as it was — not chmodded into shape, not removed, not
// adopted. The pre-B3 sequence would have found this directory through its own
// openat and turned it 1777 as root; QNAP's root-owned @Recycle is the real
// instance of it, and PLAN.md decision 10 says @Recycle is never written to.
func TestEnsureDoesNotRepairAPlantedTrashDirectory(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	dir := filepath.Join(root, DirName)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kept"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrUnsafeTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", got, created, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 || fi.Mode()&fs.ModeSticky != 0 {
		t.Errorf("mode = %v, want the planted directory untouched at 0755", fi.Mode())
	}
	if _, err := os.Lstat(filepath.Join(dir, "kept")); err != nil {
		t.Errorf("the planted directory's contents were disturbed: %v", err)
	}
	if rest := leftovers(t, root); len(rest) != 0 {
		t.Errorf("the refusal left %v behind", rest)
	}
}

// TestEnsureRefusesADirectoryOwnedBySomebodyElse is F3's ownership check: the
// owner of a sticky directory is EXEMPT from its restrictions, so a 1777
// directory that does not belong to root may have every one of its entries
// renamed or unlinked by whoever made it. Reusing one would hand a stream of
// other people's deleted files to its owner.
func TestEnsureRefusesADirectoryOwnedBySomebodyElse(t *testing.T) {
	root := tempMount(t)
	dir := filepath.Join(root, DirName)
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	plat := storageAt(t, root)
	// The directory really belongs to this process; saying the front-end runs as
	// somebody else is the same comparison the other way up, and it is the only
	// one a test without a second account can make.
	expectOwner(t, os.Geteuid()+1)

	got, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrUnsafeTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", got, created, err)
	}
	if created {
		t.Error("nothing may be reported as created here")
	}
}

// TestEnsureAppliesTheModeThroughTheDescriptor is the rest of F3. The old shape
// was os.Mkdir followed by os.Chmod — two lookups of one name, with a window
// between them in which whoever owns the parent directory could rename the new
// directory away and put a symlink in its place, so the chmod landed 1777 on
// whatever that link pointed at, as root.
//
// The observable consequence is that the directory Ensure reports is the one it
// actually made, sticky and 0777, and that a second call finds it rather than
// re-chmod'ing a name.
func TestEnsureAppliesTheModeThroughTheDescriptor(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)
	decoy := filepath.Join(root, "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if err != nil || !created {
		t.Fatalf("Ensure = %q,%v,%v", dir, created, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&fs.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf("mode = %v, want 1777 applied through the descriptor", fi.Mode())
	}
	// Nothing else on the volume was touched: the fchmod went to the descriptor
	// the mkdir produced and could not have reached a neighbour.
	dfi, err := os.Lstat(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if dfi.Mode().Perm() != 0o700 {
		t.Errorf("the decoy directory is now %v: the mode was applied by name", dfi.Mode())
	}
}

// TestEnsureCreatesASticky1777DirectoryOnce is the whole contract: the
// directory is made once, with the sticky bit the kernel will enforce, and a
// second call finds it rather than making it again.
func TestEnsureCreatesASticky1777DirectoryOnce(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public", "deep", "file.txt"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Fatal("the first Ensure must report that it created the directory — the caller audits that as a milestone")
	}
	if want := filepath.Join(root, DirName); dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory: %v", dir, fi.Mode())
	}
	if fi.Mode().Perm() != 0o777 {
		t.Fatalf("mode = %v, want 0777 regardless of the daemon's umask", fi.Mode().Perm())
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		t.Fatalf("mode = %v, want the sticky bit: without it any user could take another's trashed files", fi.Mode())
	}

	// Idempotent, and it does not touch what is already there.
	marker := filepath.Join(dir, "1001")
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	again, created, err := Ensure(plat, filepath.Join(root, "Other"))
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if created {
		t.Error("the second Ensure must not report a creation")
	}
	if again != dir {
		t.Errorf("dir = %q, want %q", again, dir)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("Ensure disturbed an existing entry: %v", err)
	}
}

// TestEnsureRefusesSomethingElseAtTheName: a symlink, a plain file or a
// directory that is not sticky is never used and never replaced. Following a
// planted symlink would let whoever made it redirect a stream of other
// people's deleted files anywhere on the NAS.
func TestEnsureRefusesSomethingElseAtTheName(t *testing.T) {
	cases := []struct {
		name  string
		place func(t *testing.T, dir string)
	}{
		{"symlink", func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), "elsewhere")
			if err := os.Mkdir(target, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"regular file", func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory without the sticky bit", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := tempMount(t)
			c.place(t, filepath.Join(root, DirName))
			plat := storageAt(t, root)

			dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
			if !errors.Is(err, ErrUnsafeTrash) {
				t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", dir, created, err)
			}
			if created {
				t.Error("nothing may be reported as created here")
			}
		})
	}
}

// TestEnsureOnAnUnwritableRootIsNoTrash: a read-only or permission-refusing
// filesystem has no trash, which the caller turns into a permanent delete with
// a confirmation rather than a half-made directory or an internal error.
func TestEnsureOnAnUnwritableRootIsNoTrash(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on (INV-2: the kernel decides)")
	}
	root := tempMount(t)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	plat := storageAt(t, root)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrNoTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrNoTrash", dir, created, err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, DirName)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("something was created on a read-only root: %v", statErr)
	}
}

// TestEnsureUsesTheNearestStorageMount is decision 10 in one assertion: on a
// hero-shaped table the trash lands on the share's own dataset, not on the pool
// root, because a rename into the pool root would cross devices.
func TestEnsureUsesTheNearestStorageMount(t *testing.T) {
	pool := tempMount(t)
	share := filepath.Join(pool, "Public")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	plat := mountinfo(t,
		line(30, "0:50", pool, "zfs", "pool0/vol"),
		line(31, "0:51", share, "zfs", "pool0/vol/Public"),
	)
	dir, created, err := Ensure(plat, filepath.Join(share, "a", "b"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Error("the directory should have been created")
	}
	if want := filepath.Join(share, DirName); dir != want {
		t.Fatalf("dir = %q, want %q (the share's own dataset, next to @Recycle)", dir, want)
	}
}
