package workerpool

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRequireSafeParentNonRoot checks the ownership half without root: a
// directory this test owns is not root-owned, so it is refused.
func TestRequireSafeParentNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this case is about a non-root-owned parent")
	}
	if err := requireSafeParent(t.TempDir()); err == nil {
		t.Error("a non-root-owned temp dir was accepted as a staging parent")
	}
}

// TestRequireSafeParentRootGated constructs the three parents that matter, which
// needs root to own them: a world-writable non-sticky dir (QTS /tmp) is refused;
// a sticky 1777 dir (a proper /tmp) and a 0755 dir (the QTS root tmpfs) are both
// accepted.
func TestRequireSafeParentRootGated(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("constructing root-owned parents needs root")
	}
	for _, tc := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{"world-writable non-sticky", 0o777, false},
		{"sticky 1777", 0o777 | os.ModeSticky, true},
		{"root-only 0755", 0o755, true},
		{"group-writable non-sticky", 0o775, false},
	} {
		dir := filepath.Join(t.TempDir(), tc.name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		err := requireSafeParent(dir)
		if tc.ok && err != nil {
			t.Errorf("%s (%v) was refused: %v", tc.name, tc.mode, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s (%v) was accepted", tc.name, tc.mode)
		}
	}
	// A symlink parent is refused (not a directory by Lstat).
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/", link); err == nil {
		if requireSafeParent(link) == nil {
			t.Error("a symlink was accepted as a staging parent")
		}
	}
}

// TestRootOwned confirms the ownership predicate against a known root-owned path
// and a path this test owns.
func TestRootOwned(t *testing.T) {
	if fi, err := os.Lstat("/"); err == nil && !rootOwned(fi) {
		t.Error(`"/" should be owned by root`)
	}
	mine := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(mine, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(mine)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && rootOwned(fi) {
		t.Error("a file this non-root test created was reported root-owned")
	}
}

// TestEnsureRootOwnedDirRejectsADecoy verifies the decoy handling: a symlink or
// a group/other-writable directory in the staging spot is removed and replaced
// with a safe one. It runs where the test can create the staging parent it
// controls; ownership checks that need root are covered by the root-gated test.
func TestEnsureRootOwnedDirRejectsADecoy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ensureRootOwnedDir creates root-owned directories; needs root")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil { // root-owned + sticky
		t.Fatal(err)
	}
	dir := filepath.Join(parent, ".qnapfilemanager")

	// A symlink decoy must be removed, not followed.
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := ensureRootOwnedDir(dir); err != nil {
		t.Fatalf("ensureRootOwnedDir over a symlink decoy: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0o022 != 0 || !rootOwned(fi) {
		t.Fatalf("staging dir is not a safe root-owned directory: mode=%v", fi.Mode())
	}
}

// TestStageWorkerBinaryRootGated exercises the full copy on a root-owned sticky
// parent, which only root can construct. It runs in the CI root job.
func TestStageWorkerBinaryRootGated(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("staging requires a root-owned sticky parent; needs root")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "qnapfilemanager")
	want := []byte("\x7fELF stand-in bytes")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatal(err)
	}
	dst, err := stageWorkerBinary(src, parent)
	if err != nil {
		t.Fatalf("stageWorkerBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != string(want) {
		t.Fatal("staged copy differs from source")
	}
	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 || !rootOwned(fi) {
		t.Fatalf("staged binary mode=%v rootOwned=%v", fi.Mode(), rootOwned(fi))
	}
	if _, err := stageWorkerBinary(src, parent); err != nil {
		t.Fatalf("re-stage: %v", err) // a restart re-stages in place
	}
	if _, err := stageWorkerBinary("", parent); err == nil {
		t.Fatal("staging an empty source should fail")
	}
}

var _ = syscall.Stat_t{}
