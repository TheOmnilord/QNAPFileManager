package workerpool

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRequireRootStickyDir checks the parent gate: a normal temp directory is
// not sticky and not root-owned, so it is refused; /tmp on a Linux runner is
// root-owned and sticky, so it is accepted.
func TestRequireRootStickyDir(t *testing.T) {
	if err := requireRootStickyDir(t.TempDir()); err == nil {
		t.Error("a non-sticky, non-root temp dir was accepted as a staging parent")
	}
	if err := requireRootStickyDir("/tmp"); err != nil {
		// Every Linux system ships /tmp root-owned and sticky; if this fails the
		// runner is unusual, not the code.
		t.Skipf("/tmp is not the usual root-owned sticky dir here: %v", err)
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
