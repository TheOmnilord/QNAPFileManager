package workerpool

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStageWorkerBinaryProducesAnExecutableCopy pins the QTS hardware fix: the
// worker binary is copied to a root-owned, world-traversable directory on a
// tmpfs so a non-root worker can exec it even when the install tree (a QTS
// ext4 shared folder) denies that. The copy must be byte-identical, mode 0755,
// and its directory 0755.
func TestStageWorkerBinaryProducesAnExecutableCopy(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src", "qnapfilemanager")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("\x7fELF not really, but enough bytes to copy")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatal(err)
	}

	stageRoot := filepath.Join(tmp, "tmpfs")
	if err := os.MkdirAll(stageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	dst, err := stageWorkerBinary(src, stageRoot)
	if err != nil {
		t.Fatalf("stageWorkerBinary: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != string(want) {
		t.Fatalf("staged copy differs from the source")
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("staged binary mode = %o, want 0755", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(dst))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o755 {
		t.Errorf("staged dir mode = %o, want 0755", di.Mode().Perm())
	}
	// A re-stage overwrites in place and stays valid (a daemon restart).
	if _, err := stageWorkerBinary(src, stageRoot); err != nil {
		t.Fatalf("second stage: %v", err)
	}

	if _, err := stageWorkerBinary("", stageRoot); err == nil {
		t.Fatal("staging an empty source should fail")
	}
}
