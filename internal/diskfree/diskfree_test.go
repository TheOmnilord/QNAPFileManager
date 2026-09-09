package diskfree

import (
	"path/filepath"
	"runtime"
	"testing"
)

// GitBackup shipped this package without tests. It is small, but Free is what
// the upload path will size a transfer against and SameDevice is how the QTS
// /share RAM disk is detected, so both deserve at least a smoke test on every
// platform the daemon builds for.
func TestFree(t *testing.T) {
	dir := t.TempDir()
	n, err := Free(dir)
	if err != nil {
		t.Fatalf("Free(%s): %v", dir, err)
	}
	if n == 0 {
		t.Errorf("Free(%s) = 0 — a writable temporary directory should have some room", dir)
	}
	if _, err := Free(filepath.Join(dir, "no", "such", "path")); err == nil {
		t.Error("Free of a missing path should fail rather than report a number")
	}
}

func TestSameDevice(t *testing.T) {
	dir := t.TempDir()
	same, err := SameDevice(dir, dir)
	if err != nil {
		t.Fatalf("SameDevice: %v", err)
	}
	if runtime.GOOS == "windows" {
		// The Windows build is a deliberate stub: this is a QTS-specific
		// check and there is no /share RAM disk to detect.
		if same {
			t.Error("the Windows stub must report false rather than guess")
		}
		return
	}
	if !same {
		t.Error("a directory must be on the same device as itself")
	}
}
