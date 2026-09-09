// Copied from GitBackup internal/logfile/rotate_failure_test.go

package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rotation used to delete the previous generation before finding out
// whether the rename would work. When it did not — a log viewer holding
// the current file open is enough on Windows — yesterday's log was gone
// and no rotation had happened: the investigation lost exactly the history
// this file is kept for.
func TestFailedRotationKeepsThePreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitbackup.log")
	previous := path + ".1"
	if err := os.WriteFile(previous, []byte("yesterday's log"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Fail exactly the rename that a locked current log fails: moving it
	// onto the previous generation's name.
	realRename := renameFile
	renameFile = func(from, to string) error {
		if from == path {
			return os.ErrPermission
		}
		return realRename(from, to)
	}
	t.Cleanup(func() { renameFile = realRename })

	w, err := Open(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 4; i++ {
		if _, err := w.Write([]byte("a line long enough to pass the limit\n")); err != nil {
			t.Fatalf("logging must continue even when rotation cannot: %v", err)
		}
	}

	data, err := os.ReadFile(previous)
	if err != nil {
		t.Fatalf("the previous generation was destroyed by a rotation that did not happen: %v", err)
	}
	if string(data) != "yesterday's log" {
		t.Errorf("previous generation = %q, want it untouched", data)
	}
	// And no scratch name is left lying around.
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("a leftover .2 file survived the failed rotation")
	}
}

// The ordinary case must still keep exactly one previous generation, with
// no scratch file beside it.
func TestSuccessfulRotationLeavesOneGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitbackup.log")
	w, err := Open(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 8; i++ {
		if _, err := w.Write([]byte("a line long enough to pass the limit\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("rotation kept no previous generation: %v", err)
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("rotation left a .2 scratch file behind")
	}
}

// A rotation that cannot reopen the file must not end logging for the life
// of the process — the next write tries again.
func TestWriterRecoversAfterAFailedReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitbackup.log")
	w, err := Open(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("first line\n")); err != nil {
		t.Fatal(err)
	}
	// Simulate the aftermath of a reopen that failed: no handle, but not
	// closed either.
	w.mu.Lock()
	w.f.Close()
	w.f = nil
	w.mu.Unlock()

	if _, err := w.Write([]byte("after the stumble\n")); err != nil {
		t.Fatalf("the writer never came back: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "after the stumble") {
		t.Errorf("the recovered write did not reach the log: %q", data)
	}
}

// A rotation interrupted between its two renames leaves the previous
// generation stranded at .2, where nothing reads it. The next rotation
// used to delete that file first thing — throwing away the only surviving
// copy of yesterday's log through the recovery path rather than the happy
// one.
// The scenario is a rotation that cannot complete while a generation is
// stranded. A successful rotation discarding the older copy is the policy
// working — one previous generation is kept, and the log just rotated out
// is now that one. The defect is losing the stranded copy for nothing.
func TestStrandedGenerationSurvivesAFailedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitbackup.log")
	// The state a killed process leaves behind: no .1, the real previous
	// generation sitting at .2 where nothing reads it.
	if err := os.WriteFile(path+".2", []byte("yesterday's log"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Rotation cannot complete: the current log will not move aside.
	realRename := renameFile
	renameFile = func(from, to string) error {
		if from == path {
			return os.ErrPermission
		}
		return realRename(from, to)
	}
	t.Cleanup(func() { renameFile = realRename })

	w, err := Open(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 4; i++ {
		if _, err := w.Write([]byte("a line long enough to pass the limit\n")); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing was superseded, so those bytes must still be somewhere.
	for _, candidate := range []string{path + ".1", path + ".2"} {
		if data, err := os.ReadFile(candidate); err == nil && string(data) == "yesterday's log" {
			return
		}
	}
	t.Error("the stranded previous generation was deleted by a rotation that never happened")
}
