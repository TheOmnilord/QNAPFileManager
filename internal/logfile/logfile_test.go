// Copied from GitBackup internal/logfile/logfile_test.go

package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendsAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "gitbackup.log")
	w, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	w2, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	w2.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\n" {
		t.Errorf("a restart truncated the log: %q", data)
	}
}

func TestRotatesAtLimitAndKeepsOneGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gitbackup.log")
	w, err := Open(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	line := strings.Repeat("x", 20) + "\n"
	for i := 0; i < 10; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(current)) > 64 {
		t.Errorf("current log is %d bytes, past the 64-byte limit", len(current))
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("no previous generation was kept: %v", err)
	}
	// Exactly one generation: a .2 would mean unbounded growth.
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("a second generation was kept; the log is not bounded")
	}
}

// A single entry larger than the limit must still be written whole rather
// than being split or dropped.
func TestOversizeEntryIsWrittenWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gitbackup.log")
	w, err := Open(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("short\n")); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("y", 100) + "\n"
	if _, err := w.Write([]byte(big)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != big {
		t.Errorf("oversize entry was not written whole into the fresh file: %q", data)
	}
}

func TestWriteAfterCloseDoesNotPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gitbackup.log")
	w, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("writing to a closed log should fail")
	}
	if err := w.Close(); err != nil {
		t.Errorf("double close: %v", err)
	}
}
