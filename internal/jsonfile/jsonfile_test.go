// Copied from GitBackup internal/jsonfile/jsonfile_test.go

package jsonfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Write publishes by rename, so a failure must leave the previous document
// exactly as it was — and must not leave a scratch file for the next snapshot
// to copy into the archive.
func TestWriteLeavesPreviousVersionOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	if err := Write(path, map[string]string{"name": "repo"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A channel cannot be marshalled.
	if err := Write(path, make(chan int)); err == nil {
		t.Fatal("marshalling a channel succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("the previous document changed:\n%s", after)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		for _, e := range entries {
			t.Logf("left behind: %s", e.Name())
		}
		t.Errorf("directory holds %d files, want just the published one", len(entries))
	}
}

// The published document parses, and it carries the archive's mode rather than
// CreateTemp's 0600.
func TestWritePublishesReadableDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.json")
	if err := Write(path, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("published document does not parse: %v\n%s", err, data)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("round-trip gave %v, want [a b]", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports 0666 for any writable file; only the Unix archive cares.
	if perm := fi.Mode().Perm(); perm&0o044 == 0 {
		t.Errorf("mode is %v — the rest of the archive is world-readable", perm)
	}
}
