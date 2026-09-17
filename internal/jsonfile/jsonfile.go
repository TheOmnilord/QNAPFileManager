// Copied from GitBackup internal/jsonfile/jsonfile.go

// Package jsonfile writes the archive's JSON files atomically.
package jsonfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"qnapfilemanager/internal/durable"
)

// Write marshals v and publishes it at path by renaming a scratch file, so a
// reader never sees a half-written document and a crash — or a power loss,
// which is why the bytes are flushed before the name is published — leaves the
// previous version intact.
//
// The scratch file has a unique name. A fixed "<path>.tmp" is the same path
// for every process, so a CLI run alongside the daemon — both backing up the
// same repository, which nothing prevents — would have them truncate and
// write over each other, publishing a file whose first half is one dump and
// whose tail is the other. That file is valid to neither, and it would then
// be copied into every snapshot taken afterwards.
func Write(path string, v any) error { return WriteMode(path, v, 0o644) }

// WriteMode is Write with the published mode fixed by the caller.
//
// The mode is applied to the SCRATCH file, before the rename, so the document
// never exists under its final name at a wider mode than it should be. Write's
// 0644 default is right for archive data; a file holding a credential passes
// 0600 here, because chmodding after the rename leaves a window — however
// short — in which the break-glass password hash is world-readable under the
// name every reader knows (round-2 P3-5).
func WriteMode(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename has succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Flush before publishing the name. The rename is atomic, but a power loss
	// can let it outlive the data behind it, and the result is an empty or
	// half-written file standing where the last good one used to be — which is
	// then copied into every snapshot taken afterwards.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file 0600. Widen (or keep) it HERE, on the scratch
	// name, so the published file is already at its final mode the instant the
	// rename makes it visible.
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := publish(tmp, path); err != nil {
		return err
	}
	// The rename itself is an entry in the directory, and durable only once
	// the directory is flushed: without this a power cut can put the
	// previous version back under the name — harmless for a metadata dump,
	// not for a manifest that a later snapshot's base link already names.
	return durable.SyncDir(dir)
}

// ReadArchived reads a JSON document already in the archive, for a writer
// about to replace it. ok is false — with a nil error — when there is no
// capture to preserve: the file is missing, empty, or the literal null a
// previous run wrote to record "unknown". Anything else that stops the file
// being read as a document — a permission, an EIO, malformed JSON — is an
// error, and the caller must not replace the file on it: a read failure is
// not an absence, and a writer that took it for one rewrote the only copy of
// months of captured settings as null.
func ReadArchived(path string) (json.RawMessage, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, false, nil
	}
	if !json.Valid(trimmed) {
		return nil, false, fmt.Errorf("%s is not valid JSON — it cannot be read to be preserved; repair it, or delete it to let the next run rebuild it from the API", path)
	}
	return json.RawMessage(trimmed), true, nil
}
