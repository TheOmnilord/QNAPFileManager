package fsops

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestFailedCopyNeverUnlinksSomebodyElsesFile is the round-4 finding 2, which
// the reviewer reproduced: every cleanup path unlinked the destination by NAME,
// so a process that renamed our in-progress file aside and saved an unrelated
// file under the same name — an editor writing out, a download finishing — had
// that file deleted by our tidying up.
//
// It is staged on the direct-create path, where there is no temporary at all
// and the name being cleaned up is the user's own.
func TestFailedCopyNeverUnlinksSomebodyElsesFile(t *testing.T) {
	forceNamedCreate(t)
	forceNoStaging(t)
	r, base := copyFixture(t)
	victim := filepath.Join(base, "dst", "one.txt")
	rescued := filepath.Join(base, "dst", "rescued.txt")

	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		// Our in-progress file is moved aside and somebody else's save lands
		// under the name we created.
		if err := os.Rename(victim, rescued); err != nil {
			return 0, err
		}
		if err := os.WriteFile(victim, []byte("somebody else's save"), 0o644); err != nil {
			return 0, err
		}
		return 0, errors.New("the copy failed here")
	}
	t.Cleanup(func() { copyStream = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got := readFile(t, base, "dst/one.txt"); got != "somebody else's save" {
		t.Fatalf("dst/one.txt = %q — the cleanup deleted a file that was never this job's", got)
	}
	if !exists(t, base, "dst/rescued.txt") {
		t.Error("our own partial file went missing; it is the residual the warning names")
	}
	if res.Files != 0 {
		t.Errorf("result = %+v, want the entry counted as not copied", res)
	}
	if !warnSaying(log, warnChanged, "belongs to somebody else") {
		t.Fatalf("warnings = %v, want one saying the name was left alone", log.warns)
	}
}

// TestFailedOverwriteNeverUnlinksSomebodyElsesFile is the same rule on the
// temporary: it too is only ever removed while it still names what this job
// wrote.
func TestFailedOverwriteNeverUnlinksSomebodyElsesFile(t *testing.T) {
	forceNamedCreate(t)
	forceNoStaging(t)
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "the original bytes")

	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		des, err := os.ReadDir(filepath.Join(base, "dst"))
		if err != nil {
			return 0, err
		}
		for _, de := range des {
			if !hasCopyTmpPrefix(de.Name()) {
				continue
			}
			p := filepath.Join(base, "dst", de.Name())
			if rerr := os.Rename(p, filepath.Join(base, "dst", "rescued.part")); rerr != nil {
				return 0, rerr
			}
			if werr := os.WriteFile(p, []byte("somebody else's save"), 0o644); werr != nil {
				return 0, werr
			}
		}
		return 0, errors.New("the copy failed here")
	}
	t.Cleanup(func() { copyStream = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictOverwrite}, "/src/a/one.txt"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got := readFile(t, base, "dst/one.txt"); got != "the original bytes" {
		t.Fatalf("dst/one.txt = %q — the original was disturbed by a failed overwrite", got)
	}
	found := false
	des, err := os.ReadDir(filepath.Join(base, "dst"))
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if hasCopyTmpPrefix(de.Name()) {
			found = true
			if got, _ := os.ReadFile(filepath.Join(base, "dst", de.Name())); string(got) != "somebody else's save" {
				t.Errorf("the file at the temporary name is %q", got)
			}
		}
	}
	if !found {
		t.Error("the stranger's file at the temporary name was removed; it was never this job's")
	}
	if !warnSaying(log, warnChanged, "belongs to somebody else") {
		t.Fatalf("warnings = %v, want one saying the name was left alone", log.warns)
	}
}

func hasCopyTmpPrefix(name string) bool {
	return len(name) >= len(copyTmpPrefix) && name[:len(copyTmpPrefix)] == copyTmpPrefix
}
