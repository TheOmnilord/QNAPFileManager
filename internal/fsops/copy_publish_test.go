package fsops

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestOverwriteRefusesATargetThatChangedKind is round 5's third finding: place
// refuses a mismatched kind under every policy, but it decided that before a
// transfer that can run for minutes, and renameat replaces whatever it finds.
// An existing regular file swapped for a symlink during the write would have
// been renamed over — a refusal turned into a silent replacement.
func TestOverwriteRefusesATargetThatChangedKind(t *testing.T) {
	requireSymlinks(t)
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "the original bytes")
	target := filepath.Join(base, "dst", "one.txt")

	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		// While the temporary is being written, the target this overwrite was
		// decided against becomes a symlink.
		if err := os.Remove(target); err != nil {
			return 0, err
		}
		if err := os.Symlink(filepath.Join(base, "src", "a", "sub", "two.txt"), target); err != nil {
			return 0, err
		}
		return io.CopyBuffer(dst, src, buf)
	}
	t.Cleanup(func() { copyStream = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictOverwrite}, "/src/a/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	fi := lstat(t, base, "dst/one.txt")
	if kindOf(fi) != kindLink {
		t.Fatalf("dst/one.txt is a %s; the symlink that appeared there was replaced anyway", kindName(kindOf(fi)))
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the entry refused", res)
	}
	if len(log.warns) != 1 || log.warns[0].Code != warnConflict {
		t.Fatalf("warns = %v, want one %q", log.warns, warnConflict)
	}
	assertNoTempLeft(t, base, "dst")
}

// TestASwappedDestinationSymlinkIsNeverPublished is round 10's adversarial
// finding 3: the pinned link used to be proved only on the way to a chown, so
// on the ordinary NON-ROOT path — where nothing chowns — nothing checked.
// Anybody able to write the destination directory had only to replace the fresh
// link between the symlinkat and the pin: the replacement's inode became the
// recorded identity, its target was never compared, and "link -> good" was
// published as "link -> bad" with the original deleted.
func TestASwappedDestinationSymlinkIsNeverPublished(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "src")
	mkdir(t, base, "dst")
	write(t, base, "src/good.txt", "the real one")
	write(t, base, "src/bad.txt", "the other one")
	if err := os.Symlink("good.txt", filepath.Join(base, "src", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	// symlinkAt is the last thing that touches the name before it is pinned.
	prev := symlinkAtSeam
	symlinkAtSeam = func(d *dirRef, name, target string) error {
		if err := prev(d, name, target); err != nil {
			return err
		}
		if !strings.HasPrefix(d.rel, "dst") {
			return nil
		}
		// Somebody else's link, under the name this job just created.
		p := filepath.Join(base, filepath.FromSlash(d.rel), name)
		if err := os.Remove(p); err != nil {
			return err
		}
		return os.Symlink("bad.txt", p)
	}
	t.Cleanup(func() { symlinkAtSeam = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/link"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/link") {
		t.Fatal("the source link was deleted although what was published points somewhere else")
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
	// The stranger's link is left where it is: it was never this job's.
	if got, err := os.Readlink(filepath.Join(base, "dst", "link")); err == nil && got != "bad.txt" {
		t.Errorf("dst/link points at %q; nothing of somebody else's may be rewritten", got)
	}
}
