package fsops

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/wproto"
)

// The four races of the second review that can only be staged on a kernel that
// renames directories out from under an open descriptor and unlinks an open
// file. Windows does neither, so none of this is simulated there (INV-2).

// TestWalkFromNeverNamesItsRootAgain is finding 1: Walk's first act is to
// resolve a pathname, so a caller that had already pinned the root threw that
// away at the one moment it mattered. walkFrom starts on the descriptor.
//
// The proof is that renaming the root away mid-flight changes nothing — the
// walk enumerates the object it was handed, not whatever the old name means by
// then.
func TestWalkFromNeverNamesItsRootAgain(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "real/sub")
	write(t, base, "real/one.txt", "one")
	write(t, base, "real/sub/two.txt", "twotwo")
	mkdir(t, base, "decoy")
	write(t, base, "decoy/should-never-be-seen.txt", "planted")
	r := newRoot(t, base)

	tg, err := resolve(r, "/real", true)
	if err != nil {
		t.Fatal(err)
	}
	held, err := openDirRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := statAt(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	// The name now means something else entirely, which is the swap a
	// re-resolving walk would have followed.
	if err := os.Rename(filepath.Join(base, "real"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "decoy"), filepath.Join(base, "real")); err != nil {
		t.Fatal(err)
	}

	var rec recorder
	if err := walkFrom(context.Background(), r, nil, held, "/real", fi, WalkOptions{}, rec.visitor()); err != nil {
		t.Fatalf("walkFrom: %v", err)
	}
	if indexOf(rec.pre, "/real/one.txt") < 0 || indexOf(rec.pre, "/real/sub/two.txt") < 0 {
		t.Fatalf("walkFrom visited %v, want the tree it was handed", rec.pre)
	}
	if indexOf(rec.pre, "/real/should-never-be-seen.txt") >= 0 {
		t.Fatal("the walk followed the name instead of the descriptor")
	}
}

// TestMoveKeepsAFileRewrittenWithTheSameLengthAndMtime is the reviewer's
// finding-4 probe: identity, size and modification time are all things a writer
// controls. st_ctim is not.
func TestMoveKeepsAFileRewrittenWithTheSameLengthAndMtime(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	path := filepath.Join(base, "src", "a", "one.txt")
	before := lstat(t, base, "src/a/one.txt")
	var log jobLog
	emit := onceAt(&log, "/dst/a/one.txt", 2, func() {
		// The same inode, the same three bytes, and the modification time put
		// back exactly. Only the change time moves, and nothing an
		// unprivileged process can call moves it back.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if _, werr := f.WriteAt([]byte("ONE"), 0); werr != nil {
			t.Error(werr)
		}
		f.Close()
		if cerr := os.Chtimes(path, before.ModTime(), before.ModTime()); cerr != nil {
			t.Error(cerr)
		}
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, emit); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("a file rewritten in place with its mtime restored was deleted: the change-time check is not being made")
	}
	if got := readFile(t, base, "src/a/one.txt"); got != "ONE" {
		t.Fatalf("src/a/one.txt = %q — the rewritten contents were destroyed", got)
	}
	if !warnSaying(log, warnKept, "changed since it was copied") {
		t.Fatalf("warnings = %v, want one saying the entry changed since it was copied", log.warns)
	}
}

// TestCopyRefusesItsOwnOutputMovedIntoTheSource is the reviewer's finding-5
// probe: the container and its ancestry are not the whole story. A directory
// this job CREATED, renamed into the tree being walked, was copied back into
// itself until the volume filled.
func TestCopyRefusesItsOwnOutputMovedIntoTheSource(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/zsub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	write(t, base, "src/a/zsub/filler.txt", "filler")
	r := newRoot(t, base)

	var log jobLog
	emit := onceAt(&log, "/dst/a/one.txt", 1, func() {
		// /dst/a is this job's own output, and no ancestry check has ever heard
		// of it.
		if err := os.Rename(filepath.Join(base, "dst", "a"),
			filepath.Join(base, "src", "a", "zsub", "planted")); err != nil {
			t.Error(err)
		}
	})

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, emit)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if indexOf(log.codes(), "invalid_target") < 0 {
		t.Fatalf("warn codes = %v, want invalid_target when the job met its own output", log.codes())
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the root reported as skipped", res)
	}
	if exists(t, base, "src/a/zsub/planted/a/zsub/planted") {
		t.Fatal("the copy recursed into its own output")
	}
}

// TestOverwriteRefusesToPublishAStrangersFile is the finding-3 race, staged:
// the temporary is unlinked and another file created under its name while the
// copy writes to the held inode. Every write and the size check succeed — on an
// inode nobody can reach any more — and publishing would hand somebody else's
// file over under the user's name, after which a move would delete the source.
func TestOverwriteRefusesToPublishAStrangersFile(t *testing.T) {
	forceNamedCreate(t)
	forceNoStaging(t)
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "the original bytes")

	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		// Take the name away from the temporary this job just created, exactly
		// as anybody who can write the destination directory can.
		des, err := os.ReadDir(filepath.Join(base, "dst"))
		if err != nil {
			return 0, err
		}
		for _, de := range des {
			if !strings.HasPrefix(de.Name(), copyTmpPrefix) {
				continue
			}
			p := filepath.Join(base, "dst", de.Name())
			if rerr := os.Remove(p); rerr != nil {
				return 0, rerr
			}
			if werr := os.WriteFile(p, []byte("somebody else's file"), 0o644); werr != nil {
				return 0, werr
			}
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
	if got := readFile(t, base, "dst/one.txt"); got != "the original bytes" {
		t.Fatalf("dst/one.txt = %q — somebody else's file was published under this name", got)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the entry counted as not copied", res)
	}
	if len(log.warns) != 1 || log.warns[0].Code != warnChanged {
		t.Fatalf("warns = %v, want one %q", log.warns, warnChanged)
	}
	// The stranger's file is still there: it was never this job's to remove.
	found := false
	des, err := os.ReadDir(filepath.Join(base, "dst"))
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if !strings.HasPrefix(de.Name(), copyTmpPrefix) {
			continue
		}
		found = true
		if got, _ := os.ReadFile(filepath.Join(base, "dst", de.Name())); string(got) != "somebody else's file" {
			t.Errorf("the file at the temporary name is %q", got)
		}
	}
	if !found {
		t.Error("the stranger's file was removed; it was never this job's")
	}
}

// TestRmdirProvesTheNameOneMoreTime is round 5's finding 7: the directory's
// identity was proved before its children were removed, and emptying a
// directory takes as long as it takes. A process that renames it aside and
// creates an empty replacement under the old name in that window had the
// REPLACEMENT removed, silently — rmdir takes a name, and there is no
// rmdir-by-descriptor.
func TestRmdirProvesTheNameOneMoreTime(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/sub/one.txt", "one")
	r := newRoot(t, base)
	forceEXDEV(t)

	log := &jobLog{}
	emit := log.emit()
	swapped := false
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			// The child has just been removed and the rmdir of its directory is
			// next.
			if p.Phase == wproto.PhaseFinishing && !swapped && string(p.Current) == "/src/a/sub/one.txt" {
				swapped = true
				if err := os.Rename(filepath.Join(base, "src", "a", "sub"),
					filepath.Join(base, "src", "a", "gone")); err != nil {
					t.Error(err)
					return
				}
				mkdir(t, base, "src/a/sub")
			}
			emit.Prog(p)
		},
		Warn: emit.Warn,
	}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, wrapped); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !swapped {
		t.Fatal("the delete never reported removing the child, so nothing was staged")
	}
	if !exists(t, base, "src/a/sub") {
		t.Fatal("the empty replacement directory was removed; it was never this job's")
	}
	if !warnSaying(*log, warnKept, "replaced while its contents were being removed") {
		t.Fatalf("warnings = %v, want one naming the replaced directory", log.warns)
	}
}

// TestDirectoryTimesAreStampedThroughItsDescriptor is round 11's first finding:
// a directory's times can only be set once its children have stopped changing
// them, so it happens at the end of a subtree that may have taken minutes — and
// naming the directory again there was the last metadata step still trusting a
// lookup. A destination directory renamed aside and replaced under its name in
// that window had the REPLACEMENT stamped and the copy left with the wrong time.
func TestDirectoryTimesAreStampedThroughItsDescriptor(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/sub/one.txt", "one")
	when := time.Date(2019, 4, 2, 11, 22, 33, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(base, "src", "a", "sub"), when, when); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// While dst/a/sub's child is being copied, the directory is renamed aside
	// and an impostor takes its name.
	var log jobLog
	emit := onceAt(&log, "/dst/a/sub/one.txt", 1, func() {
		if err := os.Rename(filepath.Join(base, "dst", "a", "sub"),
			filepath.Join(base, "dst", "a", "moved")); err != nil {
			t.Error(err)
			return
		}
		mkdir(t, base, "dst/a/sub")
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, emit); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	// The copy went into the held descriptor, which followed the rename.
	if got := lstat(t, base, "dst/a/moved").ModTime(); !got.Equal(when) {
		t.Errorf("the copied directory's mtime = %v, want the source's %v", got, when)
	}
	// The impostor is untouched: this job never named it.
	if got := lstat(t, base, "dst/a/sub").ModTime(); got.Equal(when) {
		t.Error("a directory this job never created was stamped with the source's time")
	}
}
