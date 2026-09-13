package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The M2-B engine's tests. Everything that depends on Linux semantics — mode
// bits, fifos, ownership, inode identity — is skipped elsewhere rather than
// simulated (INV-2); the CI non-root, root and ZFS jobs run those for real.

// copyFixture builds
//
//	/src/a/one.txt      3 bytes
//	/src/a/sub/two.txt  6 bytes
//	/src/a/empty/       empty
//	/dst/
func copyFixture(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "src/a/empty")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	write(t, base, "src/a/sub/two.txt", "twotwo")
	return newRoot(t, base), base
}

func copyReq(dst string, o wproto.CopyOptions, srcs ...string) wproto.CopyReq {
	req := wproto.CopyReq{DstDir: []byte(dst), Opts: o}
	for _, s := range srcs {
		req.Src = append(req.Src, []byte(s))
	}
	return req
}

func readFile(t *testing.T, base, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

func lstat(t *testing.T, base, rel string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("lstat %s: %v", rel, err)
	}
	return fi
}

// requireRoot skips a test whose subject is something only uid 0 may do. The CI
// root job runs them.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("this asserts a chown, which only root may make")
	}
}

// requireUnixModes skips a test about POSIX mode bits. Windows has none of the
// shape being asserted.
func requireUnixModes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not exist here")
	}
}

// forceEXDEV makes every root rename answer "different filesystems", which is
// what a move between two QuTS hero shares really gets. Two filesystems cannot
// be produced on a dev box, and the branch behind this is the whole
// copy-verify-delete half of a move.
func forceEXDEV(t *testing.T) {
	t.Helper()
	prev := renameRoot
	renameRoot = func(dst, srcParent *dirRef, fromName, toName string, noReplace bool) error {
		// The real errno, wrapped the way renameFrom wraps it, so isCrossDevice
		// classifies it exactly as it classifies the kernel's own.
		return &fs.PathError{Op: "renameat", Path: fromName, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { renameRoot = prev })
}

// buildingIn reports whether a creation seam was handed the place where the
// children of one destination directory are built: the private staging
// directory inside it, or — where there is none — the directory itself.
//
// Every seam that stages a substitution has to ask this rather than compare a
// spelling, because where this engine builds is exactly what rounds 14 and 15
// changed twice.
func buildingIn(rel, dir string) bool {
	return rel == dir || strings.HasPrefix(rel, dir+"/"+copyTmpPrefix)
}

// forceNoStaging makes the engine build at the name the placement chose, in the
// destination directory itself, as it does where no private staging directory
// can be proved. The destination stays private, so the fallback is the
// build-in-place one and not the refusal.
//
// It is what every race staged on a half-made object's NAME needs: inside a
// staging directory there is no name for anybody else to take, which is the
// whole point of staging.
func forceNoStaging(t *testing.T) {
	t.Helper()
	prev := aclFactsOf
	aclFactsOf = func(d *dirRef) (aclFacts, error) {
		return aclFacts{otherWriter: strings.Contains(d.rel, stageSuffix)}, nil
	}
	t.Cleanup(func() { aclFactsOf = prev })
}

// forceNamedCreate makes the engine create destination files under a NAME, as
// it does on a filesystem with no O_TMPFILE.
//
// It is how the fallback path is exercised on a kernel that has one — and it is
// what every race staged on a half-written file's name needs, because on the
// unnamed path there is no name for anybody to take away. That is the whole
// point of the unnamed path; these tests are what is left of the old one.
func forceNamedCreate(t *testing.T) {
	t.Helper()
	prev := openUnnamedFile
	openUnnamedFile = func(d *dirRef, mode os.FileMode) (*os.File, error) {
		return nil, errNoUnnamed
	}
	t.Cleanup(func() { openUnnamedFile = prev })
}

// fakeFree puts a number in front of the free-space measurement.
func fakeFree(t *testing.T, avail uint64, ok bool) {
	t.Helper()
	prev := statfsAvail
	statfsAvail = func(d *dirRef) (uint64, bool, error) { return avail, ok, nil }
	t.Cleanup(func() { statfsAvail = prev })
}

// failAfter makes the transfer of every file stop after n bytes, so the
// destination's state after a failure can be observed.
func failAfter(t *testing.T, n int64, cause error) {
	t.Helper()
	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		if n > 0 {
			_, _ = dst.Write(make([]byte, n))
		}
		return n, cause
	}
	t.Cleanup(func() { copyStream = prev })
}

func TestCopyTreeCopiesEverythingItShould(t *testing.T) {
	r, base := copyFixture(t)
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a healthy copy: %v", log.warns)
	}
	// 2 files, 3 directories (a, sub, empty), 9 bytes — the same numbers the
	// pre-scan counted, which is what makes the progress denominator usable.
	if res.Files != 2 || res.Dirs != 3 || res.Bytes != 9 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want 2 files, 3 dirs, 9 bytes, nothing skipped", res)
	}
	if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
		t.Errorf("dst/a/one.txt = %q", got)
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Errorf("dst/a/sub/two.txt = %q", got)
	}
	if !exists(t, base, "dst/a/empty") {
		t.Error("the empty directory was not created")
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Error("a copy removed its source")
	}
}

// TestCopyScansBeforeItWrites pins the two-phase shape (§1.10): the scan gives
// the bar its denominator before a single byte moves.
func TestCopyScansBeforeItWrites(t *testing.T) {
	r, _ := copyFixture(t)
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	var scanned, worked bool
	for _, p := range log.progs {
		switch p.Phase {
		case wproto.PhaseScanning:
			scanned = true
			if worked {
				t.Fatal("a scanning update arrived after the copy had started")
			}
		case wproto.PhaseWorking:
			worked = true
			if p.FilesTotal != 5 || p.BytesTotal != 9 {
				t.Fatalf("progress = %+v, want the pre-scan's 5 items / 9 bytes", p)
			}
		}
	}
	if !scanned || !worked {
		t.Fatalf("phases seen: scanning=%v working=%v", scanned, worked)
	}
}

// TestCopyRecreatesASymlinkAndNeverFollowsIt: the link is copied as the link it
// is, with its target text byte for byte, and nothing is read through it.
func TestCopyRecreatesASymlinkAndNeverFollowsIt(t *testing.T) {
	requireSymlinks(t)
	r, base := copyFixture(t)
	if err := os.Symlink("sub/two.txt", filepath.Join(base, "src", "a", "link")); err != nil {
		t.Fatal(err)
	}
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings: %v", log.warns)
	}
	fi := lstat(t, base, "dst/a/link")
	if fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("dst/a/link is a %v, want a symlink — the copy followed it", fi.Mode())
	}
	// Compared against what the SOURCE link actually reads back as, not against
	// the literal that was written: Windows rewrites the separators of a target
	// when the link is created, and the property under test is that the copy
	// reproduces whatever is there byte for byte.
	want, err := os.Readlink(filepath.Join(base, "src", "a", "link"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(base, "dst", "a", "link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != want {
		t.Errorf("link target = %q, want the source's own text %q", target, want)
	}
	if res.Files != 3 {
		t.Errorf("result = %+v, want the link counted as an item", res)
	}
}

func TestCopyPreservesTheModificationTime(t *testing.T) {
	r, base := copyFixture(t)
	when := time.Date(2019, 4, 2, 11, 22, 33, 0, time.UTC)
	src := filepath.Join(base, "src", "a", "one.txt")
	if err := os.Chtimes(src, when, when); err != nil {
		t.Fatal(err)
	}
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got := lstat(t, base, "dst/one.txt").ModTime()
	if !got.Equal(when) {
		t.Fatalf("mtime = %v, want %v", got, when)
	}
}

// TestCopyStripsTheSpecialBits: setuid, setgid and sticky are never propagated
// (§1.5). A copy that carried a setuid bit across would be a privilege
// escalation in a file manager.
func TestCopyStripsTheSpecialBits(t *testing.T) {
	requireUnixModes(t)
	r, base := copyFixture(t)
	src := filepath.Join(base, "src", "a", "one.txt")
	if err := os.Chmod(src, 0o755|os.ModeSetuid|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	m := lstat(t, base, "dst/one.txt").Mode()
	if m&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		t.Fatalf("destination mode = %v, want the special bits gone", m)
	}
	// The umask may clear group and other bits; it never clears the owner's,
	// so that is the half this can assert without reading the process umask.
	if m.Perm()&0o700 != 0o700 {
		t.Fatalf("destination mode = %v, want the owner's bits carried over", m)
	}
}

func TestCopyConflictPolicies(t *testing.T) {
	for _, tc := range []struct {
		policy   string
		wantAt   string // path that must hold the source's bytes afterwards
		wantKeep string // path that must still hold the old bytes ("" = gone)
		wantCode string
	}{
		{policy: wproto.ConflictSkip, wantKeep: "dst/one.txt", wantCode: warnExists},
		{policy: wproto.ConflictOverwrite, wantAt: "dst/one.txt"},
		{policy: wproto.ConflictRename, wantAt: "dst/one (2).txt", wantKeep: "dst/one.txt"},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			r, base := copyFixture(t)
			write(t, base, "dst/one.txt", "older")
			var log jobLog

			res, err := Copy(context.Background(), r, nil,
				copyReq("/dst", wproto.CopyOptions{Conflict: tc.policy}, "/src/a/one.txt"), false, log.emit())
			if err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if tc.wantAt != "" {
				if got := readFile(t, base, tc.wantAt); got != "one" {
					t.Errorf("%s = %q, want the source's bytes", tc.wantAt, got)
				}
			}
			switch tc.policy {
			case wproto.ConflictSkip:
				if got := readFile(t, base, "dst/one.txt"); got != "older" {
					t.Errorf("skip overwrote the destination: %q", got)
				}
				if res.Skipped != 1 {
					t.Errorf("result = %+v, want one skip", res)
				}
			case wproto.ConflictRename:
				if got := readFile(t, base, "dst/one.txt"); got != "older" {
					t.Errorf("keep-both disturbed the existing file: %q", got)
				}
			}
			if tc.wantCode != "" {
				if len(log.warns) != 1 || log.warns[0].Code != tc.wantCode {
					t.Fatalf("warns = %v, want one %q", log.warns, tc.wantCode)
				}
			} else if len(log.warns) != 0 {
				t.Fatalf("warns = %v, want none", log.warns)
			}
		})
	}
}

// TestCopyMergesDirectories: a directory meeting a directory of the same name
// merges under every policy — nobody has ever meant "delete the folder that is
// there first" (§1.3).
func TestCopyMergesDirectories(t *testing.T) {
	for _, policy := range []string{wproto.ConflictSkip, wproto.ConflictOverwrite, wproto.ConflictRename} {
		t.Run(policy, func(t *testing.T) {
			r, base := copyFixture(t)
			mkdir(t, base, "dst/a")
			write(t, base, "dst/a/keep.txt", "kept")
			var log jobLog

			if _, err := Copy(context.Background(), r, nil,
				copyReq("/dst", wproto.CopyOptions{Conflict: policy}, "/src/a"), false, log.emit()); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if got := readFile(t, base, "dst/a/keep.txt"); got != "kept" {
				t.Errorf("the merge disturbed what was already there: %q", got)
			}
			if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
				t.Errorf("dst/a/one.txt = %q", got)
			}
			if exists(t, base, "dst/a (2)") {
				t.Error("a directory was given a keep-both name instead of merging")
			}
		})
	}
}

// TestCopyTypeMismatchIsRefusedUnderEveryPolicy: a file over a folder, or a
// folder over a file, is not a replacement — it is a destruction — so it is a
// warning and a skip whatever the policy says.
func TestCopyTypeMismatchIsRefusedUnderEveryPolicy(t *testing.T) {
	for _, policy := range []string{wproto.ConflictSkip, wproto.ConflictOverwrite, wproto.ConflictRename} {
		t.Run(policy, func(t *testing.T) {
			r, base := copyFixture(t)
			// A FILE at the destination called "a", where the source is a folder.
			write(t, base, "dst/a", "not a folder")
			var log jobLog

			res, err := Copy(context.Background(), r, nil,
				copyReq("/dst", wproto.CopyOptions{Conflict: policy}, "/src/a"), false, log.emit())
			if err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if res.Skipped != 1 || res.Files != 0 {
				t.Fatalf("result = %+v, want the root refused", res)
			}
			if len(log.warns) != 1 || log.warns[0].Code != warnConflict {
				t.Fatalf("warns = %v, want one %q", log.warns, warnConflict)
			}
			if got := readFile(t, base, "dst/a"); got != "not a folder" {
				t.Errorf("the destination file was disturbed: %q", got)
			}
		})
	}
}

// TestOverwriteWritesATemporaryAndRenamesIt is the §1.3 guarantee: a copy that
// fails half way leaves the ORIGINAL destination exactly as it was, and leaves
// nothing else behind either.
func TestOverwriteWritesATemporaryAndRenamesIt(t *testing.T) {
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "the original bytes")
	failAfter(t, 2, errors.New("the disk went away"))
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictOverwrite}, "/src/a/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the file refused", res)
	}
	if got := readFile(t, base, "dst/one.txt"); got != "the original bytes" {
		t.Fatalf("dst/one.txt = %q — a failed overwrite damaged the original", got)
	}
	des, err := os.ReadDir(filepath.Join(base, "dst"))
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), copyTmpPrefix) {
			t.Fatalf("a temporary was left behind: %q", de.Name())
		}
	}
}

// TestCopyRefusesAFolderIntoItself, before anything is created — including when
// the destination is spelled through a symlink, which a lexical test on the
// REQUEST would not have caught (§1.7).
func TestCopyRefusesAFolderIntoItself(t *testing.T) {
	t.Run("directly", func(t *testing.T) {
		r, base := copyFixture(t)
		var log jobLog
		res, err := Copy(context.Background(), r, nil, copyReq("/src/a/sub", wproto.CopyOptions{}, "/src/a"), false, log.emit())
		if err != nil {
			t.Fatalf("Copy: %v", err)
		}
		if res.Skipped != 1 || res.Files != 0 || res.Dirs != 0 {
			t.Fatalf("result = %+v, want a refusal with nothing created", res)
		}
		if len(log.warns) != 1 || log.warns[0].Code != "invalid_target" {
			t.Fatalf("warns = %v, want invalid_target", log.warns)
		}
		if exists(t, base, "src/a/sub/a") {
			t.Fatal("the copy started before it was refused")
		}
	})

	t.Run("through a symlink", func(t *testing.T) {
		requireSymlinks(t)
		r, base := copyFixture(t)
		if err := os.Symlink(filepath.Join(base, "src", "a", "sub"), filepath.Join(base, "inside")); err != nil {
			t.Fatal(err)
		}
		var log jobLog
		res, err := Copy(context.Background(), r, nil, copyReq("/inside", wproto.CopyOptions{}, "/src/a"), false, log.emit())
		if err != nil {
			t.Fatalf("Copy: %v", err)
		}
		if res.Skipped != 1 || res.Dirs != 0 {
			t.Fatalf("result = %+v, want a refusal", res)
		}
		if len(log.warns) != 1 || log.warns[0].Code != "invalid_target" {
			t.Fatalf("warns = %v, want invalid_target", log.warns)
		}
	})
}

// TestCopyCancelledLeavesWhatItHadDone: nothing is rolled back, and the error
// is the cancellation so the worker can report a partial result.
func TestCopyCancelledLeavesWhatItHadDone(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	for i := 0; i < 40; i++ {
		write(t, base, fmt.Sprintf("src/a/f%02d.txt", i), "x")
	}
	r := newRoot(t, base)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &jobLog{}
	emit := log.emit()
	seen := 0
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			emit.Prog(p)
			if p.Phase == wproto.PhaseWorking {
				seen++
				if seen == 5 {
					cancel()
				}
			}
		},
		Warn: emit.Warn,
	}
	res, err := Copy(ctx, r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, wrapped)
	if err == nil {
		t.Fatal("Copy must report the cancellation")
	}
	if res.Files == 0 || res.Files >= 40 {
		t.Fatalf("result = %+v, want a partial count", res)
	}
	left, err := os.ReadDir(filepath.Join(base, "dst", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) == 0 {
		t.Fatal("a cancelled copy rolled its work back")
	}
	if len(left) >= 40 {
		t.Fatalf("%d files were copied; the cancellation was not honoured", len(left))
	}
}

// TestCopyRefusesWhenThereIsNotEnoughRoom: the refusal is made before anything
// is written, and it is the JOB's error rather than a per-item warning (§1.9).
func TestCopyRefusesWhenThereIsNotEnoughRoom(t *testing.T) {
	r, base := copyFixture(t)
	fakeFree(t, 8, true) // the tree is 9 bytes
	var log jobLog

	_, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if !errors.Is(err, fsx.ErrNoSpace) {
		t.Fatalf("Copy = %v, want ErrNoSpace", err)
	}
	if exists(t, base, "dst/a") {
		t.Fatal("the copy created something before refusing")
	}

	// And with room it proceeds, which is what proves the refusal was the
	// comparison and not the seam being installed at all.
	fakeFree(t, 1<<30, true)
	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy with room: %v", err)
	}
}

// TestMoveOnOneFilesystemIsARename: no bytes are read, the source is gone, and
// the object at the destination is the very same one (Linux, where identity can
// be observed at all).
func TestMoveOnOneFilesystemIsARename(t *testing.T) {
	r, base := copyFixture(t)
	before := lstat(t, base, "src/a/one.txt")
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean move: %v", log.warns)
	}
	if res.Files != 1 || res.Bytes != 3 {
		t.Fatalf("result = %+v, want the scanned totals credited to the rename", res)
	}
	if exists(t, base, "src/a/one.txt") {
		t.Fatal("the source is still there")
	}
	after := lstat(t, base, "dst/one.txt")
	if same, known := sameObject(before, after); known && !same {
		t.Fatal("the destination is a different object: this was a copy, not a rename")
	}
}

// TestMoveAcrossFilesystemsCopiesThenDeletes drives the EXDEV fallback — the
// ordinary case on QuTS hero, where every share is its own dataset.
func TestMoveAcrossFilesystemsCopiesThenDeletes(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean move: %v", log.warns)
	}
	if res.Files != 2 || res.Dirs != 3 {
		t.Fatalf("result = %+v, want the whole tree copied", res)
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Errorf("dst/a/sub/two.txt = %q", got)
	}
	if exists(t, base, "src/a") {
		t.Fatal("the source was not removed after a verified copy")
	}
	// The delete of the source is phase "finishing" (§1.10).
	finishing := false
	for _, p := range log.progs {
		if p.Phase == wproto.PhaseFinishing {
			finishing = true
		}
	}
	if !finishing {
		t.Error("no finishing-phase progress was reported for the source delete")
	}
}

// TestMoveKeepsASourceWhoseCopyWarned is the rule the whole feature turns on:
// the source of a root is deleted only when that root copied with zero warnings
// and zero skips (§1.1).
func TestMoveKeepsASourceWhoseCopyWarned(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	// A FILE at the destination where the source has a directory: a type
	// mismatch, which is refused under every policy — one warning, one skip.
	mkdir(t, base, "dst/a")
	write(t, base, "dst/a/sub", "not a folder")
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/sub/two.txt") {
		t.Fatal("the source was deleted even though part of it could not be copied")
	}
	codes := log.codes()
	if indexOf(codes, warnKept) < 0 {
		t.Fatalf("warn codes = %v, want a %q warning naming the kept source", codes, warnKept)
	}
	if res.Detail == "" {
		t.Error("the job says nothing about the source it kept")
	}
}

// TestMoveCancelledLeavesBothCopies: a cancelled move never deletes, whatever
// it managed to copy (§1.1).
func TestMoveCancelledLeavesBothCopies(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	for i := 0; i < 40; i++ {
		write(t, base, fmt.Sprintf("src/a/f%02d.txt", i), "x")
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &jobLog{}
	emit := log.emit()
	seen := 0
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			emit.Prog(p)
			if p.Phase == wproto.PhaseWorking {
				seen++
				if seen == 5 {
					cancel()
				}
			}
		},
		Warn: emit.Warn,
	}
	if _, err := Copy(ctx, r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, wrapped); err == nil {
		t.Fatal("the move must report the cancellation")
	}
	if !exists(t, base, "src/a/f00.txt") {
		t.Fatal("a cancelled move deleted its source")
	}
}

// TestMoveIntoTheDirectoryItIsAlreadyIn is the no-op the route refuses
// lexically and the engine refuses again (§1.7): nothing to do under skip and
// overwrite, a "(2)" under keep-both.
func TestMoveIntoTheDirectoryItIsAlreadyIn(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		r, base := copyFixture(t)
		var log jobLog
		res, err := Copy(context.Background(), r, nil, copyReq("/src/a", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit())
		if err != nil {
			t.Fatalf("Copy(move): %v", err)
		}
		if res.Skipped != 1 {
			t.Fatalf("result = %+v, want one skip", res)
		}
		if len(log.warns) != 1 || log.warns[0].Code != warnExists {
			t.Fatalf("warns = %v, want %q", log.warns, warnExists)
		}
		if !exists(t, base, "src/a/one.txt") {
			t.Fatal("the no-op move removed the file")
		}
	})

	t.Run("keep both", func(t *testing.T) {
		r, base := copyFixture(t)
		var log jobLog
		if _, err := Copy(context.Background(), r, nil,
			copyReq("/src/a", wproto.CopyOptions{Conflict: wproto.ConflictRename}, "/src/a/one.txt"), false, log.emit()); err != nil {
			t.Fatalf("Copy: %v", err)
		}
		if got := readFile(t, base, "src/a/one (2).txt"); got != "one" {
			t.Fatalf("src/a/one (2).txt = %q", got)
		}
		if got := readFile(t, base, "src/a/one.txt"); got != "one" {
			t.Fatalf("the original was disturbed: %q", got)
		}
	})
}

// TestCopyAppliesTheRequestedOwnerToEveryCreatedEntry (§1.4). Root only: the
// kernel refuses anybody else, which is exactly why the engine does not try.
func TestCopyAppliesTheRequestedOwnerToEveryCreatedEntry(t *testing.T) {
	requireRoot(t)
	requireSymlinks(t)
	r, base := copyFixture(t)
	if err := os.Symlink("sub/two.txt", filepath.Join(base, "src", "a", "link")); err != nil {
		t.Fatal(err)
	}
	var log jobLog

	// GID -1 inherits, which is the documented meaning and what keeps a
	// destination's setgid group intact.
	opts := wproto.CopyOptions{As: &wproto.CreateAs{UID: 1, GID: -1}}
	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", opts, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings: %v", log.warns)
	}
	for _, rel := range []string{"dst/a", "dst/a/sub", "dst/a/empty", "dst/a/one.txt", "dst/a/sub/two.txt", "dst/a/link"} {
		uid, _, _, ok := statDetail(lstat(t, base, rel))
		if !ok {
			t.Fatalf("%s: no ownership to read", rel)
		}
		if uid != 1 {
			t.Errorf("%s is owned by uid %d, want 1 — every CREATED entry is chowned", rel, uid)
		}
	}
	// The destination directory itself was not created by this job and must be
	// left alone.
	if uid, _, _, ok := statDetail(lstat(t, base, "dst")); ok && uid != os.Geteuid() {
		t.Errorf("the pre-existing destination was chowned to %d", uid)
	}
}

// TestMoveByCopyPreservesTheSourceOwner: what the rename it fell back from
// would have done (§1.4). As is ignored for a move.
func TestMoveByCopyPreservesTheSourceOwner(t *testing.T) {
	requireRoot(t)
	r, base := copyFixture(t)
	for _, rel := range []string{"src/a", "src/a/sub", "src/a/one.txt", "src/a/sub/two.txt"} {
		if err := os.Lchown(filepath.Join(base, filepath.FromSlash(rel)), 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	forceEXDEV(t)
	var log jobLog

	// As is set and must be ignored: a move reproduces the source's own owner.
	opts := wproto.CopyOptions{As: &wproto.CreateAs{UID: 2, GID: 2}}
	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", opts, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings: %v", log.warns)
	}
	for _, rel := range []string{"dst/a", "dst/a/sub", "dst/a/one.txt", "dst/a/sub/two.txt"} {
		uid, gid, _, ok := statDetail(lstat(t, base, rel))
		if !ok {
			t.Fatalf("%s: no ownership to read", rel)
		}
		if uid != 1 || gid != 1 {
			t.Errorf("%s is owned by %d:%d, want the source's 1:1", rel, uid, gid)
		}
	}
}

func TestKeepBothName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		isDir bool
		n     int
		want  string
	}{
		{name: "report.pdf", n: 2, want: "report (2).pdf"},
		{name: "report.pdf", n: 3, want: "report (3).pdf"},
		{name: "notes", n: 2, want: "notes (2)"},
		{name: ".bashrc", n: 2, want: ".bashrc (2)"},
		{name: ".tar.gz", n: 2, want: ".tar (2).gz"},
		{name: "archive.tar.gz", n: 2, want: "archive.tar (2).gz"},
		{name: "backup.2024", isDir: true, n: 2, want: "backup.2024 (2)"},
		{name: "photos", isDir: true, n: 4, want: "photos (4)"},
	} {
		if got := keepBothName(tc.name, tc.isDir, tc.n); got != tc.want {
			t.Errorf("keepBothName(%q, dir=%v, %d) = %q, want %q", tc.name, tc.isDir, tc.n, got, tc.want)
		}
	}
}

// TestKeepBothGivesUpAfterAHundredNames: bounded, and the give-up is a warning
// and a skip rather than a loop (§1.3).
func TestKeepBothGivesUpAfterAHundredNames(t *testing.T) {
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "taken")
	for n := 2; n < 2+maxKeepBothTries; n++ {
		write(t, base, "dst/"+keepBothName("one.txt", false, n), "taken")
	}
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictRename}, "/src/a/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the file skipped", res)
	}
	if len(log.warns) != 1 || log.warns[0].Code != warnConflict {
		t.Fatalf("warns = %v, want %q", log.warns, warnConflict)
	}
}

func TestCopyRefusesAnUnknownConflictPolicy(t *testing.T) {
	r, _ := copyFixture(t)
	var log jobLog
	_, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: "ask"}, "/src/a"), false, log.emit())
	if !errors.Is(err, fsx.ErrBadName) {
		t.Fatalf("Copy = %v, want ErrBadName", err)
	}
}

func TestCopyRefusesADestinationThatIsNotADirectory(t *testing.T) {
	r, _ := copyFixture(t)
	var log jobLog
	_, err := Copy(context.Background(), r, nil,
		copyReq("/src/a/one.txt", wproto.CopyOptions{}, "/src/a/sub"), false, log.emit())
	if err == nil {
		t.Fatal("Copy into a file must fail")
	}
}

// TestFSIdentityDescribesTheEntryItself: one filesystem answers the same for
// everything on it, and a symlink answers for the link rather than its target.
func TestFSIdentityDescribesTheEntryItself(t *testing.T) {
	r, base := copyFixture(t)
	ctx := context.Background()

	dir, err := FSIdentity(ctx, r, nil, "/src/a")
	if err != nil {
		t.Fatalf("FSIdentity: %v", err)
	}
	if !dir.Dir {
		t.Error("a directory must report Dir")
	}
	file, err := FSIdentity(ctx, r, nil, "/src/a/one.txt")
	if err != nil {
		t.Fatalf("FSIdentity: %v", err)
	}
	if file.Dir {
		t.Error("a file must not report Dir")
	}
	if !dir.Same(file) {
		t.Errorf("two paths in one temporary directory are on two filesystems: %+v vs %+v", dir, file)
	}

	if _, err := FSIdentity(ctx, r, nil, "/nope"); err == nil {
		t.Error("FSIdentity of a path that is not there must fail")
	}

	requireSymlinks(t)
	if err := os.Symlink(filepath.Join(base, "src", "a"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	link, err := FSIdentity(ctx, r, nil, "/link")
	if err != nil {
		t.Fatalf("FSIdentity(link): %v", err)
	}
	if link.Dir {
		t.Error("FSIdentity followed the symlink: it reported a directory for a link")
	}
}

// TestSkipWarningsAreBoundedButSkipsAreNot: merging a large folder under the
// default policy is an ordinary request, so the per-item "already there" frames
// stop after a hundred — while the COUNT stays complete, which is what the
// front-end shows and what a move's delete-the-source decision reads.
func TestSkipWarningsAreBoundedButSkipsAreNot(t *testing.T) {
	const files = maxExistsWarnings + 25
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst/a")
	for i := 0; i < files; i++ {
		write(t, base, fmt.Sprintf("src/a/f%03d.txt", i), "x")
		write(t, base, fmt.Sprintf("dst/a/f%03d.txt", i), "older")
	}
	r := newRoot(t, base)
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != files {
		t.Fatalf("result = %+v, want all %d skips counted", res, files)
	}
	if len(log.warns) != maxExistsWarnings {
		t.Fatalf("%d warning frames, want exactly %d", len(log.warns), maxExistsWarnings)
	}
	last := log.warns[len(log.warns)-1]
	if len(last.Path) != 0 || !strings.Contains(last.Message, "not listed") {
		t.Fatalf("last warning = %+v, want the summary that says the rest are counted", last)
	}
	// And nothing was overwritten.
	if got := readFile(t, base, "dst/a/f000.txt"); got != "older" {
		t.Fatalf("dst/a/f000.txt = %q", got)
	}
}

// failTimes makes every timestamp step fail. utimensat does not fail on a
// healthy filesystem, and the rule behind it is one that must not invert.
func failTimes(t *testing.T, cause error) {
	t.Helper()
	prev := setEntryTimes
	setEntryTimes = func(dir *dirRef, name string, f *os.File, link bool, atime, mtime time.Time) error {
		return cause
	}
	t.Cleanup(func() { setEntryTimes = prev })
}

// TestMoveStillDeletesItsSourceWhenOnlyATimestampFailed: a timestamp is
// metadata about the data, not the data. A move that reproduced every byte,
// every directory and every owner, and could only not stamp an mtime, has moved
// the user's files — it reports times_unset and still removes the source
// (contentWarning).
func TestMoveStillDeletesItsSourceWhenOnlyATimestampFailed(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	failTimes(t, errors.New("utimensat: operation not permitted"))
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if res.Skipped != 0 || res.Files != 2 || res.Dirs != 3 {
		t.Fatalf("result = %+v, want the whole tree moved and nothing skipped", res)
	}
	codes := log.codes()
	if indexOf(codes, warnTimesUnset) < 0 {
		t.Fatalf("warn codes = %v, want the %q warning to be reported", codes, warnTimesUnset)
	}
	if indexOf(codes, warnKept) >= 0 {
		t.Fatalf("warn codes = %v, want no %q: a timestamp does not veto the delete", codes, warnKept)
	}
	if exists(t, base, "src/a") {
		t.Fatal("the source was kept because a timestamp could not be set")
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Errorf("dst/a/sub/two.txt = %q", got)
	}
}

// TestMoveKeepsItsSourceWhenAnOwnerCouldNotBeSet is the other half of the same
// rule: ownership IS part of what the rename this fell back from would have
// preserved, so a copy that lost it has not reproduced the source.
func TestMoveKeepsItsSourceWhenAnOwnerCouldNotBeSet(t *testing.T) {
	if !contentWarning(warnOwnerUnset) {
		t.Fatalf("%q must count as content: a rename would have preserved the owner", warnOwnerUnset)
	}
	if contentWarning(warnTimesUnset) {
		t.Fatalf("%q must not count as content", warnTimesUnset)
	}
	for _, code := range []string{warnExists, warnConflict, warnUnsupported, warnChanged, warnNoSpace, "permission", "not_found"} {
		if !contentWarning(code) {
			t.Errorf("%q must count as content: it means something of the source is not at the destination", code)
		}
	}
}

// warnSaying reports whether the job logged a warning with this code whose
// message contains want.
func warnSaying(log jobLog, code, want string) bool {
	for _, w := range log.warns {
		if w.Code == code && strings.Contains(w.Message, want) {
			return true
		}
	}
	return false
}
