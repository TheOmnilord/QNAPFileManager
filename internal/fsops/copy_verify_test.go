package fsops

import (
	"context"
	"errors"
	"io"
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

// The review-round-1 findings, one test per probe. Everything here is about
// what a move REMOVES and what a copy publishes, which is the half of this
// engine where a mistake is not a wrong number but somebody's data.

// onceAt runs do() the nth time a working-phase progress update names path. It
// is how a test changes the filesystem in the middle of a copy — the window
// every one of these findings lives in.
//
// n picks the moment precisely, and it has to: a file smaller than the transfer
// buffer produces exactly two working updates, one from the counting writer
// when its bytes have been written and one when the entry is complete. n = 1 is
// "while this entry is being copied", n = 2 is "once it has been published".
func onceAt(log *jobLog, path string, n int, do func()) Emit {
	e := log.emit()
	seen := 0
	return Emit{
		Prog: func(p wproto.Prog) {
			e.Prog(p)
			if p.Phase != wproto.PhaseWorking || string(p.Current) != path {
				return
			}
			seen++
			if seen == n {
				do()
			}
		},
		Warn: e.Warn,
	}
}

// requireRenameOfOpenDirectories skips a test that renames a directory this
// process is holding open. Windows refuses that outright — a directory with an
// open handle cannot be renamed — so the races these tests stage cannot even be
// set up there. They are the CI Linux jobs' (INV-2: this is the dev box).
func requireRenameOfOpenDirectories(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows will not rename a directory that is held open, so this race cannot be staged here")
	}
}

// forceEXDEVFor makes only the named source root answer "different
// filesystems", so a test can have one root rename and another fall back to
// copying in the same job — the mixed move of finding 8.
func forceEXDEVFor(t *testing.T, name string) {
	t.Helper()
	prev := renameRoot
	renameRoot = func(dst, srcParent *dirRef, fromName, toName string, noReplace bool) error {
		if fromName == name {
			return &os.PathError{Op: "renameat", Path: fromName, Err: syscall.EXDEV}
		}
		return prev(dst, srcParent, fromName, toName, noReplace)
	}
	t.Cleanup(func() { renameRoot = prev })
}

// TestMoveDeletesOnlyWhatItVerifiablyCopied is the reviewer's first probe: a
// file written into the source AFTER its directory was enumerated was deleted
// by a delete-by-pathname without ever having reached the destination, and the
// job said nothing about it.
func TestMoveDeletesOnlyWhatItVerifiablyCopied(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	var log jobLog
	// src/a's own names are read in one getdents before the walk descends into
	// src/a/sub, so a file created at this moment is never visited — which is
	// exactly the file that must survive.
	emit := onceAt(&log, "/dst/a/sub/two.txt", 1, func() {
		write(t, base, "src/a/late.txt", "written after the copy passed by")
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, emit); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}

	if !exists(t, base, "src/a/late.txt") {
		t.Fatal("a file added after the copy passed by was DELETED without ever reaching the destination")
	}
	if got := readFile(t, base, "src/a/late.txt"); got != "written after the copy passed by" {
		t.Fatalf("src/a/late.txt = %q", got)
	}
	if exists(t, base, "dst/a/late.txt") {
		t.Fatal("the file was never copied, so nothing may be at the destination for it")
	}
	// What WAS copied is gone: the verification removes per entry, not per tree.
	if exists(t, base, "src/a/one.txt") || exists(t, base, "src/a/sub") {
		t.Error("the entries that were verifiably copied should have been removed")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want a %q warning naming what was left behind", log.codes(), warnKept)
	}
	kept := false
	for _, w := range log.warns {
		if w.Code == warnKept && strings.Contains(w.Message, "added after it was copied") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("warnings = %v, want one that says entries were added after the copy", log.warns)
	}
}

// TestMoveKeepsAnEntryThatChangedAfterItWasCopied: the per-entry proof is
// identity, size and modification time, and a file rewritten after its copy
// matches none of them.
func TestMoveKeepsAnEntryThatChangedAfterItWasCopied(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	var log jobLog
	emit := onceAt(&log, "/dst/a/one.txt", 2, func() {
		// Longer than the three bytes that were copied, so the mismatch does
		// not depend on the host's timestamp granularity.
		write(t, base, "src/a/one.txt", "rewritten while the job was running")
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, emit); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("a file that changed after it was copied was deleted anyway")
	}
	if got := readFile(t, base, "src/a/one.txt"); got != "rewritten while the job was running" {
		t.Fatalf("src/a/one.txt = %q — the new contents were destroyed", got)
	}
	if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
		t.Errorf("the destination holds %q, which is what was actually copied", got)
	}
	changed := false
	for _, w := range log.warns {
		if w.Code == warnKept && strings.Contains(w.Message, "changed since it was copied") {
			changed = true
		}
	}
	if !changed {
		t.Fatalf("warnings = %v, want one saying the entry changed since it was copied", log.warns)
	}
}

// TestMoveWillNotDescendIntoADirectoryThatWasSwapped is the directory half of
// the same proof, and the structural answer to the reviewer's second probe: the
// delete opens each level from the descriptor above it and checks its identity
// against the record before it removes anything inside it. A directory
// substituted after the copy is refused, so a component swapped for a link to
// /etc has nothing to unlink there.
func TestMoveWillNotDescendIntoADirectoryThatWasSwapped(t *testing.T) {
	requireRenameOfOpenDirectories(t)
	r, base := copyFixture(t)
	forceEXDEV(t)
	var log jobLog
	emit := onceAt(&log, "/dst/a/sub/two.txt", 2, func() {
		if err := os.Rename(filepath.Join(base, "src", "a", "sub"), filepath.Join(base, "src", "a", "gone")); err != nil {
			t.Error(err)
			return
		}
		mkdir(t, base, "src/a/sub")
		write(t, base, "src/a/sub/planted.txt", "not this job's to delete")
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, emit); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/sub/planted.txt") {
		t.Fatal("the delete descended into a directory that is not the one that was copied")
	}
	if got := readFile(t, base, "src/a/sub/planted.txt"); got != "not this job's to delete" {
		t.Fatalf("planted.txt = %q", got)
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

// TestShortCopyIsNeverPublished is the reviewer's second reproduced probe: a
// source truncated mid-copy makes io.CopyBuffer return short with NO error, and
// the old shape renamed that temporary over an intact destination. A
// verification failure is a failed transfer.
func TestShortCopyIsNeverPublished(t *testing.T) {
	r, base := copyFixture(t)
	write(t, base, "dst/one.txt", "the original bytes, all of them")
	// One byte, no error: exactly what a truncation underneath the reader does.
	failAfter(t, 1, nil)
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictOverwrite}, "/src/a/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got := readFile(t, base, "dst/one.txt"); got != "the original bytes, all of them" {
		t.Fatalf("dst/one.txt = %q — a short copy was published over an intact file", got)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the entry counted as not copied", res)
	}
	if len(log.warns) != 1 || log.warns[0].Code != warnChanged {
		t.Fatalf("warns = %v, want one %q", log.warns, warnChanged)
	}
	assertNoTempLeft(t, base, "dst")

	// And with no existing destination: nothing is published under the real
	// name either.
	failAfter(t, 1, nil)
	var plain jobLog
	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a/sub/two.txt"), false, plain.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if exists(t, base, "dst/two.txt") {
		t.Fatal("a short copy was left at the destination under its real name")
	}
	assertNoTempLeft(t, base, "dst")
}

// TestShortCopyOfAMoveKeepsTheSource: the same failure seen from the move's
// side — `changed` is a content warning, so the source stays.
func TestShortCopyOfAMoveKeepsTheSource(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	failAfter(t, 1, nil)
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("a move deleted a source whose files were never fully copied")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

func assertNoTempLeft(t *testing.T, base, rel string) {
	t.Helper()
	des, err := os.ReadDir(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), copyTmpPrefix) {
			t.Fatalf("a temporary was left behind in %s: %q", rel, de.Name())
		}
	}
}

// TestCopyRefusesTheDestinationThatArrivesInsideTheSource is finding 6: the
// containment answer was taken once, before a pre-scan that can run for thirty
// seconds, and never asked again. Here the destination is moved into the tree
// while the copy is running, which the held descriptor follows.
func TestCopyRefusesTheDestinationThatArrivesInsideTheSource(t *testing.T) {
	requireRenameOfOpenDirectories(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/zsub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	write(t, base, "src/a/zsub/filler.txt", "filler")
	r := newRoot(t, base)

	var log jobLog
	emit := onceAt(&log, "/dst/a/one.txt", 1, func() {
		// The destination becomes a directory inside the source. The job holds
		// its descriptor, so every write still lands in it — now from inside
		// the tree being copied.
		if err := os.Rename(filepath.Join(base, "dst"), filepath.Join(base, "src", "a", "zsub", "dst")); err != nil {
			t.Error(err)
		}
	})

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, emit)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if indexOf(log.codes(), "invalid_target") < 0 {
		t.Fatalf("warn codes = %v, want invalid_target once the destination was met inside the source", log.codes())
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the root reported as skipped", res)
	}
	// The recursion stopped: nothing was copied into a copy of itself.
	if exists(t, base, "src/a/zsub/dst/a/zsub/dst") {
		t.Fatal("the copy descended into its own output")
	}
}

// TestMixedMoveChargesSpacePerRoot is finding 8: a rename writes nothing, so a
// hundred-gigabyte same-filesystem root must not make a one-kilobyte
// cross-filesystem root fail for want of room.
func TestMixedMoveChargesSpacePerRoot(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src")
	mkdir(t, base, "dst")
	write(t, base, "src/big.bin", strings.Repeat("x", 400))
	write(t, base, "src/small.bin", "s")
	r := newRoot(t, base)

	// Only the small root falls back to copying. There is room for it and not
	// for the pair.
	forceEXDEVFor(t, "small.bin")
	fakeFree(t, 100, true)
	var log jobLog

	res, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/big.bin", "/src/small.bin"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move) = %v, want the renamed root not to be charged for", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings = %v, want none", log.warns)
	}
	if res.Skipped != 0 {
		t.Fatalf("result = %+v, want nothing skipped", res)
	}
	for _, rel := range []string{"dst/big.bin", "dst/small.bin"} {
		if !exists(t, base, rel) {
			t.Errorf("%s was not moved", rel)
		}
	}
	if exists(t, base, "src/small.bin") || exists(t, base, "src/big.bin") {
		t.Error("both sources should be gone")
	}

	// And the check is still made: a root that genuinely does not fit is
	// refused before it writes.
	base2 := tempDir(t)
	mkdir(t, base2, "src")
	mkdir(t, base2, "dst")
	write(t, base2, "src/small.bin", strings.Repeat("y", 400))
	r2 := newRoot(t, base2)
	forceEXDEVFor(t, "small.bin")
	fakeFree(t, 100, true)
	var tight jobLog
	if _, err := Copy(context.Background(), r2, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/small.bin"), true, tight.emit()); !errors.Is(err, fsx.ErrNoSpace) {
		t.Fatalf("Copy(move) = %v, want ErrNoSpace", err)
	}
	if exists(t, base2, "dst/small.bin") {
		t.Error("the refusal came after something had been written")
	}
}

// TestDestinationMountIsNotMergedInto is finding 7: an EXISTING destination
// directory that is the root of another filesystem is adopted by name, and the
// destination never crosses (§1.8). The identity comes from the same seam the
// walk's own crossing decisions use.
func TestDestinationMountIsNotMergedInto(t *testing.T) {
	r, base := copyFixture(t)
	mkdir(t, base, "dst/a")
	write(t, base, "dst/a/already.txt", "on the other filesystem")
	// Only the destination's own "dst/a" is on another mount; "src/a" is not,
	// because the key is matched against the whole jail-relative path.
	fakeIdentities(t, map[string]uint64{"dst/a": 7})
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the root refused and nothing written", res)
	}
	w, ok := log.warnFor("/dst/a")
	if !ok || w.Code != "protected" {
		t.Fatalf("warns = %v, want protected for the destination mount", log.warns)
	}
	if exists(t, base, "dst/a/one.txt") {
		t.Fatal("the copy wrote into a mount point at the destination")
	}
	if got := readFile(t, base, "dst/a/already.txt"); got != "on the other filesystem" {
		t.Errorf("dst/a/already.txt = %q", got)
	}
}

// TestSameHeldDirIsIdentityAndNotSpelling is the mechanism behind finding 4:
// two names for one directory — a bind mount is the case that matters on a NAS
// — are one directory, and only a comparison of the held descriptors can say
// so. The real bind mount needs root and lives in copy_linux_test.go.
func TestSameHeldDirIsIdentityAndNotSpelling(t *testing.T) {
	r, base := copyFixture(t)
	tg, err := resolve(r, "/dst", true)
	if err != nil {
		t.Fatal(err)
	}
	one, err := openPathRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer one.close()
	two, err := openPathRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer two.close()

	same, known := sameHeldDir(one, two)
	if !known {
		t.Skipf("this platform cannot compare two descriptors (inodeIdentity = %v)", inodeIdentity)
	}
	if !same {
		t.Fatal("two descriptors for one directory were reported as two directories")
	}

	other, err := resolve(r, "/src", true)
	if err != nil {
		t.Fatal(err)
	}
	third, err := openPathRef(other.jail, other.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer third.close()
	if same, _ := sameHeldDir(one, third); same {
		t.Fatal("two different directories were reported as one")
	}
	_ = base
}

// TestCreatedByUsRefusesWhatWeDidNotCreate is finding 3's check in isolation:
// before any metadata is set on a freshly created entry it has to BE that
// entry — the right kind, and owned by this worker.
func TestCreatedByUsRefusesWhatWeDidNotCreate(t *testing.T) {
	_, base := copyFixture(t)
	file := lstat(t, base, "src/a/one.txt")
	dir := lstat(t, base, "src/a")

	if err := createdByUs(file, kindRegular); err != nil {
		t.Errorf("a regular file we own must pass as a regular file: %v", err)
	}
	if err := createdByUs(file, kindLink); err == nil {
		t.Error("a regular file must not pass as the symlink that was just created")
	}
	if err := createdByUs(dir, kindLink); err == nil {
		t.Error("a directory must not pass as the symlink that was just created")
	}
	if err := createdByUs(nil, kindLink); err == nil {
		t.Error("something that cannot be described must not pass")
	}
}

// TestLedgerBoundKeepsTheSource: past what the worker will record, the source is
// KEPT rather than removed on the strength of a record that was never finished.
func TestLedgerBoundKeepsTheSource(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	prev := ledgerBound
	ledgerBound = 2
	t.Cleanup(func() { ledgerBound = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was removed although the record of what was copied was incomplete")
	}
	kept := false
	for _, w := range log.warns {
		if w.Code == warnKept && strings.Contains(w.Message, "record and verify") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("warnings = %v, want one saying the tree was too large to verify", log.warns)
	}
	// The copy itself still completed.
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Errorf("dst/a/sub/two.txt = %q", got)
	}

}

// TestProvenanceNeedsEmptinessAndNotJustAnOwner is finding 2 of the second
// review: a uid match says only that root owns it. A pre-existing root-owned
// directory full of somebody's data, renamed over the fresh name between the
// mkdirat and the openat, satisfies kind and owner — and would then be chowned
// away to the requested user. Only emptiness proves creation.
func TestProvenanceNeedsEmptinessAndNotJustAnOwner(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "fresh")
	mkdir(t, base, "occupied")
	write(t, base, "occupied/somebody-elses-data.txt", "private")
	r := newRoot(t, base)
	c := &copier{r: r}

	for _, tc := range []struct {
		rel  string
		want bool // true = must pass
	}{
		{rel: "fresh", want: true},
		{rel: "occupied", want: false},
	} {
		tg, err := resolve(r, "/"+tc.rel, true)
		if err != nil {
			t.Fatal(err)
		}
		d, err := openPathRef(tg.jail, tg.rel)
		if err != nil {
			t.Fatal(err)
		}
		err = c.provenance(d, kindDir)
		d.close()
		if tc.want && err != nil {
			t.Errorf("provenance(%q) = %v, want it to pass: it is empty and ours", tc.rel, err)
		}
		if !tc.want && err == nil {
			t.Errorf("provenance(%q) passed; a directory with entries in it is not the one just created", tc.rel)
		}
	}
}

// TestCreatedDestinationLevelIsAlsoCheckedForCrossing is finding 6: a mkdir that
// succeeded proves nothing about the descriptor opened after it. A mount placed
// over the name in between puts the copy on another filesystem with the
// crossing rule switched off, and the free-space check describing a filesystem
// the bytes never reach.
func TestCreatedDestinationLevelIsAlsoCheckedForCrossing(t *testing.T) {
	r, base := copyFixture(t)
	// dst/a does not exist, so this is the CREATED path — the one the old shape
	// exempted from the check entirely.
	//
	// The identity is faked for the directory the engine actually OPENS for the
	// CREATED LEVEL: off Linux that is the final name, and on Linux it is the
	// unguessable name it is built under inside the staging directory before it
	// is renamed into place. Keying it on the final spelling alone stopped
	// firing when creation moved to a staged name — the CHECK did not move, it
	// still asks the descriptor that was just opened, which is the only moment
	// anything could have been put underneath it.
	//
	// The staging directory itself is deliberately left on the destination's own
	// filesystem here: it has a crossing check of its own, with a different
	// answer (TestAStagingDirectoryOnAnotherFilesystemRefuses), and this test is
	// about the level being copied.
	//
	// And a mount placed over the FINAL name after the rename is not a crossing
	// at all: every child is created through the descriptor this job holds,
	// which still refers to the directory the mount was laid over, so the bytes
	// land on the filesystem the free-space check measured and nothing of the
	// copy reaches the mount.
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		switch {
		case strings.HasSuffix(d.rel, stageSuffix):
			return mountIdentity{mnt: 1, hasMnt: true}
		case d.rel == "dst/a" || strings.Contains(d.rel, "/"+copyTmpPrefix):
			return mountIdentity{mnt: 9, hasMnt: true}
		}
		return mountIdentity{mnt: 1, hasMnt: true}
	}
	t.Cleanup(func() { identityFor = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 {
		t.Fatalf("result = %+v, want the root refused", res)
	}
	w, ok := log.warnFor("/dst/a")
	if !ok || w.Code != "protected" {
		t.Fatalf("warns = %v, want protected for the created level that moved filesystem", log.warns)
	}
	if exists(t, base, "dst/a/one.txt") {
		t.Fatal("the copy wrote into a level it had not proved was on the destination's own filesystem")
	}
}

// TestPublishRefusesAStrangerAtTheName is finding 3 seen through its predicate:
// the temporary's NAME has to still refer to the inode this job wrote, and a
// stranger standing there is never removed — it is not ours.
func TestPublishRefusesAStrangerAtTheName(t *testing.T) {
	r, base := copyFixture(t)
	write(t, base, "dst/mine.txt", "written by this job")
	write(t, base, "dst/theirs.txt", "written by somebody else")
	tg, err := resolve(r, "/dst", true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := openPathRef(tg.jail, tg.rel)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()

	mine := lstat(t, base, "dst/mine.txt")
	theirs := lstat(t, base, "dst/theirs.txt")

	if same, known := sameNamedObject(d, "mine.txt", mine); known && !same {
		t.Error("a name that still refers to our own inode was reported as a stranger")
	}
	same, known := sameNamedObject(d, "mine.txt", theirs)
	if !known {
		t.Skipf("this platform cannot compare identities (inodeIdentity = %v)", inodeIdentity)
	}
	if same {
		t.Fatal("a different inode at the name was reported as ours; the publication check is not a check")
	}
	if _, kerr := sameNamedObject(d, "gone.txt", mine); !kerr {
		t.Error("a name that is not there at all must be a definite answer, not an unknown one")
	}
}

// TestTooManyFoldersStopsTheRootRatherThanTheCheck is the round-3 adversarial
// finding 2: the set of destination folders this job has created used to stop
// growing at its bound and let the job carry on, which meant the self-copy
// protection was silently absent on exactly the enormous job where an unbounded
// recursion costs the most. A folder that cannot be tracked is one this job
// will not write under.
func TestTooManyFoldersStopsTheRootRatherThanTheCheck(t *testing.T) {
	if !inodeIdentity {
		t.Skip("the set is keyed by inode identity, which this platform does not have")
	}
	// Only the security set is lowered. The copy record keeps its own bound:
	// the two have opposite consequences and sharing one made this refusal fire
	// wherever either was reached.
	prev := trackedDirBound
	trackedDirBound = 1
	t.Cleanup(func() { trackedDirBound = prev })

	for _, move := range []bool{false, true} {
		r, base := copyFixture(t)
		// A move that RENAMES creates no destination directory and walks
		// nothing, so it never touches the set and is never refused by it —
		// which is correct, and is why the move case has to be forced onto the
		// copy path to mean anything here.
		if move {
			forceEXDEV(t)
		}
		var log jobLog
		res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), move, log.emit())
		if err != nil {
			t.Fatalf("move=%v: Copy: %v", move, err)
		}
		if indexOf(log.codes(), warnTooMany) < 0 {
			t.Fatalf("move=%v: warn codes = %v, want %q", move, log.codes(), warnTooMany)
		}
		if res.Skipped == 0 {
			t.Errorf("move=%v: result = %+v, want the root reported as skipped", move, res)
		}
		if !exists(t, base, "src/a/one.txt") {
			t.Fatalf("move=%v: the source was removed by a job that had stopped tracking its own output", move)
		}
	}
}

// TestARenamingMoveIsNotRefusedByTheFolderSet is the other half of the rule
// above: the set exists to stop a job copying its own output back into itself,
// and a rename copies nothing. A root that the kernel can move in one syscall
// is not refused because some earlier root exhausted a protection it does not
// need.
func TestARenamingMoveIsNotRefusedByTheFolderSet(t *testing.T) {
	if !inodeIdentity {
		t.Skip("the set is keyed by inode identity, which this platform does not have")
	}
	prev := trackedDirBound
	trackedDirBound = 1
	t.Cleanup(func() { trackedDirBound = prev })

	r, base := copyFixture(t)
	var log jobLog
	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a move the kernel completed in one syscall: %v", log.warns)
	}
	if res.Skipped != 0 {
		t.Fatalf("result = %+v, want nothing skipped", res)
	}
	if exists(t, base, "src/a") {
		t.Fatal("the source is still there")
	}
	if !exists(t, base, "dst/a/sub/two.txt") {
		t.Fatal("the tree was not moved")
	}
}

// TestMoveKeepsASourceWhoseCopyWasRewrittenInPlace is round 9's finding: the
// destination check was identity, kind and length, so a published copy
// rewritten in place with the same number of bytes passed it and the source was
// deleted with the copy holding somebody else's contents.
// It is staged at the engine's own "delete" step — before ANY entry of the root
// is judged — and not on the first finishing update, which is emitted only
// after the first entry's source has already been unlinked: when enumeration
// happened to hand one.txt over first, the corruption landed after that source
// was already gone and a correct engine failed the assertion. Readdirnames
// order is not a thing to build a test on.
func TestMoveKeepsASourceWhoseCopyWasRewrittenInPlace(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	done := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "delete" || done {
			return
		}
		done = true
		// The published copy is rewritten: same inode, same three bytes.
		write(t, base, "dst/a/one.txt", "BAD")
	}
	t.Cleanup(func() { verifyTrace = prev })
	log := &jobLog{}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !done {
		t.Fatal("the delete never started, so nothing was staged")
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was deleted although its copy had been rewritten at the destination")
	}
	if got := readFile(t, base, "src/a/one.txt"); got != "one" {
		t.Fatalf("src/a/one.txt = %q", got)
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

// TestAnOrdinaryMoveStillCompletes is the other half: the destination checks
// are made on every entry of every move, so they have to be quiet when nothing
// is wrong.
func TestAnOrdinaryMoveStillCompletes(t *testing.T) {
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
	if res.Files != 2 || res.Dirs != 3 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want the whole tree moved", res)
	}
	if exists(t, base, "src/a") {
		t.Fatal("the source is still there")
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Fatalf("dst/a/sub/two.txt = %q", got)
	}
}

// TestACancellationThatArrivesLateIsStillACancellation: the per-root loop
// checks the context at the top of each iteration, which says nothing about a
// cancellation that arrived while the last root was finishing. A job that
// returns no error is reported as ordinary completion, so a CancelJob that
// landed a moment too late looked like the job having simply finished.
func TestACancellationThatArrivesLateIsStillACancellation(t *testing.T) {
	r, _ := copyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &jobLog{}
	emit := log.emit()
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			emit.Prog(p)
			// Cancelled once the copy is over — after the last item this job
			// will ever report.
			cancel()
		},
		Warn: emit.Warn,
	}

	_, err := Copy(ctx, r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, wrapped)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Copy = %v, want the cancellation the caller asked for", err)
	}
}

// TestMoveByteVerifiesEveryFile is round 10's probe: somebody with write access
// to the destination replaces already-written bytes BEFORE publication, so the
// tampered copy is what gets recorded as the baseline. No timestamp scheme can
// see a write that happened before the baseline existed — only reading the
// bytes back can.
func TestMoveByteVerifiesEveryFile(t *testing.T) {
	// The tampering is done through the copy's NAME, which only the named
	// path has while it is being written.
	forceNamedCreate(t)
	forceNoStaging(t)
	base := tempDir(t)
	mkdir(t, base, "src")
	mkdir(t, base, "dst")
	write(t, base, "src/one.txt", "one")
	r := newRoot(t, base)
	forceEXDEV(t)

	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		n, err := io.CopyBuffer(dst, src, buf)
		if err != nil {
			return n, err
		}
		// The copy is written but not yet published; its bytes are replaced
		// through the name, keeping the length, so everything the record is
		// about to capture describes the tampered file.
		f, oerr := os.OpenFile(filepath.Join(base, "dst", "one.txt"), os.O_WRONLY, 0)
		if oerr != nil {
			return n, nil // nothing to tamper with on this path
		}
		defer f.Close()
		if _, werr := f.WriteAt([]byte("BAD"), 0); werr != nil {
			t.Error(werr)
		}
		return n, nil
	}
	t.Cleanup(func() { copyStream = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/one.txt"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/one.txt") {
		t.Fatal("the source was deleted although its copy does not hold its bytes")
	}
	if got := readFile(t, base, "src/one.txt"); got != "one" {
		t.Fatalf("src/one.txt = %q", got)
	}
	if !warnSaying(log, warnKept, "byte for byte") {
		t.Fatalf("warnings = %v, want the byte comparison's own reason", log.warns)
	}
}

// TestTheClockScratchKeepsADirectoryMtime is round 10's second finding: the
// clock scratch used to be created inside a destination directory this job had
// just restored the source's modification time on, which undid it.
func TestTheClockScratchKeepsADirectoryMtime(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	when := time.Date(2019, 4, 2, 11, 22, 33, 0, time.UTC)
	for _, rel := range []string{"src/a/sub", "src/a"} {
		if err := os.Chtimes(filepath.Join(base, filepath.FromSlash(rel)), when, when); err != nil {
			t.Fatal(err)
		}
	}
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean move: %v", log.warns)
	}
	for _, rel := range []string{"dst/a", "dst/a/sub"} {
		if got := lstat(t, base, rel).ModTime(); !got.Equal(when) {
			t.Errorf("%s mtime = %v, want the source's %v — something wrote into it after it was restored", rel, got, when)
		}
	}
}

// TestMoveKeepsASourceWhoseModeChanged is round 11's third finding: the change
// time is exempted for a hard-linked entry — this job moved it itself — so a
// chmod or a chown of the source after the copy left identity, size,
// modification time and even the bytes matching, and the source was deleted
// with its copies still under the OLD permissions. A restriction the user had
// just applied, dropped.
func TestMoveKeepsASourceWhoseModeChanged(t *testing.T) {
	requireUnixModes(t)
	r, base := copyFixture(t)
	forceEXDEV(t)
	done := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "delete" || done {
			return
		}
		done = true
		// Tightened after the copy: 0644 -> 0600.
		if err := os.Chmod(filepath.Join(base, "src", "a", "one.txt"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	log := &jobLog{}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !done {
		t.Fatal("the delete never started, so nothing was staged")
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was deleted although its permissions had changed since it was copied")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

// TestMoveKeepsASubtreeWhoseDirectoryModeChanged is round 12's finding, one
// level up from round 11's: a directory was verified by its inode alone, so a
// source folder tightened 0755 -> 0700 after its copy was made was removed and
// the destination left under the old mode — the restriction dropped at the
// moment the user applied it.
func TestMoveKeepsASubtreeWhoseDirectoryModeChanged(t *testing.T) {
	requireUnixModes(t)
	r, base := copyFixture(t)
	forceEXDEV(t)
	done := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "delete" || done {
			return
		}
		done = true
		if err := os.Chmod(filepath.Join(base, "src", "a", "sub"), 0o700); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	log := &jobLog{}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !done {
		t.Fatal("the delete never started, so nothing was staged")
	}
	// The whole subtree stays: the check is made before a single entry inside
	// it is touched.
	if !exists(t, base, "src/a/sub/two.txt") {
		t.Fatal("an entry was removed from a directory whose permissions had changed since it was copied")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnKept)
	}
}

// TestSameDirStateAgreesWithWhatItRecorded pins the predicate the root's
// creation-versus-record verification rests on. The integration around it is
// Linux-only — a directory's mode and ownership are not things a test can
// change on the dev box — so this at least keeps the two halves in step.
func TestSameDirStateAgreesWithWhatItRecorded(t *testing.T) {
	_, base := copyFixture(t)
	a := lstat(t, base, "src/a")
	sub := lstat(t, base, "src/a/sub")

	rec := &copiedDir{}
	recordDirState(rec, a)
	if !sameDirState(rec, a) {
		t.Error("a directory must agree with the record taken from it")
	}
	if sameDirState(rec, nil) {
		t.Error("nothing at all must not agree with a record")
	}
	if sameDirState(nil, a) {
		t.Error("a record that was never taken must not agree with anything")
	}
	if inodeIdentity && sameDirState(rec, sub) {
		t.Error("a different directory must not agree with this record")
	}
}
