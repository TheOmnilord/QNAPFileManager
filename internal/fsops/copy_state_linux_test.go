package fsops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// Round 13 adversarial, the state a copy and a delete are allowed to rest on:
// the group a created object came out in, a directory nobody could give an
// owner to, and a source directory whose permissions change part way through
// its own contents — during the copy and during the delete.

// TestACreatedFolderInAnotherGroupIsNotAdopted is the first finding, and it has
// no privileges in it. Root copies into a shared setgid destination, so every
// directory it creates there comes out in that destination's group; another
// user renames an existing EMPTY root-owned 0750 directory of their own group
// over the fresh name. Kind, creator uid, emptiness and mode-subset all pass,
// and with no gid to chown to, the private tree lands in a group that was never
// meant to see it.
func TestACreatedFolderInAnotherGroupIsNotAdopted(t *testing.T) {
	requireRoot(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/private")
	mkdir(t, base, "dst")
	write(t, base, "src/a/private/secret.txt", "not for everybody")
	if err := os.Chmod(filepath.Join(base, "src", "a", "private"), 0o750); err != nil {
		t.Fatal(err)
	}
	// The destination is setgid and in a group of its own, which is what makes
	// the expectation something other than the worker's own gid.
	dst := filepath.Join(base, "dst")
	if err := os.Chown(dst, os.Geteuid(), 4000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, os.ModeSetgid|0o775); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	swapped := false
	prev := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if swapped || !buildingIn(d.rel, "dst/a") {
			return nil
		}
		swapped = true
		// The name the engine asked for, which is a staged one it will rename
		// into place — never a name this test writes down.
		p := filepath.Join(base, filepath.FromSlash(d.rel), name)
		if err := os.Remove(p); err != nil {
			return err
		}
		// Empty, this worker's own, and no wider than what was asked for. Only
		// its group says it is not the one the kernel just made.
		if err := os.Mkdir(p, 0o750); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o750); err != nil {
			return err
		}
		return os.Chown(p, os.Geteuid(), 4001)
	}
	t.Cleanup(func() { mkdirForCopy = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !swapped {
		t.Fatal("the impostor was never put in place, so nothing was staged")
	}
	if exists(t, base, "dst/a/private/secret.txt") {
		t.Fatal("the secret was copied into a folder in a group the kernel never gave it")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the subtree reported as skipped", res)
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
}

// TestAFolderWhoseOwnerCannotBeSetIsNotCopiedInto is the second finding. A
// failed chown used to be a remark: the directory stood there with whatever
// group the destination gave it and the whole subtree was copied into it
// anyway. Root moving a user's tree into a setgid `public` destination creates
// every directory root:public, so a chown that does not happen hands that group
// what it was moving. The file path has always refused to write into an object
// it could not own; a directory is the same disclosure one level up.
func TestAFolderWhoseOwnerCannotBeSetIsNotCopiedInto(t *testing.T) {
	requireRoot(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/sub/secret.txt", "not for everybody")
	if err := os.Lchown(filepath.Join(base, "src", "a", "sub"), 1, 1); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	// A cross-filesystem move reproduces each entry's own owner, which is what
	// makes this job chown at all.
	forceEXDEV(t)

	// Keyed on WHO the entry is being given to and not on where it is: the
	// directory is created under an unguessable staged name and renamed into
	// place afterwards, so "sub" is not a name the chown ever sees. 1:1 is the
	// ownership this fixture put on src/a/sub and on nothing else.
	refused := false
	prev := setEntryOwner
	setEntryOwner = func(d *dirRef, name string, f *os.File, uid, gid int) error {
		if uid == 1 && gid == 1 {
			refused = true
			return syscall.EPERM
		}
		return prev(d, name, f, uid, gid)
	}
	t.Cleanup(func() { setEntryOwner = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !refused {
		t.Fatal("the chown was never attempted, so nothing was staged")
	}
	if exists(t, base, "dst/a/sub/secret.txt") {
		t.Fatal("the contents were copied into a folder this job could not give an owner")
	}
	if exists(t, base, "dst/a/sub") {
		t.Error("the empty folder was left standing at the destination")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the subtree reported as skipped", res)
	}
	if indexOf(log.codes(), warnOwnerUnset) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnOwnerUnset)
	}
	if !exists(t, base, "src/a/sub/secret.txt") {
		t.Fatal("the move removed a source it had not copied")
	}
}

// stateFixture is a directory of several files, so that whichever one the
// filesystem hands over first there are siblings after it.
func stateFixture(t *testing.T) (string, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	for i := 0; i < 6; i++ {
		write(t, base, fmt.Sprintf("src/a/f%d.txt", i), "contents")
	}
	return base, filepath.Join(base, "src", "a")
}

// TestASourceFolderTightenedDuringItsCopyStopsTheRest is the third finding. A
// directory's state was proved ONCE, when its destination was created and its
// record taken, and a thousand entries were then copied on the strength of that
// one reading. Tighten it 0755 -> 0700 during a long file — and replace a
// not-yet-visited sibling's contents while you are there — and the sibling was
// copied into a destination directory still standing at 0755: a restriction
// applied before the data was read and undone by this job after it was applied.
func TestASourceFolderTightenedDuringItsCopyStopsTheRest(t *testing.T) {
	base, srcDir := stateFixture(t)
	r := newRoot(t, base)
	var log jobLog

	tightened := false
	e := log.emit()
	emit := Emit{
		Prog: func(p wproto.Prog) {
			e.Prog(p)
			if tightened || p.Phase != wproto.PhaseWorking || !strings.HasPrefix(string(p.Current), "/dst/a/") {
				return
			}
			tightened = true
			if err := os.Chmod(srcDir, 0o700); err != nil {
				t.Errorf("chmod: %v", err)
			}
		},
		Warn: e.Warn,
	}

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, emit)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !tightened {
		t.Fatal("the folder was never tightened, so nothing was staged")
	}
	if res.Files != 1 {
		t.Fatalf("result = %+v, want only the entry that was being copied when the folder changed", res)
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the rest reported as not copied", res)
	}
	w, ok := log.warnFor("/src/a")
	if !ok || w.Code != warnChanged {
		t.Fatalf("warnings = %v, want a %q naming the folder that changed", log.warns, warnChanged)
	}
	if !strings.Contains(w.Message, "the rest of it was left alone") {
		t.Errorf("warning = %q, want it to say the rest of the folder was left alone", w.Message)
	}
}

// TestASourceFolderTightenedDuringItsDeleteKeepsTheRest is the fourth, and it is
// the same window on the other side of the move: the directory's record was
// checked once, before the entry loop, and a single byte comparison can run for
// minutes. A directory tightened or chowned during one had every remaining
// child removed and then itself, on a judgement its owner had already withdrawn.
func TestASourceFolderTightenedDuringItsDeleteKeepsTheRest(t *testing.T) {
	base, srcDir := stateFixture(t)
	r := newRoot(t, base)
	forceEXDEV(t)

	tightened := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "compare" || tightened {
			return
		}
		tightened = true
		if err := os.Chmod(srcDir, 0o700); err != nil {
			t.Errorf("chmod: %v", err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !tightened {
		t.Fatal("no comparison was announced, so nothing was staged")
	}
	left := 0
	for i := 0; i < 6; i++ {
		if exists(t, base, fmt.Sprintf("src/a/f%d.txt", i)) {
			left++
		}
	}
	if left != 5 {
		t.Fatalf("%d source files are left, want 5: only the entry judged before the folder changed may be removed", left)
	}
	if !exists(t, base, "src/a") {
		t.Fatal("the folder itself was removed although it was not the one that was recorded any more")
	}
	w, ok := log.warnFor("/src/a")
	if !ok || w.Code != warnKept {
		t.Fatalf("warnings = %v, want a %q naming the folder that changed", log.warns, warnKept)
	}
	if !strings.Contains(w.Message, "while its contents were being removed") {
		t.Errorf("warning = %q, want it to say when the folder changed", w.Message)
	}
}
