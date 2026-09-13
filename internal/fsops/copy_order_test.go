package fsops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestTheComparisonSettlesBeforeItReads is round 7's finding, tested as what it
// is: an ORDER. Settling after the byte comparison proves only that the tick had
// ended by then — on a coarse-timestamp filesystem this job's own unlink gives a
// survivor a current-tick change time, and a writer who modifies already
// compared bytes inside that tick leaves it equal on both sides of the compare.
//
// Every earlier attempt to infer that order from an OUTCOME had to stage a
// condition that changed what the engine did, and each one drifted away from
// the property: corrupting the destination made round 9's record check fire
// first, and rewriting the source made the entry recent, so the PRE-READ settle
// refused it in the copy phase and the delete-time comparison was never reached
// at all. The order is not something a filesystem can be asked about
// afterwards, so the engine reports its own steps (verifyTrace) and the
// assertion is on the sequence.
//
// Nothing is stalled and nothing is corrupted: an ordinary clean move is what
// exercises it, which is also what makes it stable on a real filesystem — and
// what lets it run on every platform, since an order does not depend on a
// kernel having change times.
func TestTheComparisonSettlesBeforeItReads(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)

	var steps []string
	prev := verifyTrace
	verifyTrace = func(step string) { steps = append(steps, step) }
	t.Cleanup(func() { verifyTrace = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean move: %v", log.warns)
	}
	if res.Files != 2 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want both files moved", res)
	}

	compares := 0
	for i, s := range steps {
		if s != "compare" {
			continue
		}
		compares++
		if i == 0 || steps[i-1] != "settle" {
			t.Fatalf("steps = %v: a comparison ran without its settle immediately before it", steps)
		}
	}
	if compares != 2 {
		t.Fatalf("steps = %v, want a settle and a comparison for each of the two files", steps)
	}
	if exists(t, base, "src/a") {
		t.Fatal("the source is still there")
	}
}

// TestTheComparisonBaselineIsCheckedAgainstTheRecord is round 13's finding. The
// delete's byte comparison opened the source and then trusted the fstat of that
// descriptor on its INODE alone, so a chmod (or a chown) landing after the
// caller's matchesRecord and before that fstat became the baseline everything
// below was judged against: the source was compared with its copy, found equal,
// and removed — with the permissions its owner had just applied thrown away
// with it.
//
// The window is exactly the one the "settle" step announces, which is why the
// step is emitted before the open rather than after it. Staging there is the
// only way to reach it: it is two syscalls wide and nothing about the outcome
// distinguishes it afterwards.
func TestTheComparisonBaselineIsCheckedAgainstTheRecord(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	path := filepath.Join(base, "src", "a", "one.txt")
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	staged := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "settle" || staged {
			return
		}
		staged = true
		if err := os.Chmod(path, 0o400); err != nil {
			t.Errorf("chmod: %v", err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !staged {
		t.Fatal("the comparison never announced its settle, so nothing was staged")
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was removed although its recorded state changed before the comparison's baseline was taken")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want a %q warning saying the original was kept", log.codes(), warnKept)
	}
}

// TestTheDestinationIsPersistedBeforeAnyOriginalIsRemoved is round 13
// adversarial's fifth finding: a cross-filesystem move published its
// destination names — files, links, the directories it created — without ever
// fsyncing a directory, so a power cut could land with the source unlinks
// committed and the destination entries never written. Both copies gone.
//
// It is an ORDER, so it is observed rather than inferred (verifyTrace): every
// destination directory is flushed while its descriptor is still held, deepest
// first, and the container last, all of it before the first original is
// touched.
func TestTheDestinationIsPersistedBeforeAnyOriginalIsRemoved(t *testing.T) {
	r, _ := copyFixture(t)
	forceEXDEV(t)

	var steps []string
	prevTrace := verifyTrace
	verifyTrace = func(step string) { steps = append(steps, step) }
	t.Cleanup(func() { verifyTrace = prevTrace })
	prevSync := persistDir
	persistDir = func(d *dirRef) error {
		steps = append(steps, "sync:"+d.rel)
		return prevSync(d)
	}
	t.Cleanup(func() { persistDir = prevSync })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean move: %v", log.warns)
	}

	deleted := indexOf(steps, "delete")
	persisted := indexOf(steps, "persisted")
	if deleted < 0 || persisted < 0 {
		t.Fatalf("steps = %v, want both a persist and a delete step", steps)
	}
	if persisted > deleted {
		t.Fatalf("steps = %v: the originals were judged before the destination was on disk", steps)
	}
	synced := map[string]bool{}
	for i, s := range steps {
		if !strings.HasPrefix(s, "sync:") {
			continue
		}
		if i > deleted {
			t.Fatalf("steps = %v: %q was flushed after the delete started", steps, s)
		}
		synced[strings.TrimPrefix(s, "sync:")] = true
	}
	// Every directory this root created, and the container the root's own name
	// lives in.
	for _, want := range []string{"dst", "dst/a", "dst/a/sub", "dst/a/empty"} {
		if !synced[filepath.FromSlash(want)] && !synced[want] {
			t.Errorf("steps = %v, want %q flushed before the delete", steps, want)
		}
	}

	// And a plain COPY pays none of it: it deletes nothing, so there is nothing
	// a crash could leave it without.
	steps = nil
	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{Conflict: wproto.ConflictRename}, "/src"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	for _, s := range steps {
		if strings.HasPrefix(s, "sync:") {
			t.Fatalf("steps = %v: a copy fsynced a destination directory it never deletes anything for", steps)
		}
	}
}

// TestAPlainCopyKeepsNoDeletionLedger is round 14's third finding: the
// per-entry proofs exist so a MOVE can show what it is about to delete, and a
// copy deletes nothing — but it wrote them all down anyway and held them for as
// long as the job ran. A few hundred bytes an entry is hundreds of megabytes
// over a million files, for proofs nothing would ever read.
//
// The per-DIRECTORY records stay for both kinds: the ancestor re-check compares
// every entry against them (ancestorUnchanged), and there is one per directory
// rather than one per file.
func TestAPlainCopyKeepsNoDeletionLedger(t *testing.T) {
	r, base := copyFixture(t)
	var seen []*copiedDir
	prev := ledgerObserved
	ledgerObserved = func(rec *copiedDir) { seen = append(seen, rec) }
	t.Cleanup(func() { ledgerObserved = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("%d roots recorded, want 1", len(seen))
	}
	if n := recordedEntries(seen[0]); n != 0 {
		t.Fatalf("a plain copy wrote down %d per-entry proofs it will never read", n)
	}
	if seen[0].mode == 0 {
		t.Error("the source directory's own state was not recorded; the ancestor check has nothing to compare against")
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Fatalf("dst/a/sub/two.txt = %q — the copy itself has to be unaffected", got)
	}

	// A move writes them down, because a move reads them back.
	seen = nil
	r2, _ := copyFixture(t)
	forceEXDEV(t)
	var moved jobLog
	if _, err := Copy(context.Background(), r2, nil,
		copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, moved.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("%d roots recorded for the move, want 1", len(seen))
	}
	if n := recordedEntries(seen[0]); n == 0 {
		t.Fatal("a move recorded nothing, so it has no proof to delete its source against")
	}
}

// recordedEntries counts every per-entry proof a root's record holds, at every
// depth.
func recordedEntries(rec *copiedDir) int {
	if rec == nil {
		return 0
	}
	n := len(rec.entries)
	for _, e := range rec.entries {
		n += recordedEntries(e.dir)
	}
	return n
}
