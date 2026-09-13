package fsops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The change-time settling of the round-3 adversarial review (finding 1). It is
// Linux-only because it is about st_ctim, which no other platform here has.

// fakeClock puts a scripted destination clock in front of the settling loop.
// Making a real kernel hand out two identical change times on demand is not
// something a test can do, and the branch behind it decides whether a move
// deletes anything at all.
// The script is given the DIRECTORY the reading was asked about as well as the
// call number, because a job reads two clocks: the source's, before it reads a
// file, and the destination's, before it trusts a copy. Keying on the call
// number alone tied each scripted step to whichever reading happened to come
// first, which is a property of the engine's internal ordering rather than of
// anything a test means — and it broke the moment that ordering changed.
func fakeClock(t *testing.T, reads *int, at func(n int, d *dirRef) (time.Time, error)) {
	t.Helper()
	prev := fsClockAt
	fsClockAt = func(d *dirRef) (time.Time, error) {
		*reads++
		return at(*reads, d)
	}
	t.Cleanup(func() { fsClockAt = prev })
}

// onSource reports whether a clock reading was asked of the source side of the
// fixture. The two sides share a filesystem in these tests, so the directory is
// what tells them apart.
func onSource(d *dirRef) bool { return d != nil && strings.HasPrefix(d.rel, "src") }

// realClock is what a healthy filesystem's clock does, for the side of a test
// that is not its subject: a scripted stall belongs on the reading under test
// and nowhere else.
func realClock() (time.Time, error) { return time.Now(), nil }

// ctimeOf is the change time of one path in the fixture.
func ctimeOf(t *testing.T, base, rel string) time.Time {
	t.Helper()
	ct, ok := changeTimeOf(lstat(t, base, rel))
	if !ok {
		t.Skip("this filesystem does not report a change time")
	}
	return ct
}

// TestMoveWaitsForTheFilesystemClockToAdvance: while the filesystem's own clock
// still reads the instant the copied file was last changed, a later in-place
// rewrite would be indistinguishable from what was recorded. So the job waits
// for the tick to move — and then trusts the record and completes.
func TestMoveWaitsForTheFilesystemClockToAdvance(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	stuck := ctimeOf(t, base, "src/a/one.txt")

	reads := 0
	fakeClock(t, &reads, func(n int, d *dirRef) (time.Time, error) {
		if !onSource(d) {
			// The destination proof is not what this test stalls.
			return realClock()
		}
		if n <= 3 {
			// The same tick: nothing that happens now can be told apart from
			// what was recorded.
			return stuck, nil
		}
		return stuck.Add(10 * time.Millisecond), nil
	})
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if reads < 4 {
		t.Fatalf("the clock was read %d times; the job did not wait for the tick to advance", reads)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings after the clock advanced: %v", log.warns)
	}
	if res.Files != 1 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want the file moved", res)
	}
	if exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was kept although the record became verifiable")
	}
	if got := readFile(t, base, "dst/one.txt"); got != "one" {
		t.Fatalf("dst/one.txt = %q", got)
	}
}

// TestMoveKeepsWhatTheClockCannotSettle is the reviewer's probe, in the only
// form a test can stage it: a kernel whose inode clock does not advance inside
// the bound. A same-length rewrite with a restored mtime would then be
// indistinguishable from the state about to be copied — so the file is not
// moved at all, and NOTHING is published for it: the settle now happens before
// a byte is read, so there is no half-trusted copy to explain away.
func TestMoveKeepsWhatTheClockCannotSettle(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	stuck := ctimeOf(t, base, "src/a/one.txt")

	reads := 0
	fakeClock(t, &reads, func(_ int, d *dirRef) (time.Time, error) {
		if !onSource(d) {
			return realClock()
		}
		return stuck, nil
	})
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if reads <= ctimeWaitTries {
		t.Fatalf("the clock was read %d times, want the bounded wait to have run out", reads)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was deleted on a state that could not be proved settled")
	}
	if exists(t, base, "dst/one.txt") {
		t.Fatal("something was published for an entry that was never settled")
	}
	if indexOf(log.codes(), warnUnverified) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnUnverified)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Errorf("result = %+v, want the entry skipped before anything was copied", res)
	}
}

// TestMoveNoticesARewriteDuringTheSettle is the round-4 scenario: the rewrite
// happens in the window the settle itself opens — same length, mtime restored —
// and the second look is what catches it. Nothing is published with the old
// bytes and the source is never deleted.
func TestMoveNoticesARewriteDuringTheSettle(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	path := filepath.Join(base, "src", "a", "one.txt")
	before := lstat(t, base, "src/a/one.txt")
	stuck := ctimeOf(t, base, "src/a/one.txt")

	reads := 0
	fakeClock(t, &reads, func(n int, d *dirRef) (time.Time, error) {
		if !onSource(d) {
			return realClock()
		}
		if n == 1 {
			// While the job is waiting for the tick to pass, the file is
			// rewritten in place with the same number of bytes and its
			// modification time put back.
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Error(err)
			} else {
				if _, werr := f.WriteAt([]byte("XXX"), 0); werr != nil {
					t.Error(werr)
				}
				f.Close()
			}
			if cerr := os.Chtimes(path, before.ModTime(), before.ModTime()); cerr != nil {
				t.Error(cerr)
			}
		}
		// The clock then advances, so the wait itself succeeds and only the
		// second look can notice what happened.
		return stuck.Add(time.Duration(n) * time.Millisecond), nil
	})
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a/one.txt"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("a file rewritten during the settle was deleted")
	}
	if got := readFile(t, base, "src/a/one.txt"); got != "XXX" {
		t.Fatalf("src/a/one.txt = %q — the newer bytes were destroyed", got)
	}
	if exists(t, base, "dst/one.txt") {
		if got := readFile(t, base, "dst/one.txt"); got == "one" {
			t.Fatal("the older bytes were published at the destination for a file that had already changed")
		}
	}
	if res.Skipped != 1 {
		t.Errorf("result = %+v, want the entry skipped", res)
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
}

// TestASurvivingHardLinkIsProvedByItsBytes is the round-5 adversarial finding,
// and the reason the re-baselining machinery is gone: no amount of care with
// timestamps can prove a hard-linked file, because the change time the second
// link is judged by was moved by this job's OWN unlink of the first, and any
// value carried forward from that lies in the current tick.
//
// So the surviving link is compared with its copy byte for byte. Here it is
// rewritten — same length, so every timestamp-shaped check would have passed —
// after its sibling was removed, and it is kept.
func TestASurvivingHardLinkIsProvedByItsBytes(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/original.txt", "shared bytes")
	if err := os.Link(filepath.Join(base, "src", "a", "original.txt"),
		filepath.Join(base, "src", "a", "sub", "linked.txt")); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	// Staged at the engine's own "delete" step, before ANY entry is judged, and
	// not on the first finishing update — that one is emitted only after an
	// entry's source has already been unlinked, so which link it caught
	// depended on the order Readdirnames happened to return.
	rewritten := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "delete" || rewritten {
			return
		}
		rewritten = true
		// One inode, two names. Same length AND the modification time put back,
		// so identity, size and mtime all still match the record — and a
		// hard-linked entry does not consult the change time — leaving the
		// bytes as the only thing that can give it away.
		rel := "src/a/original.txt"
		was := lstat(t, base, rel).ModTime()
		write(t, base, rel, "SHARED BYTES")
		if cerr := os.Chtimes(filepath.Join(base, filepath.FromSlash(rel)), was, was); cerr != nil {
			t.Error(cerr)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	log := &jobLog{}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !rewritten {
		t.Fatal("the delete never started, so nothing was staged")
	}
	survivor := exists(t, base, "src/a/original.txt") || exists(t, base, "src/a/sub/linked.txt")
	if !survivor {
		t.Fatal("the surviving link was removed although its bytes no longer matched the copy")
	}
	if !warnSaying(*log, warnKept, "byte for byte") {
		t.Fatalf("warnings = %v, want one saying the bytes did not match", log.warns)
	}
}

// TestACopyNeverPaysForTheClock: the record is only ever read back by a move,
// so a copy neither waits for the clock nor warns about it.
func TestACopyNeverPaysForTheClock(t *testing.T) {
	r, base := copyFixture(t)
	stuck := ctimeOf(t, base, "src/a/one.txt")
	reads := 0
	fakeClock(t, &reads, func(_ int, d *dirRef) (time.Time, error) {
		if !onSource(d) {
			return realClock()
		}
		return stuck, nil
	})
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if reads != 0 {
		t.Errorf("a copy read the filesystem clock %d times; it never reads its own record back", reads)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a plain copy: %v", log.warns)
	}
}

// TestAnOldRecordNeedsNoProof: a change time older than the window cannot
// collide with a write made now, so the clock is not consulted at all.
func TestAnOldRecordNeedsNoProof(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)
	reads := 0
	fakeClock(t, &reads, func(int, *dirRef) (time.Time, error) { return time.Time{}, fsx.ErrUnsupported })

	c := &copier{move: true}
	if !c.settled(nil, time.Now().Add(-time.Hour), true) {
		t.Fatal("a change time from an hour ago needs no proof")
	}
	if reads != 0 {
		t.Errorf("the clock was read %d times for a record that cannot collide", reads)
	}
	_ = base
	_ = r
}

// TestADestinationRemovedDuringTheSettleIsNoticed is round 9's adversarial
// finding: the deletion proofs used to be taken BEFORE the clock wait and not
// refreshed, so a copy truncated or unlinked while that wait was running was
// judged on figures from before it and the source was removed anyway.
//
// The sources are aged past ctimeRecent so the copy phase needs no clock at
// all; every reading below therefore belongs to the delete, and the copies are
// removed from underneath it at exactly that moment.
func TestADestinationRemovedDuringTheSettleIsNoticed(t *testing.T) {
	r, base := copyFixture(t)
	time.Sleep(ctimeRecent + 200*time.Millisecond)
	forceEXDEV(t)

	reads := 0
	fakeClock(t, &reads, func(n int, d *dirRef) (time.Time, error) {
		if n == 1 {
			// The wait is running. Both published copies go away.
			for _, rel := range []string{"dst/a/one.txt", "dst/a/sub/two.txt"} {
				if exists(t, base, rel) {
					if err := os.Remove(filepath.Join(base, filepath.FromSlash(rel))); err != nil {
						t.Error(err)
					}
				}
			}
		}
		return time.Now(), nil
	})
	log := &jobLog{}

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if reads == 0 {
		t.Fatal("the delete never consulted the clock, so nothing was staged")
	}
	if !exists(t, base, "src/a/one.txt") && !exists(t, base, "src/a/sub/two.txt") {
		t.Fatal("a source was deleted although its copy had gone during the clock wait")
	}
	if !warnSaying(*log, warnKept, "no longer at the destination") {
		t.Fatalf("warnings = %v, want one naming the copy that had gone", log.warns)
	}
}
