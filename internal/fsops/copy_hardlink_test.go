package fsops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestMoveOfATreeWithHardLinksCompletes is the round-3 finding: two names for
// one inode both record that inode's change time, and unlinking the first moves
// it — the link count is part of the inode. The second link's record then did
// not match, and a move of an entirely ordinary tree was left half done with a
// `kept` warning for something nobody had touched.
//
// Hard links are copied as independent files (§1.6), which is what the
// destination is checked for here; the point of the test is that the SOURCE is
// fully removed and the job is clean.
func TestMoveOfATreeWithHardLinksCompletes(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/original.txt", "shared bytes")
	// A second name for the same inode, in another directory of the same tree,
	// so the two are removed at different points of the post-order walk.
	if err := os.Link(filepath.Join(base, "src", "a", "original.txt"),
		filepath.Join(base, "src", "a", "sub", "linked.txt")); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}
	if inodeIdentity && nlinkOf(t, base, "src/a/original.txt") < 2 {
		t.Skip("this filesystem does not report a link count above one, so there is no re-baselining to exercise")
	}
	r := newRoot(t, base)
	forceEXDEV(t)
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a move of a tree with a hard link in it: %v", log.warns)
	}
	if res.Files != 2 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want both links copied and nothing skipped", res)
	}

	// Both names are gone from the source, and so is the tree they were in.
	if exists(t, base, "src/a") {
		t.Fatal("the source was left behind although every entry was verifiably copied")
	}
	// Both are at the destination, as independent files with the same contents.
	for _, rel := range []string{"dst/a/original.txt", "dst/a/sub/linked.txt"} {
		if got := readFile(t, base, rel); got != "shared bytes" {
			t.Errorf("%s = %q", rel, got)
		}
		if n := nlinkOf(t, base, rel); n > 1 {
			t.Errorf("%s has a link count of %d; a copy makes independent files", rel, n)
		}
	}
}

// TestMoveStillNoticesAnExternalChangeToAHardLinkedFile: re-baselining must not
// buy the completed move at the price of the detection it exists beside. A
// write through one link after the copy still keeps both.
func TestMoveStillNoticesAnExternalChangeToAHardLinkedFile(t *testing.T) {
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
	var log jobLog
	emit := onceAt(&log, "/dst/a/original.txt", 2, func() {
		// One inode, two names, rewritten through the one that is not being
		// copied at this instant.
		write(t, base, "src/a/sub/linked.txt", "rewritten through the other name")
	})

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, emit); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !exists(t, base, "src/a/original.txt") && !exists(t, base, "src/a/sub/linked.txt") {
		t.Fatal("a file rewritten while the job ran was removed through both of its names")
	}
	if indexOf(log.codes(), warnKept) < 0 {
		t.Fatalf("warn codes = %v, want %q: the change has to be noticed", log.codes(), warnKept)
	}
}

// nlinkOf reports a file's link count, or 1 where the platform does not say.
func nlinkOf(t *testing.T, base, rel string) uint64 {
	t.Helper()
	_, _, nlink, ok := statDetail(lstat(t, base, rel))
	if !ok {
		return 1
	}
	return nlink
}

// TestCancellingTheComparisonIsACancellation is round 6's third finding: a
// ctx error inside the byte comparison became a per-entry warning and the job
// went on to report ordinary success with Cancelled unset — so a CancelJob from
// another request looked like completion.
func TestCancellingTheComparisonIsACancellation(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "shared bytes")
	if err := os.Link(filepath.Join(base, "src", "a", "one.txt"),
		filepath.Join(base, "src", "a", "two.txt")); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &jobLog{}
	emit := log.emit()
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			// The delete has started: stop the job while it is proving the
			// links.
			if p.Phase == wproto.PhaseFinishing {
				cancel()
			}
			emit.Prog(p)
		},
		Warn: emit.Warn,
	}

	_, err := Copy(ctx, r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, wrapped)
	if err == nil {
		t.Fatal("a move cancelled during its delete reported ordinary success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Copy(move) = %v, want the cancellation", err)
	}
}

// TestSameBytesStopsWhenTheJobIsCancelled pins the propagation at its source:
// the comparison itself returns the context's error rather than "these files
// differ", which is what kept a cancellation from being mistaken for a mismatch.
func TestSameBytesStopsWhenTheJobIsCancelled(t *testing.T) {
	base := tempDir(t)
	write(t, base, "one.txt", "some bytes")
	write(t, base, "two.txt", "some bytes")
	a, err := os.Open(filepath.Join(base, "one.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.Open(filepath.Join(base, "two.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &copier{}
	same, cerr := c.sameBytes(ctx, a, b)
	if same {
		t.Error("a cancelled comparison must not report a match")
	}
	if !errors.Is(cerr, context.Canceled) {
		t.Fatalf("sameBytes = %v, want the cancellation", cerr)
	}
}
