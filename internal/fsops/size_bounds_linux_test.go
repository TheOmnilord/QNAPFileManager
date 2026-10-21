package fsops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"taproot/internal/wproto"
)

// TestSizeTimeBoundHoldsOverChildrenItCannotEnter is Astra stabilization r1 P2
// on a real kernel. A directory the user may LIST but not ENTER — read without
// execute — gives up every child's name and refuses every child's lstat, so the
// walk visits none of them: each refusal is a warning, and the visitor's clock
// reading, taken only when an entry is counted, never runs. Before the walk had
// a deadline context of its own, a measurement of such a directory ran on past
// its time bound to the last child and finished as though it had measured the
// folder, holding its metadata slot throughout.
//
// The first refusal here takes longer than the whole bound, the way a walk
// through millions of such children spends its ten minutes, and the walk must
// stop at the very next child with Capped: done, with a floor, not complete.
func TestSizeTimeBoundHoldsOverChildrenItCannotEnter(t *testing.T) {
	requireUnprivileged(t)
	const children = 64
	base := tempDir(t)
	mkdir(t, base, "listed")
	for i := 0; i < children; i++ {
		write(t, base, fmt.Sprintf("listed/f%03d", i), "x")
	}
	listed := filepath.Join(base, "listed")
	if err := os.Chmod(listed, 0o644); err != nil {
		t.Fatal(err)
	}
	// Back to enterable before the temporary directory is removed.
	t.Cleanup(func() { _ = os.Chmod(listed, 0o755) })
	r := newRoot(t, base)

	const bound = 200 * time.Millisecond
	var log jobLog
	emit := log.emit()
	refused := 0
	emit.Warn = func(w wproto.Warn) {
		log.warns = append(log.warns, w)
		if w.Code == scanCappedCode {
			return
		}
		refused++
		if refused == 1 {
			time.Sleep(2 * bound)
		}
	}
	res, err := Size(context.Background(), r, nil, []string{"/listed"}, SizeOptions{MaxDuration: bound}, emit)
	if err != nil {
		t.Fatalf("Size: %v, want the time bound reported as one", err)
	}
	if !res.Capped {
		t.Fatalf("result = %+v after %d of %d refused children: the walk ran past its time bound", res, refused, children)
	}
	if refused == 0 || refused >= children {
		t.Fatalf("%d of %d children refused before the walk stopped, want it stopped at the first one past the bound", refused, children)
	}
	if indexOf(log.codes(), scanCappedCode) < 0 {
		t.Fatalf("warn codes = %v, want the capped walk said", log.codes())
	}
}

// TestSizeCancellationOverChildrenItCannotEnterStaysACancellation is the other
// half on the same kernel shape: a caller that cancels while the walk is
// spending its time on refused children gets a cancellation, not a bound —
// even though, by the time the walk looks again, its own deadline has expired
// as well.
func TestSizeCancellationOverChildrenItCannotEnterStaysACancellation(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "listed")
	for i := 0; i < 16; i++ {
		write(t, base, fmt.Sprintf("listed/f%03d", i), "x")
	}
	listed := filepath.Join(base, "listed")
	if err := os.Chmod(listed, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(listed, 0o755) })
	r := newRoot(t, base)

	const bound = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var log jobLog
	emit := log.emit()
	emit.Warn = func(w wproto.Warn) {
		log.warns = append(log.warns, w)
		if len(log.warns) == 1 {
			cancel()              // the caller gives up...
			time.Sleep(2 * bound) // ...and the walk's own deadline passes too
		}
	}
	res, err := Size(ctx, r, nil, []string{"/listed"}, SizeOptions{MaxDuration: bound}, emit)
	if err == nil || ctx.Err() == nil || res.Capped {
		t.Fatalf("result = %+v, %v: want the cancellation, not the bound", res, err)
	}
	if indexOf(log.codes(), scanCappedCode) >= 0 {
		t.Fatalf("warn codes = %v: a cancellation was reported as the bound", log.codes())
	}
}
