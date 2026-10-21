package fsops

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"taproot/internal/wproto"
)

// The size walk's own bounds (stabilization contract §2.1): MaxDuration beside
// MaxEntries, the tighter of the caller's and the package's, and a cancellation
// that is never reported as either.

// boundsTree builds /many holding n one-byte files. The scan reads its clock
// once every scanTimeCheck items, so a time bound can only be reached by a tree
// with more entries than that.
func boundsTree(t *testing.T, n int) string {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "many")
	for i := 0; i < n; i++ {
		write(t, base, fmt.Sprintf("many/f%04d", i), "x")
	}
	return base
}

// TestSizeStopsAtItsTimeBound: a walk that reaches MaxDuration ends where it
// stands and answers exactly as an entry bound does — Capped, the counts so
// far, one "capped" warning, and no error. It is the walk's verdict on itself,
// not a failure and not a cancellation.
func TestSizeStopsAtItsTimeBound(t *testing.T) {
	const files = 3 * scanTimeCheck
	r := newRoot(t, boundsTree(t, files))
	var log jobLog

	// A nanosecond is long gone by the walk's first look at its deadline — the
	// walk context's, or at the latest the visitor's clock reading scanTimeCheck
	// items in — so it stops long before the end of the tree, possibly before
	// counting anything at all.
	res, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxDuration: time.Nanosecond}, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if !res.Capped {
		t.Fatalf("result = %+v, want Capped", res)
	}
	if got := res.Files + res.Dirs; got >= files+1 {
		t.Fatalf("counted %d of %d items, want the walk stopped before the end", got, files+1)
	}
	if indexOf(log.codes(), scanCappedCode) < 0 {
		t.Fatalf("warn codes = %v, want the capped walk reported", log.codes())
	}
}

// TestSizeTakesTheEarlierOfTwoDeadlines: the caller's MaxDuration and the
// package's own sizeScanLimits are combined the way the two entry bounds are —
// whichever deadline comes first applies, on either side — and a duration that
// is not positive is no bound at all.
func TestSizeTakesTheEarlierOfTwoDeadlines(t *testing.T) {
	const files = 3 * scanTimeCheck
	r := newRoot(t, boundsTree(t, files))
	cases := []struct {
		name   string
		pkg    time.Time     // sizeScanLimits.deadline
		opt    time.Duration // SizeOptions.MaxDuration
		capped bool
	}{
		{"the caller's deadline is the earlier", time.Now().Add(time.Hour), time.Nanosecond, true},
		{"the package's deadline is the earlier", time.Now().Add(-time.Hour), time.Hour, true},
		{"the caller's deadline alone, not reached", time.Time{}, time.Hour, false},
		{"a negative duration is no bound", time.Time{}, -time.Second, false},
		{"no bound at all", time.Time{}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := sizeScanLimits
			sizeScanLimits = scanLimits{deadline: tc.pkg}
			t.Cleanup(func() { sizeScanLimits = prev })

			var log jobLog
			res, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxDuration: tc.opt}, log.emit())
			if err != nil {
				t.Fatalf("Size: %v", err)
			}
			if res.Capped != tc.capped {
				t.Fatalf("Capped = %v, want %v (result %+v)", res.Capped, tc.capped, res)
			}
			if !tc.capped && (res.Files != files || res.Dirs != 1) {
				t.Fatalf("result = %+v, want the whole tree: %d files and the folder", res, files)
			}
		})
	}
}

// TestSizeNeverReportsACancellationAsItsBound: a cancellation can land in the
// very instant the walk reaches its bound — the visitor that counts the entry
// reaching it runs after the context was cancelled and before the walk looks
// at the context again. The job stopped because somebody asked it to, so it is
// a cancellation (§2.1): the error is the context's, Capped is not set, and no
// "stopped at its limit" warning goes out to be read as the measurement's own
// verdict.
func TestSizeNeverReportsACancellationAsItsBound(t *testing.T) {
	r := newRoot(t, boundsTree(t, 20))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const bound = 5
	var log jobLog
	seen := 0
	emit := log.emit()
	// The progress hook runs inside the visitor, after the entry is counted and
	// before the bound is checked: cancelling on the bound-th entry is exactly
	// the race.
	emit.Prog = func(p wproto.Prog) {
		seen++
		if seen == bound {
			cancel()
		}
		log.progs = append(log.progs, p)
	}
	res, err := Size(ctx, r, nil, []string{"/many"}, SizeOptions{MaxEntries: bound}, emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Size error = %v, want the cancellation", err)
	}
	if res.Capped {
		t.Fatalf("result = %+v: a cancelled walk was reported as one that reached its bound", res)
	}
	if indexOf(log.codes(), scanCappedCode) >= 0 {
		t.Fatalf("warn codes = %v: a cancelled walk warned that it stopped at its limit", log.codes())
	}
	if got := res.Files + res.Dirs; got != bound {
		t.Fatalf("partial counts = %d, want the %d items counted before it stopped", got, bound)
	}
}

// expiredSizeWalk replaces the walk's own deadline with a context that is
// already done — the shape of a walk that spent its whole bound on entries it
// never visited, which only a real kernel can stage (see the Linux test of the
// same name) — and records the deadline Size asked for.
func expiredSizeWalk(t *testing.T, asked *time.Time) {
	t.Helper()
	prev := sizeWalkDeadline
	sizeWalkDeadline = func(ctx context.Context, d time.Time) (context.Context, context.CancelFunc) {
		*asked = d
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c, cancel
	}
	t.Cleanup(func() { sizeWalkDeadline = prev })
}

// TestSizeTimeBoundIsAContextOfItsOwn is the plumbing of Astra stabilization r1
// P2, portable: the time bound reaches the walk as a context of its own, the
// expiry of that context is the bound — Capped, warned once, no error, so the
// job ends done — the caller's cancellation still wins when both are over, the
// deadline handed over is the earlier of the two, and a measurement with no
// time bound gets no context of its own at all, which is what leaves the
// pre-scans, whose clock is their request, exactly as they were.
func TestSizeTimeBoundIsAContextOfItsOwn(t *testing.T) {
	r := newRoot(t, boundsTree(t, 20))

	t.Run("its expiry is the bound", func(t *testing.T) {
		var asked time.Time
		expiredSizeWalk(t, &asked)
		var log jobLog
		start := time.Now()
		res, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxDuration: time.Hour}, log.emit())
		if err != nil {
			t.Fatalf("Size: %v, want the bound reported as one and not as an error", err)
		}
		if !res.Capped {
			t.Fatalf("result = %+v, want Capped", res)
		}
		capped := 0
		for _, code := range log.codes() {
			if code == scanCappedCode {
				capped++
			}
		}
		if capped != 1 {
			t.Fatalf("warn codes = %v, want the capped walk said exactly once", log.codes())
		}
		if asked.Before(start.Add(time.Hour)) || asked.After(time.Now().Add(time.Hour)) {
			t.Fatalf("walk deadline %v, want an hour from when the walk started", asked)
		}
	})

	t.Run("the caller's cancellation still wins", func(t *testing.T) {
		var asked time.Time
		expiredSizeWalk(t, &asked)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var log jobLog
		res, err := Size(ctx, r, nil, []string{"/many"}, SizeOptions{MaxDuration: time.Hour}, log.emit())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Size error = %v, want the cancellation", err)
		}
		if res.Capped || indexOf(log.codes(), scanCappedCode) >= 0 {
			t.Fatalf("result = %+v, warn codes %v: a cancellation was reported as the bound", res, log.codes())
		}
	})

	t.Run("the earlier deadline is the one handed over", func(t *testing.T) {
		prev := sizeScanLimits
		earlier := time.Now().Add(time.Minute)
		sizeScanLimits = scanLimits{deadline: earlier}
		t.Cleanup(func() { sizeScanLimits = prev })
		var asked time.Time
		expiredSizeWalk(t, &asked)
		if _, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxDuration: time.Hour}, Emit{}); err != nil {
			t.Fatalf("Size: %v", err)
		}
		if !asked.Equal(earlier) {
			t.Fatalf("walk deadline %v, want the earlier one, %v", asked, earlier)
		}
	})

	t.Run("no time bound, no context of its own", func(t *testing.T) {
		prev := sizeWalkDeadline
		called := false
		sizeWalkDeadline = func(ctx context.Context, d time.Time) (context.Context, context.CancelFunc) {
			called = true
			return prev(ctx, d)
		}
		t.Cleanup(func() { sizeWalkDeadline = prev })
		res, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxEntries: 1000}, Emit{})
		if err != nil || res.Capped || res.Files != 20 {
			t.Fatalf("result = %+v, %v, want the whole tree", res, err)
		}
		if called {
			t.Fatal("a measurement with no time bound was given a deadline of its own")
		}
	})
}

// TestSizeEntryBoundIsStillABound: the same entry bound, with nobody
// cancelling, is the capped answer it always was.
func TestSizeEntryBoundIsStillABound(t *testing.T) {
	r := newRoot(t, boundsTree(t, 20))
	var log jobLog
	res, err := Size(context.Background(), r, nil, []string{"/many"}, SizeOptions{MaxEntries: 5}, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if !res.Capped || res.Files+res.Dirs != 5 {
		t.Fatalf("result = %+v, want Capped at 5 items", res)
	}
	if indexOf(log.codes(), scanCappedCode) < 0 {
		t.Fatalf("warn codes = %v, want the capped walk reported", log.codes())
	}
}
