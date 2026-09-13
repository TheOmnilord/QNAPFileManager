package config

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestLockLetsExactlyOneWriterThrough is the contention assertion, and it runs
// against whichever implementation the platform uses: flock on Linux, O_EXCL on
// the dev box.
//
// It contends for a lock that is being TAKEN, not one being broken. That is the
// case the daemon and the CLI actually produce, and on Linux it is now the only
// case there is — flock has no break logic, because the kernel releases the lock
// when the holder dies (round-4).
func TestLockLetsExactlyOneWriterThrough(t *testing.T) {
	// Shortened so twenty rounds of real contention cost a second rather than
	// forty: the loser waits out LockWait by design. Set before any goroutine
	// exists and restored after they are all joined.
	defaultWait := LockWait
	t.Cleanup(func() { LockWait = defaultWait })
	LockWait = 50 * time.Millisecond

	for round := 0; round < 20; round++ {
		p := filepath.Join(t.TempDir(), "config.json")
		// Both start together and both HOLD whatever they get, so a double
		// acquisition cannot be hidden by one of them finishing first.
		start := make(chan struct{})
		type result struct {
			release func()
			err     error
		}
		results := make(chan result, 4)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				release, err := Lock(p)
				results <- result{release, err}
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		var held int
		var releases []func()
		for r := range results {
			if r.err == nil {
				held++
				releases = append(releases, r.release)
			} else if !errors.Is(r.err, ErrLocked) {
				t.Fatalf("round %d: unexpected error %v", round, r.err)
			}
		}
		for _, release := range releases {
			release()
		}
		if held != 1 {
			t.Fatalf("round %d: %d writers held the lock at once, want exactly 1", round, held)
		}
		// And the lock is reusable once released.
		again, err := Lock(p)
		if err != nil {
			t.Fatalf("round %d: the lock was not released: %v", round, err)
		}
		again()
	}
}
