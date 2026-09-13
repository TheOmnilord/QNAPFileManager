//go:build !linux

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The stale-lock machinery exists only off Linux, so its tests do too. On the
// NAS the kernel releases a dead holder's flock and there is nothing to break —
// which is the whole reason this path was split away (round-4).

func TestStaleLockIsBroken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	lockPath := p + ".lock"
	if err := os.WriteFile(lockPath, []byte("999999 2020-01-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * LockStale)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	// A process that died holding the lock must not shut the operator out of
	// their own configuration forever.
	release, err := Lock(p)
	if err != nil {
		t.Fatalf("a stale lock was not broken: %v", err)
	}
	release()
	// The broken lock leaves no debris.
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".dead-") {
			t.Errorf("%s was left behind", e.Name())
		}
	}
}

// A stale-break rename that keeps failing — a directory that has gone
// read-only, the loser of a race — must not send Lock straight back to the top
// with neither a deadline check nor a sleep. That is a spin on a core.
func TestAFailingStaleBreakStillTimesOut(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	lockPath := p + ".lock"
	if err := os.WriteFile(lockPath, []byte("999999 2020-01-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * LockStale)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}

	defaultWait, defaultRename := LockWait, renameLock
	t.Cleanup(func() { LockWait, renameLock = defaultWait, defaultRename })
	LockWait = 120 * time.Millisecond
	var attempts int
	renameLock = func(string, string) error {
		attempts++
		return errors.New("the break always fails here")
	}

	start := time.Now()
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("Lock = %v, want ErrLocked", err)
	}
	elapsed := time.Since(start)
	if elapsed < LockWait {
		t.Fatalf("Lock gave up after %v, before its %v budget", elapsed, LockWait)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Lock took %v; the wait is no longer bounded", elapsed)
	}
	if attempts == 0 {
		t.Fatal("the stale break was never attempted")
	}
	if maxTries := int(LockWait/lockPoll) + 4; attempts > maxTries {
		t.Fatalf("%d break attempts in %v; Lock is spinning rather than polling", attempts, elapsed)
	}
	// And the unbroken lock is still there for whoever looks next.
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("the unbroken lock disappeared: %v", err)
	}
}
