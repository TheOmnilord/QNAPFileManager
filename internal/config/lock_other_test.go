//go:build !linux

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// --- Astra r8 CI: the Windows delete-pending window --------------------------

// The flake this is about: on Windows a file that another writer is in the
// middle of deleting stays in its directory in a delete-pending state, and an
// open of that name is refused with ERROR_ACCESS_DENIED rather than ErrExist.
// The acquire loop used to call that fatal, so a generator that arrived during
// somebody else's release did not wait its turn — it failed, and the CI job
// reported "a generator could not take the lock" and one writer short.
//
// The window cannot be staged from pure Go, so the refusal is injected at the
// open seam: once, then the real thing. What is asserted is the branch, not the
// sharing state — that the first refusal is waited out rather than returned.
func TestADeletePendingCreateIsWaitedOutNotRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	lockPath := p + ".lock"

	defaultOpen := openLock
	t.Cleanup(func() { openLock = defaultOpen })
	var attempts int
	openLock = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		attempts++
		if attempts == 1 {
			// What Windows returns for a name whose deletion has not finished.
			return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
		}
		return defaultOpen(name, flag, perm)
	}

	release, err := Lock(p)
	if err != nil {
		t.Fatalf("a momentary refusal was treated as fatal: %v", err)
	}
	if attempts < 2 {
		t.Fatalf("the open was attempted %d times; the refusal was not retried", attempts)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("the lock was reported taken but no lock file exists: %v", err)
	}
	release()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("the lock file survived release: %v", err)
	}
}

// ERROR_SHARING_VIOLATION is the same news from a handle opened without
// FILE_SHARE_DELETE, and Go does not map it to ErrPermission — so it needs its
// own arm, and that arm is only meaningful where the number means what it says.
func TestASharingViolationIsWaitedOutNotRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ERROR_SHARING_VIOLATION is a Windows number; elsewhere 32 is something else entirely")
	}
	p := filepath.Join(t.TempDir(), "config.json")

	defaultOpen := openLock
	t.Cleanup(func() { openLock = defaultOpen })
	var attempts int
	openLock = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		attempts++
		if attempts == 1 {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.Errno(32)}
		}
		return defaultOpen(name, flag, perm)
	}

	release, err := Lock(p)
	if err != nil {
		t.Fatalf("a sharing violation was treated as fatal: %v", err)
	}
	release()
	if attempts < 2 {
		t.Fatalf("the open was attempted %d times; the refusal was not retried", attempts)
	}
}

// Waiting it out is bounded, and the wait that runs out still says what it kept
// being told: a directory that has gone read-only must not read as a phantom
// holder.
func TestANameThatNeverOpensStillEndsAsErrLocked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")

	defaultWait, defaultOpen := LockWait, openLock
	t.Cleanup(func() { LockWait, openLock = defaultWait, defaultOpen })
	LockWait = 120 * time.Millisecond
	openLock = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}

	start := time.Now()
	_, err := Lock(p)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Lock = %v, want ErrLocked", err)
	}
	if elapsed := time.Since(start); elapsed < LockWait || elapsed > 2*time.Second {
		t.Fatalf("Lock took %v, want about its %v budget", elapsed, LockWait)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the refusal must carry what it kept being told: %v", err)
	}
}

// The other half of the same sharing state: the delete is refused too. Dropping
// it on the first refusal leaves the lock file behind, and then every later
// writer waits out LockWait and is told the config is held by a process that
// finished long ago — which is how TestUpdateSerialisesConcurrentWriters saw
// "the O_EXCL lock file was left behind".
func TestAReleaseRefusedOnceStillRemovesTheLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	lockPath := p + ".lock"

	defaultRemove := removeLock
	t.Cleanup(func() { removeLock = defaultRemove })
	var attempts int
	removeLock = func(name string) error {
		attempts++
		if attempts == 1 {
			return &os.PathError{Op: "remove", Path: name, Err: os.ErrPermission}
		}
		return defaultRemove(name)
	}

	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if attempts < 2 {
		t.Fatalf("the remove was attempted %d times; the refusal was not retried", attempts)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("the lock file was left behind: %v", err)
	}
	// And the name is free for the next writer, immediately.
	again, err := Lock(p)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	again()
}

// A delete that keeps being refused must not be retried forever: past LockStale
// the name can belong to another writer, and removing it would be removing
// their live lock. The retry is a fifth of a second against thirty, and it
// stops.
func TestAReleaseThatIsAlwaysRefusedGivesUpQuickly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")

	defaultRemove := removeLock
	t.Cleanup(func() { removeLock = defaultRemove })
	var attempts int
	removeLock = func(name string) error {
		attempts++
		return &os.PathError{Op: "remove", Path: name, Err: os.ErrPermission}
	}

	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	release()
	elapsed := time.Since(start)
	if attempts < 2 {
		t.Fatalf("the remove was attempted %d times; the refusal was not retried at all", attempts)
	}
	if attempts > lockReleaseTries+2 {
		t.Fatalf("%d remove attempts; release is no longer bounded", attempts)
	}
	if elapsed > LockStale/10 {
		t.Fatalf("release took %v; it must not outlive a stale break", elapsed)
	}
	// The file is still there, because it genuinely could not be deleted — but
	// the caller was not held up, and the next writer will break it on age.
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Fatalf("the lock file vanished after a failing remove: %v", err)
	}
}
