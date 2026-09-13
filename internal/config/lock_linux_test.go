package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// flock is per OPEN FILE DESCRIPTION, so a second open of the same file — even
// in this same process — is exactly as excluded as another process would be.
// That is what lets this assert the property without forking anything.
func TestFlockExcludesASecondOpenOfTheSameFile(t *testing.T) {
	defaultWait := LockWait
	t.Cleanup(func() { LockWait = defaultWait })
	LockWait = 50 * time.Millisecond

	p := filepath.Join(t.TempDir(), "config.json")
	lockPath := p + ".lock"

	// Stand in for another process: its own open file description on the same
	// inode, holding the lock.
	other, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := tryFlock(other)
	if err != nil || !locked {
		other.Close()
		t.Fatalf("the stand-in holder could not take the lock: %v %v", locked, err)
	}
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		other.Close()
		t.Fatalf("Lock = %v while another description held it, want ErrLocked", err)
	}

	// The kernel releases the lock when that description goes away — which is
	// what a dead holder looks like, and why this path needs no stale
	// detection, no age heuristic and no break (round-4).
	other.Close()
	start := time.Now()
	release, err := Lock(p)
	if err != nil {
		t.Fatalf("the lock was not released when the holder went away: %v", err)
	}
	if waited := time.Since(start); waited > LockWait {
		t.Fatalf("acquiring took %v after the holder went away; it should be immediate", waited)
	}
	release()
}

// The lock file is deliberately LEFT in place: flock lives on the inode, and
// unlinking the name would let another writer create a fresh file and lock that
// instead — two writers, one config.
func TestFlockLockFileSurvivesReleaseAndCarriesTheHint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if hint := lockHint(p); hint == "" {
		t.Error("a held lock records nothing about who holds it")
	}
	release()
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Fatalf("the lock file was removed on release: %v", err)
	}
	// A surviving file is not a held lock.
	again, err := Lock(p)
	if err != nil {
		t.Fatalf("the surviving lock file blocked the next writer: %v", err)
	}
	again()
	// And it is owner-only: it sits in the same directory as the credential.
	fi, err := os.Stat(p + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the lock file is mode %04o", fi.Mode().Perm())
	}
}
