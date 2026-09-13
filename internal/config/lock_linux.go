package config

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// acquireLock holds the config lock with flock(2), which is what the NAS runs.
//
// The kernel owns the lock and drops it when the last file description holding
// it is closed — including when the holding process dies, crashes or is killed
// by App Center's stop timeout. So there is NO stale state here and no break
// logic: the whole family of bugs that comes from deciding a lock is dead and
// removing it simply does not exist on this path. That matters because the
// decision cannot be made safely: a staleness verdict is about an inode, and by
// the time the verdict is acted on the name may point at somebody else's live
// lock (round-4).
//
// The lock file is created if absent and then LEFT IN PLACE. Removing it on
// release would be wrong: another process may already hold flock on that same
// inode through its own open file description, and unlinking the name would let
// a third create a fresh file and lock that instead — two writers, one config.
// An empty 0600 file beside the config is a small price for not reintroducing
// the problem this replaced.
func acquireLock(lockPath string) (release func(), err error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("config: taking the lock at %s: %w", lockPath, err)
	}
	deadline := time.Now().Add(LockWait)
	for {
		locked, err := tryFlock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("config: taking the lock at %s: %w", lockPath, err)
		}
		if locked {
			writeLockHint(f)
			var once bool
			return func() {
				if once {
					return
				}
				once = true
				// Closing the file description releases the lock; doing both is
				// belt and braces for a caller that holds the *os.File longer
				// than it should.
				_ = flockUnlock(f)
				f.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrLocked
		}
		time.Sleep(lockPoll)
	}
}

// tryFlock attempts a non-blocking exclusive lock. It reports whether the lock
// was taken; a contended lock is (false, nil), and anything else is an error
// worth refusing on.
func tryFlock(f *os.File) (bool, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var flockErr error
	// Control rather than Fd(): Fd() takes the file out of the runtime poller
	// and switches it to blocking mode as a side effect, which is a surprising
	// thing for taking a lock to do.
	if cerr := rc.Control(func(fd uintptr) {
		flockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); cerr != nil {
		return false, cerr
	}
	if flockErr == nil {
		return true, nil
	}
	if errors.Is(flockErr, syscall.EWOULDBLOCK) || errors.Is(flockErr, syscall.EAGAIN) {
		return false, nil
	}
	return false, flockErr
}

func flockUnlock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var unlockErr error
	if cerr := rc.Control(func(fd uintptr) {
		unlockErr = syscall.Flock(int(fd), syscall.LOCK_UN)
	}); cerr != nil {
		return cerr
	}
	return unlockErr
}
