//go:build !linux

package config

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

// LockStale is when a lock file is assumed to belong to a process that died
// holding it. It must be comfortably longer than any real save and shorter than
// an operator's patience.
//
// It exists only off Linux. The NAS uses flock(2), where the kernel releases
// the lock on process death and there is nothing to detect (lock_linux.go).
const LockStale = 30 * time.Second

// The three filesystem calls this fallback makes, in variables so a test can
// make each of them fail on cue: the stale break (prove the wait is still
// bounded rather than spinning), the O_EXCL create and the release (prove a
// momentary refusal is waited out rather than turned into a hard error or a
// lock file left lying about). Nothing writes them at run time.
var (
	renameLock = os.Rename
	openLock   = os.OpenFile
	removeLock = os.Remove
)

// lockReleaseTries is how many times release retries a refused delete, at
// lockPoll apiece — a fifth of a second in total. See removeLockFile for why it
// is patient at all and why it is not patient for long.
const lockReleaseTries = 20

// acquireLock is the O_EXCL fallback for hosts without flock — in practice the
// Windows dev loop, since the NAS is Linux.
//
// KNOWN RESIDUAL, accepted deliberately (round-4): the stale break is not
// atomic with the verdict that produced it. Writer A can judge a lock stale,
// rename it away and create a fresh one; writer B, which judged the SAME old
// lock stale a moment earlier, then renames away A's LIVE lock and proceeds
// beside it. Rename is atomic; deciding to rename is not, and binding the two
// together needs the inode identity that this platform does not hand out
// cheaply.
//
// It is left because of where it runs. The two writers this lock exists to
// serialise — the daemon's settings route and `qnapfilemanager break-glass` —
// never both run on a dev box, the config there holds no real credential, and
// the path that matters has no break logic at all. Anything that changes that
// (a NAS without flock, a second real writer here) makes this a bug again.
func acquireLock(lockPath string) (release func(), err error) {
	deadline := time.Now().Add(LockWait)
	// The last refusal, kept so a wait that runs out can say what it was
	// actually waiting on — "the file exists" and "the name is busy" are not the
	// same news to an operator (Astra r8 CI).
	var last error
	for {
		f, err := openLock(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			writeLockHint(f)
			f.Close()
			var once bool
			return func() {
				if once {
					return
				}
				once = true
				removeLockFile(lockPath)
			}, nil
		}
		if !lockNameBusy(err) {
			return nil, fmt.Errorf("config: taking the lock at %s: %w", lockPath, err)
		}
		last = err
		// Break a lock whose holder is long gone. Age, not pid: a pid check
		// would be wrong in a container and racy everywhere. Only a SUCCESSFUL
		// break skips the wait — looping on the branch itself would spin,
		// burning a core while a rename kept failing (round-4 P3).
		if fi, statErr := os.Stat(lockPath); statErr == nil && time.Since(fi.ModTime()) > LockStale {
			dead := fmt.Sprintf("%s.dead-%d-%d", lockPath, os.Getpid(), time.Now().UnixNano())
			// Only the file this break renamed is removed, and it is removed
			// under the name only this break knows: whatever else happens at
			// lockPath afterwards belongs to somebody else.
			if renameLock(lockPath, dead) == nil {
				removeLockFile(dead)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, lockedAfterWaiting(lockPath, last)
		}
		time.Sleep(lockPoll)
	}
}

// lockNameBusy reports whether a failed O_EXCL create means somebody else has
// this name for the moment — something to wait out — rather than a reason to
// refuse outright.
//
// ErrExist is the plain answer, and on Linux it would be the only one. Windows
// has more, and they are what the test-windows job kept failing on (Astra r8
// CI): a file that another writer is in the middle of deleting stays in its
// directory in a delete-pending state, and every open of that name is refused
// with ERROR_ACCESS_DENIED — not ErrExist — until the last handle to it closes.
// One reader of the lock hint, or a virus scanner opening the file that was
// just written, is enough to stretch that window past the next writer's
// attempt. ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION are the same news
// from a handle opened without FILE_SHARE_DELETE. All of them say the name is
// busy, which is precisely what the wait is for; treating them as fatal turned
// an ordinary contended moment into "a generator could not take the lock".
//
// A permission error that is genuinely a permission error — an unwritable
// config directory — is now waited out too, for LockWait and no longer, and the
// refusal that follows carries the original error, so nothing is hidden.
func lockNameBusy(err error) bool {
	if os.IsExist(err) || os.IsPermission(err) {
		return true
	}
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// Spelled as numbers because this file also builds for hosts whose
		// syscall package has never heard of them: 32 is
		// ERROR_SHARING_VIOLATION, 33 is ERROR_LOCK_VIOLATION.
		switch errno {
		case 32, 33:
			return true
		}
	}
	return false
}

// lockedAfterWaiting is the refusal when the wait ran out. A lock that was
// simply held is ErrLocked and nothing more — that is the ordinary case, and
// the caller retries. A lock whose NAME stayed unopenable for the whole budget
// is still ErrLocked, because the writer must not write either way, but it says
// what it kept being told, so an operator staring at a directory that has gone
// read-only is not sent looking for a process that does not exist.
func lockedAfterWaiting(lockPath string, last error) error {
	if last == nil || os.IsExist(last) {
		return ErrLocked
	}
	return fmt.Errorf("%w (%s was not openable: %v)", ErrLocked, lockPath, last)
}

// removeLockFile deletes a lock file this process is finished with, and is
// briefly patient about it. The same Windows sharing state that refuses a
// create refuses a delete (Astra r8 CI), and giving up on the first refusal
// leaves the lock file behind — after which every later writer waits out
// LockWait and is told the file is being written by a holder that has already
// gone.
//
// Patient, but not for long. The retry must not outlive the moment at which
// another writer could judge this lock stale, rename it away and create its
// own: from then on the name belongs to somebody else, and removing it would be
// removing THEIR lock. A fifth of a second against LockStale's thirty seconds
// keeps that distance absurd.
func removeLockFile(path string) {
	for try := 0; ; try++ {
		err := removeLock(path)
		if err == nil || os.IsNotExist(err) {
			return
		}
		if try >= lockReleaseTries || !lockNameBusy(err) {
			return
		}
		time.Sleep(lockPoll)
	}
}
