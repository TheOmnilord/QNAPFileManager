//go:build !linux

package config

import (
	"fmt"
	"os"
	"time"
)

// LockStale is when a lock file is assumed to belong to a process that died
// holding it. It must be comfortably longer than any real save and shorter than
// an operator's patience.
//
// It exists only off Linux. The NAS uses flock(2), where the kernel releases
// the lock on process death and there is nothing to detect (lock_linux.go).
const LockStale = 30 * time.Second

// renameLock is os.Rename, in a variable so a test can make the stale break
// fail and prove the wait is still bounded rather than spinning.
var renameLock = os.Rename

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
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			writeLockHint(f)
			f.Close()
			var once bool
			return func() {
				if once {
					return
				}
				once = true
				os.Remove(lockPath)
			}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("config: taking the lock at %s: %w", lockPath, err)
		}
		// Break a lock whose holder is long gone. Age, not pid: a pid check
		// would be wrong in a container and racy everywhere. Only a SUCCESSFUL
		// break skips the wait — looping on the branch itself would spin,
		// burning a core while a rename kept failing (round-4 P3).
		if fi, statErr := os.Stat(lockPath); statErr == nil && time.Since(fi.ModTime()) > LockStale {
			dead := fmt.Sprintf("%s.dead-%d-%d", lockPath, os.Getpid(), time.Now().UnixNano())
			if renameLock(lockPath, dead) == nil {
				os.Remove(dead)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, ErrLocked
		}
		time.Sleep(lockPoll)
	}
}
