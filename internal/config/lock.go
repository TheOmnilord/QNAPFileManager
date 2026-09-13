package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// The config file is written by two different processes: the daemon (the
// read-only toggle) and `qnapfilemanager break-glass` on the shell. Both do a
// read-modify-write, and nothing in the filesystem makes that pair atomic — so
// a toggle that read the file before the CLI wrote a password hash, and saved
// after, would publish the old credential over the new one and neither process
// would notice (round-2 P3-5).
//
// A lock file beside the config is what serialises them, and HOW it is held is
// a platform decision (round-4):
//
//   - Linux, which is the NAS, uses flock(2). The kernel owns the lock and
//     releases it when the holding process dies, so there is no stale state to
//     detect and no break logic at all — which is the point, because breaking a
//     lock correctly turned out to be the hard part. A staleness verdict is not
//     bound to the inode it was made about: one writer can judge a lock stale,
//     a second can rename that lock away and create a fresh one, and the first
//     then renames away the SECOND writer's live lock and proceeds beside it.
//     Rename is atomic; the decision to rename is not.
//   - Everywhere else — the Windows dev loop, where no NAS exists — falls back
//     to O_EXCL plus an age-based break, residual race and all. See lock_other.go.
//
// Neither is a substitute for the fact that the loser retries; the lock only has
// to make the window small enough that a retry is the normal case rather than
// the corruption.

// LockWait is how long a writer waits for the other one to finish. A save is
// a marshal, a write, an fsync and a rename — milliseconds — so two seconds is
// a very long time to be waiting, and waiting longer than that on a root
// daemon's request path is worse than telling the caller to retry.
//
// A variable, not a constant, so the contention tests can run many rounds
// without each loser paying two real seconds. Nothing writes it at run time.
var LockWait = 2 * time.Second

// lockPoll is how often the wait rechecks.
const lockPoll = 10 * time.Millisecond

// ErrLocked is returned when the config lock could not be taken within
// LockWait. The caller retries or refuses; it must never write anyway.
var ErrLocked = errors.New("config: the configuration file is being written by another process")

// Lock takes the write lock for the config at path and returns the function
// that releases it. Every writer — the daemon's settings route and every
// break-glass subcommand — takes it around its whole read-modify-write, not
// just around the save.
func Lock(path string) (release func(), err error) {
	return acquireLock(path + ".lock")
}

// writeLockHint records who holds the lock, for a human reading a stuck one. It
// is never a liveness check: pids are reused, and the file may have been written
// by a process in another namespace entirely.
func writeLockHint(f *os.File) {
	_ = f.Truncate(0)
	if _, err := f.Seek(0, 0); err != nil {
		return
	}
	fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
}

// lockHint is what a stuck lock file can tell an operator, for a log line.
func lockHint(path string) string {
	data, err := os.ReadFile(path + ".lock")
	if err != nil {
		return ""
	}
	var pid int
	var when string
	if _, err := fmt.Sscanf(string(data), "%d %s", &pid, &when); err != nil {
		return ""
	}
	return "held by pid " + strconv.Itoa(pid) + " since " + when
}
