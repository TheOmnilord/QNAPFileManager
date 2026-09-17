package jsonfile

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// publish renames the scratch file over the published name.
//
// On Windows a rename over a name somebody has open — the credential watcher
// re-reading config.json a moment after the CLI rewrote it, a virus scanner
// looking at the file it just saw appear — is refused with "Access is denied"
// or a sharing violation rather than queued, where Linux simply swaps the
// directory entry. The reader is done in microseconds, so the honest answer is
// to wait it out, briefly and boundedly: the atomic publish is preserved (the
// scratch file is complete and flushed before the first attempt, and nothing
// is visible under the published name until a rename succeeds), and a name
// that stays refused past the bound is reported as the error it is. This is
// the dev box's and the Windows CI job's concern only; on Linux the plain
// rename is the whole story (Astra r8 CI).
func publish(tmp, path string) error {
	const (
		tries = 40
		pause = 5 * time.Millisecond
	)
	var err error
	for i := 0; i < tries; i++ {
		err = os.Rename(tmp, path)
		if err == nil || !renameBusy(err) {
			return err
		}
		time.Sleep(pause)
	}
	return err
}

// renameBusy reports the refusals Windows gives for a name that is momentarily
// in use: ERROR_ACCESS_DENIED (surfaced as os.ErrPermission), and the two
// sharing errnos Go leaves unmapped.
func renameBusy(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 32 || errno == 33 // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
	}
	return false
}
