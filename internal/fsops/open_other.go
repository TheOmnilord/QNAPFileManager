//go:build !linux

package fsops

import "os"

// openReadFlags off Linux is a plain read-only open: there is no O_NOFOLLOW and
// no O_NONBLOCK to ask for. The no-follow rule itself is not lost — OpenRead
// classifies the name with lstat and verifies the descriptor with os.SameFile,
// which holds on every platform.
func openReadFlags() int { return os.O_RDONLY }

// openDirFlags off Linux is a plain read-only open: there is no O_DIRECTORY, so
// the "is this really a directory" answer comes from the fstat that follows.
// Nothing but the dev loop runs here, and it has no fifos to be parked on.
func openDirFlags() int { return os.O_RDONLY }

// clearNonblock has nothing to undo where the open was blocking to begin with.
func clearNonblock(*os.File) error { return nil }
