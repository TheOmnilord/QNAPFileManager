package fsops

import (
	"os"
	"syscall"
)

// openReadFlags is what OpenRead passes to open(2). O_NOFOLLOW makes the
// kernel refuse a symlink as the final component with ELOOP instead of
// following it, so the descriptor handed up to the root front-end is always
// the file the guard classified, not something a symlink swapped in after the
// check.
func openReadFlags() int { return os.O_RDONLY | syscall.O_NOFOLLOW }
