//go:build !windows

package breakglass

import "os"

// publish renames tmp over path. On a POSIX filesystem the rename is atomic and
// replaces the destination in one step, so a reader either sees the whole old
// file or the whole new one — never the gap that a remove-then-rename opens,
// during which the break-glass key simply does not exist and a daemon starting
// at that instant would regenerate a fingerprint the operator has already
// written down (round-1 P3-11).
func publish(tmp, path string) error { return os.Rename(tmp, path) }
