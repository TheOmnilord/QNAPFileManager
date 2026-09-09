//go:build !linux

package fsops

import "os"

// statDetail has nothing to report off Linux: Windows has no uid, gid or link
// count of this shape. The false return is what keeps the dev box from
// labelling every file as owned by root — the caller leaves UID, GID, User and
// Group at their zero values instead of inventing ownership.
func statDetail(fi os.FileInfo) (uid, gid int, nlink uint64, ok bool) {
	_ = fi
	return 0, 0, 0, false
}
