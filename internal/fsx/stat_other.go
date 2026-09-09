//go:build !linux

package fsx

import "os"

// statDetail has nothing to report off Linux: Windows has no uid/gid/inode of
// this shape, and the dev/ino pair it does have is not what the recursion
// rules mean by a storage domain. Every caller must treat zeros as "unknown"
// rather than as root-owned — the UI shows the numbers only when the entry
// came from a Linux stat.
func statDetail(fi os.FileInfo) (uid, gid int, dev, ino, nlink uint64) {
	_ = fi
	return 0, 0, 0, 0, 0
}
