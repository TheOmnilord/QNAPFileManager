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

// devOf has nothing to report off Linux either: there is no st_dev behind a
// Windows FileInfo. The false return leaves mount-point classification to the
// mount table alone, which is the same answer platform's own stat fallback gives
// here (probe_other.go).
func devOf(fi os.FileInfo) (uint64, bool) {
	_ = fi
	return 0, false
}
