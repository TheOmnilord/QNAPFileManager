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

// sameObject cannot be answered off Linux: a Windows FileInfo carries no device
// and no inode number. The false "known" is what keeps the trash's payload check
// from firing on the dev box — a check that cannot be made must not be reported
// as failed, which would rewrite every sidecar's size as unknown here (INV-2).
// The CI Linux jobs make it for real.
func sameObject(a, b os.FileInfo) (same, known bool) {
	_, _ = a, b
	return false, false
}

// devOf has nothing to report off Linux either: there is no st_dev behind a
// Windows FileInfo. The false return leaves mount-point classification to the
// mount table alone, which is the same answer platform's own stat fallback gives
// here (probe_other.go).
func devOf(fi os.FileInfo) (uint64, bool) {
	_ = fi
	return 0, false
}
