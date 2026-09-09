package fsx

import (
	"os"
	"syscall"
)

// statDetail pulls the fields fs.FileInfo does not expose out of the
// underlying stat structure. Callers pass the FileInfo they already have —
// os.ReadDir's DirEntry.Info is the getdents data on Linux, so this costs no
// extra syscall.
//
// Everything is zero when the FileInfo did not come from the OS filesystem
// (a synthetic fs.FS in a test, say), which is the same answer the non-Linux
// build gives.
//
// The field widths differ by architecture — Nlink is uint64 on linux/amd64 and
// uint32 on linux/arm64, and both are release targets — so every value is
// converted explicitly rather than assigned.
func statDetail(fi os.FileInfo) (uid, gid int, dev, ino, nlink uint64) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, 0, 0, 0
	}
	return int(st.Uid), int(st.Gid), uint64(st.Dev), uint64(st.Ino), uint64(st.Nlink)
}
