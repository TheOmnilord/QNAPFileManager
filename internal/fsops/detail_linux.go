package fsops

import (
	"os"
	"syscall"
)

// statDetail pulls uid, gid and nlink out of the stat structure behind a
// FileInfo. The FileInfo that os.ReadDir's DirEntry.Info returns is the
// getdents data on Linux, so this costs no extra syscall.
//
// The field widths differ by architecture — Nlink is uint64 on linux/amd64 and
// uint32 on linux/arm64, and both are release targets — so every value is
// converted explicitly rather than assigned.
func statDetail(fi os.FileInfo) (uid, gid int, nlink uint64, ok bool) {
	st, is := fi.Sys().(*syscall.Stat_t)
	if !is || st == nil {
		return 0, 0, 0, false
	}
	return int(st.Uid), int(st.Gid), uint64(st.Nlink), true
}
