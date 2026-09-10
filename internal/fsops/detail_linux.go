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

// devOf pulls the device number out of a FileInfo the walk already obtained.
// It is how a mount point is recognised without asking the kernel about a
// pathname: the entry's device against its parent directory's, both stat'ed
// through descriptors inside the jail.
//
// Dev is uint64 on linux/amd64 and uint64 on linux/arm64, but it is converted
// explicitly like every other field here, because that assumption is what broke
// the arm64 build the last time somebody assigned one.
func devOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Dev), true
}
