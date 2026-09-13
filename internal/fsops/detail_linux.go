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

// sameObject reports whether two FileInfos describe one and the same object —
// the same inode on the same device — and whether the question could be answered
// at all.
//
// It is how the trash proves that the tree it measured is the payload that
// landed in the entry (trash.go): the scan and the rename each looked the item
// up by NAME, and a name is a thing another writer can re-point in between.
// os.SameFile answers the same question, but only for a FileInfo the os package
// produced; this package's lstat wrappers are the ones in play here, and being
// explicit about the two fields is also what makes the "could not tell" case
// visible to the caller instead of silently false.
func sameObject(a, b os.FileInfo) (same, known bool) {
	if a == nil || b == nil {
		return false, false
	}
	sa, aok := a.Sys().(*syscall.Stat_t)
	sb, bok := b.Sys().(*syscall.Stat_t)
	if !aok || !bok || sa == nil || sb == nil {
		return false, false
	}
	// Converted explicitly, like every other field in this file: the widths of
	// Dev and Ino are the architecture's, and amd64 and arm64 are both targets.
	return uint64(sa.Dev) == uint64(sb.Dev) && uint64(sa.Ino) == uint64(sb.Ino), true
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
