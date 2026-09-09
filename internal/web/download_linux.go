package web

import (
	"os"
	"syscall"
)

func pseudoFilesystem(f *os.File) bool {
	return pseudoFilesystemWithStatfs(int(f.Fd()), syscall.Fstatfs)
}

func pseudoFilesystemWithStatfs(fd int, statfs func(int, *syscall.Statfs_t) error) bool {
	var st syscall.Statfs_t
	if err := statfs(fd, &st); err != nil {
		return true // Unknown filesystem: do not advertise an unproven length.
	}
	switch uint64(st.Type) {
	case 0x9fa0, 0x62656572, 0x64626720, 0x74726163, 0x63677270,
		0xcafe4a11, 0x73636673, 0x62656570, 0xde5e81e4:
		return true
	}
	return false
}
