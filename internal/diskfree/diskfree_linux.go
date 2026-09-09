// Copied from GitBackup internal/diskfree/diskfree_linux.go

//go:build linux

package diskfree

import "syscall"

// Free reports available bytes for the caller. POSIX defines f_bavail in
// f_frsize units — on local ext4 the two block sizes agree, but network and
// FUSE filesystems may report f_bsize as a preferred I/O size far larger
// than the fragment size, which would over-report free space and keep the
// low-space warning green on a nearly full volume.
func Free(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	bsize := st.Frsize
	if bsize <= 0 {
		bsize = st.Bsize
	}
	return st.Bavail * uint64(bsize), nil
}
