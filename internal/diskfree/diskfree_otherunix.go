// Copied from GitBackup internal/diskfree/diskfree_otherunix.go

//go:build !windows && !linux

package diskfree

import "syscall"

// Free reports available bytes. Statfs_t has no Frsize field on these
// platforms (Darwin, the BSDs), where f_bsize is the fundamental block size.
func Free(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
