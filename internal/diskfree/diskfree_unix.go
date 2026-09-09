// Copied from GitBackup internal/diskfree/diskfree_unix.go

//go:build !windows

// Package diskfree reports available bytes on the filesystem holding a path.
package diskfree

import "syscall"

// SameDevice reports whether two paths live on the same filesystem device.
// Used to detect QTS's /share RAM disk (same device as /).
func SameDevice(a, b string) (bool, error) {
	var sa, sb syscall.Stat_t
	if err := syscall.Stat(a, &sa); err != nil {
		return false, err
	}
	if err := syscall.Stat(b, &sb); err != nil {
		return false, err
	}
	return sa.Dev == sb.Dev, nil
}
