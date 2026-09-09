// Copied from GitBackup internal/durable/durable_unix.go

//go:build !windows

package durable

import "os"

// syncDir is fsync on the directory: a read-only descriptor is enough.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
