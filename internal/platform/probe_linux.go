//go:build linux

package platform

import (
	"errors"
	"path"
	"syscall"
)

// defaultGetxattr asks the kernel for the size of an extended attribute,
// mapping the two errno values that carry meaning onto package sentinels so
// that callers (and tests on other operating systems) can reason about them.
func defaultGetxattr(p, name string) (int, error) {
	n, err := syscall.Getxattr(p, name, nil)
	if err == nil {
		return n, nil
	}
	switch {
	case errors.Is(err, syscall.ENODATA):
		return 0, ErrNoData
	case errors.Is(err, syscall.EOPNOTSUPP):
		return 0, ErrNotSupported
	}
	return 0, err
}

// statIsMountPoint reports whether p sits on a different device than its
// parent directory, which catches mounts that appeared since the mount table
// was last read.
func statIsMountPoint(p string) bool {
	var self syscall.Stat_t
	if err := syscall.Stat(p, &self); err != nil {
		return false
	}
	parent := path.Dir(p)
	if parent == p {
		return true // "/" is always a mount point
	}
	var up syscall.Stat_t
	if err := syscall.Stat(parent, &up); err != nil {
		return false
	}
	return self.Dev != up.Dev
}
