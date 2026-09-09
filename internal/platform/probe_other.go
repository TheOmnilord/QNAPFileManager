//go:build !linux

package platform

// defaultGetxattr has no meaning off Linux: there are no POSIX or NFSv4 ACL
// extended attributes to probe, so every mount reports the "none" backend.
func defaultGetxattr(p, name string) (int, error) {
	return 0, ErrNotSupported
}

// statIsMountPoint falls back to the mount table alone off Linux.
func statIsMountPoint(p string) bool { return false }
