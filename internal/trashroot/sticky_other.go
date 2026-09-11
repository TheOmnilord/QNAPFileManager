//go:build !linux

package trashroot

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The no-op stubs for the dev box. Windows has no sticky bit, no uid behind a
// FileInfo, no O_NOFOLLOW and no openat, so every fd-bound guarantee this
// package makes on Linux (F3) degrades here to the path-based shape it always
// had. That is deliberate and it is INV-2: the kernel decides, and this is not
// that kernel. The CI Linux jobs run the real thing.

// stickyEnforced is false off Linux. os.Chmod ignores os.ModeSticky and
// os.Lstat never reports it, so asserting it would fail on the dev box for a
// property the kernel there does not have.
const stickyEnforced = false

// openDirNoFollow opens a directory by pathname. The no-follow rule is enforced
// by the lstat rather than by the kernel here.
func openDirNoFollow(p string) (*os.File, error) {
	if err := refuseSymlink(p); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.IsDir() {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOTDIR}
	}
	return f, nil
}

// openDirIn opens a subdirectory by joining the name onto the parent's own
// pathname: there is no openat here.
func openDirIn(dir *os.File, name string) (*os.File, error) {
	return openDirNoFollow(filepath.Join(dir.Name(), name))
}

// mkdirIn creates a subdirectory by pathname.
func mkdirIn(dir *os.File, name string, mode uint32) error {
	return os.Mkdir(filepath.Join(dir.Name(), name), fs.FileMode(mode))
}

// applyMode sets the mode by pathname. os.File.Chmod on Windows needs a handle
// opened for FILE_WRITE_ATTRIBUTES, which a read-only directory open is not, so
// the name is used here — on the one platform where the mode bits being set
// carry no security meaning anyway.
func applyMode(_ *os.File, dir string, mode fs.FileMode) error { return os.Chmod(dir, mode) }

// ownerOf has nothing to report: Windows has no uid of this shape, so the
// ownership check is skipped rather than invented.
func ownerOf(fs.FileInfo) (int, bool) { return 0, false }

// refuseSymlink is the stand-in for O_NOFOLLOW.
func refuseSymlink(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return &fs.PathError{Op: "open", Path: p, Err: syscall.ELOOP}
	}
	if !fi.IsDir() {
		return &fs.PathError{Op: "open", Path: p, Err: syscall.ENOTDIR}
	}
	return nil
}
