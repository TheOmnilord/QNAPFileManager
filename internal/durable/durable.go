// Copied from GitBackup internal/durable/durable.go

// Package durable holds the two fsync questions the archive keeps asking:
// whether a directory's entries are on the disk, and whether a refusal to
// flush means "cannot" or "did not".
package durable

import (
	"errors"
	"runtime"
	"syscall"
)

// SyncDir flushes a directory's entries — the names it holds — to the disk.
//
// A rename or unlink is journalled metadata. The file's bytes were flushed
// by whoever wrote them, but the *name* that publishes them lives in the
// parent directory, and until that is flushed too a power cut can bring the
// directory back without the entry: a snapshot whose files were all on the
// disk and whose directory is not listed, after retention has already
// removed what it superseded. Call it after the rename that publishes
// something the next step will rely on.
//
// On Unix this is fsync on the directory. On Windows it is FlushFileBuffers
// on a directory handle opened with the one right the caller already holds
// — the right to add the entry it just added (see durable_windows.go). A
// filesystem that does not implement the flush at all (some network
// mounts) is tolerated for the same reason files are: the entry is as safe
// as everything else on that mount, and failing on it would protect
// nothing.
func SyncDir(dir string) error {
	if err := syncDir(dir); err != nil && !Unsupported(err) {
		return err
	}
	return nil
}

// Unsupported reports whether err says the filesystem cannot flush at all,
// as opposed to having tried and failed. Only the former is tolerable: EIO,
// a refused open, a sharing violation all mean the bytes may not be on the
// disk, and nothing durable may be built on that doubt.
func Unsupported(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if runtime.GOOS == "windows" {
		// FlushFileBuffers on a share or device that does not implement it.
		const errorInvalidFunction, errorNotSupported = 1, 50
		return errno == errorInvalidFunction || errno == errorNotSupported
	}
	return errno == syscall.EINVAL || errno == syscall.ENOTSUP ||
		errno == syscall.EOPNOTSUPP || errno == syscall.ENOSYS
}
