// Copied from GitBackup internal/durable/durable_windows.go

//go:build windows

package durable

import (
	"errors"
	"os"
	"syscall"
)

// fileWriteData is FILE_WRITE_DATA, which on a directory is FILE_ADD_FILE:
// the right to create a file in it. syscall does not name it.
const fileWriteData = 0x0002

// syncDir is FlushFileBuffers on a directory handle.
//
// The handle needs backup semantics, which is what lets CreateFile open a
// directory at all, and a write-class right: FlushFileBuffers refuses a
// read handle with "access denied", which is what os.Open's handle gets,
// so the obvious port does not work. The right asked for is deliberately
// the narrowest that works, and it is chosen to be one the caller already
// holds: whoever just renamed a file into this directory had FILE_ADD_FILE
// on it, and whoever renamed a subdirectory in had FILE_ADD_SUBDIRECTORY
// (FILE_APPEND_DATA). Asking for GENERIC_WRITE instead would also demand
// attribute and EA rights that a tightly cut ACL or share can withhold
// from a directory the app is otherwise allowed to publish into, and the
// flush would then fail a backup that had in fact succeeded. Measured on
// Windows Server 2025: either right alone flushes; write-attributes alone
// and a read handle are refused.
func syncDir(dir string) error {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := openDir(p, fileWriteData)
	if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		h, err = openDir(p, syscall.FILE_APPEND_DATA)
	}
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer syscall.CloseHandle(h)
	if err := syscall.FlushFileBuffers(h); err != nil {
		return &os.PathError{Op: "sync", Path: dir, Err: err}
	}
	return nil
}

func openDir(p *uint16, access uint32) (syscall.Handle, error) {
	return syscall.CreateFile(p, access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
}
