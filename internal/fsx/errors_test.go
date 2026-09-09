package fsx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},

		// Our own refusals.
		{"protected", fmt.Errorf("/etc/config: %w", ErrProtected), "protected"},
		{"read only", ErrReadOnly, "readonly"},
		{"ram disk", ErrRAMDisk, "ramdisk"},
		{"confirm required", ErrConfirmRequired, "confirm_required"},
		{"queue full", ErrQueueFull, "queue_full"},
		{"unsupported", ErrUnsupported, "unsupported"},
		{"cross device sentinel", ErrCrossDevice, "cross_device"},
		{"no space sentinel", ErrNoSpace, "no_space"},
		{"not absolute", ErrNotAbsolute, "bad_request"},
		{"bad name", ErrBadName, "bad_request"},
		{"outside root", ErrOutsideRoot, "bad_request"},
		// A dead worker is our problem, not the caller's.
		{"worker gone", ErrWorkerGone, "internal"},

		{"cancelled", context.Canceled, "cancelled"},
		// A deadline is not a cancellation and must not be mislabelled as one.
		{"deadline", context.DeadlineExceeded, "internal"},

		// Kernel truth.
		{"not exist", fs.ErrNotExist, "not_found"},
		{"not exist wrapped in PathError", &fs.PathError{Op: "open", Path: "/x", Err: syscall.ENOENT}, "not_found"},
		{"exists", fs.ErrExist, "exists"},
		{"eexist errno", syscall.EEXIST, "exists"},
		{"permission", fs.ErrPermission, "permission"},
		{"eacces", syscall.EACCES, "permission"},
		{"eperm", syscall.EPERM, "permission"},
		{"not empty", syscall.ENOTEMPTY, "not_empty"},
		{"cross device errno", syscall.EXDEV, "cross_device"},
		{"no space errno", syscall.ENOSPC, "no_space"},
		{"quota", syscall.EDQUOT, "no_space"},
		{"read only fs", syscall.EROFS, "readonly"},
		{"symlink loop", syscall.ELOOP, "bad_request"},
		{"name too long", syscall.ENAMETOOLONG, "bad_request"},
		{"busy", syscall.EBUSY, "conflict"},

		// Wrapping must not change the answer.
		{"wrapped errno", fmt.Errorf("rename: %w", &fs.PathError{Op: "rename", Path: "/a", Err: syscall.EXDEV}), "cross_device"},

		{"unknown", errors.New("something new"), "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Code(c.err); got != c.want {
				t.Fatalf("Code(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

// The sentinel a caller most often wraps is ErrProtected, and it usually wraps
// a syscall error too; the daemon's own reason must win over the kernel's.
func TestCodePrefersOurSentinel(t *testing.T) {
	err := fmt.Errorf("%w: %w", ErrProtected, syscall.EACCES)
	if got := Code(err); got != "protected" {
		t.Fatalf("Code = %q, want protected", got)
	}
}

func TestErrno(t *testing.T) {
	if got := Errno(&fs.PathError{Op: "unlink", Path: "/x", Err: syscall.ENOTEMPTY}); got != int(syscall.ENOTEMPTY) {
		t.Fatalf("Errno = %d, want %d", got, int(syscall.ENOTEMPTY))
	}
	if got := Errno(ErrProtected); got != 0 {
		t.Fatalf("Errno = %d, want 0 for a non-syscall error", got)
	}
	if got := Errno(nil); got != 0 {
		t.Fatalf("Errno(nil) = %d, want 0", got)
	}
}

// A real failure from the OS must map, on every platform the daemon builds
// for: this is the one case where Windows genuinely returns a different errno
// number behind the same fs.Err* sentinel.
func TestCodeFromRealSyscall(t *testing.T) {
	_, err := os.Open(t.TempDir() + "/definitely-absent")
	if got := Code(err); got != "not_found" {
		t.Fatalf("Code(%v) = %q, want not_found", err, got)
	}
}
