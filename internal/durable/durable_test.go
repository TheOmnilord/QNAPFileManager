// Copied from GitBackup internal/durable/durable_test.go

package durable

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestSyncDirFlushesAnOrdinaryDirectory(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir on a plain directory: %v", err)
	}
}

// A directory that is not there cannot be flushed, and saying so matters:
// the caller has just renamed something into it. On every platform — the
// Windows port is a real barrier, not a no-op.
func TestSyncDirReportsAMissingDirectory(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "gone"))
	if err == nil {
		t.Fatal("a missing directory was reported as flushed")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want not-exist", err)
	}
}

// The one refusal that may be excused is a filesystem that does not
// implement fsync at all; everything else — EIO, a refused open, a sharing
// violation — means the bytes may not be on the disk.
func TestUnsupportedOnlyExcusesAFilesystemThatCannotFlush(t *testing.T) {
	type tc struct {
		err  error
		want bool
	}
	wrap := func(e error) error { return &fs.PathError{Op: "sync", Path: "repo.bundle", Err: e} }
	cases := map[string]tc{
		"plain error":     {errors.New("boom"), false},
		"EIO":             {wrap(syscall.EIO), false},
		"EACCES":          {wrap(syscall.EACCES), false},
		"nil":             {nil, false},
		"unwrapped errno": {syscall.EIO, false},
	}
	if runtime.GOOS == "windows" {
		cases["ERROR_INVALID_FUNCTION"] = tc{wrap(syscall.Errno(1)), true}
		cases["ERROR_NOT_SUPPORTED"] = tc{wrap(syscall.Errno(50)), true}
		cases["ERROR_ACCESS_DENIED"] = tc{wrap(syscall.Errno(5)), false}
		cases["ERROR_SHARING_VIOLATION"] = tc{wrap(syscall.Errno(32)), false}
	} else {
		cases["ENOTSUP"] = tc{wrap(syscall.ENOTSUP), true}
		cases["EINVAL"] = tc{wrap(syscall.EINVAL), true}
		cases["ENOSYS"] = tc{wrap(syscall.ENOSYS), true}
	}
	for name, c := range cases {
		if got := Unsupported(c.err); got != c.want {
			t.Errorf("%s: Unsupported = %v, want %v", name, got, c.want)
		}
	}
}
