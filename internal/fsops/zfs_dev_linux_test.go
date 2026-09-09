package fsops

import (
	"os"
	"syscall"
	"testing"
)

// zfsStatDev returns st_dev for a path. It is split by file suffix like the
// rest of the platform-specific code: there is no st_dev on Windows, and the
// caller skips there long before it would be reached.
func zfsStatDev(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: no syscall.Stat_t behind the FileInfo", path)
	}
	return uint64(st.Dev)
}
