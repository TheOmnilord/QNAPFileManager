//go:build !linux

package fsops

import "testing"

// zfsStatDev never runs off Linux — the ZFS fixture tests skip on runtime.GOOS
// — but the file has to compile so that the Windows job builds the package.
func zfsStatDev(t *testing.T, path string) uint64 {
	t.Helper()
	t.Fatalf("st_dev is not available on this platform (asked for %s)", path)
	return 0
}
