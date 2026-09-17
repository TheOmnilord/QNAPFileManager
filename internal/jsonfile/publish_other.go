//go:build !windows

package jsonfile

import "os"

// publish renames the scratch file over the published name. On every platform
// but Windows a rename over an open file is an ordinary directory-entry swap,
// so there is nothing to wait for; see publish_windows.go for why that one
// waits.
func publish(tmp, path string) error { return os.Rename(tmp, path) }
