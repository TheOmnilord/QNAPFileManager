//go:build !linux

package fsops

// The dev loop's half of "create it where nobody can reach it": there is none.
// See unnamed_linux.go for what the NAS and the CI Linux jobs do.

import (
	"errors"
	"os"
)

// errNoUnnamed says this filesystem cannot make an unnamed file. Off Linux
// nothing can, so openUnnamed always says so.
var errNoUnnamed = errors.New("fsops: this filesystem has no unnamed files")

// openUnnamed has no answer off Linux: there is no O_TMPFILE and no linkat, so
// a file is created under its name as this engine always did. The window that
// closes on Linux — between a file being created and its owner being installed
// — stays open here, which is the dev box's documented degradation (INV-2);
// nothing off Linux chowns at all, since os.Geteuid reports -1 on Windows.
func openUnnamed(d *dirRef, mode os.FileMode) (*os.File, error) {
	_, _ = d, mode
	return nil, errNoUnnamed
}

// linkUnnamed is unreachable off Linux: openUnnamed never hands anybody an
// unnamed file to publish.
func linkUnnamed(f *os.File, d *dirRef, name string) error {
	_, _, _ = f, d, name
	return errNoUnnamed
}

// stagedCreate is false off Linux: a dirRef here is a jail-relative pathname
// that os.Root resolves on every call, so a directory renamed after it was
// opened would take every later operation with it. See the Linux half.
const stagedCreate = false
