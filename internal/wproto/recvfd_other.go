//go:build !linux

package wproto

import "os"

// receivedFile off Linux is a plain os.NewFile. Nothing gets here: ReadFrame
// on this platform refuses the whole exchange because there is no SCM_RIGHTS
// to carry a descriptor in the first place, and the in-process transport
// declares that it passes none. It exists so transport.go stays one file.
func receivedFile(fd int, name string) *os.File {
	return os.NewFile(uintptr(fd), name)
}
