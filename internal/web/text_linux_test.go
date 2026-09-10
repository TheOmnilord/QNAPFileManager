package web

import (
	"os"
	"syscall"
	"testing"
)

func TestTextRawDescriptorCancellation(t *testing.T) {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	// Match a blocking descriptor received from a worker via SCM_RIGHTS.
	reader := os.NewFile(uintptr(fds[0]), "raw preview reader")
	writer := os.NewFile(uintptr(fds[1]), "raw preview writer")
	testTextStreamCancellation(t, reader, writer, true)
}
