package fsops

// The upload's one platform-specific need: a second descriptor for the same
// open file, for the front-end to stream into.

import (
	"fmt"
	"os"

	"qnapfilemanager/internal/fsx"
)

// dupForWire duplicates the handle's descriptor so the front-end can be given
// one over SCM_RIGHTS while this worker keeps its own.
//
// Two descriptors for one open file is exactly what is wanted, and it is not
// the same as opening the file twice. They share the file's offset and its
// status flags, so the bytes the front-end writes land where the worker's fstat
// and fsync see them; and there is no second lookup of any name, which for an
// unnamed inode there could not be anyway.
//
// F_DUPFD_CLOEXEC rather than dup(2): the flag is set atomically, so no
// concurrent fork in this process can leak the upload's descriptor into a child
// (the same reason dupCloexec exists for the mkdir provenance check).
func dupForWire(h *UploadHandle) (*os.File, error) {
	if h == nil || h.f == nil {
		return nil, fmt.Errorf("this upload has no descriptor to hand over: %w", fsx.ErrUnsupported)
	}
	rc, err := h.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fd   int
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) {
		fd, serr = dupCloexec(int(pfd))
	}); cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, &os.SyscallError{Syscall: "fcntl(F_DUPFD_CLOEXEC)", Err: serr}
	}
	return os.NewFile(uintptr(fd), h.f.Name()), nil
}
