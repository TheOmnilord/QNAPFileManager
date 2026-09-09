package web

import (
	"os"
	"syscall"
)

// prepareDownloadStream registers raw worker descriptors with the runtime
// poller. SetNonblock alone cannot make an existing blocking os.NewFile pollable.
func prepareDownloadStream(f *os.File) (*os.File, error) {
	conn, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dup uintptr
	var setupErr error
	err = conn.Control(func(fd uintptr) {
		setupErr = syscall.SetNonblock(int(fd), true)
		if setupErr != nil {
			return
		}
		var errno syscall.Errno
		dup, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_DUPFD_CLOEXEC, 0)
		if errno != 0 {
			setupErr = errno
		}
	})
	if err != nil {
		return nil, err
	}
	if setupErr != nil {
		return nil, os.NewSyscallError("prepare download stream", setupErr)
	}
	// A separate descriptor gives NewFile ownership without double-closing f's
	// descriptor. NewFile observes O_NONBLOCK and registers pipes/FIFOs; regular
	// files ignore O_NONBLOCK and continue to use ordinary file reads.
	return os.NewFile(dup, f.Name()), nil
}

func pseudoFilesystem(f *os.File) bool {
	return pseudoFilesystemWithStatfs(int(f.Fd()), syscall.Fstatfs)
}

func pseudoFilesystemWithStatfs(fd int, statfs func(int, *syscall.Statfs_t) error) bool {
	var st syscall.Statfs_t
	if err := statfs(fd, &st); err != nil {
		return true // Unknown filesystem: do not advertise an unproven length.
	}
	switch uint64(st.Type) {
	case 0x9fa0, 0x62656572, 0x64626720, 0x74726163, 0x63677270,
		0xcafe4a11, 0x73636673, 0x62656570, 0xde5e81e4:
		return true
	}
	return false
}
