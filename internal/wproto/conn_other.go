//go:build !linux

package wproto

import (
	"fmt"
	"net"

	"qnapfilemanager/internal/fsx"
)

// WriteFrame and ReadFrame need SCM_RIGHTS, which exists only on the NAS.
// They are declared here so the whole tree compiles and vets on the Windows
// dev box; the length-framed codec (Encode/Decode) is platform-independent and
// is what the protocol tests exercise there.
//
// Impersonation itself is Linux-only by design: PLAN.md decision 5 rejects
// in-process setuid, so there is no non-Linux fallback to offer.

func WriteFrame(c *net.UnixConn, f Frame, fds []int) error {
	_, _, _ = c, f, fds
	return fmt.Errorf("passing file descriptors between processes: %w", fsx.ErrUnsupported)
}

func ReadFrame(c *net.UnixConn) (Frame, []int, error) {
	_ = c
	return Frame{}, nil, fmt.Errorf("passing file descriptors between processes: %w", fsx.ErrUnsupported)
}
