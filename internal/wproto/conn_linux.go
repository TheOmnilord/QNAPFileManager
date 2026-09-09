package wproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"syscall"
)

// WriteFrame sends one frame, with fds attached through SCM_RIGHTS, in a
// single WriteMsgUnix. One frame per sendmsg is a requirement, not a
// convenience: Linux does not merge stream data across a sendmsg that carried
// ancillary data, so an fd-bearing frame is always delivered whole and the fds
// cannot end up attached to the wrong message.
//
// The caller keeps ownership of fds: they are duplicated into the receiving
// process, and the sender still has to close its own copies.
func WriteFrame(c *net.UnixConn, f Frame, fds []int) error {
	f.NFD = len(fds)
	buf, err := marshalFrame(f)
	if err != nil {
		return err
	}
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	n, oobn, err := c.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return err
	}
	if oobn != len(oob) {
		return fmt.Errorf("sent %d of %d ancillary bytes: %w", oobn, len(oob), ErrProtocol)
	}
	// A short write on a stream socket after ancillary data has already gone
	// out cannot be retried without splitting the fds from their frame.
	if n != len(buf) {
		return fmt.Errorf("short write, %d of %d bytes: %w", n, len(buf), ErrProtocol)
	}
	return nil
}

// ReadFrame reads one frame and any file descriptors that arrived with it.
// The returned fds belong to the caller, which must close them.
//
// Reads are sized to exactly what is still needed, so this never consumes
// bytes belonging to the next frame and needs no buffering between calls.
// Descriptors are collected across every recvmsg that makes up this frame:
// the sender put the whole frame in one sendmsg, so any ancillary data seen
// while reading it belongs to it, even if the header and the body come back
// in separate recvmsg calls.
func ReadFrame(c *net.UnixConn) (Frame, []int, error) {
	var hdr [4]byte
	fds, err := readFullMsg(c, hdr[:], nil)
	if err != nil {
		closeFDs(fds)
		return Frame{}, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		closeFDs(fds)
		return Frame{}, nil, fmt.Errorf("empty frame: %w", ErrProtocol)
	}
	if n > MaxFrame {
		closeFDs(fds)
		return Frame{}, nil, fmt.Errorf("frame of %d bytes exceeds the %d byte cap: %w", n, MaxFrame, ErrFrameTooLarge)
	}
	buf := make([]byte, n)
	fds, err = readFullMsg(c, buf, fds)
	if err != nil {
		closeFDs(fds)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, nil, err
	}
	f, err := unmarshalFrame(buf)
	if err != nil {
		closeFDs(fds)
		return Frame{}, nil, err
	}
	if f.NFD != len(fds) {
		closeFDs(fds)
		return Frame{}, nil, fmt.Errorf("frame declared %d fds, %d arrived: %w", f.NFD, len(fds), ErrFDMismatch)
	}
	return f, fds, nil
}

// readFullMsg fills p, appending any descriptors it picks up on the way to
// fds. The oob buffer is sized for a generous number of descriptors; anything
// beyond that would be truncated by the kernel (MSG_CTRUNC) and is reported
// rather than silently leaking the extras.
func readFullMsg(c *net.UnixConn, p []byte, fds []int) ([]int, error) {
	oob := make([]byte, syscall.CmsgSpace(4*maxFDsPerFrame))
	for off := 0; off < len(p); {
		n, oobn, flags, _, err := c.ReadMsgUnix(p[off:], oob)
		if oobn > 0 {
			got, perr := parseFDs(oob[:oobn])
			fds = append(fds, got...)
			if perr != nil {
				return fds, perr
			}
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			return fds, fmt.Errorf("ancillary data was truncated: %w", ErrProtocol)
		}
		if n > 0 {
			off += n
		}
		if err != nil {
			return fds, err
		}
		if n == 0 && oobn == 0 {
			return fds, io.ErrUnexpectedEOF
		}
	}
	return fds, nil
}

// maxFDsPerFrame bounds the control-message buffer. Nothing in the protocol
// passes more than one descriptor today; the headroom is for a future batched
// open without having to change the framing.
const maxFDsPerFrame = 8

func parseFDs(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing ancillary data: %v", ErrProtocol, err)
	}
	var out []int
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_SOCKET || m.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		got, err := syscall.ParseUnixRights(&m)
		if err != nil {
			return out, fmt.Errorf("%w: parsing SCM_RIGHTS: %v", ErrProtocol, err)
		}
		out = append(out, got...)
	}
	return out, nil
}

// closeFDs releases descriptors the caller will never see. Every error path
// that has already received fds goes through here: a leaked fd in the root
// front-end is a file the user opened that the daemon then holds open
// indefinitely.
func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
