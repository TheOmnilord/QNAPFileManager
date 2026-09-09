package wproto

import "errors"

var (
	// ErrProtocol: the bytes on the socket are not a frame we understand.
	// Unrecoverable — the connection's framing is lost, so the caller must
	// retire the worker rather than try to resynchronise.
	ErrProtocol = errors.New("protocol error")
	// ErrFrameTooLarge: a length prefix or an outgoing frame above MaxFrame.
	ErrFrameTooLarge = errors.New("frame too large")
	// ErrFDMismatch: the frame declared a different number of file
	// descriptors than the ancillary data carried.
	ErrFDMismatch = errors.New("file descriptor count does not match the frame")
)
