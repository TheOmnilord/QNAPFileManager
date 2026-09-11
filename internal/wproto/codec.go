package wproto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"qnapfilemanager/internal/fsx"
)

// MaxFrame caps a single frame's payload. A 5 000-entry listing is roughly
// 1.5 MB of JSON, so 64 MiB is far above anything legitimate; the cap exists
// so a corrupt or hostile length prefix cannot make the reader allocate the
// machine's memory in one go.
const MaxFrame = 64 << 20

// Frame is one message. Replies, progress and warnings echo the request's ID.
type Frame struct {
	ID   uint64          `json:"i"`
	Kind string          `json:"k"`
	Op   Op              `json:"o,omitempty"`
	NFD  int             `json:"n,omitempty"` // fds attached to this frame
	Body json.RawMessage `json:"b,omitempty"`
	Err  *Err            `json:"e,omitempty"`
}

// NewReq builds a request frame with body marshalled from v (which may be nil).
func NewReq(id uint64, op Op, v any) (Frame, error) {
	f := Frame{ID: id, Kind: KindReq, Op: op}
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return Frame{}, fmt.Errorf("marshal %s request: %w", op, err)
		}
		f.Body = b
	}
	return f, nil
}

// NewOK builds a terminal success frame.
func NewOK(id uint64, v any) (Frame, error) {
	f := Frame{ID: id, Kind: KindOK}
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return Frame{}, fmt.Errorf("marshal reply: %w", err)
		}
		f.Body = b
	}
	return f, nil
}

// NewErr builds a terminal failure frame, classifying err with fsx.Code so the
// front-end and the HTTP layer speak one vocabulary.
func NewErr(id uint64, err error, path []byte) Frame {
	return Frame{ID: id, Kind: KindErr, Err: &Err{
		Code:    fsx.Code(err),
		Errno:   fsx.Errno(err),
		Message: err.Error(),
		Path:    path,
	}}
}

// NewProg builds a non-terminal progress frame for the job running under id.
// It carries the SAME id as the JobReq, so the pool's pending table routes it
// to the waiting Job call without any second channel (identity plan §2.5).
func NewProg(id uint64, p Prog) (Frame, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return Frame{}, fmt.Errorf("marshal progress: %w", err)
	}
	return Frame{ID: id, Kind: KindProg, Body: b}, nil
}

// NewWarn builds a non-terminal per-item warning frame for the job running
// under id. A warning does not end the job; the terminal JobResult also folds
// it in, so a frame lost to a slow reader is never a lost record.
func NewWarn(id uint64, w Warn) (Frame, error) {
	b, err := json.Marshal(w)
	if err != nil {
		return Frame{}, fmt.Errorf("marshal warning: %w", err)
	}
	return Frame{ID: id, Kind: KindWarn, Body: b}, nil
}

// Decode reads one length-prefixed JSON frame. It is the fd-free half of the
// codec: the Unix-socket path in conn_linux.go uses the same framing, which is
// what lets the protocol be tested on Windows where SCM_RIGHTS does not exist.
func Decode(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Frame{}, fmt.Errorf("empty frame: %w", ErrProtocol)
	}
	if n > MaxFrame {
		return Frame{}, fmt.Errorf("frame of %d bytes exceeds the %d byte cap: %w", n, MaxFrame, ErrFrameTooLarge)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		// A short read after a good length prefix means the peer died
		// mid-frame; say so rather than reporting a JSON syntax error.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return unmarshalFrame(buf)
}

// Encode writes one length-prefixed JSON frame.
func Encode(w io.Writer, f Frame) error {
	buf, err := marshalFrame(f)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// marshalFrame produces the complete on-the-wire bytes, header included, so
// both Encode and the sendmsg path emit exactly one write.
func marshalFrame(f Frame) ([]byte, error) {
	body, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("marshal frame: %w", err)
	}
	if len(body) > MaxFrame {
		return nil, fmt.Errorf("frame of %d bytes exceeds the %d byte cap: %w", len(body), MaxFrame, ErrFrameTooLarge)
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

func unmarshalFrame(buf []byte) (Frame, error) {
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if f.NFD < 0 {
		return Frame{}, fmt.Errorf("negative fd count %d: %w", f.NFD, ErrProtocol)
	}
	return f, nil
}

// Unmarshal decodes a frame body into v.
func (f Frame) Unmarshal(v any) error {
	if len(f.Body) == 0 {
		return fmt.Errorf("%s frame has no body: %w", f.Kind, ErrProtocol)
	}
	return json.Unmarshal(f.Body, v)
}
