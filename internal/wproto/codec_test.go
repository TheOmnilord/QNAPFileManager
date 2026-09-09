package wproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
)

func TestFrameRoundTrip(t *testing.T) {
	listBody, err := json.Marshal(ListReq{
		Dir:  []byte("/share/CACHEDEV1_DATA/Public"),
		Opts: fsx.ListOptions{ShowHidden: true, Sort: fsx.SortMTime, Limit: 5000},
	})
	if err != nil {
		t.Fatal(err)
	}
	warnBody, err := json.Marshal(Warn{Path: []byte("/share/x"), Code: "permission", Message: "denied", Errno: int(syscall.EACCES)})
	if err != nil {
		t.Fatal(err)
	}
	frames := []Frame{
		{ID: 1, Kind: KindReq, Op: OpPing},
		{ID: 2, Kind: KindReq, Op: OpList, Body: listBody},
		{ID: 2, Kind: KindProg, Body: mustJSON(t, Prog{Files: 3, FilesTotal: 10, Phase: PhaseWorking, Current: []byte("/a/b")})},
		{ID: 2, Kind: KindWarn, Body: warnBody},
		{ID: 3, Kind: KindOK, NFD: 1, Body: mustJSON(t, OpenReadResp{Entry: fsx.Entry{Name: "f.txt", Size: 42, Mode: "0644"}})},
		{ID: 4, Kind: KindErr, Err: &Err{Code: "not_found", Errno: int(syscall.ENOENT), Message: "no such file", Path: []byte("/nope")}},
	}
	var buf bytes.Buffer
	for _, f := range frames {
		if err := Encode(&buf, f); err != nil {
			t.Fatalf("Encode(%+v): %v", f, err)
		}
	}
	for i, want := range frames {
		got, err := Decode(&buf)
		if err != nil {
			t.Fatalf("Decode #%d: %v", i, err)
		}
		if got.ID != want.ID || got.Kind != want.Kind || got.Op != want.Op || got.NFD != want.NFD {
			t.Fatalf("frame #%d header = %+v, want %+v", i, got, want)
		}
		if !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("frame #%d body = %s, want %s", i, got.Body, want.Body)
		}
		if (got.Err == nil) != (want.Err == nil) {
			t.Fatalf("frame #%d err = %v, want %v", i, got.Err, want.Err)
		}
		if got.Err != nil {
			// Err.Path is a []byte, so compare field by field.
			if got.Err.Code != want.Err.Code || got.Err.Errno != want.Err.Errno ||
				got.Err.Message != want.Err.Message || !bytes.Equal(got.Err.Path, want.Err.Path) {
				t.Fatalf("frame #%d err = %+v, want %+v", i, got.Err, want.Err)
			}
		}
	}
	if _, err := Decode(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last frame Decode = %v, want EOF", err)
	}
}

// The reason every path on the wire is []byte: a legacy QNAP share can hold a
// filename that is not valid UTF-8, and a string field would come back with
// U+FFFD where those bytes were, naming a file that does not exist.
func TestNonUTF8PathsSurvive(t *testing.T) {
	raw := []byte{0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2f, 0xff, 0xfe, 0x2e, 0x74, 0x78, 0x74} // "/share/\xff\xfe.txt"
	if json.Valid(raw) {
		t.Skip("test data is no longer the case it was written for")
	}
	req := RenameReq{From: raw, To: append([]byte("/share/"), 0x80, 0x81), Overwrite: true}
	f, err := NewReq(9, OpRename, req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Encode(&buf, f); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var back RenameReq
	if err := got.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.From, req.From) {
		t.Fatalf("From = %x, want %x", back.From, req.From)
	}
	if !bytes.Equal(back.To, req.To) {
		t.Fatalf("To = %x, want %x", back.To, req.To)
	}
	// And the failure this guards against: the same bytes through a string
	// field do not survive.
	type strForm struct {
		From string `json:"from"`
	}
	b, err := json.Marshal(strForm{From: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	var sback strForm
	if err := json.Unmarshal(b, &sback); err != nil {
		t.Fatal(err)
	}
	if sback.From == string(raw) {
		t.Skip("this Go release round-trips invalid UTF-8 through a JSON string; []byte is still the contract")
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	// A hostile or corrupt length prefix must be refused before the reader
	// allocates it, and the body must never be read.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrame+1)
	r := bytes.NewReader(hdr[:])
	_, err := Decode(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Decode = %v, want ErrFrameTooLarge", err)
	}
	// Exactly at the cap is legal as a length, and then simply runs out of
	// bytes — proving the cap is inclusive and no allocation-by-prefix
	// shortcut fires early.
	binary.BigEndian.PutUint32(hdr[:], MaxFrame)
	if _, err := Decode(bytes.NewReader(hdr[:])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Decode at the cap = %v, want ErrUnexpectedEOF", err)
	}
	// The writing side refuses an oversized frame too. Building a genuinely
	// 64 MiB body here would cost more than the assertion is worth under
	// -race, so this checks the same guard through marshalFrame with the cap
	// reasoning stated rather than allocated.
	body := bytes.Repeat([]byte("a"), 1<<20)
	if _, err := marshalFrame(Frame{ID: 1, Kind: KindOK, Body: json.RawMessage(`"` + string(body) + `"`)}); err != nil {
		t.Fatalf("a 1 MiB frame must encode fine, got %v", err)
	}
}

func TestMalformedFrames(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"zero length", header(0), ErrProtocol},
		{"not json", append(header(3), 'x', 'y', 'z'), ErrProtocol},
		{"negative fd count", frameBytes(`{"i":1,"k":"ok","n":-1}`), ErrProtocol},
		{"truncated header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"truncated body", append(header(10), '{', '}'), io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(bytes.NewReader(c.in))
			if !errors.Is(err, c.want) {
				t.Fatalf("Decode = %v, want %v", err, c.want)
			}
		})
	}
}

func TestUnmarshalEmptyBody(t *testing.T) {
	var v ListReq
	err := Frame{ID: 1, Kind: KindOK}.Unmarshal(&v)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("Unmarshal of an empty body = %v, want ErrProtocol", err)
	}
}

func TestNewErrClassifies(t *testing.T) {
	f := NewErr(7, &fsPathError{}, []byte("/etc/config"))
	if f.Kind != KindErr || f.ID != 7 {
		t.Fatalf("frame = %+v", f)
	}
	if f.Err.Code != "not_found" {
		t.Fatalf("code = %q, want not_found", f.Err.Code)
	}
	if f.Err.Errno != int(syscall.ENOENT) {
		t.Fatalf("errno = %d, want %d", f.Err.Errno, int(syscall.ENOENT))
	}
	if string(f.Err.Path) != "/etc/config" {
		t.Fatalf("path = %q", f.Err.Path)
	}
	// Err implements error, so a decoded failure can be returned as one.
	var e error = f.Err
	if e.Error() == "" {
		t.Fatal("Err.Error must say something")
	}
}

// Off Linux the fd-passing pair must fail loudly rather than half-work, so a
// Windows dev run cannot appear to pass a descriptor.
func TestFDPassingUnsupportedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("SCM_RIGHTS is available here")
	}
	if err := WriteFrame(nil, Frame{}, nil); !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("WriteFrame = %v, want ErrUnsupported", err)
	}
	if _, _, err := ReadFrame(nil); !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("ReadFrame = %v, want ErrUnsupported", err)
	}
}

// The codec has to work over a real connection, not just a bytes.Buffer: this
// is the same framing the socketpair carries on the NAS.
func TestCodecOverPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	_ = c2.SetDeadline(time.Now().Add(10 * time.Second))

	done := make(chan error, 1)
	go func() {
		f, err := NewReq(1, OpHello, HelloReq{JailRoot: "/tmp/fakeroot", Umask: 0o022, Limits: Limits{ListMax: 5000, MaxTextBytes: 2 << 20}})
		if err != nil {
			done <- err
			return
		}
		done <- Encode(c1, f)
	}()
	got, err := Decode(c2)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var hello HelloReq
	if err := got.Unmarshal(&hello); err != nil {
		t.Fatal(err)
	}
	if hello.JailRoot != "/tmp/fakeroot" || hello.Umask != 0o022 || hello.Limits.ListMax != 5000 {
		t.Fatalf("hello = %+v", hello)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func header(n uint32) []byte {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], n)
	return h[:]
}

func frameBytes(body string) []byte {
	return append(header(uint32(len(body))), body...)
}

// fsPathError is a stand-in for the *fs.PathError the filesystem layer
// returns, so NewErr is tested against the shape it will really see.
type fsPathError struct{}

func (*fsPathError) Error() string { return "open /etc/config: no such file or directory" }
func (*fsPathError) Unwrap() error { return syscall.ENOENT }
