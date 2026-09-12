package worker

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestMkdirAsOwnerRoundTrips proves the MkdirReq.As owner survives the wire and
// reaches fsops, which applies it. It runs unprivileged by asking for the
// worker's OWN uid (a chown to self is permitted without root) and an explicit
// mode the umask alone would not produce, so the post-create mode is the
// load-bearing assertion: 0700 can only come from the fchmod fsops does when As
// is honoured, not from a umask-trimmed 0755. GID -1 leaves the group alone.
// Linux-only because the owner is ignored off Linux (no uid/chown; INV-2).
func TestMkdirAsOwnerRoundTrips(t *testing.T) {
	base := fixture(t)
	tr, _ := dial(t, base)
	if f := req(t, tr, 1, wproto.OpHello, wproto.HelloReq{JailRoot: base, Umask: 0o022}); f.Kind != wproto.KindOK {
		t.Fatalf("hello = %+v", f)
	}

	self := os.Getuid()
	f := req(t, tr, 2, wproto.OpMkdir, wproto.MkdirReq{
		Dir:  []byte("/"),
		Name: []byte("owned"),
		As:   &wproto.CreateAs{UID: self, GID: -1, Mode: 0o700},
	})
	if f.Kind != wproto.KindOK {
		t.Fatalf("mkdir with an owner = %+v", f.Err)
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(base, "owned"), &st); err != nil {
		t.Fatalf("lstat the created directory: %v", err)
	}
	if int(st.Uid) != self {
		t.Errorf("owner uid = %d, want %d (the As uid reached fsops)", st.Uid, self)
	}
	if st.Mode&0o777 != 0o700 {
		t.Errorf("mode = %#o, want 0700 (As.Mode reached fsops and defeated the umask)", st.Mode&0o777)
	}
}
