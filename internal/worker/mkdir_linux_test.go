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
// worker's OWN uid (a chown to self is permitted without root), so the post-create
// uid is the load-bearing assertion: the chown reached fsops and landed on the
// new leaf. The create path never chmods (findings B/D), so the mode is whatever
// the umask produced and is deliberately not asserted. GID -1 leaves the group
// alone. Linux-only because the owner is ignored off Linux (no uid/chown; INV-2).
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
		As:   &wproto.CreateAs{UID: self, GID: -1},
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
}
