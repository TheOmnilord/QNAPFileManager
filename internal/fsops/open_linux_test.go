package fsops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
)

// TestOpenReadDoesNotBlockOnAFifo is the reason the Linux open carries
// O_NONBLOCK. Opening a fifo for reading with no writer blocks inside open(2),
// where neither the HTTP deadline nor the pool's call timeout can reach it, so
// 64 requests for one fifo used to take every worker slot in the daemon and
// stop everybody's browsing.
func TestOpenReadDoesNotBlockOnAFifo(t *testing.T) {
	r, base := fixture(t)
	if err := syscall.Mkfifo(filepath.Join(base, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo is not available here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, _, err := OpenRead(context.Background(), r, "/pipe")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrUnsupported) {
			t.Fatalf("opening a fifo = %v, want ErrUnsupported", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("OpenRead blocked in open(2) on a fifo with no writer")
	}
}

// A regular file must come back in blocking mode all the same: O_NONBLOCK is
// only there to survive the open, and a descriptor that leaves this package
// still carrying it would behave differently from every other file in the
// process once it is streamed.
func TestOpenReadClearsNonblock(t *testing.T) {
	r, _ := fixture(t)
	f, _, err := OpenRead(context.Background(), r, "/a/one.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if flags := fileStatusFlags(t, f); flags&syscall.O_NONBLOCK != 0 {
		t.Errorf("file status flags = %#o, want O_NONBLOCK cleared", flags)
	}
}

func fileStatusFlags(t *testing.T, f *os.File) int {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var (
		flags int
		serr  error
	)
	if err := rc.Control(func(fd uintptr) {
		n, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, uintptr(syscall.F_GETFL), 0)
		if errno != 0 {
			serr = errno
			return
		}
		flags = int(n)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatalf("F_GETFL: %v", serr)
	}
	return flags
}
