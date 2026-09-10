package fsops

import (
	"context"
	"errors"
	"io"
	"io/fs"
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

// TestListDoesNotBlockOnAFifo is the same trap on the listing side, which
// O_DIRECTORY closes: the kernel refuses a non-directory in may_open, before
// the fifo machinery gets a chance to park the caller inside open(2).
func TestListDoesNotBlockOnAFifo(t *testing.T) {
	r, base := fixture(t)
	if err := syscall.Mkfifo(filepath.Join(base, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo is not available here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := List(context.Background(), r, nil, "/pipe", fsx.ListOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrBadName) {
			t.Fatalf("listing a fifo = %v, want ErrBadName", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("List blocked in open(2) on a fifo with no writer")
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

// TestOpenFinalRefusesASymlinkAsTheFinalComponent: os.Root.OpenFile puts
// O_NOFOLLOW on its openat and then follows the link anyway when it stays
// inside the root, so the caller's no-follow contract was enforced only by an
// lstat and an os.SameFile check — which an inode swap between the two can
// satisfy. openFinal opens the parent through the root and the final component
// relative to that descriptor, where the kernel honours the flag and says
// ELOOP.
func TestOpenFinalRefusesASymlinkAsTheFinalComponent(t *testing.T) {
	requireSymlinks(t)
	r, base := fixture(t)
	if err := os.Symlink("one.txt", filepath.Join(base, "a", "link")); err != nil {
		t.Fatal(err)
	}
	rt, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}
	f, err := openFinal(rt, "a/link")
	if err == nil {
		f.Close()
		t.Fatal("a symlink as the final component must be refused by the kernel, not followed")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("err = %v, want ELOOP", err)
	}
	if code := fsx.Code(err); code != "bad_request" {
		t.Errorf("code = %q, want bad_request", code)
	}
	// The regular file beside it still opens, through the same path.
	ok, err := openFinal(rt, "a/one.txt")
	if err != nil {
		t.Fatalf("opening a regular file through openFinal: %v", err)
	}
	ok.Close()
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

// TestListMetadataComesFromTheOpenedDirectory is the round-six adversarial
// finding, run as a race that has already happened.
//
// The listing used os.File.ReadDir, whose DirEntry.Info lstats
// f.Name()+"/"+name for a file that did not come from an os.Root — and openDir
// deliberately does not return one, because os.Root asks for read permission on
// every directory on the way. So the names came from the descriptor and the
// metadata came from a path. Rename the listed directory away and put a symlink
// to somewhere else in its place, and every entry kept its original name while
// its size, mode and owner described a file in the replacement — outside the
// jail, if that is where the link pointed.
//
// The swap is done between the open and the read rather than raced against it,
// so the test either observes the defect or does not exist.
func TestListMetadataComesFromTheOpenedDirectory(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "d")
	mkdir(t, base, "d/sub")
	write(t, base, "d/f.txt", "original")
	mkdir(t, base, "elsewhere")
	mkdir(t, base, "elsewhere/sub")
	write(t, base, "elsewhere/f.txt", "a longer replacement, with a different size")
	r := newRoot(t, base)
	rt, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}

	f, err := openDir(rt, "d", filepath.Join(base, "d"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// The swap: the listed directory is renamed away and a symlink to another
	// directory holding the same names takes its place.
	if err := os.Rename(filepath.Join(base, "d"), filepath.Join(base, "d.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(base, "d")); err != nil {
		t.Fatal(err)
	}
	// Precondition: a path-based lookup really would land on the replacement now.
	swapped, err := os.Lstat(filepath.Join(base, "d", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if swapped.Size() != int64(len("a longer replacement, with a different size")) {
		t.Fatalf("the swap did not take effect: size by path = %d", swapped.Size())
	}

	des, err := readDirInfos(f, readChunk, true)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	seen := map[string]fs.FileInfo{}
	for _, de := range des {
		if de.err != nil {
			t.Fatalf("%s: %v", de.name, de.err)
		}
		seen[de.name] = de.info
	}
	if len(seen) != 2 {
		t.Fatalf("entries = %v, want f.txt and sub from the original directory", seen)
	}
	fi, ok := seen["f.txt"]
	if !ok {
		t.Fatalf("entries = %v, want f.txt", seen)
	}
	if fi.Size() != int64(len("original")) {
		t.Errorf("size = %d, want %d: the metadata came from the replacement directory",
			fi.Size(), len("original"))
	}
	// The same file, not merely the same length: the descriptor's f.txt and the
	// renamed directory's f.txt are one inode, and the replacement's is another.
	moved, err := os.Lstat(filepath.Join(base, "d.moved", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !sameInode(t, fi, moved) {
		t.Error("the entry describes a different inode than the one in the directory that was opened")
	}
	if sameInode(t, fi, swapped) {
		t.Error("the entry describes the replacement file")
	}
	// The mode mapping is this package's own now, so the type has to survive it.
	if sub := seen["sub"]; sub == nil || !sub.IsDir() {
		t.Errorf("sub = %v, want a directory", sub)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want a regular file with 0644", fi.Mode())
	}
	if _, _, _, ok := statDetail(fi); !ok {
		t.Error("statDetail cannot read the syscall.Stat_t behind the entry's FileInfo")
	}
	if fi.ModTime().IsZero() {
		t.Error("mtime is zero")
	}
}

// sameInode compares two FileInfos by device and inode. os.SameFile cannot do
// it here: it type-asserts both sides to the os package's own unexported
// fileStat, so it answers false for anything else — including the FileInfo the
// listing now builds from a raw stat structure. Nothing in fsops uses SameFile
// on a listing entry (OpenRead's check is on FileInfos from statAt, which are
// still the os package's own), so this is a test's problem rather than a
// caller's.
func sameInode(t *testing.T, a, b fs.FileInfo) bool {
	t.Helper()
	sa, oka := a.Sys().(*syscall.Stat_t)
	sb, okb := b.Sys().(*syscall.Stat_t)
	if !oka || !okb {
		t.Fatalf("no syscall.Stat_t behind %v / %v", a, b)
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

// TestStatModeCarriesTheSpecialBits: setuid, setgid and sticky are separate
// flags in fs.FileMode, and both fsx.ModeOctal and fsx.ModeString report them,
// so the hand-rolled st_mode mapping has to carry them across.
func TestStatModeCarriesTheSpecialBits(t *testing.T) {
	cases := []struct {
		mode uint32
		want fs.FileMode
	}{
		{syscall.S_IFREG | 0o644, 0o644},
		{syscall.S_IFDIR | syscall.S_ISVTX | 0o777, fs.ModeDir | fs.ModeSticky | 0o777},
		{syscall.S_IFREG | syscall.S_ISUID | 0o755, fs.ModeSetuid | 0o755},
		{syscall.S_IFREG | syscall.S_ISGID | 0o755, fs.ModeSetgid | 0o755},
		{syscall.S_IFLNK | 0o777, fs.ModeSymlink | 0o777},
		{syscall.S_IFIFO | 0o644, fs.ModeNamedPipe | 0o644},
		{syscall.S_IFSOCK | 0o755, fs.ModeSocket | 0o755},
		{syscall.S_IFCHR | 0o666, fs.ModeDevice | fs.ModeCharDevice | 0o666},
		{syscall.S_IFBLK | 0o660, fs.ModeDevice | 0o660},
	}
	for _, c := range cases {
		if got := statMode(c.mode); got != c.want {
			t.Errorf("statMode(%#o) = %v, want %v", c.mode, got, c.want)
		}
	}
}
