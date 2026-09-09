package fsops

import (
	"io/fs"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// openDirFlags is what List passes to open(2) for the directory it enumerates.
//
// O_DIRECTORY makes the kernel refuse anything that is not a directory, and it
// refuses it in may_open(2) — before the fifo machinery runs. That is what
// stops "list /path/to/a/fifo" from parking a worker goroutine inside open(2)
// with no writer on the other end, where no deadline in this process can reach
// it; sixty-four such requests would otherwise take every slot the worker has.
func openDirFlags() int { return os.O_RDONLY | syscall.O_DIRECTORY }

// oPath is O_PATH. The value is the same on every Linux architecture, but the
// standard syscall package only spells it out for some of them (amd64, the
// architecture the NAS x86 build targets, is one of the ones it omits), so it is
// written here rather than made a per-GOARCH problem.
const oPath = 0x200000

// walkOPath opens the directory named by rel inside rt and hands back a
// descriptor for it, one component at a time, asking the kernel for nothing it
// does not need.
//
// It exists because *os.Root asks for more than the kernel does. Every
// intermediate component of an os.Root path is opened with a plain O_RDONLY —
// see rootOpenDir in $GOROOT/src/os/root_unix.go, which calls
// openat(parent, name, O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) with no access mode at
// all, and O_RDONLY is what "no access mode" means. So os.Root demands read
// permission on every directory on the way to a file, where the kernel demands
// only search. Mode 0111 on a directory is precisely the difference: a private
// index with readable files inside it, which is an ordinary shape for a QNAP
// share, and which os.Root turned into EACCES for the stat and the download
// alike. Refusing what the kernel would have allowed is the wrong half of INV-2.
//
// Each component here is opened O_PATH instead: the kernel resolves the name
// and returns a handle that can be the dirfd of a later openat, and checks
// nothing else. Resolving the name still needs search permission on the parent,
// which is exactly the permission the kernel itself requires, and no more.
//
// The confinement is unchanged, and it is worth being explicit about why:
//
//   - the walk starts at rt's own descriptor, reached through os.Root, so there
//     is no name for it to be given;
//   - every step is an openat relative to the previous descriptor, so nothing
//     is resolved through this process's cwd or through an absolute path;
//   - O_NOFOLLOW with O_DIRECTORY refuses a symlink component outright (the
//     kernel opens the link itself and then fails the directory check), so a
//     link swapped in underneath cannot redirect the walk. Nothing needs it to
//     follow one: resolve() has already followed every symlink on the path and
//     what it hands over is a list of resolved components;
//   - ".." is refused rather than applied, for the same reason — resolve()
//     applies it, against the directory it is written in and with the kernel's
//     permission check (see checkTraversable), and a second interpretation here
//     could only disagree with the first.
//
// The caller owns the returned descriptor and must close it.
func walkOPath(rt *os.Root, rel string) (*os.File, error) {
	// "." is the jail base itself. os.Root resolves that against the descriptor
	// it holds, so this needs no name and cannot be pointed anywhere else.
	dir, err := rt.OpenFile(".", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := splitRel(rel)
	for i, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			dir.Close()
			return nil, &fs.PathError{Op: "openat", Path: relOf(parts[:i+1]), Err: syscall.EINVAL}
		}
		fd, err := openatIn(dir, part, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
		dir.Close()
		if err != nil {
			return nil, &fs.PathError{Op: "openat", Path: relOf(parts[:i+1]), Err: err}
		}
		dir = os.NewFile(uintptr(fd), relOf(parts[:i+1]))
	}
	return dir, nil
}

// openatIn is openat(2) relative to an open directory, retried over EINTR.
//
// The descriptor is reached through SyscallConn rather than File.Fd, which
// would detach the directory from the runtime poller as a side effect.
func openatIn(dir *os.File, name string, flags int) (int, error) {
	rc, err := dir.SyscallConn()
	if err != nil {
		return -1, err
	}
	var (
		fd   int
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			fd, serr = syscall.Openat(int(pfd), name, flags, 0)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return -1, cerr
	}
	if serr != nil {
		return -1, serr
	}
	return fd, nil
}

// statAt is lstat(2) — or stat(2), when follow is set — for a path that has
// already been resolved, taken through the O_PATH walk rather than through
// os.Root so that a search-only directory on the way costs nothing.
//
// The metadata itself comes from fstat on an O_PATH descriptor for the final
// component, opened O_NOFOLLOW so a symlink describes itself. Going through a
// descriptor rather than fstatat is deliberate: what comes back is the os
// package's own FileInfo, so os.SameFile still works on it — and os.SameFile is
// what OpenRead uses to prove the descriptor it opened is the file it checked.
func statAt(rt *os.Root, rel string, follow bool) (os.FileInfo, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		// The jail base itself, or a name openat cannot address on its own.
		// There is nothing above it to walk, so os.Root asks for nothing extra.
		if follow {
			return rt.Stat(rel)
		}
		return rt.Lstat(rel)
	}
	parent, err := walkOPath(rt, dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := openatIn(parent, base, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "statat", Path: rel, Err: err}
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if follow && fi.Mode()&fs.ModeSymlink != 0 {
		// resolve() follows every link on a path it was asked to follow, so a
		// link still here is one that appeared underneath us. Following it is
		// os.Root's job, because following it safely means checking that it
		// lands back inside the jail, and os.Root is what knows how to do that.
		return rt.Stat(rel)
	}
	return fi, nil
}

// readlinkAt is readlink(2) for an already-resolved path, through the same
// O_PATH walk and for the same reason: naming a link inside a search-only
// directory is not a listing.
func readlinkAt(rt *os.Root, rel string) (string, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		return rt.Readlink(rel)
	}
	parent, err := walkOPath(rt, dir)
	if err != nil {
		return "", err
	}
	defer parent.Close()

	rc, err := parent.SyscallConn()
	if err != nil {
		return "", err
	}
	// A target longer than any kernel will produce (PATH_MAX is 4096) is a
	// filesystem misbehaving, not a buffer to keep doubling.
	for size := 256; size <= 1<<16; size *= 2 {
		buf := make([]byte, size)
		var (
			n    int
			serr error
		)
		if cerr := rc.Control(func(pfd uintptr) {
			for {
				n, serr = readlinkatIn(int(pfd), base, buf)
				if serr != syscall.EINTR {
					return
				}
			}
		}); cerr != nil {
			return "", cerr
		}
		if serr != nil {
			return "", &fs.PathError{Op: "readlinkat", Path: rel, Err: serr}
		}
		if n < size {
			return string(buf[:n]), nil
		}
		// The target filled the buffer exactly, so it may have been truncated:
		// readlinkat(2) does not distinguish the two, and it does not
		// null-terminate. Round again with twice the room.
	}
	return "", &fs.PathError{Op: "readlinkat", Path: rel, Err: syscall.ENAMETOOLONG}
}

// readlinkatIn is readlinkat(2). The syscall package exposes openat but not
// this one on any Linux architecture, so it is made by hand — which is why it
// is three lines of unsafe rather than none. The shape is the one the unsafe
// rules sanction for exactly this case (rule 4: a Pointer converted to uintptr
// in the argument list of a syscall.Syscall call), and the arguments are kept
// alive across the call rather than trusted to escape analysis.
func readlinkatIn(dirfd int, name string, buf []byte) (int, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	var out unsafe.Pointer
	if len(buf) > 0 {
		out = unsafe.Pointer(&buf[0])
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(out), uintptr(len(buf)), 0, 0)
	runtime.KeepAlive(p)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// openFinal opens the last component of an already-resolved path for reading,
// and is the one place the no-follow rule is actually enforced by the kernel.
//
// os.Root.OpenFile cannot do it. It puts O_NOFOLLOW on every openat it makes,
// but when that comes back ELOOP it checks whether the link stays inside the
// root and, if it does, follows it — the caller's own O_NOFOLLOW gets no say.
// So the parent directory is walked with O_PATH, which is what keeps the walk
// confined, and the final component is opened relative to that descriptor with
// the flag the kernel will honour. A symlink there is then ELOOP, which
// fsx.Code already maps to bad_request, rather than something quietly followed.
//
// O_NONBLOCK is what keeps a fifo from taking a worker hostage: opening one for
// reading with no writer blocks inside open(2) itself, and nothing above can
// interrupt a blocked syscall. With the flag the open returns immediately and
// fstat gets its turn. The caller clears it again once the descriptor has been
// proved to be a regular file (clearNonblock).
func openFinal(rt *os.Root, rel string) (*os.File, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		// Never a regular file, and never something to hand to openat here.
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: syscall.EINVAL}
	}
	parent, err := walkOPath(rt, dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := openatIn(parent, base,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: err}
	}
	return os.NewFile(uintptr(fd), rel), nil
}

// checkTraversable asks the kernel whether this process may search dir, and
// reports its answer verbatim.
//
// resolve needs it because ".." is not arithmetic on a string: the kernel
// resolves it *inside* the directory it is written in, and that lookup needs
// search permission on that directory like any other. Popping a component in
// this process instead let "locked/../report" succeed for a user who cannot
// traverse "locked" at all — the app inventing an answer the kernel would have
// refused (INV-2).
//
// The question is asked by opening "." relative to dir's own descriptor. That
// is a path lookup starting at dir, so link_path_walk applies MAY_EXEC to dir
// itself; opening dir directly would not, because O_PATH deliberately skips the
// permission check on the thing being opened. Every descriptor involved is
// O_PATH, so nothing here needs read permission on anything.
func checkTraversable(rt *os.Root, dir string) error {
	d, err := walkOPath(rt, dir)
	if err != nil {
		return err
	}
	defer d.Close()
	fd, err := openatIn(d, ".", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
	if err != nil {
		return &fs.PathError{Op: "openat", Path: dir, Err: err}
	}
	syscall.Close(fd)
	return nil
}

// splitFinal splits a root-relative slash path into the directory to open and
// the final component to open inside it. A path with no separator lives in the
// root itself, which os.Root spells ".".
func splitFinal(rel string) (dir, base string) {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		dir, base = rel[:i], rel[i+1:]
		if dir == "" {
			dir = "."
		}
		return dir, base
	}
	return ".", rel
}

// clearNonblock puts a descriptor opened with O_NONBLOCK back into blocking
// mode, so the streaming read above behaves like every other file read. It is
// called only after fstat has proved the file is regular; a regular file is
// never registered with the runtime's poller, so changing the flag underneath
// os.File is safe here in a way it would not be for a fifo or a socket.
//
// The flag is changed through SyscallConn rather than File.Fd, which would
// detach the file from the runtime poller as a side effect.
func clearNonblock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return serr
}
