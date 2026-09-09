package fsops

import (
	"io/fs"
	"os"
	"strings"
	"syscall"
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

// openFinal opens the last component of an already-resolved path for reading,
// and is the one place the no-follow rule is actually enforced by the kernel.
//
// os.Root.OpenFile cannot do it. It puts O_NOFOLLOW on every openat it makes,
// but when that comes back ELOOP it checks whether the link stays inside the
// root and, if it does, follows it — the caller's own O_NOFOLLOW gets no say.
// So the parent directory is opened through the root, which is what keeps the
// walk confined, and the final component is opened relative to that descriptor
// with the flag the kernel will honour. A symlink there is then ELOOP, which
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
	parent, err := openDirPath(rt, dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	rc, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fd   int
		serr error
	)
	// The descriptor is reached through SyscallConn rather than File.Fd, which
	// would detach the directory from the runtime poller as a side effect.
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			fd, serr = syscall.Openat(int(pfd), base,
				os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: serr}
	}
	return os.NewFile(uintptr(fd), rel), nil
}

// openDirPath opens a directory through the root as a *handle* rather than as
// something to read: O_PATH asks the kernel to resolve the name and hand back a
// descriptor that can be the dirfd of a later openat, and to check nothing else.
//
// That distinction is the whole point. O_RDONLY|O_DIRECTORY here asked for read
// permission on the parent directory, which is not the permission a download
// needs: a user with search but not read on /some/private/dir may open a child
// they have been given by name, and the kernel says so. Demanding the directory
// listing right first turned every such download into EACCES — the app refusing
// what the kernel would have allowed, which is the wrong half of INV-2.
//
// The confinement is unchanged: this still goes through os.Root, so every
// component is resolved against the jail's descriptor, and O_DIRECTORY still
// refuses anything that is not a directory before any of it can block.
func openDirPath(rt *os.Root, dir string) (*os.File, error) {
	return rt.OpenFile(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
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
// permission check on the thing being opened. Both descriptors are O_PATH, so
// nothing here needs read permission on anything.
func checkTraversable(rt *os.Root, dir string) error {
	d, err := openDirPath(rt, dir)
	if err != nil {
		return err
	}
	defer d.Close()
	rc, err := d.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		var fd int
		for {
			fd, serr = syscall.Openat(int(pfd), ".",
				oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
			if serr != syscall.EINTR {
				break
			}
		}
		if serr == nil {
			syscall.Close(fd)
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "openat", Path: dir, Err: serr}
	}
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
