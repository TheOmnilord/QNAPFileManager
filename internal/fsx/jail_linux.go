package fsx

import (
	"io/fs"
	"os"
	"syscall"
)

// oPath is O_PATH. The value is the same on every Linux architecture, but the
// standard syscall package only spells it out for some of them (amd64, the
// architecture the NAS x86 build targets, is one of the ones it omits), so it
// is written here rather than made a per-GOARCH problem. fsops has the same
// constant for the same reason; one line duplicated is cheaper than an exported
// name that would invite somebody to open a jail somewhere else.
const oPath = 0x200000

// Jail is the confinement handle every filesystem syscall in a worker is
// resolved against. On Linux it is one O_PATH descriptor for the jail base,
// opened by path exactly once — in the worker, after it has become the
// signed-in user, because that is the process whose credentials the kernel is
// meant to apply.
//
// O_PATH is the whole point. os.OpenRoot opens the base O_RDONLY, so a -jail
// directory the user may search but not read (mode 0111: a private index with
// readable files inside it, an ordinary shape for a QNAP share) failed at the
// handle — every operation in the worker, including the ones the kernel would
// have allowed, because the O_PATH walk that honours the kernel's own rule
// never got to run. O_PATH asks for a handle and nothing else: no read
// permission, no write permission, not even the right to enumerate the
// directory. Everything below the base is then an openat from this descriptor,
// which is where the kernel applies the permissions that are actually there
// (INV-2: the kernel decides, the app only predicts).
//
// The confinement is unchanged by that. The handle has no name — it is a
// descriptor, and nothing can hand it one — so every lookup below it is an
// openat relative to the previous descriptor, and an absolute symlink target
// re-enters from this same descriptor after fsops has checked that it lands
// inside the base.
type Jail interface {
	// OpenBase returns a descriptor for the base directory to walk from with
	// openat. The caller owns it and must close it; the handle itself outlives
	// every walk and is closed once, by Root.Close.
	//
	// It is O_PATH, so it costs the caller nothing but the search permission
	// the kernel would charge for the first component anyway.
	OpenBase() (*os.File, error)

	// StatBase describes the base directory itself. It is an fstat on the
	// handle, which resolves no name at all: the lookup that would answer
	// stat("/") lives in the base's parent, and the base's parent is outside
	// the jail. So Stat("/") succeeds whenever the handle exists, which is the
	// honest answer — the descriptor is proof the directory was reachable.
	StatBase() (os.FileInfo, error)

	// OpenBaseDir opens the base directory for reading, which is what listing
	// it means and the one operation that may fail on the base's own
	// permission bits: a user with search but no read permission may reach
	// through the directory and may not enumerate it. EACCES here is the
	// kernel saying so, and it is meant to survive (INV-2).
	OpenBaseDir() (*os.File, error)

	// Close releases the handle.
	Close() error
}

// oPathJail is the Linux Jail: one O_PATH descriptor, shared by every copy of
// the Root that owns it.
type oPathJail struct{ f *os.File }

// openJail opens the confinement handle. O_DIRECTORY is what refuses a -jail
// that names a file, and it refuses it here rather than at the first request;
// O_CLOEXEC keeps the descriptor out of anything the worker ever execs.
func openJail(dir string) (Jail, error) {
	fd, err := sysOpen(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: err}
	}
	return &oPathJail{f: os.NewFile(uintptr(fd), dir)}, nil
}

// sysOpen is open(2), retried over EINTR.
func sysOpen(dir string, flags int) (int, error) {
	for {
		fd, err := syscall.Open(dir, flags, 0)
		if err != syscall.EINTR {
			return fd, err
		}
	}
}

// OpenBase hands out a fresh O_PATH descriptor for the base by opening "."
// relative to the handle. That is a lookup starting at the base, so the kernel
// applies the search permission it applies to any other lookup there — the same
// check os.Root made for the same "." and the same check the walk's first
// component would have paid.
func (j *oPathJail) OpenBase() (*os.File, error) {
	return j.openAtBase(".", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
}

// OpenBaseDir opens the base for reading. O_DIRECTORY makes the kernel refuse
// anything that is not a directory in may_open, before the fifo machinery could
// park a worker inside open(2) — the base cannot be a fifo, since the handle is
// O_DIRECTORY, but the flag costs nothing and keeps the two openers alike.
func (j *oPathJail) OpenBaseDir() (*os.File, error) {
	return j.openAtBase(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
}

// StatBase is fstat on the handle.
func (j *oPathJail) StatBase() (os.FileInfo, error) { return j.f.Stat() }

// Close releases the descriptor.
func (j *oPathJail) Close() error { return j.f.Close() }

// openAtBase is openat(2) relative to the handle, retried over EINTR. The
// descriptor is reached through SyscallConn rather than File.Fd, which would
// detach the handle from the runtime poller as a side effect.
func (j *oPathJail) openAtBase(name string, flags int) (*os.File, error) {
	rc, err := j.f.SyscallConn()
	if err != nil {
		return nil, err
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
		return nil, cerr
	}
	if serr != nil {
		// Named for the lookup rather than for the base, which is the shape
		// os.Root produced for the same "." and keeps an operator's -jail
		// directory out of a message the front-end shows a user.
		return nil, &fs.PathError{Op: "openat", Path: name, Err: serr}
	}
	return os.NewFile(uintptr(fd), j.f.Name()), nil
}
