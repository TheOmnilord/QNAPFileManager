package fsops

import (
	"io/fs"
	"os"
	"syscall"

	"qnapfilemanager/internal/fsx"
)

// dirRef is a directory the walk is standing in: one open descriptor, and the
// handle every one of its entries is addressed through.
//
// It is the walk's whole containment story. The first directory is opened
// through the jail's O_PATH walk (openDir), and every directory below it is
// opened with openat relative to the descriptor above — O_DIRECTORY so a fifo
// cannot park the worker inside open(2), O_NOFOLLOW so a symlink is refused
// rather than followed. No pathname is ever rebuilt and handed back to the
// kernel, so nothing swapped in above the walk can redirect it.
//
// The descriptor is a real O_RDONLY one, unlike the O_PATH handles the rest of
// this package walks with, because enumerating a directory is exactly the
// operation that needs read permission on it. Search permission is still all
// that is asked of everything above it.
type dirRef struct {
	f   *os.File
	rel string
}

// openDirRef opens the directory named by rel (relative to the jail base) for
// enumeration.
func openDirRef(j fsx.Jail, rel string) (*dirRef, error) {
	f, err := openDir(j, rel, rel)
	if err != nil {
		return nil, err
	}
	return &dirRef{f: f, rel: rel}, nil
}

// child opens a subdirectory relative to this one's descriptor.
func (d *dirRef) child(name string) (*dirRef, error) {
	fd, err := openatIn(d.f, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: relJoin(d.rel, name), Err: err}
	}
	rel := relJoin(d.rel, name)
	return &dirRef{f: os.NewFile(uintptr(fd), rel), rel: rel}, nil
}

// names reads the next chunk of entry names with getdents and nothing else. It
// returns io.EOF once the directory is exhausted, exactly as Readdirnames does.
func (d *dirRef) names(n int) ([]string, error) {
	return d.f.Readdirnames(n)
}

// lstat describes one entry by name, relative to this directory's descriptor.
// The two-step openat(O_PATH|O_NOFOLLOW)+fstat is the same one readDirInfos
// makes, for the same reason: O_PATH asks the kernel for nothing but the name,
// and O_NOFOLLOW makes a symlink describe itself.
func (d *dirRef) lstat(name string) (os.FileInfo, error) {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fi   fs.FileInfo
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) { fi, serr = lstatIn(int(pfd), name) }); cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, serr
	}
	return fi, nil
}

// unlink removes one entry from this directory, with AT_REMOVEDIR for a
// directory (so a non-empty one is ENOTEMPTY rather than being recursed into by
// the kernel) and a plain unlink otherwise, which removes a symlink as the link
// it is.
func (d *dirRef) unlink(name string, isDir bool) error {
	flags := 0
	if isDir {
		flags = atRemoveDir
	}
	if err := unlinkatIn(d.f, name, flags); err != nil {
		return &fs.PathError{Op: "unlinkat", Path: relJoin(d.rel, name), Err: err}
	}
	return nil
}

// stat describes the directory itself, by fstat on the descriptor: no lookup,
// and the st_dev the walk compares a child against.
func (d *dirRef) stat() (os.FileInfo, error) { return d.f.Stat() }

func (d *dirRef) close() error { return d.f.Close() }

// openFileAt opens (or creates) a file inside an already-resolved directory,
// through that directory's own O_PATH descriptor.
//
// It exists for the trash sidecar: meta.json is written into an entry directory
// the worker has just created, and reading it back for the trash panel must not
// follow a symlink somebody else dropped in. O_NOFOLLOW is what refuses that,
// and O_CLOEXEC keeps the descriptor out of anything the worker execs.
func openFileAt(j fsx.Jail, parentRel, name string, flags int, perm os.FileMode) (*os.File, error) {
	parent, err := walkOPath(j, parentRel)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := openatPerm(parent, name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, syscallMode(perm))
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: relJoin(parentRel, name), Err: err}
	}
	return os.NewFile(uintptr(fd), relJoin(parentRel, name)), nil
}

// openatPerm is openat(2) with a creation mode, retried over EINTR. openatIn
// passes a mode of zero, which is right for every flagset that cannot create a
// file and wrong for O_CREAT — a sidecar created mode 0000 is one no later read
// can open.
//
// The descriptor is reached through SyscallConn rather than File.Fd, which
// would detach the directory from the runtime poller as a side effect.
func openatPerm(dir *os.File, name string, flags int, mode uint32) (int, error) {
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
			fd, serr = syscall.Openat(int(pfd), name, flags, mode)
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
