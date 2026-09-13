package fsops

import (
	"io/fs"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"qnapfilemanager/internal/fsx"
)

// oPath is O_PATH. The value is the same on every Linux architecture, but the
// standard syscall package only spells it out for some of them (amd64, the
// architecture the NAS x86 build targets, is one of the ones it omits), so it is
// written here rather than made a per-GOARCH problem.
const oPath = 0x200000

// walkOPath opens the directory named by rel inside the jail and hands back a
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
// which is exactly the permission the kernel itself requires, and no more. The
// jail base is the same rule applied to the start of the walk: fsx.Jail is an
// O_PATH descriptor for it, so a search-only -jail directory no longer costs
// the worker every operation it was going to perform.
//
// The confinement is unchanged, and it is worth being explicit about why:
//
//   - the walk starts at the jail's own descriptor, which has no name, so there
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
func walkOPath(j fsx.Jail, rel string) (*os.File, error) {
	// The jail base itself, addressed by descriptor: it needs no name and
	// cannot be pointed anywhere else.
	dir, err := j.OpenBase()
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

// statAt is lstat(2) for a path that has already been resolved, taken through
// the O_PATH walk rather than through os.Root so that a search-only directory
// on the way costs nothing.
//
// The metadata itself comes from fstat on an O_PATH descriptor for the final
// component, opened O_NOFOLLOW so a symlink describes itself. Going through a
// descriptor rather than fstatat is deliberate: what comes back is the os
// package's own FileInfo, so os.SameFile still works on it — and os.SameFile is
// what OpenRead uses to prove the descriptor it opened is the file it checked.
//
// There is no follow variant. Following a link means checking where it lands,
// and resolve() is the only thing here that knows how; statPath re-resolves
// rather than asking for a stat that follows (see statFollowing).
func statAt(j fsx.Jail, rel string) (os.FileInfo, error) {
	if rel == "." || rel == "" {
		// The jail base itself: the one path with nothing above it to walk, and
		// nothing to look up either. The lookup that would answer it lives in the
		// base's parent, which is outside the jail, so the answer comes from an
		// fstat on the handle.
		return j.StatBase()
	}
	ref, err := openItemRef(j, rel)
	if err != nil {
		return nil, err
	}
	defer ref.close()
	return ref.fi, nil
}

// itemRef is one item HELD open: an O_PATH descriptor for the final component
// and the fstat taken on it.
//
// O_PATH is the whole reason this is affordable. It opens nothing — no read
// permission is charged, no fifo can block, no device is activated — and yet it
// is a reference to the INODE rather than to the name, which buys the two
// properties a check across a window needs: the object cannot be freed while it
// is held, so its (dev, ino) cannot be handed to a different file underneath the
// checker, and the fstat describes what the descriptor refers to rather than
// whatever now answers to the pathname.
type itemRef struct {
	f  *os.File
	fi os.FileInfo
}

// openItemRef opens one already-resolved path with O_PATH|O_NOFOLLOW|O_CLOEXEC
// and keeps it. The final component is kept literal, so a symlink describes
// itself and is never followed.
//
// The caller MUST close it. Holding it is not free — it is an open descriptor
// per held item — and the trash holds exactly one at a time (trashOne).
func openItemRef(j fsx.Jail, rel string) (*itemRef, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		// A trailing "." or ".." is not a name openat can address here, and
		// resolve() never produces one: it applies both itself, component by
		// component, with the kernel's own permission checks.
		return nil, &fs.PathError{Op: "statat", Path: rel, Err: syscall.EINVAL}
	}
	parent, err := walkOPath(j, dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := openatIn(parent, base, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "statat", Path: rel, Err: err}
	}
	f := os.NewFile(uintptr(fd), rel)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &itemRef{f: f, fi: fi}, nil
}

func (ref *itemRef) close() {
	if ref != nil && ref.f != nil {
		_ = ref.f.Close()
	}
}

// refFD is the descriptor behind a held item, for the callers that address it
// with AT_EMPTY_PATH instead of by name (the copy engine's chown and utimensat).
// Off Linux there is no descriptor and this is nil.
func refFD(ref *itemRef) *os.File {
	if ref == nil {
		return nil
	}
	return ref.f
}

// itemRefIn opens and holds one entry of an ALREADY HELD directory, with
// openat(O_PATH|O_NOFOLLOW|O_CLOEXEC) relative to that directory's descriptor.
//
// It is openItemRef without the pathname walk, and that is the whole point: the
// copy engine holds the directory it is working in, so the entry it pins is an
// entry of THAT object and not of whatever the directory's name means by now.
// The trash's openItemRef still walks, because it starts from a request path;
// this one starts from a descriptor.
func itemRefIn(d *dirRef, name string) (*itemRef, error) {
	fd, err := openatIn(d.f, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: relJoin(d.rel, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), relJoin(d.rel, name))
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &itemRef{f: f, fi: fi}, nil
}

// itemIdentityOf reads the mount identity of a HELD item descriptor, exactly as
// identityOf reads a directory's (walk_linux.go): the kernel's mount id first,
// because two bind mounts of one device share a st_dev and QTS builds its share
// layout out of bind mounts, and st_dev as the fallback.
//
// It is the same measurement the walk makes its crossing decisions from, which
// is the point: the move pre-flight's prediction and the engine's own behaviour
// have to be derived from one notion of "the same filesystem" or the dialog
// would describe a job the worker does not perform.
//
// An O_PATH descriptor answers both halves — statx(AT_EMPTY_PATH) and
// /proc/self/fdinfo work on one — so nothing here opens the file itself.
func itemIdentityOf(ref *itemRef) mountIdentity {
	var id mountIdentity
	if ref == nil {
		return id
	}
	if ref.fi != nil {
		id.dev, id.hasDev = devOf(ref.fi)
	}
	if ref.f != nil {
		if mnt, ok := mountIDOf(ref.f); ok {
			id.mnt, id.hasMnt = mnt, true
		}
	}
	return id
}

// readlinkAt is readlink(2) for an already-resolved path, through the same
// O_PATH walk and for the same reason: naming a link inside a search-only
// directory is not a listing.
func readlinkAt(j fsx.Jail, rel string) (string, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		// The jail base is a directory and readlink of a directory is EINVAL,
		// which is also the honest answer for a trailing "." or ".." — neither
		// is a name openat can address here, and neither ever reaches this far:
		// resolve() applies both itself.
		return "", &fs.PathError{Op: "readlinkat", Path: rel, Err: syscall.EINVAL}
	}
	parent, err := walkOPath(j, dir)
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
func openFinal(j fsx.Jail, rel string) (*os.File, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		// Never a regular file, and never something to hand to openat here.
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: syscall.EINVAL}
	}
	parent, err := walkOPath(j, dir)
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

// openDir opens the directory List enumerates, and is the other half of the
// O_PATH rule: read permission is asked for on the directory being listed, and
// on nothing above it.
//
// os.Root.OpenFile could not draw that line. Its walk opens every intermediate
// component O_RDONLY (rootOpenDir, $GOROOT/src/os/root_unix.go), so listing
// /outer/child needed read permission on outer as well as on child — and the
// kernel needs only search on outer. Mode 0111 on outer with a 0755 child
// inside is exactly that shape, an ordinary one for a share with a private
// index, and it came back EACCES for a listing the kernel would have given.
// Refusing what the kernel allows is the wrong half of INV-2, the same way it
// was for stat and for downloads. So the ancestors are walked with walkOPath
// and only the final component is opened for reading.
//
// O_DIRECTORY makes the kernel refuse anything that is not a directory, and it
// refuses it in may_open(2) — before the fifo machinery runs. That is what
// stops "list /path/to/a/fifo" from parking a worker goroutine inside open(2)
// with no writer on the other end, where no deadline in this process can reach
// it; sixty-four such requests would otherwise take every slot the worker has.
//
// O_NOFOLLOW is the rule openFinal keeps for the same reason: resolve() has
// already followed every link on this path, so a symlink standing here is one
// that appeared underneath us, and ELOOP says so rather than following it.
//
// osName is the directory's full OS path, and it now names the *os.File for
// error messages only: readDirInfos stats every entry through this descriptor
// rather than through a path built from f.Name(), so nothing here resolves a
// name against the process working directory any more. (The jail base names
// itself, which is the same string: r.OS("/") is the base.)
func openDir(j fsx.Jail, rel, osName string) (*os.File, error) {
	dir, base := splitFinal(rel)
	if base == "" || base == "." || base == ".." {
		if rel == "." || rel == "" {
			// The jail base itself: opened O_RDONLY relative to the handle,
			// with no intermediate component to over-ask for — and with the
			// base's own read bit still the kernel's to require, which is why
			// the handle being O_PATH does not make a private -jail directory
			// listable (INV-2).
			return j.OpenBaseDir()
		}
		// A trailing "." or ".." is not a name openat can address here.
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: syscall.EINVAL}
	}
	parent, err := walkOPath(j, dir)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := openatIn(parent, base,
		os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: err}
	}
	// A real O_RDONLY descriptor, so os.File.Readdirnames reads it with getdents
	// the way it reads any directory opened through os.Open.
	return os.NewFile(uintptr(fd), osName), nil
}

// readDirInfos reads one chunk of a directory and describes each name, and on
// Linux every part of that happens relative to the directory's own descriptor.
//
// That is the whole point of it. os.File.ReadDir hands back DirEntry values
// whose Info() lstats f.Name()+"/"+name (unixDirent.Info in
// $GOROOT/src/os/file_unix.go) unless the file came from an os.Root — and
// openDir deliberately does not return an os.Root file, because os.Root asks
// for read permission on every directory on the way. So Info() was a *path*
// lookup: rename the listed directory and drop a symlink to somewhere else in
// its place, and enumeration would carry on down the original descriptor while
// the sizes, modes and owners came from the replacement — from outside the jail
// if the link pointed there. Names from one directory, metadata from another.
//
// os.File.Readdir is not the answer either, whatever a given release does
// internally: readdirFileInfo goes through f.lstatat in Go 1.26 but through
// Lstat(f.name+"/"+name) in the releases before it, and this is not a property
// to inherit from whichever toolchain builds the QPKG.
//
// So the names come from getdents (Readdirnames, which stats nothing) and each
// one is then opened relative to the directory descriptor with O_PATH and
// O_NOFOLLOW and fstat'ed — the same two-step statAt already uses, for the same
// reason: O_PATH asks the kernel for nothing but the name, and O_NOFOLLOW makes
// a symlink describe itself. A directory swapped in above us after openDir
// cannot reach any of that, because none of it is ever named.
//
// A per-entry failure is reported per entry rather than for the listing: an
// entry unlinked between getdents and the open is an ordinary race in a live
// directory, and List drops it.
//
// showHidden is the one thing about the caller's filter that reaches down here,
// and only to skip work: a dot-name in a listing that will not show it is handed
// back with no metadata rather than costing an openat, an fstat and a close for
// an entry List drops on the name alone. The chunk still holds every name the
// directory read produced, in order, so it is the same chunk the non-Linux path
// returns and List counts it the same way — the dropped entries were never
// counted on either platform.
func readDirInfos(f *os.File, n int, showHidden bool) ([]dirEntryInfo, error) {
	names, readErr := f.Readdirnames(n)
	if len(names) == 0 {
		return nil, readErr
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	out := make([]dirEntryInfo, 0, len(names))
	// One Control for the whole chunk: the descriptor is held once rather than
	// re-acquired per entry.
	if cerr := rc.Control(func(pfd uintptr) {
		for _, name := range names {
			if !showHidden && strings.HasPrefix(name, ".") {
				out = append(out, dirEntryInfo{name: name})
				continue
			}
			fi, serr := lstatIn(int(pfd), name)
			out = append(out, dirEntryInfo{name: name, info: fi, err: serr})
		}
	}); cerr != nil {
		return nil, cerr
	}
	return out, readErr
}

// lstatIn is lstat(2) for one name inside an open directory, addressed by that
// directory's descriptor and never by a path.
func lstatIn(dirfd int, name string) (fs.FileInfo, error) {
	var (
		fd   int
		serr error
	)
	for {
		fd, serr = syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if serr != syscall.EINTR {
			break
		}
	}
	if serr != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: serr}
	}
	defer syscall.Close(fd)
	fi := &statFileInfo{name: name}
	if err := syscall.Fstat(fd, &fi.st); err != nil {
		return nil, &fs.PathError{Op: "fstat", Path: name, Err: err}
	}
	return fi, nil
}

// statFileInfo is an fs.FileInfo over a raw syscall.Stat_t.
//
// The os package has one of these and will not share it, and going through
// os.NewFile just to call Stat would allocate an *os.File with a finalizer for
// every entry of a fifty-thousand-entry listing. Sys returns the *syscall.Stat_t
// itself, which is what statDetail (uid, gid, nlink) and fsx.statDetail (those
// plus dev and ino) read, so an fsx.Entry built from this carries everything an
// entry built from os.Lstat carries.
//
// The one thing it is not is an argument for os.SameFile, which type-asserts
// both sides to the os package's own fileStat and answers false for anything
// else. Nothing needs it to be: OpenRead's identity check compares FileInfos
// from statAt, which are still the os package's own, and a listing entry is
// never compared to anything.
type statFileInfo struct {
	name string
	st   syscall.Stat_t
}

func (fi *statFileInfo) Name() string      { return fi.name }
func (fi *statFileInfo) Size() int64       { return fi.st.Size }
func (fi *statFileInfo) Mode() fs.FileMode { return statMode(fi.st.Mode) }
func (fi *statFileInfo) IsDir() bool       { return fi.Mode().IsDir() }
func (fi *statFileInfo) Sys() any          { return &fi.st }

func (fi *statFileInfo) ModTime() time.Time {
	sec, nsec := fi.st.Mtim.Unix()
	return time.Unix(sec, nsec)
}

// statMode turns st_mode into an fs.FileMode, exactly as
// fillFileStatFromSys does in $GOROOT/src/os/stat_linux.go. The permission bits
// are the low nine; the file type is the S_IFMT field, which is a value and not
// a bitmask, so it is switched on rather than tested; setuid, setgid and sticky
// are separate flags in fs.FileMode and are carried over one by one because
// fsx.ModeOctal and fsx.ModeString both report them.
func statMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & syscall.S_IFMT {
	case syscall.S_IFBLK:
		mode |= fs.ModeDevice
	case syscall.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case syscall.S_IFDIR:
		mode |= fs.ModeDir
	case syscall.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case syscall.S_IFLNK:
		mode |= fs.ModeSymlink
	case syscall.S_IFSOCK:
		mode |= fs.ModeSocket
	case syscall.S_IFREG:
		// A regular file is the absence of a type bit.
	}
	if m&syscall.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&syscall.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&syscall.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
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
func checkTraversable(j fsx.Jail, dir string) error {
	d, err := walkOPath(j, dir)
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
