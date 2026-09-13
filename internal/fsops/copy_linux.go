package fsops

// The syscalls the copy engine makes that the rest of this package did not
// need: create a symlink, set an owner, set a timestamp, ask a filesystem how
// much room is left, and name the chain of directories above the destination.
//
// Every one of them is made relative to a descriptor the engine is already
// holding. That is the same rule the trash hardening fixed the mutation path
// on (PLAN.md §2.7): a pathname re-resolved after its directory was opened is a
// pathname somebody else can have re-pointed in between, and the engine is
// creating content — with an owner — at the far end of it.

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"qnapfilemanager/internal/fsx"
)

// copyReadFlags open a source file for reading.
//
// O_NONBLOCK is the fifo guard the download path already carries (openFinal):
// the walk classified this entry as a regular file with an lstat, and a name
// that became a fifo in between would otherwise park the worker inside open(2)
// where no deadline in this process can reach it. The fstat that follows is
// what refuses it. O_NOFOLLOW and O_CLOEXEC are added by dirRef.openFile.
const copyReadFlags = os.O_RDONLY | syscall.O_NONBLOCK

// inodeKey identifies one object: the device it is on and its inode number.
//
// It is what the "is the destination inside the source" test is made of
// (contract §1.7). A pathname comparison cannot answer that question on its
// own — a symlink, a bind mount and a rename all give one directory two
// spellings — and the engine is about to create a tree at the far end of the
// answer.
type inodeKey struct {
	dev uint64
	ino uint64
}

// inodeIdentity says a FileInfo here carries an identity worth comparing, which
// on Linux it does. It is what lets the verified delete treat a MISSING
// identity as a refusal rather than as a platform without one (the same
// distinction kernelMountIDs draws for the walk's crossing rule).
const inodeIdentity = true

// inodeOf reads the key out of a FileInfo the caller already obtained.
func inodeOf(fi os.FileInfo) (inodeKey, bool) {
	if fi == nil {
		return inodeKey{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return inodeKey{}, false
	}
	// Converted explicitly, like every other stat field in this package: the
	// widths are the architecture's and both amd64 and arm64 are targets.
	return inodeKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

// openPathRef opens a directory as a DIRFD ONLY: an O_PATH handle that can be
// the first argument of an openat, a mkdirat, a renameat or an fchownat, and
// cannot be enumerated.
//
// It is what the destination is held on, and the reason is INV-2 in its usual
// direction: enumerating a directory needs read permission on it and creating
// an entry in it does not. openDirRef asks for O_RDONLY, so copying into a
// mode-0333 drop directory — an ordinary shape for an upload target — would
// have been refused by this app for a kernel that allows it.
//
// names() must never be called on the result; getdents on an O_PATH descriptor
// is EBADF. Nothing here calls it: the destination is only ever written to, and
// the source directories the walk enumerates are the walk's own O_RDONLY refs.
func openPathRef(j fsx.Jail, rel string) (*dirRef, error) {
	f, err := walkOPath(j, rel)
	if err != nil {
		return nil, err
	}
	return &dirRef{f: f, rel: rel}, nil
}

// childPath opens a subdirectory of this one as another dirfd-only handle, with
// openat relative to the held descriptor. It is childPath rather than child for
// the reason openPathRef exists: the destination tree is created, never read.
func (d *dirRef) childPath(name string) (*dirRef, error) {
	fd, err := openatIn(d.f, name, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: relJoin(d.rel, name), Err: err}
	}
	rel := relJoin(d.rel, name)
	return &dirRef{f: os.NewFile(uintptr(fd), rel), rel: rel}, nil
}

// symlinkAt recreates a symlink inside this directory, byte for byte: the
// target text is whatever readlink handed back and is never resolved, cleaned
// or made absolute on the way.
func symlinkAt(d *dirRef, name, target string) error {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = symlinkatIn(target, int(pfd), name)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "symlinkat", Path: relJoin(d.rel, name), Err: serr}
	}
	return nil
}

// symlinkatIn is symlinkat(2), which the syscall package does not export on any
// Linux architecture. The unsafe shape is the one the vet rules sanction for a
// syscall call (a Pointer converted to uintptr in the argument list), and both
// names are kept alive across it rather than trusted to escape analysis.
func symlinkatIn(target string, dirfd int, name string) error {
	tp, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	np, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_SYMLINKAT,
		uintptr(unsafe.Pointer(tp)), uintptr(dirfd), uintptr(unsafe.Pointer(np)))
	runtime.KeepAlive(tp)
	runtime.KeepAlive(np)
	if errno != 0 {
		return errno
	}
	return nil
}

// readlinkRef reads a symlink's target from a descriptor for the LINK ITSELF,
// with readlinkat and an empty pathname — the form the kernel documents for an
// O_PATH|O_NOFOLLOW handle (Linux 2.6.39+).
//
// It is how the copy takes a link's content and its metadata from one and the
// same object: with the target read by name, a link replaced between the fstat
// and the readlink would have had its predecessor's owner and times reproduced
// onto a copy of its successor's target. dir and name are carried for the error
// message and for the platforms with no such call.
func readlinkRef(ref *itemRef, dir *dirRef, name string) (string, error) {
	rc, err := ref.f.SyscallConn()
	if err != nil {
		return "", err
	}
	for size := 256; size <= 1<<16; size *= 2 {
		buf := make([]byte, size)
		var (
			n    int
			serr error
		)
		if cerr := rc.Control(func(pfd uintptr) {
			for {
				n, serr = readlinkatIn(int(pfd), "", buf)
				if serr != syscall.EINTR {
					return
				}
			}
		}); cerr != nil {
			return "", cerr
		}
		if serr != nil {
			return "", &fs.PathError{Op: "readlinkat", Path: relJoin(dir.rel, name), Err: serr}
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", &fs.PathError{Op: "readlinkat", Path: relJoin(dir.rel, name), Err: syscall.ENAMETOOLONG}
}

// readlinkIn reads a symlink's target through this directory's held descriptor,
// so the link that is read is the one the walk enumerated.
func readlinkIn(d *dirRef, name string) (string, error) {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return "", err
	}
	// PATH_MAX is 4096; a target longer than 64 KiB is a filesystem
	// misbehaving, not a buffer to keep doubling (the same bound readlinkAt
	// uses).
	for size := 256; size <= 1<<16; size *= 2 {
		buf := make([]byte, size)
		var (
			n    int
			serr error
		)
		if cerr := rc.Control(func(pfd uintptr) {
			for {
				n, serr = readlinkatIn(int(pfd), name, buf)
				if serr != syscall.EINTR {
					return
				}
			}
		}); cerr != nil {
			return "", cerr
		}
		if serr != nil {
			return "", &fs.PathError{Op: "readlinkat", Path: relJoin(d.rel, name), Err: serr}
		}
		if n < size {
			return string(buf[:n]), nil
		}
		// The target filled the buffer exactly, so it may have been truncated.
	}
	return "", &fs.PathError{Op: "readlinkat", Path: relJoin(d.rel, name), Err: syscall.ENAMETOOLONG}
}

// chownEntry sets the owner of one entry the copy just created (contract §1.4).
//
// When f is non-nil the fchown is made on THAT descriptor — the regular file
// the bytes were written through, or the directory the children are being
// created in — which is the strongest form available: it names an inode, not a
// name, so nothing swapped into the directory afterwards can be chowned by
// mistake. A symlink has no such descriptor (opening one opens its target), so
// it is fchownat(AT_SYMLINK_NOFOLLOW) relative to the held parent instead,
// which never follows.
//
// There is no chmod here and there never will be on this path: an fchmod on a
// QNAP ACL share can widen the POSIX ACL mask or, on a hero dataset with
// aclmode=discard, drop inherited ACLs, and it would clear the parent's
// inherited setgid bit (ownership review findings B/D). The creation mode plus
// the umask is the whole mode story (§1.5).
//
// -1 for either id leaves that half alone, exactly as chown(2) says, which is
// how "GID -1 inherits the destination's group" is expressed.
func chownEntry(dir *dirRef, name string, f *os.File, uid, gid int) error {
	if uid == -1 && gid == -1 {
		return nil
	}
	if f != nil {
		// fchownat(fd, "", AT_EMPTY_PATH) and NOT fchown(fd). The descriptors
		// this engine holds for a directory and for a pinned symlink are O_PATH
		// handles, and fchown on an O_PATH descriptor is EBADF — which would
		// have left every directory of an administrator's copy root-owned and
		// made every root fallback move keep its source on an owner_unset
		// warning. fchownat with an empty pathname is the form the kernel
		// documents for exactly this, it accepts an ordinary descriptor just as
		// happily, and it still names an inode rather than a name.
		rc, err := f.SyscallConn()
		if err != nil {
			return err
		}
		var serr error
		if cerr := rc.Control(func(pfd uintptr) {
			for {
				serr = syscall.Fchownat(int(pfd), "", uid, gid, atEmptyPath)
				if serr != syscall.EINTR {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return serr
	}
	rc, err := dir.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = syscall.Fchownat(int(pfd), name, uid, gid, atSymlinkNoFollow)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "fchownat", Path: relJoin(dir.rel, name), Err: serr}
	}
	return nil
}

// utimesEntry preserves an entry's modification (and access) time, to the
// nanosecond the source reported.
//
// f non-nil is futimens on the held descriptor — utimensat(2) with a NULL
// pathname, which is what futimens is — and it is used for a regular file the
// engine still has open. Everything else is utimensat relative to the parent
// with AT_SYMLINK_NOFOLLOW, so a symlink's own times are set rather than its
// target's, and a directory's are set after its children have been written
// (writing a child is what moved them in the first place).
//
// link is not consulted here: the no-follow flag is already right for every
// kind. It exists for the platforms with no Lchtimes at all (copy_other.go).
func utimesEntry(dir *dirRef, name string, f *os.File, link bool, atime, mtime time.Time) error {
	_ = link
	times := [2]syscall.Timespec{timespecOf(atime), timespecOf(mtime)}
	if f != nil {
		// utimensat with a NULL pathname, which is what futimens is. The kernel
		// takes this branch from f_path and never looks at the file's access
		// mode, so it works on the O_PATH handles this engine holds for a
		// directory and for a pinned symlink as well as on the write descriptor
		// of a file — which is what keeps the timestamp of something we just
		// created from being applied to whatever now answers to its name.
		rc, err := f.SyscallConn()
		if err != nil {
			return err
		}
		var serr error
		if cerr := rc.Control(func(pfd uintptr) { serr = utimensAt(int(pfd), "", times, 0) }); cerr != nil {
			return cerr
		}
		if serr == nil {
			return nil
		}
		if !errors.Is(serr, syscall.EBADF) && !errors.Is(serr, syscall.EINVAL) {
			return &fs.PathError{Op: "futimens", Path: relJoin(dir.rel, name), Err: serr}
		}
		// A kernel that will not take an empty pathname here. Fall through to
		// the by-name form, whose residual is named in setTimes: losing that
		// race costs a wrong timestamp on an object somebody else already
		// controls, never a change of ownership.
	}
	rc, err := dir.f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) { serr = utimensAt(int(pfd), name, times, atSymlinkNoFollow) }); cerr != nil {
		return cerr
	}
	if serr != nil {
		return &fs.PathError{Op: "utimensat", Path: relJoin(dir.rel, name), Err: serr}
	}
	return nil
}

// accessTimeOf reads st_atim out of a FileInfo the caller already obtained.
//
// os.FileInfo publishes the modification time and nothing else, so this is the
// only way to reproduce the access time as well (§1.5) without a second stat.
// A FileInfo from somewhere other than this package's own lstat wrappers has no
// Stat_t behind it and answers false, at which point the caller uses the
// modification time for both — which is what `cp -p` does for a filesystem
// mounted noatime anyway.
func accessTimeOf(fi os.FileInfo) (time.Time, bool) {
	if fi == nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return time.Time{}, false
	}
	sec, nsec := st.Atim.Unix()
	return time.Unix(sec, nsec), true
}

// changeTimeOf reads st_ctim — the inode CHANGE time — out of a FileInfo the
// caller already obtained.
//
// It is the one timestamp an unprivileged writer cannot forge. utimensat sets
// atime and mtime and can restore them to anything; it moves ctime forward as a
// side effect, and there is no interface at all for setting ctime backwards.
// Every write, every chmod, every chown and every rename of an entry moves it.
// That is exactly the property the move's verified delete needs (finding 4 of
// the second review): a file rewritten in place with the same length and its
// mtime put back matched identity, size and mtime, and was deleted as though
// nothing had happened.
func changeTimeOf(fi os.FileInfo) (time.Time, bool) {
	if fi == nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return time.Time{}, false
	}
	sec, nsec := st.Ctim.Unix()
	return time.Unix(sec, nsec), true
}

// enumerable opens a READABLE descriptor for a directory this process is
// holding as a dirfd-only O_PATH handle, by opening "." relative to it.
//
// The destination is held O_PATH on purpose — creating an entry needs search
// permission and not read — but the provenance check that has to run before a
// root worker chowns a freshly created directory needs to know it is EMPTY, and
// emptiness needs getdents. Opening "." relative to the held descriptor asks for
// that one privilege on that one object without ever naming it again: whatever
// the directory's pathname means by now, this is the same inode.
func enumerable(d *dirRef) (*os.File, error) {
	fd, err := openatIn(d.f, ".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: d.rel, Err: err}
	}
	return os.NewFile(uintptr(fd), d.rel), nil
}

// timespecOf converts a Go time to the struct the kernel takes, without going
// through UnixNano — which overflows an int64 outside 1678..2262 and would turn
// a file dated 1200 into one dated somewhere else entirely.
func timespecOf(t time.Time) syscall.Timespec {
	return syscall.Timespec{Sec: t.Unix(), Nsec: int64(t.Nanosecond())}
}

// utimensAt is utimensat(2), which the syscall package does not export. An
// empty name means a NULL pathname, which makes the call futimens on dirfd
// itself. The unsafe shape is the sanctioned one and both arguments are kept
// alive across the call.
func utimensAt(dirfd int, name string, times [2]syscall.Timespec, flags int) error {
	var (
		np   *byte
		path unsafe.Pointer
	)
	if name != "" {
		var err error
		if np, err = syscall.BytePtrFromString(name); err != nil {
			return err
		}
		path = unsafe.Pointer(np)
	}
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_UTIMENSAT,
			uintptr(dirfd), uintptr(path), uintptr(unsafe.Pointer(&times[0])), uintptr(flags), 0, 0)
		runtime.KeepAlive(np)
		runtime.KeepAlive(&times)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}

// fsStatfs asks the filesystem behind a held descriptor how many bytes an
// unprivileged writer may still use (contract §1.9).
//
// f_bavail rather than f_bfree on purpose: f_bfree counts the reserved blocks
// only root may touch, and the worker is usually not root — promising a user
// the reserve would be a refusal deferred to ENOSPC half way through a 40 GB
// copy. fstatfs on an O_PATH descriptor is allowed (Linux 3.6+), which is what
// lets the destination stay a dirfd-only handle.
func fsStatfs(d *dirRef) (avail uint64, ok bool, err error) {
	rc, cerr := d.f.SyscallConn()
	if cerr != nil {
		return 0, false, cerr
	}
	var (
		st   syscall.Statfs_t
		serr error
	)
	if ctrlErr := rc.Control(func(pfd uintptr) {
		for {
			serr = syscall.Fstatfs(int(pfd), &st)
			if serr != syscall.EINTR {
				return
			}
		}
	}); ctrlErr != nil {
		return 0, false, ctrlErr
	}
	if serr != nil {
		return 0, false, serr
	}
	if st.Bsize <= 0 {
		// A filesystem that will not say how big a block is cannot be asked how
		// much room it has; "unknown" is the honest answer and the check is
		// skipped rather than guessed at.
		return 0, false, nil
	}
	bsize := uint64(st.Bsize)
	if st.Bavail != 0 && bsize > 0 && st.Bavail > ^uint64(0)/bsize {
		// More room than a uint64 of bytes can express. There is no refusal to
		// make here, so say so rather than wrapping into "almost full".
		return ^uint64(0), true, nil
	}
	return st.Bavail * bsize, true, nil
}

// destAncestry names the destination directory and every directory above it,
// as (dev, ino) pairs read from descriptors (contract §1.7).
//
// It is the identity half of "you cannot copy a folder into itself". The route
// refuses the lexical case on both spellings and the engine repeats that, but a
// lexical test cannot see a symlink, a bind mount or a rename that happened
// between the request and the job — and getting this wrong means an unbounded
// recursion that fills the volume. So the chain is walked with
// openat(fd, "..") from the destination's own held descriptor: no pathname is
// resolved, and nothing that is swapped in afterwards changes an answer already
// taken from an inode.
//
// The climb stops at the filesystem root (".." of the root is the root itself)
// or at the jail base, whichever comes first: under -jail nothing above the
// base is this job's business, and maxWalkDepth bounds it in any case. A
// failure part way up is not an error — what has been collected is still true,
// and the lexical test is still there — so the caller gets the prefix.
func destAncestry(j fsx.Jail, d *dirRef) []inodeKey {
	fi, err := d.stat()
	if err != nil {
		return nil
	}
	k, ok := inodeOf(fi)
	if !ok {
		return nil
	}
	out := []inodeKey{k}

	var (
		baseKey  inodeKey
		haveBase bool
	)
	if bfi, berr := j.StatBase(); berr == nil {
		baseKey, haveBase = inodeOf(bfi)
	}
	if haveBase && baseKey == k {
		return out
	}

	cur := d.f
	defer func() {
		if cur != d.f {
			_ = cur.Close()
		}
	}()
	for i := 0; i < maxWalkDepth; i++ {
		fd, err := openatIn(cur, "..", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC)
		if err != nil {
			return out
		}
		up := os.NewFile(uintptr(fd), "..")
		if cur != d.f {
			_ = cur.Close()
		}
		cur = up
		ufi, err := cur.Stat()
		if err != nil {
			return out
		}
		uk, ok := inodeOf(ufi)
		if !ok {
			return out
		}
		if uk == out[len(out)-1] {
			// ".." of a filesystem root is the root itself: the top.
			return out
		}
		out = append(out, uk)
		if haveBase && uk == baseKey {
			return out
		}
	}
	return out
}

// isCrossDevice reports that the kernel refused a rename because the two ends
// are on different filesystems — the EXDEV every move between two QuTS hero
// shares gets, since each share is its own dataset.
func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, fsx.ErrCrossDevice)
}

// isQuota reports that a write failed because the user's quota is exhausted
// rather than because the filesystem is full. Both map to no_space, and the
// message is what tells the two apart for somebody who has to act on it.
func isQuota(err error) bool { return errors.Is(err, syscall.EDQUOT) }

// fsyncDir flushes a directory's own entries to stable storage, through a
// readable descriptor opened from the held O_PATH handle — fsync(2) on an
// O_PATH fd is EBADF, and the name is never resolved again.
//
// A directory fsync is what makes a created name durable: the file's own data
// is flushed when it is written (copyFile), but the entry that points at it
// lives in the directory and is not.
func fsyncDir(d *dirRef) error {
	f, err := enumerable(d)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
