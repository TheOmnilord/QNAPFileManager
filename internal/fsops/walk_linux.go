package fsops

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

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
//
// A DIRECTORY's birth time comes back with it (Astra r3 #9). This is the stat a
// walk classifies an entry by, and a directory is the one kind of entry whose
// name the walk looks up a second time — to descend into it, to change it in
// post-order, or to reach it through the fallback for a directory that could not
// be opened. Device and inode alone cannot tell "the same directory" from "a
// directory created at that name after the first one was removed", because the
// allocator is free to hand the number straight back; the birth time can, and
// reading it here is the only place it describes the object the walk classified
// rather than whatever answers to the name later.
func (d *dirRef) lstat(name string) (os.FileInfo, error) {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		fi   fs.FileInfo
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) { fi, serr = lstatIn(int(pfd), name, true) }); cerr != nil {
		return nil, cerr
	}
	if serr != nil {
		return nil, serr
	}
	return fi, nil
}

// lstatHeld is lstat for the WALK's own enumeration: the same reading, plus the
// O_PATH descriptor it was taken through where letting go of it would leave the
// Unopened fallback with nothing but a device and an inode number to prove an
// object by (Astra r4 #7).
//
// held is nil for everything except a directory on a filesystem that records no
// birth time, and the caller closes it when it is not.
func (d *dirRef) lstatHeld(name string) (os.FileInfo, *os.File, error) {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var (
		fi   fs.FileInfo
		held *os.File
		serr error
	)
	if cerr := rc.Control(func(pfd uintptr) { fi, held, serr = lstatUnprovenHeld(int(pfd), name) }); cerr != nil {
		return nil, nil, cerr
	}
	if serr != nil {
		return nil, nil, serr
	}
	return fi, held, nil
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
// and the ownership and mode every trash check is made against (F1, F2).
func (d *dirRef) stat() (os.FileInfo, error) { return d.f.Stat() }

func (d *dirRef) close() error { return d.f.Close() }

// syncDir gets this directory's own entries onto the disk — the names, not the
// files they point at.
//
// fsync on a directory descriptor is what makes a rename durable. A file's own
// fsync only promises its contents; the link that publishes it under a name
// lives in the directory, and a filesystem is free to write the two in either
// order. The trash's sidecar rewrite depends on the rename being on the disk
// before the removals that follow it (rewriteTrashMeta), so it asks for it.
func syncDir(d *dirRef) error { return d.f.Sync() }

// mkdir creates a subdirectory of this one, with mkdirat relative to the held
// descriptor (F2). Nothing is named: whatever the pathname of this directory
// meant when it was opened, the entry lands inside the object the descriptor
// refers to and nowhere else.
func (d *dirRef) mkdir(name string, mode os.FileMode) error {
	if err := mkdiratIn(d.f, name, syscallMode(mode)); err != nil {
		return &fs.PathError{Op: "mkdirat", Path: relJoin(d.rel, name), Err: err}
	}
	return nil
}

// openFile opens (or creates) a file inside this directory, with openat relative
// to the held descriptor (F2). O_NOFOLLOW refuses a symlink somebody dropped in
// rather than following it, and O_CLOEXEC keeps the descriptor out of anything
// the worker execs.
func (d *dirRef) openFile(name string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := openatPerm(d.f, name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, syscallMode(perm))
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: relJoin(d.rel, name), Err: err}
	}
	return os.NewFile(uintptr(fd), relJoin(d.rel, name)), nil
}

// readSidecarFlags are the flags a trash sidecar is opened with (F8).
// O_NONBLOCK is what keeps a planted fifo from taking a worker hostage: opening
// one for reading with no writer blocks inside open(2) itself, where no deadline
// in this process can reach it. The fstat that follows is what refuses it.
const readSidecarFlags = os.O_RDONLY | syscall.O_NONBLOCK

// renameInto renames one entry from an already-resolved parent into THIS
// directory's held descriptor, with RENAME_NOREPLACE (F2).
//
// The destination half is the descriptor rather than a pathname, which is the
// whole point: the trash is a 1777 directory shared with every other uid on the
// volume, and a pathname re-resolved at rename time is a pathname somebody else
// can have swapped in the meantime.
func (d *dirRef) renameInto(fromJail fsx.Jail, fromParentRel, fromName, toName string) error {
	return d.renameFrom(fromJail, fromParentRel, fromName, toName, true)
}

// renameFrom is renameInto with the no-overwrite guarantee as a parameter,
// because the move half of the copy engine needs both answers (M2-B contract
// §1.1 and §1.3).
//
// noReplace is the trash's rule and the default: RENAME_NOREPLACE, so the
// kernel itself refuses an existing destination in the one syscall and there is
// no check-then-act window to lose. It is dropped for exactly one case — the
// `overwrite` conflict policy moving a NON-DIRECTORY onto an existing
// non-directory of the same kind — where replacing is what the user asked for
// and renameat's replacement is atomic: a reader sees the old file or the new
// one and never a half file.
//
// A directory is never renamed over anything: a directory meeting an existing
// directory is a merge (the copy path), and every other pairing is a type
// mismatch the engine refuses before it gets here.
// renameFromDir is renameFrom between two descriptors this process is ALREADY
// holding, with no pathname walk at either end.
//
// It is what the copy engine's move uses. renameFrom has to re-walk the source
// parent's pathname, and the move holds that directory open for the whole root
// anyway — so re-resolving it would reopen a window the engine had already
// closed, on the one operation that moves a whole tree in a single syscall.
func (d *dirRef) renameFromDir(fromDir *dirRef, fromName, toName string, noReplace bool) error {
	var err error
	if noReplace {
		err = renameNoReplaceIn(fromDir.f, fromName, d.f, toName)
	} else {
		err = renameatIn(fromDir.f, fromName, d.f, toName, false)
	}
	if err != nil {
		return &fs.PathError{Op: "renameat", Path: relJoin(fromDir.rel, fromName), Err: err}
	}
	return nil
}

func (d *dirRef) renameFrom(fromJail fsx.Jail, fromParentRel, fromName, toName string, noReplace bool) error {
	fromDir, err := walkOPath(fromJail, fromParentRel)
	if err != nil {
		return err
	}
	defer fromDir.Close()
	var rerr error
	if noReplace {
		rerr = renameNoReplaceIn(fromDir, fromName, d.f, toName)
	} else {
		rerr = renameatIn(fromDir, fromName, d.f, toName, false)
	}
	if rerr != nil {
		return &fs.PathError{Op: "renameat", Path: relJoin(fromParentRel, fromName), Err: rerr}
	}
	return nil
}

// renameOver renames one entry of this directory over another name in the SAME
// directory, replacing whatever is there — both sides of the renameat are this
// one held descriptor (F2).
//
// It is the opposite of every other rename here, and the one place replacing is
// what is wanted: it publishes a rewritten trash sidecar (trash.go), where the
// name being replaced is one this worker wrote seconds earlier inside its own
// 0700 entry directory, and where a reader must see the old sidecar or the new
// one and never a half-written file.
//
// renameatIn holds both descriptors at once, and here they are the same one.
// That is safe rather than a deadlock: SyscallConn's Control takes a reference
// on the descriptor, not a lock, so the inner Control simply counts one more.
func (d *dirRef) renameOver(fromName, toName string) error {
	if err := renameatIn(d.f, fromName, d.f, toName, false); err != nil {
		return &fs.PathError{Op: "renameat", Path: relJoin(d.rel, fromName), Err: err}
	}
	return nil
}

// renameOut renames one entry OUT of this directory's held descriptor to an
// already-resolved destination, with RENAME_NOREPLACE (F2). It is the restore
// half of renameInto.
func (d *dirRef) renameOut(fromName string, toJail fsx.Jail, toParentRel, toName string) error {
	toDir, err := walkOPath(toJail, toParentRel)
	if err != nil {
		return err
	}
	defer toDir.Close()
	if err := renameNoReplaceIn(d.f, fromName, toDir, toName); err != nil {
		return &fs.PathError{Op: "renameat", Path: relJoin(toParentRel, toName), Err: err}
	}
	return nil
}

// renameNoReplaceIn is renameat2(RENAME_NOREPLACE) between two held
// descriptors, with the same fallback renameAt takes when the syscall or the
// flag is unavailable (PLAN.md §2.4): an fstatat pre-check against the
// destination descriptor, never a fresh walk of its pathname.
func renameNoReplaceIn(fromDir *os.File, fromName string, toDir *os.File, toName string) error {
	err := renameatIn(fromDir, fromName, toDir, toName, true)
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		exists, serr := destExistsAt(toDir, toName)
		if serr != nil {
			return serr
		}
		if exists {
			return syscall.EEXIST
		}
		err = renameatIn(fromDir, fromName, toDir, toName, false)
	}
	return err
}

// kernelMountIDs says the kernel here can name the mount behind a descriptor,
// which on Linux it can: statx(STATX_MNT_ID) since 5.8, and /proc/self/fdinfo
// since 3.15 before that. It is what lets a mutating walk fail closed when no
// ID comes back (B4, unidentifiedMount) instead of trusting a st_dev comparison
// a bind mount defeats.
const kernelMountIDs = true

// identityOf reads the mount identity of a held directory descriptor (F4).
//
// The mount ID comes first because it is the only answer that separates two
// mounts of one device — a bind mount, which is how QTS builds its share layout,
// and which a st_dev comparison reports as "same filesystem, carry on". statx
// with STATX_MNT_ID (Linux 5.8) answers it in one syscall; /proc/self/fdinfo is
// the fallback for an older kernel or an architecture whose statx number is not
// compiled in here, and st_dev is the fallback for a system with neither.
func identityOf(d *dirRef) mountIdentity {
	var id mountIdentity
	if fi, err := d.stat(); err == nil {
		id.dev, id.hasDev = devOf(fi)
	}
	if mnt, ok := mountIDOf(d.f); ok {
		id.mnt, id.hasMnt = mnt, true
	}
	return id
}

// statxMntID is STATX_MNT_ID, the request mask bit (and the reply mask bit) for
// the mount ID. atEmptyPath is AT_EMPTY_PATH, which makes statx describe the
// descriptor itself rather than a name below it, and atSymlinkNoFollow is
// AT_SYMLINK_NOFOLLOW. All three are stable across Linux architectures, and
// every one of them is an AT_ flag: an O_ flag passed here would be an unknown
// bit and the kernel would answer EINVAL.
const (
	statxMntID        = 0x1000
	atEmptyPath       = 0x1000
	atSymlinkNoFollow = 0x100
)

// statxNoMntID records that statx cannot answer here — an old kernel (ENOSYS,
// EINVAL) or an architecture whose syscall number is not compiled in. A walk of
// a million directories must not make a million syscalls the kernel has already
// refused, and the worker serves several jobs at once, so the flag is atomic:
// the only transition is false to true and both values are correct to act on,
// but "correct to act on" is not the same as "safe to race on" under -race.
var statxNoMntID atomic.Bool

// mountIDOf returns the kernel's mount ID for an open descriptor.
func mountIDOf(f *os.File) (uint64, bool) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		id uint64
		ok bool
	)
	if cerr := rc.Control(func(pfd uintptr) {
		if sysStatx != 0 && !statxNoMntID.Load() {
			mnt, serr := statxMountID(int(pfd))
			if serr == nil {
				id, ok = mnt, true
				return
			}
			if errors.Is(serr, syscall.ENOSYS) || errors.Is(serr, syscall.EINVAL) {
				statxNoMntID.Store(true)
			}
		}
		id, ok = fdinfoMountID(int(pfd))
	}); cerr != nil {
		return 0, false
	}
	return id, ok
}

// statxTimestamp is struct statx_timestamp.
type statxTimestamp struct {
	Sec  int64
	Nsec uint32
	_    int32
}

// statxData is struct statx (256 bytes). Every field is spelled out rather than
// skipped with padding because the kernel fills the whole structure and the
// offset of stx_mnt_id is what this file is for; a short or mis-aligned struct
// would read a neighbouring field and call it a mount ID.
type statxData struct {
	Mask           uint32
	Blksize        uint32
	Attributes     uint64
	Nlink          uint32
	UID            uint32
	GID            uint32
	Mode           uint16
	_              uint16
	Ino            uint64
	Size           uint64
	Blocks         uint64
	AttributesMask uint64
	Atime          statxTimestamp
	Btime          statxTimestamp
	Ctime          statxTimestamp
	Mtime          statxTimestamp
	RdevMajor      uint32
	RdevMinor      uint32
	DevMajor       uint32
	DevMinor       uint32
	MntID          uint64
	DioMemAlign    uint32
	DioOffsetAlign uint32
	_              [12]uint64
}

// struct statx is 256 bytes and stx_mnt_id sits at offset 144 inside it. If the
// Go struct above ever stops being exactly that size — a field dropped, a
// padding word forgotten, an architecture with different alignment — this line
// fails to compile rather than letting mountIDOf read a neighbouring field and
// call it a mount ID.
var (
	_ [1]struct{} = [unsafe.Sizeof(statxData{}) - 255]struct{}{}
	_ [1]struct{} = [unsafe.Offsetof(statxData{}.MntID) - 143]struct{}{}
)

// statxMountID is statx(2) asking for nothing but the mount ID of the
// descriptor itself.
//
// The syscall package exports no SYS_STATX on any architecture, so the number is
// named per architecture here (statx_linux_*.go) the way sysRenameat2 already
// is. The unsafe shape is the one the vet rules sanction for a syscall call (a
// Pointer converted to uintptr in the argument list), and both arguments are
// kept alive across it rather than trusted to escape analysis.
func statxMountID(fd int) (uint64, error) {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return 0, err
	}
	var stx statxData
	_, _, errno := syscall.Syscall6(sysStatx,
		uintptr(fd), uintptr(unsafe.Pointer(empty)),
		uintptr(atEmptyPath|atSymlinkNoFollow), uintptr(statxMntID),
		uintptr(unsafe.Pointer(&stx)), 0)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(&stx)
	if errno != 0 {
		return 0, errno
	}
	if stx.Mask&statxMntID == 0 {
		// The kernel understood statx but has no mount ID to give (before 5.8).
		return 0, syscall.ENOSYS
	}
	return stx.MntID, nil
}

// fdinfoMountID reads the mount ID out of /proc/self/fdinfo/<fd>, which every
// kernel since 3.8 prints as "mnt_id:". It is the fallback for a kernel without
// STATX_MNT_ID and for an architecture whose statx number is not compiled in.
func fdinfoMountID(fd int) (uint64, bool) {
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, found := strings.CutPrefix(line, "mnt_id:")
		if !found {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, false
		}
		return id, true
	}
	return 0, false
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
