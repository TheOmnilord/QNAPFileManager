package fsops

// The two syscalls of M3, addressed to a held descriptor rather than to a name
// (m3-contract §2.3), and the fstatfs the properties dialog needs.

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"qnapfilemanager/internal/fsx"
)

// atEmptyPath is already spelled in walk_linux.go for statx; fchownat takes the
// same flag and the same value. It is named again here only in prose: passing
// an empty pathname with it makes the call act on the descriptor itself, which
// is the one form of chown that cannot be pointed at another object.

// chmodHeld changes the mode of the object ref refers to, and returns the fstat
// of that same descriptor afterwards.
//
// The primary form is chmod("/proc/self/fd/N") on the held O_PATH handle. That
// is the established idiom in this tree — linkUnnamed publishes an O_TMPFILE
// inode the same way — and it is the only way to reach an O_PATH descriptor with
// chmod at all, because fchmod(2) on one is EBADF. It acts on the inode the
// descriptor refers to, and on a symlink it answers EOPNOTSUPP, which is exactly
// where lchmod would have refused: the magic link under /proc is followed to its
// target, and a symlink's "target" through O_PATH|O_NOFOLLOW is the link itself,
// which has no mode to set. A symlink is refused before this is called anyway
// (mode.go); this is the kernel saying the same thing.
//
// Where /proc is not mounted the fallback is fchmod on a READABLE re-open of the
// same entry, taken through the held parent descriptor with O_NOFOLLOW and then
// PROVED to be the same object (device, inode and birth time) before anything is
// done to it — a re-open by name is a second lookup, and the whole discipline
// here is that a second lookup proves nothing on its own. Where that open fails
// too — a 0200 file this process may write but not read — the honest answer is
// fsx.ErrUnsupported: there is no writable route to that inode from here, and
// reaching for the pathname instead would undo everything above.
func chmodHeld(parent *dirRef, name string, ref *itemRef, mode uint32) (os.FileInfo, error) {
	var err error
	if noProcFD {
		err = syscall.ENOENT
	} else {
		err = chmodViaProc(ref.f, mode)
	}
	if err != nil && procUnavailable(err) {
		err = chmodViaReopen(parent, name, ref, mode)
	}
	if err != nil {
		return nil, &fs.PathError{Op: "chmod", Path: relJoin(parentRel(parent), name), Err: err}
	}
	return ref.f.Stat()
}

// noProcFD and noEmptyPath make this file behave as though /proc were not
// mounted, or as though the kernel did not take AT_EMPTY_PATH.
//
// They are variables for the same reason sizeScanLimits and identityFor are:
// the fallbacks they gate are the paths a NAS takes when something is missing,
// and a dev box cannot produce a kernel without AT_EMPTY_PATH or a container
// without /proc just to prove the second branch works. Production never assigns
// to either, and nothing in the worker reads them concurrently with a test — the
// tests that set them do not run in parallel.
var (
	noProcFD    bool
	noEmptyPath bool
)

// onFD runs one syscall against a held descriptor. The descriptor is reached
// through SyscallConn rather than File.Fd, which would detach the file from the
// runtime poller as a side effect, and it stays valid for the whole callback.
func onFD(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) { serr = fn(int(pfd)) }); cerr != nil {
		return cerr
	}
	return serr
}

// chmodViaProc is chmod(2) on the /proc name of a held descriptor, retried over
// EINTR.
func chmodViaProc(f *os.File, mode uint32) error {
	return onFD(f, func(fd int) error {
		name := "/proc/self/fd/" + fdString(fd)
		for {
			err := syscall.Chmod(name, mode)
			if err != syscall.EINTR {
				return err
			}
		}
	})
}

// chownViaProc is chmodViaProc's counterpart: chown(2) on the /proc name of a
// held descriptor.
//
// It must NEVER be called for a symlink. /proc/self/fd/N jumps to the dentry the
// descriptor refers to, and chown(2) then follows a symlink found there — which
// would change the TARGET's ownership, the one thing §1.4 forbids. Its caller
// gates on the fstat of the held descriptor, which is authoritative about that.
func chownViaProc(f *os.File, uid, gid int) error {
	return onFD(f, func(fd int) error {
		name := "/proc/self/fd/" + fdString(fd)
		for {
			err := syscall.Chown(name, uid, gid)
			if err != syscall.EINTR {
				return err
			}
		}
	})
}

// procUnavailable reports the errnos that mean "/proc/self/fd is not there",
// as opposed to a chmod the kernel refused on its merits. ENOENT and ENOTDIR
// are what a missing /proc looks like from inside a path lookup; ENOSYS is a
// kernel built without it. EACCES and EPERM are deliberately NOT here: those are
// the kernel's verdict on the chmod itself and must reach the caller unchanged
// (INV-2).
func procUnavailable(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENOSYS)
}

// reopenProved re-opens the entry called name inside the HELD parent, readable
// and O_NOFOLLOW, proves it is the object ref holds, and hands back that same
// open descriptor.
//
// Handing the descriptor back is the whole point, and it is what the M3 round-1
// review asked for: the proof and the act then happen on ONE open file, so there
// is no second lookup in between for a rename to slip a different inode — a
// planted hardlink to a system file, say — into. A helper that returned only
// "yes, it matched" and left the caller to name the entry again would be
// check-then-name, which proves nothing at all.
//
// O_NONBLOCK is what keeps a fifo from parking the worker inside open(2), the
// same backstop openFinal takes. fsx.ErrChanged means the name refers to
// something else now.
//
// Every OTHER failure of the open is reported as the kernel reported it. Mapping
// them all to fsx.ErrUnsupported meant an EACCES — the kernel's verdict on this
// caller — reached the user as "that kind of item cannot be changed" (415)
// rather than as a permission refusal (403), which is both untrue and the
// opposite of what INV-2 asks for; the same reasoning procUnavailable already
// applies to the /proc route (round-2 review, P3). Only noReadableRoute's
// errnos, which say the OBJECT has no readable descriptor to be had at all,
// become fsx.ErrUnsupported.
func reopenProved(parent *dirRef, name string, ref *itemRef) (*os.File, error) {
	if parent == nil {
		return nil, fsx.ErrUnsupported
	}
	fd, err := openatIn(parent.f, name,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK)
	if err != nil {
		if renamedAway(err) {
			return nil, fsx.ErrChanged
		}
		if noReadableRoute(err) {
			return nil, fsx.ErrUnsupported
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), relJoin(parent.rel, name))
	fi, serr := f.Stat()
	if serr != nil {
		f.Close()
		return nil, serr
	}
	if !objectIDOf(f, fi).same(objectIDOf(ref.f, ref.fi)) {
		f.Close()
		return nil, fsx.ErrChanged
	}
	return f, nil
}

// renamedAway reports the errnos that, on a RE-open of a name whose object this
// process is still HOLDING, can only mean the name is not that object's any
// more: it was renamed away (ENOENT), or a component of it was replaced by
// something that is not a directory (ENOTDIR).
//
// They become fsx.ErrChanged rather than travelling as themselves, because
// "not_found" is a lie about an inode the worker demonstrably has open — the
// dialog would say "this path no longer exists" about a file it is holding — and
// because "the tree changed after it was authorized" is the word §2.2 already
// has for exactly this (round-3 review). A GENUINE not-found belongs to the
// first canonical walk, which has nothing open yet and is untouched by this.
func renamedAway(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR)
}

// noReadableRoute reports the errnos that mean "this OBJECT cannot be opened for
// reading at all, by anybody", as opposed to the kernel refusing this caller.
//
// ELOOP is the one that matters: O_NOFOLLOW on a symlink, which Linux will never
// open, and which is how a chown's ladder learns it must fall to its last rung.
// The rest are the exotic shapes of the same answer — a device with no driver,
// a filesystem that does not implement the open. EACCES and EPERM are
// deliberately NOT here: those are verdicts on the caller and belong to the
// caller, unchanged (INV-2).
func noReadableRoute(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENXIO) ||
		errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}

// chmodViaReopen is the no-/proc fallback: fchmod the descriptor reopenProved
// proved. A kernel refusal of the open reaches the caller as itself; only an
// object with no readable descriptor to be had is fsx.ErrUnsupported, and
// reaching for the pathname instead would undo everything above.
func chmodViaReopen(parent *dirRef, name string, ref *itemRef, mode uint32) error {
	f, err := reopenProved(parent, name, ref)
	if err != nil {
		return err
	}
	defer f.Close()
	return onFD(f, func(fd int) error { return fchmodRetry(fd, mode) })
}

// fchmodRetry is fchmod(2) retried over EINTR. The descriptor is the raw one
// this file just opened, which nothing else holds.
func fchmodRetry(fd int, mode uint32) error {
	for {
		err := syscall.Fchmod(fd, mode)
		if err != syscall.EINTR {
			return err
		}
	}
}

// chownHeld changes the owner of the object ref refers to and returns the fstat
// of that same descriptor afterwards.
//
// The primary form is fchownat(fd, "", uid, gid, AT_EMPTY_PATH): no name at all,
// so there is nothing for a concurrent rename to re-point. On an
// O_PATH|O_NOFOLLOW descriptor of a symlink it changes the LINK, which is
// precisely what lchown does and precisely what M3 wants (§1.4).
//
// AT_EMPTY_PATH has been in Linux since 2.6.39, so everything below the primary
// form is for kernels older than anything this app runs on and for filesystems
// that refuse the flag. The ladder is chownWithoutEmptyPath's; it exists in this
// shape because the first version of it was check-then-NAME (M3 round-1 review,
// P3), which is exactly the mistake the descriptor discipline exists to prevent.
func chownHeld(parent *dirRef, name string, ref *itemRef, uid, gid int) (os.FileInfo, error) {
	var err error
	if noEmptyPath {
		err = syscall.EINVAL
	} else {
		err = fchownatRetry(ref.f, "", uid, gid, atEmptyPath|atSymlinkNoFollow)
	}
	if err != nil && emptyPathUnavailable(err) {
		err = chownWithoutEmptyPath(parent, name, ref, uid, gid)
	}
	if err != nil {
		return nil, &fs.PathError{Op: "fchownat", Path: relJoin(parentRel(parent), name), Err: err}
	}
	return ref.f.Stat()
}

// chownWithoutEmptyPath is the ladder a kernel that will not take AT_EMPTY_PATH
// climbs, in order of how little it trusts a name (M3 round-1 review, P3).
//
// The version this replaces was check-then-name: it proved the entry's identity,
// closed the descriptor it had proved, and THEN called
// fchownat(parent, name, …), which looks the name up a second time. A rename in
// a writable parent between the two handed the chown — root's chown, for an
// admin session — to whatever was standing at that name by then: a hardlink to a
// system binary would have done. The proof has to be on a descriptor that is
// still open when the syscall is made, or it is not a proof.
//
//  1. chown("/proc/self/fd/N") on the HELD descriptor, the same idiom chmod
//     uses. No directory is consulted, so nothing can be substituted. It is not
//     used for a symlink: /proc/self/fd/N jumps to the dentry and chown(2) then
//     follows a symlink found there, which would change the target.
//  2. fchown on the descriptor reopenProved hands back — opened through the held
//     parent, proved, and never closed in between.
//  3. Only when neither is possible — a symlink (which cannot be opened at all)
//     or a file this process may write but not read, on a system with no /proc —
//     the named call, after re-proving. This rung is the RESIDUAL: the identity
//     is proved on one lookup and acted on by another, and the window between
//     them is real. It is reachable only on a pre-2.6.39 kernel AND without
//     /proc, which no NAS this ships to has ever been, and the alternative would
//     be to refuse an operation the kernel would allow (INV-2).
func chownWithoutEmptyPath(parent *dirRef, name string, ref *itemRef, uid, gid int) error {
	// The fstat of the held O_PATH|O_NOFOLLOW descriptor, which is authoritative
	// about what this object is — a name would not be.
	link := ref != nil && ref.fi != nil && ref.fi.Mode()&fs.ModeSymlink != 0

	if !link && ref != nil {
		if !noProcFD {
			if err := chownViaProc(ref.f, uid, gid); !procUnavailable(err) {
				// nil, or the kernel's own verdict on the chown; either way it
				// is the answer and no other route is tried (INV-2).
				return err
			}
		}
		switch f, err := reopenProved(parent, name, ref); {
		case err == nil:
			defer f.Close()
			return onFD(f, func(fd int) error { return fchownRetry(fd, uid, gid) })
		case errors.Is(err, fsx.ErrChanged):
			return err
		}
		// fsx.ErrUnsupported: no readable route to the inode. Fall through.
	}
	if parent == nil {
		return fsx.ErrUnsupported
	}
	if cerr := sameAsHeld(parent, name, ref); cerr != nil {
		return cerr
	}
	return fchownatRetry(parent.f, name, uid, gid, atSymlinkNoFollow)
}

// parentRel names the held parent for an error message, tolerating the nil the
// jail base would produce (mode.go refuses that case before either syscall).
func parentRel(parent *dirRef) string {
	if parent == nil {
		return "."
	}
	return parent.rel
}

// emptyPathUnavailable reports the errnos that mean "this kernel or this
// filesystem does not take AT_EMPTY_PATH", as opposed to a chown refused on its
// merits. EPERM and EACCES are the kernel's verdict and are never re-tried by
// another route.
func emptyPathUnavailable(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EBADF)
}

// sameAsHeld proves that the entry called name inside parent is still the object
// ref holds open: device, inode and — where the filesystem records it — birth
// time. An inode number alone is only an identity while its object is alive, and
// the gap this covers is one somebody else can widen at will.
//
// It is the WEAK form of the check and has exactly one caller left: rung 3 of
// chownWithoutEmptyPath, where there is no descriptor to act through. It closes
// what it proved before the syscall is made, so a rename in between defeats it;
// reopenProved is the form to use wherever the caller can act on a descriptor,
// and everything else here does.
func sameAsHeld(parent *dirRef, name string, ref *itemRef) error {
	named, err := itemRefIn(parent, name)
	if err != nil {
		if renamedAway(err) {
			return fsx.ErrChanged
		}
		return err
	}
	defer named.close()
	if !objectIDOf(named.f, named.fi).same(objectIDOf(ref.f, ref.fi)) {
		return fsx.ErrChanged
	}
	return nil
}

// fchownatRetry is fchownat(2) retried over EINTR. The syscall package exports
// Fchownat, but without a way to pass an empty pathname safely alongside
// AT_EMPTY_PATH on every architecture, so the raw call is made here the way the
// other *at helpers in this package are.
func fchownatRetry(dir *os.File, name string, uid, gid, flags int) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = rawFchownat(int(pfd), name, uid, gid, flags)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	return serr
}

// rawFchownat is fchownat(2). The unsafe shape is the one the vet rules sanction
// for a syscall call — a Pointer converted to uintptr inside the argument list —
// and the name is kept alive across it rather than trusted to escape analysis.
func rawFchownat(dirfd int, name string, uid, gid, flags int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_FCHOWNAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(uint32(uid)), uintptr(uint32(gid)), uintptr(flags), 0)
	runtime.KeepAlive(p)
	if errno != 0 {
		return errno
	}
	return nil
}

// reopenDir re-opens a held entry as an ENUMERABLE directory and proves it is
// the same object.
//
// A recursive job holds its root as an O_PATH reference, which getdents cannot
// read, so the walk needs a real O_RDONLY|O_DIRECTORY descriptor. Getting one
// means naming the entry once more — relative to the held parent, never by a
// pathname — and the identity check is what makes that second lookup safe: the
// directory the walk enumerates is the directory that was authorized, or the job
// refuses with fsx.ErrChanged.
func reopenDir(parent *dirRef, name string, ref *itemRef) (*dirRef, error) {
	fd, err := openatIn(parent.f, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err != nil {
		if renamedAway(err) {
			err = fsx.ErrChanged
		}
		return nil, &fs.PathError{Op: "openat", Path: relJoin(parent.rel, name), Err: err}
	}
	rel := relJoin(parent.rel, name)
	f := os.NewFile(uintptr(fd), rel)
	fi, serr := f.Stat()
	if serr != nil {
		f.Close()
		return nil, serr
	}
	if !objectIDOf(f, fi).same(objectIDOf(ref.f, ref.fi)) {
		f.Close()
		return nil, &fs.PathError{Op: "openat", Path: rel, Err: fsx.ErrChanged}
	}
	return &dirRef{f: f, rel: rel}, nil
}

// statfsHeld reads the filesystem's block numbers off a HELD descriptor.
//
// fstatfs(2) is one of the few operations an O_PATH descriptor is explicitly
// allowed to be the subject of (Linux 3.6), so the properties dialog's free
// space describes the filesystem the opened object is really on — on a per-share
// QuTS hero dataset, that dataset's quota view rather than the pool's.
func statfsHeld(ref *itemRef) (avail, total uint64, ok bool) {
	if ref == nil || ref.f == nil {
		return 0, 0, false
	}
	rc, err := ref.f.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var st syscall.Statfs_t
	var serr error
	if cerr := rc.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), &st) }); cerr != nil || serr != nil {
		return 0, 0, false
	}
	// Bsize is int32 on some Linux architectures and int64 on others, and the
	// block counts are unsigned on all of them; the conversions are written out
	// so this file compiles for every GOARCH the QPKG targets.
	bs := uint64(st.Bsize)
	if bs == 0 {
		return 0, 0, false
	}
	return uint64(st.Bavail) * bs, uint64(st.Blocks) * bs, true
}
