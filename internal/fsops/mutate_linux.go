package fsops

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"qnapfilemanager/internal/fsx"
)

// atRemoveDir is AT_REMOVEDIR, the unlinkat flag that turns an unlink into an
// rmdir. The value is stable across Linux architectures; the syscall package
// spells it out, but naming it here keeps unlinkAt readable.
const atRemoveDir = 0x200

// mkdirAt creates name inside the directory named by parentRel (relative to the
// jail base), through the parent's own O_PATH descriptor. When parents is set,
// the missing intermediate directories of parentRel are created first — each
// ignoring EEXIST — before the final component, which keeps its O_EXCL
// semantics: an existing final name is EEXIST and reaches the caller as
// fs.ErrExist.
//
// The descriptor is obtained the same way every read here obtains one: an
// openat walk from the base, one component at a time, O_PATH|O_DIRECTORY|
// O_NOFOLLOW so nothing is resolved by name and no symlink can redirect the
// walk. resolve() has already followed every symlink on parentRel, so the only
// components without a descriptor are the ones parents is being asked to make.
func mkdirAt(j fsx.Jail, parentRel, name string, mode os.FileMode, parents bool) error {
	parent, err := openParentDir(j, parentRel, mode, parents)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := mkdiratIn(parent, name, syscallMode(mode)); err != nil {
		return &fs.PathError{Op: "mkdirat", Path: relJoin(parentRel, name), Err: err}
	}
	return nil
}

// renameNoReplace is RENAME_NOREPLACE, the renameat2(2) flag that makes the
// kernel refuse the rename (EEXIST) if the destination already exists, rather
// than overwriting it. The value is stable across Linux architectures.
const renameNoReplace = 0x1

// renameAt renames fromName under fromParentRel to toName under toParentRel,
// with renameat(2) relative to the two resolved parent descriptors. Neither
// final component is followed: renameat operates on the name in the directory,
// which for a symlink is the link itself.
//
// When noReplace is set the no-overwrite guarantee is atomic: renameat2(2) with
// RENAME_NOREPLACE lets the kernel reject an existing destination (EEXIST) in
// the same syscall, closing the check-then-act window (adv 2). If renameat2 or
// the flag is unavailable (ENOSYS/EINVAL — an old kernel or a filesystem that
// does not implement it), it falls back to a best-effort lstat pre-check (its
// residual TOCTOU is accepted, PLAN.md §2.4) and a plain renameat.
func renameAt(fromJail fsx.Jail, fromParentRel, fromName string, toJail fsx.Jail, toParentRel, toName string, noReplace bool) error {
	fromDir, err := walkOPath(fromJail, fromParentRel)
	if err != nil {
		return err
	}
	defer fromDir.Close()
	toDir, err := walkOPath(toJail, toParentRel)
	if err != nil {
		return err
	}
	defer toDir.Close()
	err = renameatIn(fromDir, fromName, toDir, toName, noReplace)
	if noReplace && (errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)) {
		// renameat2/RENAME_NOREPLACE unsupported here: fall back to a pre-check
		// then a plain renameat. The check is fstatat *relative to the
		// destination parent descriptor toDir we already hold* — not a fresh walk
		// of the destination pathname (adv round-3 finding 5). Re-walking the
		// pathname inspected the wrong directory if the destination's parent was
		// moved between the walk and this rename, and treated every stat error as
		// "absent", so an EACCES or an EIO would let the rename overwrite. Only
		// ENOENT means the destination is genuinely absent; any other error fails
		// the rename rather than being read as room to overwrite.
		exists, serr := destExistsAt(toDir, toName)
		if serr != nil {
			return &fs.PathError{Op: "statat", Path: relJoin(toParentRel, toName), Err: serr}
		}
		if exists {
			return &fs.PathError{Op: "renameat", Path: relJoin(toParentRel, toName), Err: syscall.EEXIST}
		}
		err = renameatIn(fromDir, fromName, toDir, toName, false)
	}
	if err != nil {
		return &fs.PathError{Op: "renameat", Path: relJoin(fromParentRel, fromName), Err: err}
	}
	return nil
}

// destExistsAt reports whether name exists directly inside the directory toDir
// refers to, addressed by that already-held descriptor rather than by a fresh
// walk of the pathname (adv round-3 finding 5). It is the no-overwrite rename
// fallback's existence check, used only when renameat2(RENAME_NOREPLACE) is
// unavailable — the atomic primary path decides the same thing in the kernel.
//
// The lookup is an fstatat relative to toDir: an openat with O_PATH|O_NOFOLLOW,
// which asks the kernel for nothing but whether the name resolves and never
// follows a symlink at the destination — a link there is an existing entry, the
// same as renameat2 would treat it. ENOENT is the one error that means "absent,
// go ahead"; every other error (EACCES on the lookup, a dead mount) is returned
// so the caller fails the rename rather than overwriting on a guess.
func destExistsAt(toDir *os.File, name string) (bool, error) {
	fd, err := openatIn(toDir, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
	if err == nil {
		syscall.Close(fd)
		return true, nil
	}
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return false, err
}

// unlinkAt removes name from the directory named by parentRel, with
// AT_REMOVEDIR when it is a directory (so a non-empty one is ENOTEMPTY, not
// recursed into) and a plain unlink otherwise (so a symlink is removed as the
// link it is).
func unlinkAt(j fsx.Jail, parentRel, name string, isDir bool) error {
	parent, err := walkOPath(j, parentRel)
	if err != nil {
		return err
	}
	defer parent.Close()
	flags := 0
	if isDir {
		flags = atRemoveDir
	}
	if err := unlinkatIn(parent, name, flags); err != nil {
		return &fs.PathError{Op: "unlinkat", Path: relJoin(parentRel, name), Err: err}
	}
	return nil
}

// openParentDir is walkOPath with an option to create the directories it walks
// through. With create off it is exactly walkOPath — the descriptor of an
// existing directory. With create on, a missing component is mkdirat'ed (EEXIST
// ignored, since a racing creator that got there first is a success) and then
// opened, so the walk descends into a tree it is building as it goes.
func openParentDir(j fsx.Jail, rel string, mode os.FileMode, create bool) (*os.File, error) {
	if !create {
		return walkOPath(j, rel)
	}
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
		const flags = oPath | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		fd, err := openatIn(dir, part, flags)
		if err != nil && errors.Is(err, syscall.ENOENT) {
			if mkerr := mkdiratIn(dir, part, syscallMode(mode)); mkerr != nil && !errors.Is(mkerr, syscall.EEXIST) {
				dir.Close()
				return nil, &fs.PathError{Op: "mkdirat", Path: relOf(parts[:i+1]), Err: mkerr}
			}
			fd, err = openatIn(dir, part, flags)
		}
		dir.Close()
		if err != nil {
			return nil, &fs.PathError{Op: "openat", Path: relOf(parts[:i+1]), Err: err}
		}
		dir = os.NewFile(uintptr(fd), relOf(parts[:i+1]))
	}
	return dir, nil
}

// mkdiratIn is mkdirat(2) relative to an open directory, retried over EINTR.
// The descriptor is reached through SyscallConn rather than File.Fd, which
// would detach the directory from the runtime poller as a side effect — the
// same reason openatIn does it that way.
func mkdiratIn(dir *os.File, name string, mode uint32) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = syscall.Mkdirat(int(pfd), name, mode)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	return serr
}

// unlinkatIn is unlinkat(2) relative to an open directory, retried over EINTR.
//
// The raw syscall is made by hand because the syscall package only exports the
// two-argument Unlinkat, with no flags word, so there is no way through it to
// pass AT_REMOVEDIR — the one flag that separates deleting a file from removing
// a directory. readlinkatIn is made the same way and for the same reason.
func unlinkatIn(dir *os.File, name string, flags int) error {
	rc, err := dir.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(pfd uintptr) {
		for {
			serr = rawUnlinkat(int(pfd), name, flags)
			if serr != syscall.EINTR {
				return
			}
		}
	}); cerr != nil {
		return cerr
	}
	return serr
}

// rawUnlinkat is unlinkat(2), including the flags word the exported
// syscall.Unlinkat drops. The unsafe shape is the one the rules sanction for a
// syscall call (a Pointer converted to uintptr in the argument list), and the
// name is kept alive across it rather than trusted to escape analysis.
func rawUnlinkat(dirfd int, name string, flags int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
	runtime.KeepAlive(p)
	if errno != 0 {
		return errno
	}
	return nil
}

// renameatIn is renameat(2) between two open directories, retried over EINTR.
// Both descriptors are held at once — the destination's Control nested inside
// the source's — so neither is detached from the poller and the syscall sees
// both live fds. With noReplace it uses renameat2(2) with RENAME_NOREPLACE so
// the kernel refuses an existing destination atomically.
func renameatIn(fromDir *os.File, fromName string, toDir *os.File, toName string, noReplace bool) error {
	fromRC, err := fromDir.SyscallConn()
	if err != nil {
		return err
	}
	toRC, err := toDir.SyscallConn()
	if err != nil {
		return err
	}
	var serr, cerr2 error
	if cerr := fromRC.Control(func(fromFD uintptr) {
		cerr2 = toRC.Control(func(toFD uintptr) {
			for {
				if noReplace {
					serr = renameat2(int(fromFD), fromName, int(toFD), toName, renameNoReplace)
				} else {
					serr = syscall.Renameat(int(fromFD), fromName, int(toFD), toName)
				}
				if serr != syscall.EINTR {
					return
				}
			}
		})
	}); cerr != nil {
		return cerr
	}
	if cerr2 != nil {
		return cerr2
	}
	return serr
}

// renameat2 is renameat2(2), which the syscall package does not export. The
// unsafe shape is the one the vet rules sanction for a syscall call (a Pointer
// converted to uintptr in the argument list); both names are kept alive across
// the call rather than trusted to escape analysis.
func renameat2(fromFD int, fromName string, toFD int, toName string, flags uint) error {
	if sysRenameat2 == 0 {
		// The syscall number is not compiled in for this architecture; behave as an
		// old kernel would and let Rename take the lstat-pre-check fallback.
		return syscall.ENOSYS
	}
	fromPtr, err := syscall.BytePtrFromString(fromName)
	if err != nil {
		return err
	}
	toPtr, err := syscall.BytePtrFromString(toName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(sysRenameat2,
		uintptr(fromFD), uintptr(unsafe.Pointer(fromPtr)),
		uintptr(toFD), uintptr(unsafe.Pointer(toPtr)),
		uintptr(flags), 0)
	runtime.KeepAlive(fromPtr)
	runtime.KeepAlive(toPtr)
	if errno != 0 {
		return errno
	}
	return nil
}

// syscallMode turns an fs.FileMode into the mode_t bits mkdirat expects: the
// low nine permission bits plus setuid, setgid and sticky in their Unix
// positions. It mirrors the os package's own syscallMode, which is unexported.
func syscallMode(m os.FileMode) uint32 {
	o := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		o |= syscall.S_ISUID
	}
	if m&fs.ModeSetgid != 0 {
		o |= syscall.S_ISGID
	}
	if m&fs.ModeSticky != 0 {
		o |= syscall.S_ISVTX
	}
	return o
}
