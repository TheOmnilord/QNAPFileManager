//go:build !linux

package fsops

// The copy engine's platform half off Linux: the dev-loop path.
//
// Everything here goes through os.Root, exactly as the rest of this package
// does off Linux (open_other.go, walk_other.go, mutate_other.go). There is no
// O_PATH handle to hold, no openat to address an entry relative to one, and no
// fstatfs — so the guarantees the Linux half gets from the kernel are, here,
// guarantees os.Root gives about names resolved against the root descriptor.
//
// Three differences are the dev box's alone and are stated rather than papered
// over (INV-2 — the kernel decides, and this is not that kernel):
//
//   - there is no fstatfs, so the free-space refusal (§1.9) is not made here at
//     all. The CI Linux jobs and the NAS make it;
//   - there is no st_dev or inode behind a Windows FileInfo, so the identity
//     half of the copy-into-itself refusal is empty and the lexical test on the
//     resolved paths is the whole answer here (the Linux half has both);
//   - Chtimes follows a symlink, because os.Root has no Lchtimes, so a symlink
//     copied on the dev box gets its target's times set rather than its own.
//     Windows has no meaningful symlinks in the dev loop anyway.
//
// What IS the same on both platforms is everything the UI is exercised
// against: the conflict policies, the merge rule, the keep-both names, the
// progress, the warnings and the move's rename-first-then-copy shape.

import (
	"errors"
	"os"
	"syscall"
	"time"

	"qnapfilemanager/internal/fsx"
)

// copyReadFlags open a source file for reading. There is no O_NONBLOCK to ask
// for here and no fifo on the dev box to need it; the fstat that follows is
// still what decides, and on the NAS it is the kernel's (INV-2).
const copyReadFlags = os.O_RDONLY

// inodeKey is the Linux identity of one object. Off Linux there is nothing
// behind a FileInfo to fill it with, so it exists only to keep one engine
// compiling on both platforms.
type inodeKey struct {
	dev uint64
	ino uint64
}

// inodeIdentity is false off Linux: a Windows FileInfo carries no device and no
// inode number, so "no identity" here is the platform and not a suspicious
// answer. The verified delete falls back to kind, size and modification time —
// weaker than the NAS's proof and stated as such (INV-2); the CI Linux jobs and
// the hardware run the real one.
const inodeIdentity = false

// inodeOf cannot answer off Linux: a Windows FileInfo carries no device and no
// inode number (the same gap sameObject and devOf already report). The false
// return is what keeps the copy-into-itself refusal from firing on a comparison
// of two zero values, which would refuse every copy on this platform.
func inodeOf(fi os.FileInfo) (inodeKey, bool) {
	_ = fi
	return inodeKey{}, false
}

// openPathRef off Linux is openDirRef: there is no O_PATH here, so the handle
// that addresses a directory is the same one that would enumerate it, and it
// therefore asks for read permission where the Linux half asks only for search.
// Stricter than the kernel rather than looser, which is the safe direction.
func openPathRef(j fsx.Jail, rel string) (*dirRef, error) { return openDirRef(j, rel) }

// childPath is child off Linux, for the same reason.
func (d *dirRef) childPath(name string) (*dirRef, error) { return d.child(name) }

// symlinkAt recreates a symlink inside this directory. The target text is
// passed through byte for byte: os.Root.Symlink resolves the LINK's name
// against the root and leaves the target alone, which is what keeps a copied
// link pointing where the original did.
func symlinkAt(d *dirRef, name, target string) error {
	return d.j.Symlink(target, relJoin(d.rel, name))
}

// readlinkRef off Linux is readlinkIn: there is no descriptor for a symlink
// here (itemRef holds only a stat), so the target is read by name through the
// jail. The difference is the dev box's alone — nothing here chowns, so the
// metadata this would protect is not being reproduced in the first place.
func readlinkRef(ref *itemRef, dir *dirRef, name string) (string, error) {
	_ = ref
	return readlinkIn(dir, name)
}

// readlinkIn reads a symlink's target through the jail.
func readlinkIn(d *dirRef, name string) (string, error) {
	return readlinkAt(d.j, relJoin(d.rel, name))
}

// chownEntry sets the owner of a created entry. os.Root.Lchown never follows a
// symlink, which is the property the Linux half gets from AT_SYMLINK_NOFOLLOW;
// f is ignored because there is no portable fchown on an *os.File here.
//
// On Windows this returns an error from the os package, and it is never called
// there: the engine only chowns when the worker's euid is 0, and os.Geteuid
// reports -1 on Windows.
func chownEntry(dir *dirRef, name string, f *os.File, uid, gid int) error {
	_ = f
	if uid == -1 && gid == -1 {
		return nil
	}
	return dir.j.Lchown(relJoin(dir.rel, name), uid, gid)
}

// utimesEntry preserves an entry's times.
//
// os.Root has no Lchtimes, so a SYMLINK is left alone here rather than having
// its times set: Chtimes would follow the link and stamp its target, which is
// somebody else's file and very much not what was asked. The Linux half sets
// the link's own times with AT_SYMLINK_NOFOLLOW. Doing nothing is the honest
// degradation; doing the wrong thing quietly is not (INV-2).
func utimesEntry(dir *dirRef, name string, f *os.File, link bool, atime, mtime time.Time) error {
	_ = f
	if link {
		return nil
	}
	return dir.j.Chtimes(relJoin(dir.rel, name), atime, mtime)
}

// accessTimeOf has nothing to read off Linux: there is no Stat_t behind a
// Windows FileInfo. The false return makes the caller reproduce the
// modification time for both, which is all os.Root.Chtimes would let it set
// meaningfully here anyway.
func accessTimeOf(fi os.FileInfo) (time.Time, bool) {
	_ = fi
	return time.Time{}, false
}

// changeTimeOf has nothing to read off Linux: there is no Stat_t behind a
// Windows FileInfo and no ctime of this shape. The verified delete falls back to
// size and modification time there, which is the same degradation inodeIdentity
// already documents — the CI Linux jobs and the NAS make the real check.
func changeTimeOf(fi os.FileInfo) (time.Time, bool) {
	_ = fi
	return time.Time{}, false
}

// enumerable opens a readable descriptor for a directory. Off Linux the handle
// is already an ordinary one (openPathRef is openDirRef here), so this reopens
// it through the jail by its own relative name.
func enumerable(d *dirRef) (*os.File, error) {
	return d.j.OpenFile(d.rel, os.O_RDONLY, 0)
}

// fsStatfs has no portable answer off Linux, so the free-space refusal is
// simply not made here. Reporting "unknown" rather than inventing a number is
// the whole of INV-2: a guess would either refuse a copy that fits or promise
// room that is not there.
func fsStatfs(d *dirRef) (avail uint64, ok bool, err error) {
	_ = d
	return 0, false, nil
}

// destAncestry is empty off Linux: with no inode identity there is nothing to
// compare. The lexical refusal on the resolved paths is the whole answer here,
// and the Linux half adds the identity one.
func destAncestry(j fsx.Jail, d *dirRef) []inodeKey {
	_, _ = j, d
	return nil
}

// isCrossDevice reports the kernel's "these are two filesystems". EXDEV is
// defined by package syscall on Windows too (as an invented value), so no
// further split is needed.
func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, fsx.ErrCrossDevice)
}

// isQuota reports a write refused by a quota rather than by a full filesystem.
func isQuota(err error) bool { return errors.Is(err, syscall.EDQUOT) }

// fsyncDir has no portable answer off Linux: Windows has no fsync of a
// directory at all — FlushFileBuffers refuses a directory handle — and os.Root
// offers nothing else. The dev loop therefore does not make the durability
// proof a move makes on the NAS, which is the documented degradation (INV-2);
// the CI Linux jobs and the NAS take the real path.
func fsyncDir(d *dirRef) error {
	_ = d
	return nil
}
