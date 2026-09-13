//go:build !linux

package fsops

// chmod, chown and fstatfs off Linux: the dev loop's degradation, stated rather
// than papered over (m3-contract §14).
//
// There is no O_PATH here and therefore no held descriptor to address, so every
// operation goes back through os.Root and a jail-relative name — the same
// degradation open_other.go and mutate_other.go already accept. Nothing in
// production takes this path: a real chmod runs inside a per-user worker on the
// NAS, and the permission semantics that matter are the kernel's, which the CI
// Linux root and ZFS jobs are where they are exercised (INV-2).

import (
	"io/fs"
	"os"

	"qnapfilemanager/internal/fsx"
)

// chmodHeld applies a mode best effort. Windows mode bits are a fiction — the
// only one the runtime honours is the owner write bit — so what this buys is a
// dev loop whose route answers, not a permission model. The post-call stat is a
// fresh lstat by name, because there is no descriptor here to fstat.
func chmodHeld(parent *dirRef, name string, ref *itemRef, mode uint32) (os.FileInfo, error) {
	rel := relJoin(parent.rel, name)
	if err := parent.j.Chmod(rel, fs.FileMode(mode&0o777)); err != nil {
		return nil, err
	}
	return statAt(parent.j, rel)
}

// chownHeld is unsupported off Linux. There are no uids to set and no lchown to
// set them with, and inventing a success would be the one answer worse than
// refusing (copy_other.go's rule).
func chownHeld(parent *dirRef, name string, ref *itemRef, uid, gid int) (os.FileInfo, error) {
	return nil, fsx.ErrUnsupported
}

// reopenDir re-opens a held entry as an enumerable directory. There is no
// descriptor identity to prove it against here (itemRef holds only a stat), so
// the name is resolved through os.Root and the check the Linux half makes is
// simply not available — INV-2, and the CI jobs hold the real descriptor.
func reopenDir(parent *dirRef, name string, ref *itemRef) (*dirRef, error) {
	return openDirRef(parent.j, relJoin(parent.rel, name))
}

// statfsHeld has no answer off Linux. Avail and Total are then omitted from the
// properties dialog rather than invented: reporting "unknown" beats guessing.
func statfsHeld(ref *itemRef) (avail, total uint64, ok bool) { return 0, 0, false }
