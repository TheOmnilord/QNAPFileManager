//go:build !linux

package fsops

import (
	"os"

	"qnapfilemanager/internal/fsx"
)

// The walk off Linux goes through os.Root, exactly as the rest of this package
// does there (open_other.go, mutate_other.go). There is no O_PATH handle to
// hold and no openat to walk with, so a directory is addressed by its
// jail-relative name and os.Root resolves that name against the root
// descriptor, refusing anything that would leave the tree.
//
// Two differences from Linux are worth being honest about, and both are the
// dev box's alone (INV-2 — the kernel decides, and this is not that kernel):
// os.Root asks for read permission on every directory on the way, where Linux
// now asks only for search; and it follows a symlink that stays inside the
// tree, so the walk's "a symlink is an item, never a way down" rule is enforced
// here by the lstat that classified the entry rather than by O_NOFOLLOW. On the
// NAS it is the kernel's.
type dirRef struct {
	j   fsx.Jail
	f   *os.File
	rel string
}

// openDirRef opens the directory named by rel for enumeration.
func openDirRef(j fsx.Jail, rel string) (*dirRef, error) {
	f, err := openDir(j, rel, rel)
	if err != nil {
		return nil, err
	}
	return &dirRef{j: j, f: f, rel: rel}, nil
}

// child opens a subdirectory. The name is joined onto this directory's own
// relative path and resolved by os.Root from the jail base.
func (d *dirRef) child(name string) (*dirRef, error) {
	return openDirRef(d.j, relJoin(d.rel, name))
}

// names reads the next chunk of entry names and nothing else.
func (d *dirRef) names(n int) ([]string, error) { return d.f.Readdirnames(n) }

// lstat describes one entry without following a symlink.
func (d *dirRef) lstat(name string) (os.FileInfo, error) {
	return statAt(d.j, relJoin(d.rel, name))
}

// unlink removes one entry. os.Root.Remove deletes a file or an empty
// directory, refuses a non-empty one with ENOTEMPTY and removes a symlink as
// the link, so the isDir hint the Linux path needs to choose AT_REMOVEDIR is
// not needed here.
func (d *dirRef) unlink(name string, isDir bool) error {
	return unlinkAt(d.j, d.rel, name, isDir)
}

// stat describes the directory itself.
func (d *dirRef) stat() (os.FileInfo, error) { return statAt(d.j, d.rel) }

func (d *dirRef) close() error { return d.f.Close() }

// mkdir creates a subdirectory of this one.
func (d *dirRef) mkdir(name string, mode os.FileMode) error {
	return mkdirAt(d.j, d.rel, name, mode, false)
}

// openFile opens (or creates) a file inside this directory. os.Root.OpenFile
// honours O_CREATE|O_EXCL and refuses a name that would leave the tree.
func (d *dirRef) openFile(name string, flags int, perm os.FileMode) (*os.File, error) {
	return openFileAt(d.j, d.rel, name, flags, perm)
}

// readSidecarFlags are the flags a trash sidecar is opened with. There is no
// O_NONBLOCK to ask for here and no fifo on the dev box to need it (F8): the
// fstat that follows is still what decides, and on the NAS it is the kernel's
// (INV-2).
const readSidecarFlags = os.O_RDONLY

// renameInto renames one entry from an already-resolved parent into this
// directory. Both sides belong to the same os.Root, which resolves each name
// against the root descriptor.
func (d *dirRef) renameInto(fromJail fsx.Jail, fromParentRel, fromName, toName string) error {
	return renameAt(fromJail, fromParentRel, fromName, d.j, d.rel, toName, true)
}

// renameOut renames one entry out of this directory to an already-resolved
// destination.
func (d *dirRef) renameOut(fromName string, toJail fsx.Jail, toParentRel, toName string) error {
	return renameAt(d.j, d.rel, fromName, toJail, toParentRel, toName, true)
}

// identityOf has nothing to report off Linux: there is no st_dev behind a
// Windows FileInfo and no mount ID to ask for (F4). The zero value leaves
// mount-point classification to the mount table alone, which is the same
// degradation devOf and the listing's mount flag already accept.
func identityOf(*dirRef) mountIdentity { return mountIdentity{} }

// openFileAt opens (or creates) a file inside an already-resolved directory,
// for the trash sidecar. os.Root.OpenFile honours O_CREATE|O_EXCL and refuses
// a name that would leave the tree.
func openFileAt(j fsx.Jail, parentRel, name string, flags int, perm os.FileMode) (*os.File, error) {
	return j.OpenFile(relJoin(parentRel, name), flags, perm)
}
