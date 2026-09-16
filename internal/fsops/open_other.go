//go:build !linux

package fsops

import (
	"os"

	"qnapfilemanager/internal/fsx"
)

// The jail handle off Linux is os.Root itself (fsx.Jail is an alias for
// *os.Root there), so every helper here is one of its methods. That is the
// whole difference between the two platforms: there is no O_PATH to ask the
// kernel for a handle without also asking for the right to read what it names,
// and no openat to walk with, so the walk os.Root does is the walk — read
// permission on the jail base and on every directory on the way, where Linux
// now asks only for search. Stricter than the kernel rather than looser, which
// is the safe direction, and this platform is the Windows dev box, whose ACLs
// have no "search but not read" shape to get wrong.

// openDir off Linux is a plain read-only open through the root. There is no
// O_DIRECTORY, so the "is this really a directory" answer comes from the fstat
// List does next; nothing but the dev loop runs here, and it has no fifos to be
// parked on.
func openDir(j fsx.Jail, rel, _ string) (*os.File, error) {
	return j.OpenFile(rel, os.O_RDONLY, 0)
}

// readDirInfos off Linux is os.File.ReadDir and DirEntry.Info, which is what
// the shared listing used everywhere before Linux needed its own. The file
// openDir returns here comes from os.Root, and an os.Root DirEntry loads its
// metadata relative to the directory descriptor rather than through a path
// (newUnixDirent in $GOROOT/src/os/file_unix.go takes the lstatat branch when
// the parent was opened in a Root) — so the swap-the-directory-for-a-symlink
// race the Linux version exists to close does not arise on this path either.
//
// The showHidden argument is Linux's alone: there the metadata costs three
// syscalls this package makes itself and is worth not making for a name that
// will be dropped, while here it is one DirEntry.Info on the dev box. The
// entries handed back are the same either way, which is the point — the Linux
// version skips the stat, not the entry.
func readDirInfos(f *os.File, n int, _ bool) ([]dirEntryInfo, error) {
	des, readErr := f.ReadDir(n)
	out := make([]dirEntryInfo, 0, len(des))
	for _, de := range des {
		fi, err := de.Info()
		out = append(out, dirEntryInfo{name: de.Name(), info: fi, err: err})
	}
	return out, readErr
}

// statAt off Linux is os.Root's own lstat. There is no follow variant on
// either platform: following a symlink means checking where it lands, and
// resolve() is the only thing here that knows how (see statFollowing).
func statAt(j fsx.Jail, rel string) (os.FileInfo, error) {
	return j.Lstat(rel)
}

// itemRef off Linux holds nothing. There is no O_PATH here to open an inode
// without opening the file, and a Windows handle on a directory is a handle that
// can stand in the way of renaming it — which is precisely what the trash is
// about to do with the item this would be pinning.
//
// Nothing is lost that this platform had: the identity comparison the pin exists
// to protect cannot be made off Linux at all (sameObject reports nothing), so a
// reference that is only a stat is exactly as far as the dev box ever gets.
// INV-2 — the CI Linux jobs hold the real descriptor.
type itemRef struct {
	fi os.FileInfo
}

// openItemRef off Linux is statAt with somewhere to put the answer.
func openItemRef(j fsx.Jail, rel string) (*itemRef, error) {
	fi, err := statAt(j, rel)
	if err != nil {
		return nil, err
	}
	return &itemRef{fi: fi}, nil
}

func (ref *itemRef) close() {}

// restat does nothing off Linux: there is no descriptor behind a held item
// here, so there is nothing to re-read that would not simply be the pathname
// again — and re-stating by name is the one thing the caller wanted to avoid.
// The stale reading is kept, which is the same INV-2 degradation every identity
// check in this file accepts; the CI Linux jobs hold the real descriptor.
func (ref *itemRef) restat() {}

// refFD is nil off Linux: there is no descriptor behind a held item here, so
// every caller falls back to addressing the entry by name through os.Root.
func refFD(ref *itemRef) *os.File { return nil }

// itemRefIn off Linux is statAt of the entry beneath an already-held directory.
// There is no openat to address it relative to a descriptor, so the name is
// joined onto the directory's own jail-relative path and os.Root resolves it —
// the same degradation every other helper here accepts (INV-2).
func itemRefIn(d *dirRef, name string) (*itemRef, error) {
	fi, err := statAt(d.j, relJoin(d.rel, name))
	if err != nil {
		return nil, err
	}
	return &itemRef{fi: fi}, nil
}

// itemIdentityOf has almost nothing to report off Linux: there is no st_dev
// behind a Windows FileInfo (devOf) and no mount id to ask a handle for, so
// every path answers with the zero identity and the move pre-flight predicts
// "same filesystem" for everything.
//
// That is the right degradation rather than a gap. The prediction only ever
// WARNS — the kernel's own EXDEV is what the engine acts on — and the dev loop
// has one filesystem, so a prediction of "this will be an instant rename" is
// also the truth there. INV-2: the kernel that decides is the NAS's, and the CI
// Linux and ZFS jobs are where this is measured for real.
func itemIdentityOf(ref *itemRef) mountIdentity {
	var id mountIdentity
	if ref != nil && ref.fi != nil {
		id.dev, id.hasDev = devOf(ref.fi)
	}
	return id
}

// readlinkAt off Linux is os.Root's own readlink.
func readlinkAt(j fsx.Jail, rel string) (string, error) {
	return j.Readlink(rel)
}

// openFinal off Linux is a plain read-only open through the root: there is no
// O_NOFOLLOW to ask for and no openat to ask it of. The no-follow rule itself
// is not lost — OpenRead classifies the name with lstat and verifies the
// descriptor it gets back with os.SameFile, which holds on every platform.
func openFinal(j fsx.Jail, rel string) (*os.File, error) {
	return j.OpenFile(rel, os.O_RDONLY, 0)
}

// checkTraversable off Linux asks the same question with the only tool there
// is: open the directory through the root and let the host's own access rules
// answer. There is no O_PATH to ask for a handle without asking for the
// contents, so this is stricter than the Linux version — which is the safe
// direction, and this platform is the dev loop rather than the NAS.
func checkTraversable(j fsx.Jail, dir string) error {
	d, err := j.Open(dir)
	if err != nil {
		return err
	}
	return d.Close()
}

// clearNonblock has nothing to undo where the open was blocking to begin with.
func clearNonblock(*os.File) error { return nil }
