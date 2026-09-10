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
