//go:build !linux

package fsops

import "os"

// openDir off Linux is a plain read-only open through the root. There is no
// O_DIRECTORY, so the "is this really a directory" answer comes from the fstat
// List does next; nothing but the dev loop runs here, and it has no fifos to be
// parked on. There is no O_PATH either, so the walk to the directory is
// os.Root's own — which asks for read permission on every directory on the way,
// where Linux now asks only for search. Stricter than the kernel rather than
// looser, and for the same reason statAt gives: this platform is the Windows
// dev box, whose ACLs have no "search but not read" shape to get wrong.
func openDir(rt *os.Root, rel, _ string) (*os.File, error) {
	return rt.OpenFile(rel, os.O_RDONLY, 0)
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

// statAt off Linux is os.Root's own stat. There is no O_PATH to walk the
// intermediate directories with, so the walk is os.Root's — which asks for read
// permission on every directory on the way, where Linux now asks only for
// search. That is stricter than the kernel rather than looser, and this
// platform is the Windows dev box, whose ACLs do not have a "search but not
// read" shape to get wrong in the first place.
func statAt(rt *os.Root, rel string, follow bool) (os.FileInfo, error) {
	if follow {
		return rt.Stat(rel)
	}
	return rt.Lstat(rel)
}

// readlinkAt off Linux is os.Root's own readlink, for the same reason.
func readlinkAt(rt *os.Root, rel string) (string, error) {
	return rt.Readlink(rel)
}

// openFinal off Linux is a plain read-only open through the root: there is no
// O_NOFOLLOW to ask for and no openat to ask it of. The no-follow rule itself
// is not lost — OpenRead classifies the name with lstat and verifies the
// descriptor it gets back with os.SameFile, which holds on every platform.
func openFinal(rt *os.Root, rel string) (*os.File, error) {
	return rt.OpenFile(rel, os.O_RDONLY, 0)
}

// checkTraversable off Linux asks the same question with the only tool there
// is: open the directory through the root and let the host's own access rules
// answer. There is no O_PATH to ask for a handle without asking for the
// contents, so this is stricter than the Linux version — which is the safe
// direction, and this platform is the dev loop rather than the NAS.
func checkTraversable(rt *os.Root, dir string) error {
	d, err := rt.Open(dir)
	if err != nil {
		return err
	}
	return d.Close()
}

// clearNonblock has nothing to undo where the open was blocking to begin with.
func clearNonblock(*os.File) error { return nil }
