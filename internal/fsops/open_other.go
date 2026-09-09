//go:build !linux

package fsops

import "os"

// openDirFlags off Linux is a plain read-only open: there is no O_DIRECTORY, so
// the "is this really a directory" answer comes from the fstat that follows.
// Nothing but the dev loop runs here, and it has no fifos to be parked on.
func openDirFlags() int { return os.O_RDONLY }

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
