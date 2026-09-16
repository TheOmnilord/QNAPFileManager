package breakglass

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// fileStrict is what the kernel says about the descriptor the loader opened —
// fstat(2), not a second lookup of a name that may by then mean something else
// (Astra r2 #1, INV-2: the kernel decides, the app only predicts).
//
// The key is the file that matters: it is what the emergency door terminates
// TLS with, so anybody who can read it can impersonate the door and anybody who
// can write it can BE the door. The certificate is public, so only its owner is
// checked — a certificate somebody else can write is still a pair somebody else
// controls.
func fileStrict(fi os.FileInfo, path string, isKey bool) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file (%s)", ErrUnsafeLocation, path, fi.Mode().Type())
	}
	if isKey {
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			// The mode is not echoed as a hint to widen it: the key is
			// regenerated at 0600 by this package, and a key that has been
			// widened has already been readable by somebody.
			return fmt.Errorf("%w: the break-glass key %s is mode %04o; group and other must have no access to it at all", ErrUnsafeLocation, path, mode)
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return ownerStrict(st.Uid, path)
}

// ownerStrict is the one ownership rule this file states, so there is only one
// to disagree with: root owns it.
//
// The euid clause is not a relaxation of that rule where it counts. The daemon
// and the CLI run as root, so their euid IS 0 and the rule is exactly "owned by
// root"; the clause only lets an unprivileged process — the Windows dev loop's
// Linux CI twin, a test running as uid 1001 — check files it created itself,
// rather than refuse every path it could possibly be given and prove nothing.
func ownerStrict(uid uint32, path string) error {
	if uid == 0 || uid == uint32(os.Geteuid()) {
		return nil
	}
	return fmt.Errorf("%w: %s is owned by uid %d, not root", ErrUnsafeLocation, path, uid)
}

// treeStrict walks from the deepest EXISTING ancestor of path up to the
// filesystem root (or to treeTop, which only a test sets) and refuses any
// directory that is not root-owned or that group or other can write.
//
// Every ancestor, not the parent: replacing a file is a property of its
// directory, and replacing a DIRECTORY is a property of the one above it. A
// root-owned 0700 directory reached through a user-writable one is a directory
// that user can swap wholesale, symlinks and all — which is exactly the bypass
// a lexical parent check could not see (Astra r2 #1). sshd walks the same chain
// for the same reason.
//
// The walk is bounded by the depth of the path: each step is filepath.Dir of
// the last, which is strictly shorter until it reaches the root.
func treeStrict(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: %s could not be resolved: %v", ErrUnsafeLocation, path, err)
	}
	dir, err := deepestExistingDir(abs)
	if err != nil {
		return err
	}
	for {
		if err := dirStrict(dir); err != nil {
			return err
		}
		if dir == treeTop {
			return nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// deepestExistingDir resolves every symlink in p and returns the directory the
// walk starts from: p's own directory when p exists, otherwise the nearest
// ancestor that does. A pair that has not been generated yet has no resolved
// path of its own, and the directory it is about to be written into is the one
// that has to be checked before a private key is published into it.
func deepestExistingDir(p string) (string, error) {
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			fi, serr := os.Lstat(resolved)
			if serr != nil {
				return "", fmt.Errorf("%w: %s could not be read: %v", ErrUnsafeLocation, resolved, serr)
			}
			if fi.IsDir() {
				return resolved, nil
			}
			return filepath.Dir(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s could not be resolved: %v", ErrUnsafeLocation, cur, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("%w: %s could not be resolved: %v", ErrUnsafeLocation, p, err)
		}
		cur = parent
	}
}

func dirStrict(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %s could not be read: %v", ErrUnsafeLocation, dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafeLocation, dir)
	}
	if mode := fi.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is mode %04o — group- or world-writable, so the key the emergency door serves can be replaced by somebody other than root", ErrUnsafeLocation, dir, mode)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return ownerStrict(st.Uid, dir)
	}
	return nil
}

// openNoFollow opens a path the caller has already resolved, refusing a final
// component that has BECOME a symlink since — the window between resolving and
// opening is the only place a swapped link could still land.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
