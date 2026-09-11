// Package trashroot creates the one directory the root front-end is allowed to
// write anywhere on a user's storage: <mountRoot>/.@qfm_trash, mode 1777
// (PLAN.md decision 10, identity plan §4.2).
//
// It is a deliberate, single exception to INV-1. A non-admin must be able to
// trash a file, and the directory a delete renames into has to exist before
// their worker — which has only their own permissions — can move anything into
// it. So the front-end makes it, once, on demand, sticky, and the caller audits
// the creation as a milestone: creating a world-writable directory inside a
// share is a security-relevant act and is disclosed rather than hidden.
//
// The sticky bit is the whole security model, and it is the kernel's, not
// ours: on a 1777 directory a user may create entries and may only rename or
// unlink their own (INV-2). Per-uid subdirectories under it are the worker's
// business, not this package's.
//
// What this package will not do is as important as what it does. It never
// walks, never recurses, never touches an existing file, and never reuses
// anything that is not already a sticky directory — a symlink or a plain file
// at that name is refused outright, because following it would let whoever
// planted it redirect a root-mode mkdir (and then a stream of other people's
// deleted files) anywhere on the NAS.
package trashroot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"syscall"

	"qnapfilemanager/internal/platform"
)

// DirName is the trash directory's name. The "@" prefix matches QNAP's own
// convention (@Recycle) so it sorts and hides alongside the system's, and the
// "." keeps it out of a default listing.
const DirName = ".@qfm_trash"

// Mode is what the directory must be: world-writable and sticky.
const Mode = os.FileMode(0o777) | os.ModeSticky

var (
	// ErrNoTrash: this path has no usable same-device trash root — it is not on
	// a storage filesystem, or the filesystem will not take the directory. The
	// caller must treat the delete as permanent and confirm it as such.
	ErrNoTrash = errors.New("no trash directory is available for this location")
	// ErrUnsafeTrash: something already occupies the trash name and is not a
	// directory we may use. Never worked around, never replaced.
	ErrUnsafeTrash = errors.New("the trash directory name is occupied by something else")
)

// Ensure returns the trash directory for osPath, creating it if it is not
// there. created reports whether this call made it, so the caller can write the
// audit milestone exactly once.
//
// The root is the nearest enclosing Storage, non-network mount — the volume
// root on QTS, the share's own dataset on QuTS hero — which is what makes the
// delete that follows a same-device rename rather than a copy. A path with no
// such mount (/proc, a tmpfs, an NFS share) yields ErrNoTrash, and so does a
// read-only or permission-refusing filesystem: in every one of those cases the
// honest answer is that there is no trash here, not a half-made directory.
func Ensure(plat *platform.Platform, osPath string) (trashDir string, created bool, err error) {
	if plat == nil {
		return "", false, fmt.Errorf("no mount table is available: %w", ErrNoTrash)
	}
	root, caps, ok := plat.TrashRootFor(osPath)
	if !ok {
		return "", false, fmt.Errorf("%s is not on a storage filesystem: %w", osPath, ErrNoTrash)
	}
	if !caps.Storage || caps.Network {
		// TrashRootFor already refuses these; belt and braces, because a wrong
		// answer here is a 1777 directory on a network mount.
		return "", false, fmt.Errorf("%s is on a %s mount: %w", osPath, caps.FSType, ErrNoTrash)
	}
	dir := path.Join(root, DirName)

	// Two passes at most: the second is for the one race worth handling, where
	// another request created the directory between the Lstat and the Mkdir.
	for attempt := 0; attempt < 2; attempt++ {
		fi, lerr := os.Lstat(dir)
		switch {
		case lerr == nil:
			if err := usable(dir, fi); err != nil {
				return "", false, err
			}
			return dir, false, nil
		case errors.Is(lerr, fs.ErrNotExist):
			// Fall through to the creation below.
		case refusal(lerr):
			return "", false, fmt.Errorf("%s cannot be read: %w", dir, wrapNoTrash(lerr))
		default:
			return "", false, fmt.Errorf("checking %s: %w", dir, lerr)
		}

		// 0777 is reduced by the daemon's umask, so the mode is set explicitly
		// afterwards; the sticky bit cannot be passed to mkdir(2) through
		// os.Mkdir at all. The window between the two is a directory owned by
		// root that is not yet world-writable, which fails closed: a user's
		// worker cannot rename into it until the chmod lands.
		merr := os.Mkdir(dir, 0o777)
		switch {
		case merr == nil:
		case errors.Is(merr, fs.ErrExist):
			continue // somebody else won; re-check what they made
		case refusal(merr):
			return "", false, fmt.Errorf("%s cannot be created: %w", dir, wrapNoTrash(merr))
		default:
			return "", false, fmt.Errorf("creating %s: %w", dir, merr)
		}

		if err := os.Chmod(dir, Mode); err != nil {
			return "", false, fmt.Errorf("setting %s to 1777: %w", dir, err)
		}
		// Re-Lstat rather than trust the chmod: what the kernel actually did is
		// the only thing that matters (INV-2), and a filesystem that silently
		// drops the sticky bit must not be handed other people's deleted files.
		fi, lerr = os.Lstat(dir)
		if lerr != nil {
			return "", false, fmt.Errorf("verifying %s: %w", dir, lerr)
		}
		if err := usable(dir, fi); err != nil {
			return "", false, err
		}
		return dir, true, nil
	}
	return "", false, fmt.Errorf("%s kept changing underneath us: %w", dir, ErrUnsafeTrash)
}

// usable decides whether an existing entry may serve as the trash directory.
func usable(dir string, fi fs.FileInfo) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink: %w", dir, ErrUnsafeTrash)
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory: %w", dir, ErrUnsafeTrash)
	case stickyEnforced && fi.Mode()&fs.ModeSticky == 0:
		return fmt.Errorf("%s is not sticky (mode %v): %w", dir, fi.Mode().Perm(), ErrUnsafeTrash)
	}
	return nil
}

// refusal reports the errors that mean "this filesystem will not have it" as
// opposed to "something went wrong": a read-only mount and a permission
// refusal are both simply an absence of trash, which the caller handles by
// deleting permanently with a confirmation.
func refusal(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)
}

func wrapNoTrash(err error) error {
	return fmt.Errorf("%v: %w", err, ErrNoTrash)
}
