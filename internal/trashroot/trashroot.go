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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"syscall"

	"qnapfilemanager/internal/platform"
)

// wantOwner is the uid the trash directory must belong to. It is root because
// the root front-end is the only thing that creates it (PLAN.md decision 10),
// and because the owner of a sticky directory is EXEMPT from its restrictions:
// a 1777 directory somebody else owns has the mode bits of a safe trash and none
// of the safety, since its owner may rename and unlink everything inside it.
//
// It is a variable solely so this package's own tests can run as an ordinary
// user, where a temporary directory can never be root-owned — the same reason
// platform.mountProbe is one. Production never assigns to it, and the CI root
// job runs the tests with it at zero.
var wantOwner = 0

// DirName is the trash directory's name. The "@" prefix matches QNAP's own
// convention (@Recycle) so it sorts and hides alongside the system's, and the
// "." keeps it out of a default listing.
const DirName = ".@qfm_trash"

// Mode is what the directory must be: world-writable and sticky.
const Mode = os.FileMode(0o777) | os.ModeSticky

// tempPrefix is what an UNPUBLISHED trash directory is called (B3). The name is
// completed with 16 hex digits of randomness, so nothing can be waiting at it,
// and it keeps the ".@qfm_" prefix so a temporary directory left behind by a
// crash between the mkdir and the rename is recognisably ours.
const tempPrefix = DirName + ".tmp-"

// tempMode is what the directory is created as, and what step (c) demands to
// see: private to the process that made it, for the whole of its short life
// before it is published. A directory that is world-writable before it is sticky
// would be one anybody could fill.
const tempMode = os.FileMode(0o700)

// newTempName invents the unpublished name. It is a variable so this package's
// own tests can pin it and pre-plant something at it — the substitution B3 is
// about — the same reason wantOwner is one. Production never assigns to it.
var newTempName = randomTempName

func randomTempName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return tempPrefix + hex.EncodeToString(b[:]), nil
}

// errPublishedFirst is internal: the rename found the name already taken, so
// another process published a trash directory while this one was preparing its
// own. It is never a failure — the caller drops its temporary directory and
// validates what is there by the ordinary rules.
var errPublishedFirst = errors.New("trashroot: another process published the trash directory first")

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
//
// Creating it is a PUBLICATION rather than a mkdir at the final name: the
// directory is made under an unpredictable temporary name, proved and given its
// mode through its own descriptor, and only then renamed into place with
// RENAME_NOREPLACE (B3, see publish). What is already at the name is validated
// by the ordinary rules and never repaired.
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

	// F3: the mount root is opened as a directory WITHOUT following a symlink at
	// its final component, and everything below is addressed through that
	// descriptor — mkdirat, openat, fchmod, fstat — rather than by the pathname
	// a second time. The pathname was the flaw: os.Mkdir followed by os.Chmod is
	// two lookups of one name, and between them whatever owns the parent
	// directory can rename the new directory away and put a symlink in its
	// place. The chmod then landed 1777 on whatever that link pointed at, as
	// root.
	rootFD, oerr := openDirNoFollow(root)
	if oerr != nil {
		if refusal(oerr) {
			return "", false, fmt.Errorf("%s cannot be opened: %w", root, wrapNoTrash(oerr))
		}
		return "", false, fmt.Errorf("opening %s: %w", root, oerr)
	}
	defer rootFD.Close()

	// Two passes at most: the second is for the one race worth handling, where
	// another request published the directory while this one was preparing its
	// own (B3, errPublishedFirst).
	for attempt := 0; attempt < 2; attempt++ {
		d, lerr := openDirIn(rootFD, DirName)
		switch {
		case lerr == nil:
			err := usable(dir, d)
			d.Close()
			if err != nil {
				return "", false, err
			}
			return dir, false, nil
		case errors.Is(lerr, fs.ErrNotExist):
			// Fall through to the creation below.
		case notADirectory(lerr):
			// ELOOP or ENOTDIR: a symlink or a plain file is standing at the
			// name. Never followed, never replaced — following it would let
			// whoever planted it redirect a root-mode mkdir, and then a stream of
			// other people's deleted files, anywhere on the NAS.
			return "", false, fmt.Errorf("%s is not a directory we may use (%v): %w", dir, lerr, ErrUnsafeTrash)
		case refusal(lerr):
			return "", false, fmt.Errorf("%s cannot be read: %w", dir, wrapNoTrash(lerr))
		default:
			return "", false, fmt.Errorf("checking %s: %w", dir, lerr)
		}

		switch err := publish(rootFD, root, dir); {
		case err == nil:
			return dir, true, nil
		case errors.Is(err, errPublishedFirst):
			// Somebody else won the race. Their directory is validated by the
			// ordinary rules on the next pass, never repaired.
			continue
		default:
			return "", false, err
		}
	}
	return "", false, fmt.Errorf("%s kept changing underneath us: %w", dir, ErrUnsafeTrash)
}

// publish creates the trash directory and moves it into place (B3).
//
// The old shape was mkdirat(".@qfm_trash") immediately followed by
// openat(".@qfm_trash"): two lookups of one name, inside a directory whose
// children an ordinary user of a share can very often rename. Between the two,
// the directory just created could be moved aside and another REAL directory
// slid into the name — concretely QNAP's own root-owned @Recycle, which the
// openat then found, the fchmod turned 1777 and sticky, and Ensure adopted as
// the trash root. PLAN.md decision 10 says @Recycle is never written to; that
// sequence rewrote its mode as root and then filled it with deleted files.
//
// So the directory is published rather than named into existence:
//
//	(a) mkdirat a RANDOM name, ".@qfm_trash.tmp-<16 hex>", mode 0700, relative
//	    to the held mount-root descriptor — nobody can be waiting at a name
//	    nobody can predict, and nobody but us may write in a 0700 one;
//	(b) openat that name O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC;
//	(c) fstat the descriptor and demand what only a directory THIS PROCESS just
//	    made can show: a directory, owned by uid 0, permission bits of exactly
//	    0700, and a link count of 2 (empty). A non-root user cannot produce a
//	    root-owned directory at all, and no pre-existing directory worth
//	    substituting — @Recycle, a share — is both 0700 and empty;
//	(d) fchmod THROUGH that descriptor to 1777, then fstat it again, because
//	    what the kernel actually did is the only thing that counts (INV-2);
//	(e) renameat2 the temporary name onto ".@qfm_trash" with RENAME_NOREPLACE,
//	    so the kernel decides the race: either the name was free and we own it,
//	    or it was taken and errPublishedFirst sends the caller back to validate
//	    what is there;
//	(f) anything that fails removes the temporary directory again (AT_REMOVEDIR),
//	    so a refusal leaves no litter on the volume.
//
// The rename names both ends, so the last word goes back to a descriptor: the
// published name is re-opened and put through usable(). An attacker who managed
// to swap something in at the temporary name would have to have produced a
// root-owned sticky directory to survive that, which is the one thing an
// unprivileged attacker cannot do — and a failure there is ErrUnsafeTrash, never
// a repair.
func publish(rootFD *os.File, root, dir string) error {
	name, err := newTempName()
	if err != nil {
		return fmt.Errorf("naming a temporary directory in %s: %w", root, err)
	}
	tmp := path.Join(root, name)

	// (a) 0700, and 0777 only once the directory is proved to be ours: the mode
	// the trash ends up with is exactly the mode that makes it interesting to an
	// attacker, so it is applied as late as possible and through a descriptor.
	switch merr := mkdirIn(rootFD, name, 0o700); {
	case merr == nil:
	case errors.Is(merr, fs.ErrExist):
		// Sixteen hex digits of randomness cannot collide by accident, so
		// something is already standing at the name — which means the name was
		// not unpredictable after all. Nothing here is reused or removed.
		return fmt.Errorf("%s already exists, so it was not ours to create: %w", tmp, ErrUnsafeTrash)
	case refusal(merr):
		return fmt.Errorf("%s cannot be created: %w", dir, wrapNoTrash(merr))
	default:
		return fmt.Errorf("creating %s: %w", tmp, merr)
	}
	published := false
	defer func() {
		// (f)
		if !published {
			_ = removeDirIn(rootFD, name)
		}
	}()

	// (b), (c), (d)
	if err := prepare(rootFD, name, tmp); err != nil {
		return err
	}

	// (e)
	switch rerr := renameNoReplaceIn(rootFD, name, DirName); {
	case rerr == nil:
		published = true
	case errors.Is(rerr, fs.ErrExist):
		return errPublishedFirst
	case refusal(rerr):
		return fmt.Errorf("%s cannot be created: %w", dir, wrapNoTrash(rerr))
	default:
		return fmt.Errorf("publishing %s as %s: %w", tmp, dir, rerr)
	}

	d, oerr := openDirIn(rootFD, DirName)
	if oerr != nil {
		return fmt.Errorf("verifying %s: %w", dir, oerr)
	}
	err = usable(dir, d)
	d.Close()
	return err
}

// prepare is steps (b), (c) and (d) of the publication: the temporary directory
// is opened, proved to be the one this process just made, given the trash mode
// through its own descriptor, and re-examined.
//
// Nothing here is asked of a pathname. The openat is relative to the held
// mount-root descriptor and every question afterwards is an fstat of the
// descriptor that openat returned, so a name swapped in behind us describes a
// different object that this function never touches.
func prepare(rootFD *os.File, name, tmp string) error {
	d, err := openDirIn(rootFD, name)
	if err != nil {
		return fmt.Errorf("verifying %s: %w", tmp, err)
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("checking %s: %w", tmp, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory: %w", tmp, ErrUnsafeTrash)
	}
	if owner, ok := ownerOf(fi); ok && owner != wantOwner {
		return fmt.Errorf("%s belongs to uid %d rather than to uid %d, so it is not the directory this process made: %w",
			tmp, owner, wantOwner, ErrUnsafeTrash)
	}
	// The permission bits are only real where the kernel keeps them: off Linux a
	// FileInfo answers a synthesised 0777 for every directory, which is the same
	// platform gate the sticky assertion uses (INV-2 — the dev box is not the
	// kernel, and the CI Linux jobs run the real thing).
	if stickyEnforced {
		if perm := fi.Mode().Perm(); perm != tempMode.Perm() {
			return fmt.Errorf("%s was created %#o and is now %#o, so it is not the directory this process made: %w",
				tmp, uint32(tempMode.Perm()), uint32(perm), ErrUnsafeTrash)
		}
	}
	if n, ok := nlinkOf(fi); ok && n != 2 {
		// A directory with "." and its parent's entry and nothing else. Anything
		// an attacker would gain by substituting a REAL directory here — a share,
		// @Recycle — has subdirectories, and therefore more links.
		return fmt.Errorf("%s has %d links rather than the 2 of the empty directory this process made: %w",
			tmp, n, ErrUnsafeTrash)
	}
	if err := applyMode(d, tmp, Mode); err != nil {
		return fmt.Errorf("setting %s to 1777: %w", tmp, err)
	}
	// The re-fstat is not ceremony: a filesystem that silently drops the sticky
	// bit must not be handed other people's deleted files.
	return usable(tmp, d)
}

// usable decides whether the directory a descriptor refers to may serve as the
// trash directory. Every question is answered by fstat on that descriptor, never
// by an lstat of the name (F3).
func usable(dir string, d *os.File) error {
	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("checking %s: %w", dir, err)
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink: %w", dir, ErrUnsafeTrash)
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory: %w", dir, ErrUnsafeTrash)
	case stickyEnforced && fi.Mode()&fs.ModeSticky == 0:
		return fmt.Errorf("%s is not sticky (mode %v): %w", dir, fi.Mode().Perm(), ErrUnsafeTrash)
	}
	if owner, ok := ownerOf(fi); ok && owner != wantOwner {
		return fmt.Errorf("%s belongs to uid %d rather than to uid %d, and the owner of a sticky directory "+
			"may rename and unlink everything inside it: %w", dir, owner, wantOwner, ErrUnsafeTrash)
	}
	return nil
}

// notADirectory reports the two errnos that mean "something that is not a
// directory is standing at this name": ELOOP from O_NOFOLLOW meeting a symlink,
// and ENOTDIR from O_DIRECTORY meeting anything else.
func notADirectory(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR)
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
