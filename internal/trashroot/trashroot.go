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
	"io"
	"io/fs"
	"os"
	"path"
	"syscall"
	"time"

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

// tempMaxAge is how far the temporary directory's mtime may sit from the
// mkdirat that made it (R3-BA1, round-3 backend review).
//
// It is the one question a substituted directory cannot answer. A rename does
// NOT refresh an inode's mtime, and an unprivileged attacker cannot set the
// mtime of a root-owned directory (utimensat needs ownership or CAP_FOWNER), so
// any pre-existing directory slid into the temporary name carries the timestamp
// of whenever it was really made — minutes, days or years ago — while the one
// this process just created carries now. Five seconds is slack for a coarse
// filesystem timestamp granularity and a loaded NAS, not a design margin: the
// whole window between the mkdirat and the fstat is a handful of syscalls.
const tempMaxAge = 5 * time.Second

// maxPublishAttempts bounds how many temporary directories one Ensure may
// create when the one it made is refused for its TIMESTAMP alone (R4-1,
// errStale). Each attempt uses a new random name and a fresh time reference, so
// a stall or a clock step that hit the first one is unlikely to hit three; after
// that the refusal stands, because a timing problem this persistent cannot be
// told apart from the substitution the rule exists to catch.
const maxPublishAttempts = 3

// Logf is where this package reports what it cannot return to its caller. The
// default is a no-op and the daemon points it at its own log at startup
// (cmd/qnapfilemanager, runServe).
//
// Exactly one thing needs it (R4-2). When another process publishes the trash
// directory first, Ensure drops its own temporary directory and returns the
// winner — a SUCCESS — so any diagnostic attached to that attempt, including
// "the temporary directory could not be proved to be ours and was left in
// place", has no error to travel out on and would otherwise be lost. That
// sentence is how an operator who finds an abandoned .@qfm_trash.tmp-* on a
// volume learns where it came from, so it is logged before it is discarded.
//
// Assign it once, before anything can call Ensure: Ensure runs on request
// goroutines, so the function it holds must also be safe for concurrent use
// (log.Logger.Printf is).
var Logf = func(string, ...any) {}

// newTempName invents the unpublished name. It is a variable so this package's
// own tests can pin it and pre-plant something at it — the substitution B3 is
// about — the same reason wantOwner is one. Production never assigns to it.
var newTempName = randomTempName

// now is time.Now, and it is the reference the freshness rule is measured
// against. It is a variable for the same reason newTempName is: R4-1 is about
// what happens when that reference is wrong — a filesystem that stalls between
// the reading and the mkdirat, or a wall-clock step in that window — and
// skewing it is the only way a test can produce either without waiting.
// Production never assigns to it.
var now = time.Now

// publishRename is step (e), the no-replace rename. It is a variable for the
// same reason newTempName is: R3-BA2 is about what the FAILURE path does after
// the provenance check has passed, and the instant just before the publication
// fails is the only place a test can stand to simulate the attacker's rename at
// the mount root. Production never assigns to it.
var publishRename = renameNoReplaceIn

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

// errStale is internal too, and it is the FRESHNESS-ONLY refusal (R4-1).
//
// A directory reaches it having answered every question a substitution cannot:
// it is a directory, it belongs to uid 0 — which an unprivileged attacker
// cannot arrange at all — its permission bits are exactly the 0700 it was
// created with, and reading it through its own descriptor yields nothing. Only
// the timestamp is wrong, and the timestamp is the one property a legitimate
// directory can fail by accident: FileInfo.ModTime carries no monotonic
// reading, so the comparison is of WALL times, and a NAS that stalls longer
// than tempMaxAge before the inode exists, or a clock step in that window,
// makes the real thing look stale.
//
// So it is a distinct error rather than an ErrUnsafeTrash: the directory is
// still refused and still never used, but Ensure may drop it and publish a new
// one under a new name against a fresh reference (maxPublishAttempts) instead
// of failing a delete that nothing attacked. Every OTHER provenance failure
// stays exactly what it was — refused, never repaired, never retried.
var errStale = errors.New("trashroot: the temporary directory's timestamp is not fresh")

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
// by the ordinary rules and never repaired, and a publication refused for the
// temporary directory's TIMESTAMP alone — the one provenance rule a legitimate
// directory can fail by accident — is retried under a new name, at most
// maxPublishAttempts times in all (R4-1).
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

	// The loop exists for two bounded retries, each of which has to take a fresh
	// look at the published name before it tries again:
	//
	//   - another request published the directory while this one was preparing
	//     its own (B3, errPublishedFirst). One more pass, which validates the
	//     winner by the ordinary rules and never repairs it;
	//   - the directory this call just made was refused for its TIMESTAMP alone
	//     (R4-1, errStale). Up to maxPublishAttempts publications in total, each
	//     under a new random name and against a fresh time reference.
	//
	// Every pass publishes at most once and every outcome either returns or
	// consumes one of the two bounds, so the loop cannot run more than
	// maxPublishAttempts times.
	raced := false
	publishes := 0
	for {
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

		publishes++
		switch err := publish(rootFD, root, dir); {
		case err == nil:
			return dir, true, nil
		case errors.Is(err, errPublishedFirst):
			// Somebody else won the race. Their directory is validated by the
			// ordinary rules on the next pass, never repaired.
			//
			// R4-2: this error is about to be DISCARDED — the next pass returns the
			// winner and this call succeeds — and it may carry publish's cleanup
			// diagnostic, the one that says a temporary directory could not be
			// proved to be ours and was left behind. Nothing else will ever report
			// it, so it goes to the log here, verbatim, before the retry.
			Logf("%v", err)
			if raced {
				return "", false, fmt.Errorf("%s kept changing underneath us: %w", dir, ErrUnsafeTrash)
			}
			raced = true
		case errors.Is(err, errStale):
			// R4-1: a freshness-only refusal. The directory was root-owned, exactly
			// 0700 and empty, so nothing was substituted; its cleanup has already
			// run (or said why it could not), and the answer is a new name and a
			// new time reference rather than a failed delete.
			if publishes >= maxPublishAttempts {
				return "", false, fmt.Errorf("%v; %d attempts to create %s each produced a directory whose "+
					"timestamp was that far from the mkdirat that made it, which is a stalled filesystem or a "+
					"stepped clock rather than a substitution — but at this point the two cannot be told "+
					"apart: %w", err, publishes, dir, ErrUnsafeTrash)
			}
			Logf("trashroot: publishing %s again under a new name: %v", dir, err)
		default:
			return "", false, err
		}
	}
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
//	(c) fstat the descriptor and READ the directory through it, demanding what
//	    only a directory THIS PROCESS just made can show: a directory, owned by
//	    uid 0, permission bits of exactly 0700, genuinely empty, and with an
//	    mtime within tempMaxAge of the mkdirat (see provenance — R3-BA1). A
//	    failure of the LAST of those alone is errStale, which the caller retries
//	    under a new name rather than refusing outright (R4-1); a failure of any
//	    other is ErrUnsafeTrash and final;
//	(d) fchmod THROUGH that descriptor to 1777, then fstat it again, because
//	    what the kernel actually did is the only thing that counts (INV-2);
//	(e) renameat2 the temporary name onto ".@qfm_trash" with RENAME_NOREPLACE,
//	    so the kernel decides the race: either the name was free and we own it,
//	    or it was taken and errPublishedFirst sends the caller back to validate
//	    what is there;
//	(f) anything that fails removes the temporary directory again (AT_REMOVEDIR)
//	    — but ONLY the inode provenance proved was ours, re-identified on a fresh
//	    O_NOFOLLOW open (R3-BA2). The old cleanup removed the temporary PATHNAME,
//	    which an attacker who can rename at the mount root could by then have
//	    pointed at an unrelated empty directory of their choosing, making a failed
//	    publication into a root-mode rmdir primitive. Litter is the lesser evil,
//	    so an identity that no longer matches leaves everything alone and says so
//	    in the error the caller logs.
//
// The rename names both ends, so the last word goes back to a descriptor: the
// published name is re-opened and put through usable(). An attacker who managed
// to swap something in at the temporary name would have to have produced a
// root-owned sticky directory to survive that, which is the one thing an
// unprivileged attacker cannot do — and a failure there is ErrUnsafeTrash, never
// a repair.
func publish(rootFD *os.File, root, dir string) (retErr error) {
	name, err := newTempName()
	if err != nil {
		return fmt.Errorf("naming a temporary directory in %s: %w", root, err)
	}
	tmp := path.Join(root, name)

	// (a) 0700, and 0777 only once the directory is proved to be ours: the mode
	// the trash ends up with is exactly the mode that makes it interesting to an
	// attacker, so it is applied as late as possible and through a descriptor.
	//
	// createdAt is read immediately before the mkdirat and is the reference the
	// mtime freshness rule is measured against (R3-BA1). When it turns out to be
	// wrong — a stall or a clock step between here and the inode — the refusal is
	// errStale and Ensure tries again with a new name and a new reading (R4-1).
	createdAt := now()
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
	// made is the identity of the directory provenance accepted — or, for a
	// freshness-only refusal, the identity it refused (R4-1) — and it is the ONLY
	// thing the cleanup below is allowed to remove (R3-BA2).
	var made os.FileInfo
	defer func() {
		// (f)
		if published {
			return
		}
		if removeIfStillOurs(rootFD, name, made) || retErr == nil {
			// retErr == nil is unreachable — every path that leaves published
			// false returns an error — but a %w of nil would turn a bug here into
			// a nonsense error rather than a loud one.
			return
		}
		// Nothing was removed, because nothing at that name could be proved to be
		// the directory this process made. The caller logs this error verbatim
		// server-side (ensureTrashRoots → logRaw), which is where an operator
		// finding an abandoned .@qfm_trash.tmp-* on a volume learns why.
		retErr = fmt.Errorf("%w (the temporary directory %s could not be proved to be ours and was left in place; "+
			"a rename at the mount root may have replaced it)", retErr, tmp)
	}()

	// (b), (c), (d)
	made, err = prepare(rootFD, name, tmp, createdAt)
	if err != nil {
		return err
	}

	// (e)
	switch rerr := publishRename(rootFD, name, DirName); {
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

// removeIfStillOurs is the cleanup half of R3-BA2, and it reports whether it
// removed anything.
//
// made is what the provenance check accepted, or nil if the publication never
// got that far — and a nil made removes NOTHING: the inode standing at that name
// was never proved to be this process's, so a root-mode rmdir of it is a
// primitive handed to whoever can rename at the mount root, not a tidy-up.
//
// Even with a made in hand the name is re-opened O_NOFOLLOW and fstat'd, and the
// removal happens only if it is still the same (dev, ino). That still leaves the
// width of the unlinkat itself, which no pathname-based removal on Linux can
// close (PLAN.md §2.7) — but by then the attacker has to win a race whose prize
// is the deletion of an empty directory they already control.
func removeIfStillOurs(rootFD *os.File, name string, made os.FileInfo) bool {
	if made == nil {
		return false
	}
	d, err := openDirIn(rootFD, name)
	if err != nil {
		// ENOENT: somebody already took it away. Anything else: not a directory
		// we may touch. Either way there is nothing of ours to remove.
		return false
	}
	fi, serr := d.Stat()
	d.Close()
	if serr != nil || !os.SameFile(made, fi) {
		return false
	}
	return removeDirIn(rootFD, name) == nil
}

// prepare is steps (b), (c) and (d) of the publication: the temporary directory
// is opened, proved to be the one this process just made, given the trash mode
// through its own descriptor, and re-examined. It returns the FileInfo
// provenance accepted, which is the identity the failure cleanup re-checks
// before it removes anything (R3-BA2) — and, uniquely, the identity it REFUSED
// when the refusal was errStale (R4-1), because that directory has to be taken
// away before the publication is tried again.
//
// Nothing here is asked of a pathname. The openat is relative to the held
// mount-root descriptor and every question afterwards is an fstat or a readdir
// of the descriptor that openat returned, so a name swapped in behind us
// describes a different object that this function never touches.
func prepare(rootFD *os.File, name, tmp string, createdAt time.Time) (os.FileInfo, error) {
	d, err := openDirIn(rootFD, name)
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", tmp, err)
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", tmp, err)
	}
	if err := provenance(d, tmp, fi, createdAt); err != nil {
		if errors.Is(err, errStale) {
			// R4-1: the identity travels out with the refusal, so publish's cleanup
			// may remove this directory before Ensure publishes a new one. It is an
			// identity worth acting on even though the timestamp is unexplained:
			// the directory is root-owned, exactly 0700 and empty, and if it IS a
			// substitution then the attacker renamed their own directory here to
			// make it one — which already tore it out of wherever it was — so
			// rmdir'ing an empty directory of theirs adds nothing to what they have
			// done, while leaving it behind litters the volume on every stall.
			return fi, err
		}
		return nil, err
	}
	if err := applyMode(d, tmp, Mode); err != nil {
		return nil, fmt.Errorf("setting %s to 1777: %w", tmp, err)
	}
	// The re-fstat is not ceremony: a filesystem that silently drops the sticky
	// bit must not be handed other people's deleted files.
	if err := usable(tmp, d); err != nil {
		return nil, err
	}
	return fi, nil
}

// provenance is step (c): the four questions asked of the temporary directory's
// own descriptor before a root fchmod is aimed at it.
//
// The original shape asked for owner 0, perm 0700 and a link count of 2, and the
// round-3 backend review (R3-BA1) took that apart: nlink == 2 is also true of a
// directory full of REGULAR FILES, and any root-owned 0700 empty directory made
// by some other root process on the volume passes all three. An attacker who can
// rename at the mount root and who learns the random temporary name could then
// move ours aside and put such a directory in its place, and root would fchmod
// it to 1777 and adopt it as the trash. So two of the three are replaced:
//
//   - emptiness is READ, not inferred. The directory is read through the held
//     descriptor and must yield nothing at all (Readdirnames omits "." and
//     ".."), which no directory holding files of any kind can survive;
//   - freshness is demanded, and asked LAST. A rename does not refresh an
//     inode's mtime and an unprivileged attacker cannot set the mtime of a
//     root-owned directory, so a substituted directory carries whenever it was
//     really created while ours carries the instant of the mkdirat a few
//     syscalls ago (tempMaxAge). It is also the only one of the four a real
//     directory can fail without an attacker — a stall or a clock step — which
//     is why failing it alone is errStale and retryable (R4-1).
//
// Owner and permission bits stay exactly as they were: uid 0 (a non-root user
// cannot produce a root-owned directory at all) and precisely 0700.
//
// What is left after this is written up as PLAN.md §2.7, because it cannot be
// closed by checking harder: creation by PATHNAME inside a directory the
// attacker can rename in is not atomic on Linux.
func provenance(d *os.File, tmp string, fi os.FileInfo, createdAt time.Time) error {
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
	// Emptiness, read through the descriptor (R3-BA1). One name is enough: a
	// directory this process created a moment ago inside a 0700 it alone may
	// write has nothing in it, so the first entry is already a refusal.
	switch names, rerr := d.Readdirnames(1); {
	case rerr != nil && !errors.Is(rerr, io.EOF):
		return fmt.Errorf("reading %s: %w", tmp, rerr)
	case len(names) > 0:
		return fmt.Errorf("%s already holds entries, so it is not the empty directory this process made: %w",
			tmp, ErrUnsafeTrash)
	}
	// Freshness (R3-BA1), and the LAST question asked — which is what makes a
	// failure here a freshness-ONLY failure, errStale rather than ErrUnsafeTrash
	// (R4-1). Everything above has already passed, so this is a directory only
	// root could have made and only its timestamp is unaccounted for; since
	// ModTime carries no monotonic reading, a stalled filesystem or a stepped
	// wall clock produces exactly this. Still fail-closed — the directory is
	// refused and never used — but Ensure may publish another one rather than
	// turn a slow NAS into a failed delete.
	if age := createdAt.Sub(fi.ModTime()); age > tempMaxAge || age < -tempMaxAge {
		return fmt.Errorf("%s was last modified %v from the mkdirat that created it, which is more than %v, "+
			"so it cannot be shown to be the directory this process made: %w", tmp, age, tempMaxAge, errStale)
	}
	return nil
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
