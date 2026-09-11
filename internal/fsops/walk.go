package fsops

// The M2 tree walk: the one piece of recursion in the worker, shared by the
// pre-scan that gives a delete its denominator, by the recursive delete itself
// and by the folder-size probe.
//
// Three properties fix its shape.
//
//   - It never follows a symlink. A symlink is an item — it is visited, counted
//     and (by a delete) unlinked as the link it is — and it is never descended
//     into. That is what keeps "delete this folder" from reaching through a link
//     into /etc, and it is enforced by the kernel rather than by a check here:
//     every step down is an openat with O_NOFOLLOW|O_DIRECTORY relative to the
//     directory descriptor the walk is already holding (see walk_linux.go).
//   - It crosses a mount point only when it is told to and only where
//     platform.MayCross agrees (PLAN.md decision 9). With CrossMounts off it
//     never leaves the filesystem it started on; with it on it may descend into
//     a mount of the same storage domain — every share of one ZFS pool — and
//     still never into /proc, /sys, /dev, a tmpfs, a USB disk, another pool or a
//     network mount.
//   - A per-item failure is a warning, never the end of the job. EACCES on one
//     subdirectory of a million-file tree must not abandon the other 999 999
//     items; the visitor is told and the walk carries on. Only the context being
//     cancelled, or the visitor itself returning an error, stops it.
//
// Nothing here decides policy. The protected-path table, the read-only toggle
// and the confirmation ladder live in the root front-end's guard, before the RPC
// (INV-1). This file makes syscalls and reports what the kernel said.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// maxWalkDepth bounds the recursion. Every level holds one open directory
// descriptor for as long as its children are being visited, so an unbounded
// descent is an fd leak with a stack in front of it; a tree deeper than this is
// reported as an item-level failure and left alone. Real trees are two orders
// of magnitude shallower — PATH_MAX itself stops a Linux pathname at 4096 bytes.
const maxWalkDepth = 256

// maxDirPasses is the walker's own backstop on the re-read loop a mutating
// visitor can ask for (errRetryDir). The visitor is expected to give up long
// before this; the bound only exists so a filesystem that keeps handing back
// entries nobody can remove cannot spin here forever.
const maxDirPasses = 1000

// errRetryDir is a mutating visitor's request, from its Post hook, to read the
// directory again and re-visit whatever is still in it.
//
// It exists because removing entries from a directory that is being enumerated
// is not safe on every filesystem: ext4's htree renumbers the directory offsets
// a getdents cookie refers to, so entries can be skipped after a delete, and the
// rmdir at the end then fails with ENOTEMPTY for a directory the walk believed
// it had emptied. Reading it again from a fresh handle is how os.RemoveAll
// solves the same problem, and the retry is the visitor's decision rather than
// the walker's because only the visitor knows whether the last pass actually
// removed anything.
var errRetryDir = errors.New("fsops: read this directory again")

// WalkOptions are the knobs Walk itself understands.
type WalkOptions struct {
	// CrossMounts lets the walk descend into a child directory that is a mount
	// point — "include mounted sub-folders" in the UI — and then only where
	// Platform.MayCross agrees that the two filesystems are one storage domain.
	// With it off, a mount point is visited as an item and never descended into.
	CrossMounts bool

	// Mutating says the visitor removes entries as it goes, which is what makes
	// errRetryDir meaningful: without it a Post hook asking for another pass is
	// refused, because a read-only walk that re-read a directory would simply
	// visit everything twice.
	Mutating bool

	// Protect refuses the never-write components the front-end guard refuses,
	// per component, as the recursion reaches them (F10, never_write.go). The
	// guard only ever sees a job's root paths, so without this a delete of a
	// share would walk straight into its .zfs snapshot directory and its
	// @Recycle bin — neither of which the guard was ever asked about.
	Protect Protect
}

// WalkItem is one thing the walk reached.
type WalkItem struct {
	// Path is the item's canonical API path.
	Path string
	// Name is its basename, as the kernel spells it.
	Name string
	// Info is lstat data: a symlink describes itself, never its target.
	Info os.FileInfo
	// Depth is 0 for the path the walk was started on.
	Depth int
	// Mount is set on a directory that is a mount point the walk did not
	// descend into. Its contents are on another filesystem, so a size job must
	// not count them and a delete must not remove them.
	Mount bool

	// remove unlinks this item from its parent directory, through the
	// descriptor the walk is holding rather than through a pathname. It is
	// unexported on purpose: Walk itself is a read-only traversal, and the
	// mutating callers (DeleteTree) live in this package.
	remove func(isDir bool) error
}

// isDir reports whether the item is a directory, without following anything.
func (it WalkItem) isDir() bool { return it.Info != nil && it.Info.IsDir() }

// Visitor is what a walk does. Every hook may be nil.
//
// Pre is called for an item before its children; returning fs.SkipDir on a
// directory skips its contents (and its Post hook). Post is called for a
// directory after its children, which is the order a delete needs. Warn reports
// a per-item failure — the walk has already decided to carry on.
//
// An error other than fs.SkipDir from Pre, or other than errRetryDir from Post,
// ends the walk and is returned by Walk.
type Visitor struct {
	Pre  func(it WalkItem) error
	Post func(it WalkItem) error
	Warn func(apiPath string, err error)
}

// dirOpener opens (or re-opens) one directory of the walk. A re-open is what
// errRetryDir asks for; the closure keeps the parent descriptor the child is
// opened relative to, so the second pass addresses the same directory the first
// one did and not whatever now answers to its name.
type dirOpener func() (*dirRef, error)

// Walk traverses the tree rooted at apiPath, depth first, and never follows a
// symlink. The root itself is visited: a symlink there is one item, a file is
// one item, and a directory is visited, descended into and then visited again
// through Post.
//
// The error return is for the things that stop a walk: a path that cannot be
// resolved or stat'ed at all (so the caller can report it against that path),
// the context being cancelled, or a visitor hook failing. Everything else is a
// warning.
func Walk(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string, opts WalkOptions, v Visitor) error {
	clean, err := fsx.Clean(apiPath)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// followFinal is false: the thing named is the thing walked. A symlink at
	// the root of a delete is removed as the link, not chased to its target.
	tg, err := resolve(r, clean, false)
	if err != nil {
		return err
	}
	fi, err := statAt(tg.jail, tg.rel)
	if err != nil {
		return err
	}

	w := &walker{r: r, plat: plat, opts: opts, v: v}
	parentRel, name := splitFinal(tg.rel)
	root := WalkItem{
		Path:  tg.api,
		Name:  fsx.Base(tg.api),
		Info:  fi,
		Depth: 0,
		remove: func(isDir bool) error {
			if tg.rel == "." || tg.rel == "" || name == "" {
				return fmt.Errorf("%q is the root of the tree and cannot be removed: %w", tg.api, fsx.ErrBadName)
			}
			return unlinkAt(tg.jail, parentRel, name, isDir)
		},
	}
	return w.visit(ctx, root, func() (*dirRef, error) { return openDirRef(tg.jail, tg.rel) })
}

type walker struct {
	r    fsx.Root
	plat *platform.Platform
	opts WalkOptions
	v    Visitor
}

func (w *walker) warn(apiPath string, err error) {
	if w.v.Warn != nil {
		w.v.Warn(apiPath, err)
	}
}

// visit runs one item's hooks and, for a directory the walk may descend into,
// its children in between.
func (w *walker) visit(ctx context.Context, it WalkItem, open dirOpener) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.v.Pre != nil {
		switch err := w.v.Pre(it); {
		case err == nil:
		case errors.Is(err, fs.SkipDir):
			return nil
		default:
			return err
		}
	}
	if !it.isDir() || it.Mount || open == nil {
		return nil
	}
	if it.Depth >= maxWalkDepth {
		w.warn(it.Path, fmt.Errorf("%q is nested more than %d levels deep: %w", it.Path, maxWalkDepth, fsx.ErrUnsupported))
		return nil
	}

	for pass := 0; ; pass++ {
		d, err := open()
		if err != nil {
			// A directory that cannot be opened is one item's failure, not the
			// job's: the other branches of the tree are still perfectly good.
			w.warn(it.Path, err)
			return nil
		}
		err = w.children(ctx, d, it)
		closeErr := d.close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			w.warn(it.Path, closeErr)
		}
		if w.v.Post == nil {
			return nil
		}
		perr := w.v.Post(it)
		if perr == nil {
			return nil
		}
		if !errors.Is(perr, errRetryDir) {
			return perr
		}
		if !w.opts.Mutating || pass >= maxDirPasses {
			w.warn(it.Path, fmt.Errorf("%q kept producing entries after %d passes: %w", it.Path, pass+1, fsx.ErrUnsupported))
			return nil
		}
	}
}

// children enumerates one directory and visits everything in it.
//
// Names come from getdents and every one of them is described and addressed
// relative to this directory's own descriptor — never by a pathname rebuilt
// from its name. That is the same rule readDirInfos follows for a listing, and
// for the same reason: a directory renamed away mid-walk, with a symlink
// dropped in its place, cannot make the walk continue somewhere else.
func (w *walker) children(ctx context.Context, d *dirRef, parent WalkItem) error {
	parentOS, _ := w.r.OS(parent.Path)
	parentID := identityFor(d)
	for {
		names, readErr := d.names(readChunk)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			childPath := fsx.Join(parent.Path, name)
			if reason, hit := w.opts.Protect.refuses(name); hit {
				// F10: the component rule the guard applies to a job's root
				// paths, applied here to every entry the recursion reaches.
				// Neither entered nor removed nor counted — just reported.
				w.warn(childPath, neverWriteErr(childPath, reason))
				continue
			}
			fi, err := d.lstat(name)
			if err != nil {
				// Unlinked between getdents and the stat: an ordinary race in a
				// live directory, and there is nothing left to report on.
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				w.warn(childPath, err)
				continue
			}
			it := WalkItem{
				Path:   childPath,
				Name:   name,
				Info:   fi,
				Depth:  parent.Depth + 1,
				remove: func(isDir bool) error { return d.unlink(name, isDir) },
			}
			if !fi.IsDir() {
				if err := w.visit(ctx, it, nil); err != nil {
					return err
				}
				continue
			}
			if err := w.directory(ctx, d, it, parentOS, parentID); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			w.warn(parent.Path, readErr)
			return nil
		}
		if len(names) == 0 {
			// No names and no error: nothing more will come of asking again.
			return nil
		}
	}
}

// directory handles one child directory: it is OPENED first and the crossing
// decision is then made from that descriptor (F4).
//
// The order is the whole point. The old shape decided from the lstat that
// classified the entry and opened the directory afterwards, so the thing that
// was measured and the thing that was walked were two different lookups with a
// rename-sized gap between them. Now the openat with O_DIRECTORY|O_NOFOLLOW
// happens first and every question — is this another filesystem, may the walk
// enter it — is answered by fstat'ing that held descriptor. Whatever is swapped
// into the name afterwards is a different object that this walk never touches.
//
// A directory that cannot be opened is one item's failure, not the job's, which
// is the same answer visit() gave when it did the opening itself.
func (w *walker) directory(ctx context.Context, parentDir *dirRef, it WalkItem, parentOS string, parentID mountIdentity) error {
	child, boundary, err := w.openChild(parentDir, it.Name, it.Path, parentOS, parentID)
	if err != nil {
		// The item is still visited before the failure is reported, which is the
		// order the walk has always had: a size job counts the directory it
		// could not read, and a delete gets its Pre hook for it. Only the
		// descent and the Post hook are lost.
		if verr := w.visit(ctx, it, nil); verr != nil {
			return verr
		}
		w.warn(it.Path, err)
		return nil
	}
	if boundary {
		// Visited as an item so a size job can report the directory itself,
		// never descended into and never removed.
		it.Mount = true
		return w.visit(ctx, it, nil)
	}

	// The descriptor openChild just proved is the one the first pass uses.
	// errRetryDir asks for a second pass, and that re-open is put through the
	// identical check — a mount that appeared between two passes over a
	// directory being emptied must stop the walk just as one that was there from
	// the start does.
	first := child
	open := func() (*dirRef, error) {
		if first != nil {
			d := first
			first = nil
			return d, nil
		}
		d, boundary, err := w.openChild(parentDir, it.Name, it.Path, parentOS, parentID)
		if err != nil {
			return nil, err
		}
		if boundary {
			// openChild closed the descriptor itself; there is nothing here to
			// release, and nothing to descend into either.
			return nil, fmt.Errorf("%q became a mount point and was left alone: %w", it.Path, fsx.ErrProtected)
		}
		return d, nil
	}
	verr := w.visit(ctx, it, open)
	if first != nil {
		// Pre returned fs.SkipDir, so the descriptor was never consumed.
		first.close()
	}
	return verr
}

// openChild opens one child directory and decides, from that descriptor alone,
// whether it is a mount boundary the walk may not cross (F4). It returns either
// an open dirRef to descend into, or boundary = true with nothing open.
func (w *walker) openChild(parentDir *dirRef, name, childPath, parentOS string, parentID mountIdentity) (*dirRef, bool, error) {
	child, err := parentDir.child(name)
	if err != nil {
		return nil, false, err
	}
	childID := identityFor(child)
	if !w.isMountPoint(childPath, childID, parentID) {
		return child, false, nil
	}
	if !w.mayCrossInto(parentOS, parentID, childPath, childID) {
		child.close()
		return nil, true, nil
	}
	return child, false, nil
}

// isMountPoint reports whether a child directory that is now OPEN is the root of
// another filesystem.
//
// Two answers are combined. The mount table answers by name, because reading it
// resolves nothing — but it cannot see a mount made since it was last read. The
// descriptor answers by identity, and that is the authoritative half: the mount
// ID (statx STATX_MNT_ID, Linux 5.8+, or /proc/self/fdinfo as a fallback)
// distinguishes two mounts even when they share a st_dev, which is exactly the
// shape of a bind mount — the case a pure device comparison reports as "same
// filesystem, carry on". st_dev is the older fallback for a kernel with neither.
// Off Linux there is no identity behind a FileInfo at all, so the table is the
// whole answer there, which is the degradation the listing's mount flag already
// accepts (INV-2: this is the dev box, not the kernel).
func (w *walker) isMountPoint(childPath string, childID mountIdentity, parentID mountIdentity) bool {
	if w.plat != nil {
		if osPath, err := w.r.OS(childPath); err == nil && osPath != "" && w.plat.IsMountPointByTable(osPath) {
			return true
		}
	}
	return childID.differsFrom(parentID)
}

// mayCrossInto applies PLAN.md decision 9 to a child that the held descriptor
// says is on another mount: the walk descends only when it was asked to and only
// where the mount table says the two filesystems are one storage domain.
//
// The table is refreshed first, and then the child mount is identified from the
// DESCRIPTOR where the kernel gave one — the mount ID statx reported is the same
// number /proc/self/mountinfo prints in its first field, so the fd names its own
// row in the table rather than the table being asked about a pathname that may
// by now mean something else. A name lookup is the fallback for a kernel with no
// mount IDs and for a static table (PLAN.md decision 15), whose invented IDs
// deliberately cannot collide with a running kernel's.
//
// If neither identifies the mount the answer is NO. That is the fail-closed rule
// this function exists for: the descriptor has already proved the walk is about
// to leave the filesystem it started on, and crossing into a mount nobody can
// name is precisely the case decision 9 refuses — a USB disk, another pool, a
// network share. With no mount table there is no way to ask at all.
func (w *walker) mayCrossInto(parentOS string, parentID mountIdentity, childPath string, childID mountIdentity) bool {
	if !w.opts.CrossMounts || w.plat == nil {
		return false
	}
	childOS, err := w.r.OS(childPath)
	if err != nil || childOS == "" || parentOS == "" {
		return false
	}
	// A mount made since the last read is exactly what the fd identity just
	// caught, so the table is re-read before it is asked about it. On a static
	// table this is a no-op (Platform.Refresh).
	_ = w.plat.Refresh()
	childCaps, ok := w.capsFor(childID, childOS, true)
	if !ok {
		return false
	}
	// The parent is allowed the longest-prefix answer: it is not the thing being
	// entered, and its worst case is the zero FSCaps, which MayCross refuses.
	parentCaps, _ := w.capsFor(parentID, parentOS, false)
	return w.plat.MayCross(parentCaps, childCaps)
}

// capsFor names the mount a descriptor belongs to and returns its capabilities.
//
// byID is the authoritative lookup: statx's mount ID is mountinfo's first field,
// so a descriptor identifies its own row. requireMount says the caller needs a
// definite answer — the child of a crossing decision — in which case a name that
// the table does not list as a mount point is a failure rather than a
// longest-prefix guess.
func (w *walker) capsFor(id mountIdentity, osPath string, requireMount bool) (platform.FSCaps, bool) {
	if id.hasMnt {
		for _, m := range w.plat.Mounts() {
			if uint64(m.ID) == id.mnt {
				return w.plat.For(m.MountPoint), true
			}
		}
	}
	if requireMount && !w.plat.IsMountPointByTable(osPath) {
		return platform.FSCaps{}, false
	}
	return w.plat.For(osPath), true
}

// mountIdentity is what a held directory descriptor says about the filesystem it
// belongs to (F4).
//
// mnt is the kernel's mount ID — what statx reports as STATX_MNT_ID and what
// /proc/self/mountinfo prints in its first field. It is the value that matters,
// because two mounts of the same device (a bind mount, and QTS builds its whole
// share layout out of them) have one st_dev and two mount IDs: comparing devices
// alone would walk straight across that boundary. dev is the older fallback, for
// a kernel before 5.8 and for everything that is not Linux.
type mountIdentity struct {
	mnt    uint64
	hasMnt bool
	dev    uint64
	hasDev bool
}

// differsFrom reports whether two descriptors are on different mounts. An
// unanswerable comparison is "no": the mount table has already had its say, and
// inventing a boundary from missing data would stop every ordinary walk.
func (id mountIdentity) differsFrom(other mountIdentity) bool {
	if id.hasMnt && other.hasMnt {
		return id.mnt != other.mnt
	}
	if id.hasDev && other.hasDev {
		return id.dev != other.dev
	}
	return false
}

// identityFor reads a descriptor's mount identity. It is a variable so that a
// test can supply one without a real mount — mounting anything needs root, and
// off Linux there is no identity to read at all (walk_other.go). The CI root and
// ZFS jobs exercise the real thing.
var identityFor = identityOf

// Emit is how a long-running fsops job reports back: coalesced progress and
// per-item warnings. Both hooks may be nil, which is what the tests and the
// pre-scan use when nobody is listening.
//
// The throttling is deliberately not here. fsops emits an update per item and
// the worker decides what reaches the socket (≤10 frames a second or one per
// 8 MiB, identity plan §2.5), because the worker is the only side that knows
// what the transport is doing.
type Emit struct {
	Prog func(wproto.Prog)
	Warn func(wproto.Warn)
}

func (e Emit) prog(p wproto.Prog) {
	if e.Prog != nil {
		e.Prog(p)
	}
}

// warn reports a per-item failure with an explicit code, for the refusals this
// package makes itself (no_trash, not_empty, a mount point).
func (e Emit) warn(apiPath, code, msg string, errno int) {
	if e.Warn == nil {
		return
	}
	e.Warn(wproto.Warn{Path: []byte(apiPath), Code: code, Message: msg, Errno: errno})
}

// warnErr reports a per-item failure the kernel decided, classified with the
// one error vocabulary the whole app speaks.
func (e Emit) warnErr(apiPath string, err error) {
	e.warn(apiPath, fsx.Code(err), err.Error(), fsx.Errno(err))
}
