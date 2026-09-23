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
//     network mount. A read-only walk (ReadCrossing) may also step out of a
//     "system" filesystem — the mount at "/" or a tmpfs such as /share — into a
//     RAM filesystem or a storage volume.
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

	// ReadCrossing selects platform.MayCrossRead instead of MayCross: from a
	// "system" parent — the mount at "/", or a RAM filesystem such as the tmpfs
	// /share every volume is mounted under — the walk may enter a RAM or a
	// Storage, non-network child (PLAN.md decision 9, amended). It is an explicit
	// opt-in, set only by the two walks that read and nothing else: Search and
	// Size. It is deliberately not derived from Mutating, which the recursive
	// chmod leaves false while it writes, and a walk that is mutating() by either
	// test ignores it.
	ReadCrossing bool

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
	// Searchable is set with Mount when the walk identified that mount and it is
	// either Storage or a RAM filesystem (tmpfs, ramfs), and not Network: a
	// place that holds, or like /share can hold mounts of, user data. A read-only
	// caller counts only these as "mounted folders not searched"
	// (JobResult.MountsSkipped); /proc, /sys, /dev and the other pseudo-
	// filesystems, and a mount the table cannot name, are passed over without a
	// word (Astra r2 on the QKVM fix; RAM filesystems since the "search of /"
	// hardware report, where /share itself was the boundary).
	Searchable bool

	// remove unlinks this item from its parent directory, through the
	// descriptor the walk is holding rather than through a pathname. It is
	// unexported on purpose: Walk itself is a read-only traversal, and the
	// mutating callers (DeleteTree) live in this package.
	remove func(isDir bool) error

	// parent is the HELD descriptor of the directory this item was enumerated
	// from — the very one remove() unlinks through — and it is nil only for the
	// root of the walk, which was reached by resolving a pathname and has no
	// enumerated parent.
	//
	// It exists for the copy engine (copy.go). A copy has to READ each item —
	// openat a regular file, readlinkat a symlink — and doing that by a pathname
	// rebuilt from the item's name would undo the whole point of the walk: the
	// names come from one directory's getdents and the bytes would come from
	// whatever answers to that name a moment later. Handing the visitor the same
	// descriptor the walk is standing in keeps both halves on one object.
	//
	// It is unexported for the same reason remove is: Walk is a read-only
	// traversal to anything outside this package, and the callers that need a
	// descriptor live here.
	parent *dirRef

	// held is the enumeration's OWN descriptor on this item, kept open, and it
	// is set in one case only: a directory whose filesystem records no birth
	// time (lstatUnprovenHeld, Astra r4 #7).
	//
	// Everywhere else an identity settles what a second lookup of the name
	// reached — device, inode and the creation time nothing can forge. Where
	// there is no creation time to read, the only remaining proof is not to look
	// the name up twice at all, so the walk holds what it described and the
	// Unopened fallback acts on that object rather than on whatever answers to
	// the name by then.
	//
	// The WALK owns it: it is closed as soon as this item has been handled,
	// descended into or not, so at most one is outstanding per level. A visitor
	// must use it and must not close it.
	held *os.File
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
// Opened, when set, is called for each directory the walk actually OPENS, with
// the fstat of the held descriptor — not of the pathname it was reached by.
// That distinction is the only way to know which object is being enumerated: the
// Info in a WalkItem comes from an lstat made before the open, and between the
// two a name can be re-pointed at something else. A caller that has to prove
// afterwards that it counted the object it is still acting on (the trash's
// sidecar, trash.go) takes its identity from here.
//
// Opened may also STOP the walk by returning an error, and that is not a
// convenience: it is the only hook that sees a directory's real identity BEFORE
// a single one of its entries is enumerated. A caller that has to refuse a
// particular object — the copy engine refusing to descend into its own output —
// has to be able to refuse it there, because by the time Pre is called for the
// first child the directory has already been read.
//
// Unopened, when set, REPLACES the warning for a directory the walk could not
// open at all, and it is the only hook that hears about one: Pre still runs (the
// item was reached), Opened never does, the descent does not happen and neither
// does Post. A caller that has something to do with such a directory anyway —
// the recursive chmod, whose whole purpose on an owner-set 0000 directory is to
// repair exactly the mode that made it unreadable (Astra r2 #5) — needs the
// item, not just the pathname a warning carries, because the item is what names
// the entry relative to the held parent. It reports the failure itself, which is
// why the walker does not also warn.
type Visitor struct {
	Pre      func(it WalkItem) error
	Post     func(it WalkItem) error
	Opened   func(it WalkItem, info os.FileInfo) error
	Unopened func(it WalkItem, err error)
	Warn     func(apiPath string, err error)
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

// walkFrom is Walk starting at a directory this process is ALREADY HOLDING.
//
// It exists because Walk's first act is to resolve a pathname, and a caller that
// has gone to the trouble of holding a descriptor must not throw that away at
// the one moment it matters most. The copy engine pins the source root through
// its parent's descriptor and checks its identity; if the walk then re-opened
// the same pathname, a rename of a component to a symlink in between would send
// the whole traversal somewhere else — and for a MOVE, the delete that follows
// with it. Nothing below the root was ever at risk (every level is an openat
// from the level above); the root was the one gap.
//
// held is CONSUMED: the walker closes it when it is done enumerating, exactly
// as it closes every directory it opens itself. A root whose Pre hook returns
// fs.SkipDir never reaches that, so it is closed here instead.
//
// There is no re-read pass here. errRetryDir asks for the root to be opened
// again, and re-opening it means naming it again, which is the thing this
// exists to avoid; the mutating caller that needs retries (DeleteTree) uses
// Walk, whose opener can. A Post hook asking for one is warned about and the
// walk moves on.
//
// info is the root's own lstat, which the caller already has — it is what
// proved the descriptor is the object it meant to walk.
func walkFrom(ctx context.Context, r fsx.Root, plat *platform.Platform, held *dirRef,
	apiPath string, info os.FileInfo, opts WalkOptions, v Visitor) error {

	if err := ctx.Err(); err != nil {
		held.close()
		return err
	}
	w := &walker{r: r, plat: plat, opts: opts, v: v}
	root := WalkItem{Path: apiPath, Name: fsx.Base(apiPath), Info: info, Depth: 0}
	first := held
	open := func() (*dirRef, error) {
		if first != nil {
			d := first
			first = nil
			return d, nil
		}
		return nil, fmt.Errorf("%q cannot be read again without naming it: %w", apiPath, fsx.ErrUnsupported)
	}
	err := w.visit(ctx, root, open)
	if first != nil {
		// Pre returned fs.SkipDir, so the descriptor was never consumed.
		first.close()
	}
	return err
}

type walker struct {
	r    fsx.Root
	plat *platform.Platform
	opts WalkOptions
	v    Visitor

	// live caches whether plat's table is the RUNNING kernel's, read once per
	// walk because answering it copies the table (see liveTable).
	live     bool
	liveRead bool
}

// mutating reports whether this walk is part of an operation that CHANGES the
// filesystem: a recursive delete (Mutating) or the bounded pre-scan that gives
// it its denominator, which is the walk that carries ProtectWrite. Size — the
// one read-only caller — is neither.
//
// B4 turns on this distinction. A mutating walk that cannot identify the mount a
// child descriptor is on must not descend into it; a measurement may still fall
// back to comparing devices, because the worst a wrong answer costs there is a
// number.
func (w *walker) mutating() bool {
	return w.opts.Mutating || w.opts.Protect == ProtectWrite
}

// liveTable reports whether the mount table this walk consults came from the
// running kernel (/proc/self/mountinfo) rather than from a static one built by
// platform.FromMountinfo — the golden QTS and hero tables, and the tests
// (PLAN.md decision 15).
//
// The distinction is what makes B5's fail-closed rule safe to apply. Only a live
// table's first field is the same number statx reports as STATX_MNT_ID, so only
// on a live table does "the kernel named this mount and the table does not list
// it" mean anything; a static table's IDs are invented and deliberately cannot
// collide with a running kernel's, so a descriptor can never match one and the
// by-name lookup has to remain the answer there.
//
// Platform publishes the fact through Diag rather than as an accessor of its
// own, and Diag copies the whole table, so the answer is taken once per walk and
// only when a mount ID has actually failed to match a row.
func (w *walker) liveTable() bool {
	if !w.liveRead {
		w.liveRead = true
		w.live = liveTableOf(w.plat)
	}
	return w.live
}

// liveTableOf answers walker.liveTable. It is a variable for the same reason
// identityFor is one: the property it gates (B5) can only be observed on a table
// whose IDs are the running kernel's, and a test cannot produce one of those on
// a dev box. Production never assigns to it.
var liveTableOf = func(plat *platform.Platform) bool {
	if plat == nil {
		return false
	}
	live, _ := plat.Diag()["live"].(bool)
	return live
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
		if w.v.Opened != nil {
			// The fstat of the descriptor about to be enumerated. A failure here
			// is a per-item warning like any other, and the visitor is simply not
			// told — which leaves a caller that needed the identity without one,
			// exactly as it should.
			if fi, serr := openedInfo(d); serr == nil {
				if oerr := w.v.Opened(it, fi); oerr != nil {
					// The visitor refused this object, before any of its entries
					// was read. Nothing below it is visited and the walk ends.
					d.close()
					return oerr
				}
			} else {
				w.warn(it.Path, serr)
			}
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
			if err := w.refusedByTable(parentOS, name, childPath); err != nil {
				// Not even lstat'ed: see refusedByTable. The item is reported the
				// way any refused crossing is and the walk moves on.
				w.warn(childPath, err)
				continue
			}
			fi, held, err := d.lstatHeld(name)
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
				parent: d,
				held:   held,
			}
			if !fi.IsDir() {
				// held is nil for anything that is not a directory, so there is
				// nothing to release here.
				if err := w.visit(ctx, it, nil); err != nil {
					return err
				}
				continue
			}
			derr := w.directory(ctx, d, it, parentOS, parentID)
			if held != nil {
				// Released the moment this entry is finished with — descended
				// into, refused, or handed to the fallback — which is what keeps
				// the outstanding count to one per level rather than one per
				// entry (Astra r4 #7).
				_ = held.Close()
			}
			if derr != nil {
				return derr
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

// refusedByTable is the one decision this walk makes from the mount table ALONE,
// before the child has been touched at all — no lstat, no openat.
//
// It does not weaken F4/B4/B5 and is not allowed to: it can only REFUSE, never
// authorise, and every child that gets past it is still opened and judged on its
// own descriptor by openChild exactly as before.
//
// It exists because of what one lstat costs on a NETWORK mount whose server has
// gone. A hard NFS mount parks the caller inside the syscall indefinitely — no
// deadline in this process can reach a thread in uninterruptible sleep, and the
// scan's own deadline is only read between items — so a single unreachable NFS
// mount underneath a folder was enough to hang a size job, a delete's pre-scan
// and (since the trash measures what it moves) a delete to trash, on a path the
// walk was never going to enter in the first place. Asking the mount table
// whether that name is a mount point costs no syscall at all.
//
// It is deliberately NOT applied to a local mount. Decision 9 says a mount point
// the walk does not cross is still VISITED as the item it is — a size counts the
// directory itself, and TestSizeAppliesTheCrossingRule pins that — and the lstat
// this would skip is what supplies it. An ext4 or ZFS mount answers that lstat
// without blocking, so refusing to look would cost a real answer and buy
// nothing. The class that can block forever is the networked one, and that is
// the class this refuses.
//
// It is asked of every entry, files included, because "is this a directory" is
// itself the lstat being protected. That costs one map lookup under a read lock
// per entry, against the openat-and-fstat the walk is about to make anyway.
//
// The name is joined onto the parent's own mount-table spelling and looked up
// EXACTLY (MountByLiteralPath). Going through the ordinary lookups would have
// been a second bug in the shape of a fix: they normalise, and on Linux a
// backslash is an ordinary character in a filename, so a regular file called
// `..\export` would normalise to "/export" and be skipped as somebody else's
// NFS mount — invisible to a size and left behind by a recursive delete — while
// a genuine mount point with a backslash in its name would never match its own
// row and would still reach the lstat this exists to avoid.
func (w *walker) refusedByTable(parentOS, name, childPath string) error {
	if w.plat == nil || parentOS == "" {
		return nil
	}
	caps, ok := w.plat.MountByLiteralPath(literalChild(parentOS, name))
	if !ok || !caps.Network {
		return nil
	}
	if w.opts.CrossMounts && w.mayCross(w.plat.For(parentOS), caps) {
		// Unreachable while MayCross refuses every network mount, and written out
		// anyway: the refusal has to stay a CONSEQUENCE of the crossing rule
		// rather than a second copy of it that could drift.
		return nil
	}
	return mountNotEntered{fmt.Errorf("%q is a %s mount this walk may not enter, and it was left untouched: %w",
		childPath, caps.FSType, fsx.ErrProtected)}
}

// mountNotEntered marks a refusal that is a mount boundary the walk would not
// cross, as opposed to a directory it could not read. The code and the sentence
// are the wrapped error's; the type only lets a read-only caller COUNT the mounts
// it passed over (JobResult.MountsNetwork), so a search that could not reach a
// network share says so beside its hits and not only in a warning row.
type mountNotEntered struct{ err error }

func (e mountNotEntered) Error() string { return e.err.Error() }
func (e mountNotEntered) Unwrap() error { return e.err }

// isMountNotEntered reports whether err is refusedByTable's refusal.
func isMountNotEntered(err error) bool {
	var m mountNotEntered
	return errors.As(err, &m)
}

// literalChild joins a directory's OS path with one entry name, byte for byte
// and with nothing cleaned away. The name comes straight out of getdents, so
// whatever it contains — a backslash, a dot, a newline — stays exactly what the
// kernel handed over; the only thing added is the separator the table's own keys
// use.
func literalChild(parentOS, name string) string {
	if parentOS != "" && os.IsPathSeparator(parentOS[len(parentOS)-1]) {
		return parentOS + name
	}
	return parentOS + "/" + name
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
		if w.v.Unopened != nil {
			w.v.Unopened(it, err)
			return nil
		}
		w.warn(it.Path, err)
		return nil
	}
	if boundary.hit {
		// Visited as an item so a size job can report the directory itself,
		// never descended into and never removed.
		it.Mount, it.Searchable = true, boundary.searchable
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
		if boundary.hit {
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

// openedInfo is the reading the Opened hook is handed: the fstat of the
// descriptor that is about to be enumerated, with that descriptor's BIRTH TIME
// attached where the filesystem records one (Astra r10 #1).
//
// The birth time has to be taken HERE, because here is the only place it can be
// taken from the object rather than from a name. The hook's caller keeps the
// reading and asks about it later — the recursive chmod compares it against the
// directory it re-opens in post-order, after the walk has closed this descriptor
// and after enumeration has released its own — and device and inode alone are a
// NUMBER, which an allocator is free to hand back to the next object created at
// that name. A stat carrying the creation time is the same reading with the one
// fact nothing can forge in it.
//
// It costs one statx per directory OPENED, not per entry, and only where a
// visitor asked for the hook at all.
func openedInfo(d *dirRef) (os.FileInfo, error) {
	fi, err := d.stat()
	if err != nil {
		return nil, err
	}
	return infoWithBirthTime(d.f, fi), nil
}

// openChild opens one child directory and decides, from that descriptor alone,
// whether it is a mount boundary the walk may not cross (F4). It returns either
// an open dirRef to descend into, or boundary.hit with nothing open.
func (w *walker) openChild(parentDir *dirRef, name, childPath, parentOS string, parentID mountIdentity) (*dirRef, mountBoundary, error) {
	child, err := parentDir.child(name)
	if err != nil {
		return nil, mountBoundary{}, err
	}
	childID := identityFor(child)
	// B4: a mutating walk may not descend into a directory whose mount the
	// kernel would not name. Without a mount ID the only question that can be
	// asked is "same st_dev?", and a same-device BIND mount answers yes — which
	// is precisely the boundary a delete must not cross, and precisely the shape
	// QTS builds its share layout out of. A measurement may live with that; a
	// recursive delete may not, so the child is visited, warned about and left.
	if w.mutating() && unidentifiedMount(childID, parentID) {
		child.close()
		return nil, mountBoundary{}, unnamedMountRefusal(childPath)
	}
	if !w.isMountPoint(childPath, childID, parentID) {
		return child, mountBoundary{}, nil
	}
	cross, caps, known := w.mayCrossInto(parentOS, parentID, childPath, childID)
	if !cross {
		child.close()
		if !known {
			// Crossing was never asked about (CrossMounts off), so the mount has
			// not been named yet. It is named here the same way — by the held
			// descriptor first — only to say whether it could be searched.
			caps, known = w.boundaryCaps(childPath, childID)
		}
		return nil, mountBoundary{hit: true, searchable: known && !caps.Network && (caps.Storage || caps.RAM)}, nil
	}
	return child, mountBoundary{}, nil
}

// mountBoundary is what openChild found at a mount point it will not descend
// into. searchable says the mount was IDENTIFIED and is Storage or a RAM
// filesystem, and not network (WalkItem.Searchable). A pseudo-filesystem is
// never searchable and never what anybody was looking for; a network share is
// counted apart (MountsNetwork); a mount nobody can name fails closed and is not
// counted at all.
type mountBoundary struct {
	hit        bool
	searchable bool
}

// boundaryCaps names the mount a boundary descriptor is on, for the count alone.
// It is capsFor without the refresh mayCrossInto makes: nothing is authorised by
// the answer, and a mount the table does not know yet is simply not counted.
func (w *walker) boundaryCaps(childPath string, childID mountIdentity) (platform.FSCaps, bool) {
	if w.plat == nil {
		return platform.FSCaps{}, false
	}
	childOS, err := w.r.OS(childPath)
	if err != nil || childOS == "" {
		return platform.FSCaps{}, false
	}
	return w.capsFor(childID, childOS, true)
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
//
// It also hands back the child's caps and whether they were identified, so a
// boundary it refuses can be counted by what it is (openChild) without a second
// lookup. known is false when the question was never asked (CrossMounts off) or
// the child could not be named; the crossing answer is false either way.
func (w *walker) mayCrossInto(parentOS string, parentID mountIdentity, childPath string, childID mountIdentity) (cross bool, child platform.FSCaps, known bool) {
	if !w.opts.CrossMounts || w.plat == nil {
		return false, platform.FSCaps{}, false
	}
	childOS, err := w.r.OS(childPath)
	if err != nil || childOS == "" || parentOS == "" {
		return false, platform.FSCaps{}, false
	}
	// A mount made since the last read is exactly what the fd identity just
	// caught, so the table is re-read before it is asked about it. On a static
	// table this is a no-op (Platform.Refresh).
	_ = w.plat.Refresh()
	childCaps, ok := w.capsFor(childID, childOS, true)
	if !ok {
		return false, platform.FSCaps{}, false
	}
	// The parent is allowed the longest-prefix answer by NAME — it is not the
	// thing being entered — but not a wrong answer by identity: if the kernel
	// named its mount and the live table cannot find that mount, capsFor refuses
	// rather than describing some other filesystem, and so does this (B5). A
	// crossing is authorised by both halves or by neither.
	parentCaps, ok := w.capsFor(parentID, parentOS, false)
	if !ok {
		return false, childCaps, true
	}
	return w.mayCross(parentCaps, childCaps), childCaps, true
}

// mayCross is the final predicate of a crossing decision: MayCross, or
// MayCrossRead for a walk that opted in with ReadCrossing. Everything before it
// — the fd identity, B4, B5, the fail-closed lookups — is the same for both, so
// the relaxation changes the answer for a mount that has been positively
// identified and for nothing else.
//
// mutating() is asked again here rather than trusted to the caller: a walk that
// changes the filesystem, or the pre-scan that gives one its denominator, keeps
// the strict rule even if some later caller sets both flags.
func (w *walker) mayCross(from, to platform.FSCaps) bool {
	if w.opts.ReadCrossing && !w.mutating() {
		return w.plat.MayCrossRead(from, to)
	}
	return w.plat.MayCross(from, to)
}

// capsFor names the mount a descriptor belongs to and returns its capabilities.
//
// byID is the authoritative lookup: statx's mount ID is mountinfo's first field,
// so a descriptor identifies its own row. requireMount says the caller needs a
// definite answer — the child of a crossing decision — in which case a name that
// the table does not list as a mount point is a failure rather than a
// longest-prefix guess.
//
// B5 is the case in between, and it is the dangerous one. The kernel HAS named
// the mount this descriptor is on, and the table — just refreshed — does not
// list it. Falling through to a pathname lookup there does not answer the
// question less precisely, it answers a DIFFERENT question: what filesystem does
// this name lead to now, which after a rename or a fresh mount over the name may
// be somebody else's. A crossing must never be authorised by that, so a live
// table with no row for a known mount ID is a refusal.
//
// The by-name lookup survives for exactly one case, and it is stated here
// because it is the only reason the fall-through exists at all: a STATIC table
// (platform.FromMountinfo — the golden QTS and hero tables, and the tests,
// PLAN.md decision 15) whose row IDs are invented and can never equal a running
// kernel's, so no descriptor could ever match one.
func (w *walker) capsFor(id mountIdentity, osPath string, requireMount bool) (platform.FSCaps, bool) {
	return capsForMount(w.plat, w.liveTable, id, osPath, requireMount)
}

// capsForMount is walker.capsFor's body, as a function of the table rather than
// of a walk. The recursive mode job asks the same question about a LEAF it holds
// (mode_job.go, Astra r2 #4), and one crossing rule with two implementations is
// two crossing rules a year from now.
//
// live is the B5 predicate, taken lazily because it copies the whole table and
// is only ever needed when a mount id has already failed to match a row.
func capsForMount(plat *platform.Platform, live func() bool, id mountIdentity, osPath string, requireMount bool) (platform.FSCaps, bool) {
	if plat == nil {
		return platform.FSCaps{}, false
	}
	if id.hasMnt {
		for _, m := range plat.Mounts() {
			if uint64(m.ID) == id.mnt {
				// B7: the caps come from the matched ROW, not from
				// For(m.MountPoint). Going back through the mount point would
				// throw away everything the ID just established: For does a
				// longest-prefix lookup keyed by pathname, and where two mounts
				// are STACKED at one path — a bind mount over a share, a tmpfs
				// over a directory, the shape QTS builds its layout out of — the
				// only row that name can name is the topmost one. The descriptor
				// may well be on the one underneath, and a crossing would then be
				// authorised by the capabilities of a filesystem this walk is not
				// in. CapsFor derives them from the row itself and touches
				// nothing on disk; MayCross reads Storage, Network and Domain,
				// all three of which it fills in.
				return platform.CapsFor(m), true
			}
		}
		if live != nil && live() {
			// B5: the kernel's own mount ID, absent from the kernel's own table.
			return platform.FSCaps{}, false
		}
	}
	if requireMount && !plat.IsMountPointByTable(osPath) {
		return platform.FSCaps{}, false
	}
	return plat.For(osPath), true
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

// unidentifiedMount reports that the kernel could not name the mount one of two
// descriptors is on, where the kernel is expected to be able to (B4).
//
// It is the fail-closed half of F4. Without a mount ID the only comparison left
// is st_dev, and a same-device bind mount — one device, two mounts — passes it:
// the walk would cross a boundary it believes is not there. A measurement can
// accept that (Size keeps the st_dev fallback); an operation that DESTROYS data
// cannot, so a mutating walk refuses to descend rather than guess.
//
// This is a true corner rather than a routine path. On Linux the ID comes from
// statx(STATX_MNT_ID) since 5.8 and, failing that, from /proc/self/fdinfo/<fd>,
// which has printed "mnt_id:" since Linux 3.15 — so both have to be missing at
// once (a pre-3.15 kernel, or /proc not mounted) before a mutating walk stops.
// Off Linux there are no kernel mount IDs at all (kernelMountIDs is false there,
// walk_other.go), the mount table is the whole answer, and the rule is not
// applied: that is the dev box, not the kernel (INV-2).
func unidentifiedMount(child, parent mountIdentity) bool {
	return kernelMountIDs && (!child.hasMnt || !parent.hasMnt)
}

// unnamedMountRefusal is the one sentence B4 produces, wherever it is applied.
// The recursive mode job applies the same rule to a LEAF it is about to change
// (mode_job.go, Astra r10 #2), and a rule stated in two sentences is two rules a
// year from now.
func unnamedMountRefusal(apiPath string) error {
	return fmt.Errorf("the kernel would not name the mount %q is on, so a mutating walk left it alone: %w",
		apiPath, fsx.ErrProtected)
}

// differsFrom reports whether two descriptors are on different mounts. An
// unanswerable comparison is "no": the mount table has already had its say, and
// inventing a boundary from missing data would stop every ordinary walk.
//
// The st_dev fallback below is why unidentifiedMount exists (B4): it cannot see
// a bind mount, so a mutating walk never gets this far without a mount ID.
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
