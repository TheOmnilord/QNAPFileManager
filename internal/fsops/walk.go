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
	parentDev, hasParentDev := uint64(0), false
	if fi, err := d.stat(); err == nil {
		parentDev, hasParentDev = devOf(fi)
	}
	for {
		names, readErr := d.names(readChunk)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			childPath := fsx.Join(parent.Path, name)
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
			if w.isMountPoint(childPath, fi, parentDev, hasParentDev) && !w.mayCross(parentOS, childPath) {
				// Visited as an item so a size job can report the directory
				// itself, never descended into and never removed.
				it.Mount = true
				if err := w.visit(ctx, it, nil); err != nil {
					return err
				}
				continue
			}
			if err := w.visit(ctx, it, func() (*dirRef, error) { return d.child(name) }); err != nil {
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

// isMountPoint reports whether a child directory is the root of another
// filesystem.
//
// The mount table answers first, by name, because reading it resolves nothing.
// What it cannot answer is a mount made since the table was last read, and that
// is settled by comparing the st_dev the walk already holds for the child with
// the one it holds for the directory it lives in — both from descriptors, never
// from a pathname. Off Linux there is no st_dev behind a FileInfo, so the table
// is the whole answer there (devOf returns false), which is the same degradation
// the listing's mount flag already accepts.
func (w *walker) isMountPoint(childPath string, fi os.FileInfo, parentDev uint64, hasParentDev bool) bool {
	if w.plat != nil {
		if osPath, err := w.r.OS(childPath); err == nil && osPath != "" && w.plat.IsMountPointByTable(osPath) {
			return true
		}
	}
	if !hasParentDev {
		return false
	}
	dev, ok := devOf(fi)
	return ok && dev != parentDev
}

// mayCross applies PLAN.md decision 9 to a child that is a mount point: the
// walk descends only when it was asked to and only where the mount table says
// the two filesystems are one storage domain. With no mount table there is no
// way to ask, and the answer to a question that cannot be asked is no.
func (w *walker) mayCross(parentOS, childPath string) bool {
	if !w.opts.CrossMounts || w.plat == nil {
		return false
	}
	childOS, err := w.r.OS(childPath)
	if err != nil || childOS == "" || parentOS == "" {
		return false
	}
	return w.plat.MayCross(w.plat.For(parentOS), w.plat.For(childOS))
}

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
