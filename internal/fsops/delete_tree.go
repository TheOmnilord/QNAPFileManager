package fsops

// The M2 recursive delete: post-order, cancellable, warn-and-continue, and
// never RemoveAll.
//
// os.RemoveAll is exactly the wrong shape for this. It cannot be cancelled, it
// reports nothing while it runs, it stops at the first error instead of telling
// the user which forty files it could not remove, and it descends into any
// filesystem it happens to meet — which on a NAS means it would empty a mounted
// USB disk, or a network share, because they were underneath the folder
// somebody selected. So the tree is walked (walk.go) and the entries are
// unlinked through the descriptor the walk is holding, children first.
//
// What is deliberately not here: the protected-path table, the read-only
// toggle, the confirmation ladder and the /share RAM-disk refusal. All of that
// is the root front-end's guard, before the RPC (INV-1, PLAN.md decision 7).
// The one refusal made here is the mount-point one, and it is made twice on
// purpose — the guard checks it too. Removing a mount point is the single worst
// thing this app could do (backend plan §2.7), so it is refused on both sides
// of the socket rather than trusted to either.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The pre-scan's bounds, from backend plan §3: a scan that takes longer than
// this is worse than no scan at all, because the user is watching a progress
// bar that has not started moving. Past either bound the totals are reported as
// -1 and the UI shows an indeterminate bar.
const (
	scanMaxDuration = 30 * time.Second
	scanMaxEntries  = 500_000
)

// maxDirAttempts bounds how often one directory is read again after its rmdir
// came back ENOTEMPTY with entries removed in that pass. Two passes is the
// normal case (the second finds nothing); more than a handful means something
// is writing into the tree as fast as it is being emptied, and that is a race
// to lose rather than to keep running.
const maxDirAttempts = 16

// DeleteOptions are the per-job knobs of a recursive delete. They mirror the
// wire's DeleteReq: Trash is not here because a delete-to-trash is a different
// operation (trash.go), not a flag on this one.
type DeleteOptions struct {
	// Recursive allows the delete to descend. Without it a non-empty directory
	// is reported as not_empty and left alone, exactly as the M1 single delete
	// does.
	Recursive bool
	// CrossMounts lets the walk descend into mounts of the same storage domain
	// ("include mounted sub-folders"); see WalkOptions.CrossMounts.
	CrossMounts bool
}

// DeleteTree permanently removes each path, depth first and post-order.
//
// It runs in two phases. The scan counts what is there so progress has a
// denominator, bounded by 30 s or 500 000 entries, after which the totals are
// -1 and the UI shows an indeterminate bar. The delete then walks the same tree
// and unlinks it, counting files, directories, bytes (the lstat size, so a
// symlink counts its link text and is removed as the link) and everything it
// had to skip.
//
// A per-item failure — EACCES on one file, a directory that cannot be emptied,
// a mount point in the way — is a warning and the job carries on. The error
// return is reserved for the context being cancelled, and the counts that come
// back with it are the real partial ones: nothing is rolled back, and the
// front-end says so ("cancelled after 412 of 8 003 files").
func DeleteTree(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string, o DeleteOptions, emit Emit) (wproto.JobResult, error) {
	d := &treeDeleter{r: r, plat: plat, emit: emit, filesTotal: -1, bytesTotal: -1}

	if o.Recursive {
		lim := scanLimits{deadline: time.Now().Add(scanMaxDuration), maxEntries: scanMaxEntries}
		scan, err := scanTrees(ctx, r, plat, paths, o.CrossMounts, emit, lim, true, ProtectWrite)
		if err != nil {
			return d.res, err
		}
		// capped and nothing else. A scan that merely could not read part of the
		// tree (scanResult.incomplete) still gives the progress bar a denominator
		// worth having: the delete is about to meet the very same unreadable
		// subdirectory and will warn about it then, and a bar that went
		// indeterminate because one file in a million was refused would tell the
		// user less than a total that is slightly short. The trash sidecar is the
		// caller that cannot live with "slightly short", because it persists the
		// number instead of showing it for a minute (trashSizeOf).
		if !scan.capped {
			d.filesTotal = scan.files + scan.dirs
			d.bytesTotal = scan.bytes
		} else {
			// The bar goes indeterminate, and the reason is said once rather than
			// left to be guessed at. The pre-scan itself is quiet — the delete is
			// about to walk the same tree and report the same per-item failures —
			// but this is not a per-item failure: it is why the job has no
			// denominator, and it is the same sentence a size job gives.
			warnScanCapped(emit)
		}
	}

	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return d.res, err
		}
		if err := d.one(ctx, p, o); err != nil {
			return d.res, err
		}
	}
	return d.res, nil
}

// treeDeleter carries one delete job's counters.
type treeDeleter struct {
	r    fsx.Root
	plat *platform.Platform
	emit Emit
	res  wproto.JobResult

	filesTotal int64
	bytesTotal int64

	// frames is one entry per depth of the walk, not a push/pop stack. The walk
	// is depth first, so at any instant there is exactly one live directory at
	// each depth — and indexing by depth is immune to the hooks being called in
	// unequal numbers, which they are: a directory that cannot be opened gets a
	// Pre and never a Post.
	frames []dirFrame
}

// dirFrame is what the post-order rmdir needs to know about the pass that has
// just run over one directory: whether it removed anything (so asking for
// another pass can make progress) and how many passes it has already had.
type dirFrame struct {
	removed  int64
	attempts int
}

func (d *treeDeleter) frame(depth int) *dirFrame {
	for len(d.frames) <= depth {
		d.frames = append(d.frames, dirFrame{})
	}
	return &d.frames[depth]
}

// one deletes a single selected path.
func (d *treeDeleter) one(ctx context.Context, p string, o DeleteOptions) error {
	clean, err := fsx.Clean(p)
	if err != nil {
		d.emit.warnErr(p, err)
		d.res.Skipped++
		return nil
	}
	// F10: the never-write component rule, applied to the selected path before
	// anything is resolved. The guard refuses these too, and it is refused here
	// as well for the same reason the mount-point rule is: the guard sees a job's
	// root paths and this is the process that sees every path below them.
	if reason, hit := neverWritePath(clean); hit {
		d.refuse(clean, neverWriteErr(clean, reason))
		return nil
	}
	// The leaf is kept literal: a symlink named for deletion is the link, never
	// the thing it points at.
	tg, err := resolve(d.r, clean, false)
	if err != nil {
		d.emit.warnErr(clean, err)
		d.res.Skipped++
		return nil
	}
	fi, err := statAt(tg.jail, tg.rel)
	if err != nil {
		d.emit.warnErr(clean, err)
		d.res.Skipped++
		return nil
	}
	osPath, osErr := d.r.OS(tg.api)
	if osErr != nil {
		osPath = ""
	}
	if mountPointAt(d.r, d.plat, tg, fi, osPath) {
		// The guard refuses this too. It is refused here as well because the
		// consequence — unmounting a volume by emptying it — is the one failure
		// this app must not have, and because the worker is the process that
		// still knows which filesystem the descriptor it holds belongs to.
		d.refuse(tg.api, fmt.Errorf("%q is a mount point; deleting it would empty the filesystem mounted there: %w",
			tg.api, fsx.ErrProtected))
		return nil
	}

	parentRel, name := splitFinal(tg.rel)
	if tg.rel == "." || tg.rel == "" || name == "" {
		d.refuse(tg.api, fmt.Errorf("%q is the root of the tree: %w", tg.api, fsx.ErrBadName))
		return nil
	}

	if !fi.IsDir() {
		d.removed(tg.api, fi, unlinkAt(tg.jail, parentRel, name, false))
		return nil
	}
	if !o.Recursive {
		err := unlinkAt(tg.jail, parentRel, name, true)
		if isNotEmpty(err) {
			d.notEmpty(tg.api, err)
			return nil
		}
		d.removed(tg.api, fi, err)
		return nil
	}

	return Walk(ctx, d.r, d.plat, tg.api, WalkOptions{
		CrossMounts: o.CrossMounts,
		Mutating:    true,
		Protect:     ProtectWrite,
	}, Visitor{
		Pre:  d.pre,
		Post: d.post,
		Warn: func(apiPath string, err error) {
			d.emit.warnErr(apiPath, err)
			d.res.Skipped++
		},
	})
}

// pre removes a non-directory as the walk reaches it, and opens a frame for a
// directory the walk is about to descend into.
func (d *treeDeleter) pre(it WalkItem) error {
	if it.Mount {
		d.refuse(it.Path, fmt.Errorf("%q is a mount point and was left alone: %w", it.Path, fsx.ErrProtected))
		return fs.SkipDir
	}
	if it.isDir() {
		f := d.frame(it.Depth)
		f.removed, f.attempts = 0, 0
		return nil
	}
	err := it.remove(false)
	if err == nil && it.Depth > 0 {
		// The pass over this item's parent made progress, which is what lets
		// post ask for another pass if the rmdir comes back ENOTEMPTY.
		d.frame(it.Depth-1).removed++
	}
	d.removed(it.Path, it.Info, err)
	return nil
}

// post removes the directory itself, after everything in it.
//
// ENOTEMPTY with entries removed in this pass is the case errRetryDir exists
// for: the directory was enumerated while it was being emptied, and on a
// filesystem that renumbers directory offsets (ext4's htree) the getdents
// stream can skip entries. Reading it again from a fresh handle is the fix, and
// it is asked for only while the last pass actually removed something, so a
// directory nobody may empty is reported once rather than retried forever.
func (d *treeDeleter) post(it WalkItem) error {
	err := it.remove(true)
	if err == nil {
		d.res.Dirs++
		if it.Depth > 0 {
			d.frame(it.Depth-1).removed++
		}
		d.progress(it.Path)
		return nil
	}
	if isNotEmpty(err) {
		f := d.frame(it.Depth)
		if f.removed > 0 && f.attempts < maxDirAttempts {
			f.attempts++
			f.removed = 0
			return errRetryDir
		}
		d.notEmpty(it.Path, err)
		return nil
	}
	d.emit.warnErr(it.Path, err)
	d.res.Skipped++
	return nil
}

// removed books one removal attempt: the counts on success, a warning and a
// skip on failure. An item that had already vanished is neither — a delete
// whose target is gone got what it asked for.
func (d *treeDeleter) removed(apiPath string, fi os.FileInfo, err error) {
	switch {
	case err == nil:
		if fi != nil && fi.IsDir() {
			d.res.Dirs++
		} else {
			d.res.Files++
			if fi != nil {
				d.res.Bytes += fi.Size()
			}
		}
		d.progress(apiPath)
	case errors.Is(err, fs.ErrNotExist):
		// Removed by somebody else between the walk and the unlink.
	default:
		d.emit.warnErr(apiPath, err)
		d.res.Skipped++
	}
}

// refuse records one of this package's own refusals: a mount point, or the root
// of the tree. The code comes from the sentinel, so the front-end sees
// "protected" and can say why.
func (d *treeDeleter) refuse(apiPath string, err error) {
	d.emit.warnErr(apiPath, err)
	d.res.Skipped++
}

// notEmpty records a directory that still has entries in it.
func (d *treeDeleter) notEmpty(apiPath string, err error) {
	d.emit.warn(apiPath, "not_empty",
		fmt.Sprintf("%q still has entries in it and was left alone", apiPath), fsx.Errno(err))
	d.res.Skipped++
}

// progress reports one completed item. The rate limiting is the worker's, not
// this package's (see Emit).
func (d *treeDeleter) progress(apiPath string) {
	d.emit.prog(wproto.Prog{
		Files:      d.res.Files + d.res.Dirs,
		FilesTotal: d.filesTotal,
		Bytes:      d.res.Bytes,
		BytesTotal: d.bytesTotal,
		Current:    []byte(apiPath),
		Phase:      wproto.PhaseWorking,
	})
}

// isNotEmpty reports whether err is "the directory still has entries in it".
//
// On the Linux NAS that is ENOTEMPTY. On the Windows dev box the kernel says
// ERROR_DIR_NOT_EMPTY, which stdlib bridges to fs.ErrExist and not to
// ENOTEMPTY — a classification detail of the host rather than a difference in
// behaviour, so both spellings are accepted. POSIX allows rmdir to answer
// EEXIST for the same condition in any case, and a directory removal has no
// other reason to report that something already exists.
func isNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, fs.ErrExist)
}
