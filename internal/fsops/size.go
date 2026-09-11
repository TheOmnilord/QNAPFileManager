package fsops

// Size is the folder-size probe, and the same counting pass is what gives a
// recursive delete its denominator (the pre-scan in delete_tree.go). Both are
// the walk with a visitor that adds up what it sees and removes nothing.

import (
	"context"
	"errors"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// scanTimeCheck is how many items the scan counts between two clock readings.
// The deadline only has to be honoured to within a fraction of a second, and a
// time.Now() per entry of a four-million-file share is a cost with no buyer.
const scanTimeCheck = 128

// errScanCapped stops a bounded pre-scan from inside the visitor. It never
// leaves this file: scanTrees turns it into capped = true.
var errScanCapped = errors.New("fsops: the scan hit its bound")

// scanLimits bounds a pre-scan. The zero value is unbounded, which is what
// Size uses: a user who asked for a folder's size asked for the real number.
type scanLimits struct {
	// deadline stops the scan at a wall-clock instant. Zero means no deadline.
	deadline time.Time
	// maxEntries stops it after that many items. Zero means no cap.
	maxEntries int64
}

// scanResult is what a counting pass found. capped says the bound was hit
// before the end of the tree, so the numbers are a floor and not a total.
type scanResult struct {
	files  int64
	dirs   int64
	bytes  int64
	capped bool
}

// scanTrees counts every item under each path without touching anything.
//
// A symlink is one item with the size of its link text — what lstat reports and
// what ls -l prints — because that is the number a delete will actually remove
// and the number the tree occupies. Following it would count the target twice
// and could count a target outside the tree altogether.
//
// quiet suppresses the per-item warnings. A pre-scan is quiet on purpose: the
// pass that follows it walks the same tree and will report the same EACCES
// itself, and warning twice for one file would inflate the count the front-end
// shows.
func scanTrees(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string,
	crossMounts bool, emit Emit, lim scanLimits, quiet bool) (scanResult, error) {

	var res scanResult
	var since int64
	opts := WalkOptions{CrossMounts: crossMounts}

	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		v := Visitor{
			Pre: func(it WalkItem) error {
				if it.isDir() {
					res.dirs++
				} else {
					res.files++
					res.bytes += it.Info.Size()
				}
				emit.prog(wproto.Prog{
					Files:   res.files,
					Bytes:   res.bytes,
					Current: []byte(it.Path),
					Phase:   wproto.PhaseScanning,
				})
				if lim.maxEntries > 0 && res.files+res.dirs >= lim.maxEntries {
					res.capped = true
					return errScanCapped
				}
				since++
				if !lim.deadline.IsZero() && since >= scanTimeCheck {
					since = 0
					if time.Now().After(lim.deadline) {
						res.capped = true
						return errScanCapped
					}
				}
				return nil
			},
		}
		if !quiet {
			v.Warn = func(apiPath string, err error) { emit.warnErr(apiPath, err) }
		}
		err := Walk(ctx, r, plat, p, opts, v)
		switch {
		case err == nil:
		case errors.Is(err, errScanCapped):
			return res, nil
		case ctx.Err() != nil:
			return res, ctx.Err()
		default:
			// The path itself could not be reached. A size job reports that and
			// carries on with the rest of the selection.
			if !quiet {
				emit.warnErr(p, err)
			}
		}
	}
	return res, nil
}

// Size measures the trees named by paths: how many files, how many directories
// and how many bytes, with the crossing rule of PLAN.md decision 9 and without
// following a single symlink.
//
// The directory named by a path is itself counted, so the numbers a size job
// reports are exactly the numbers a delete of the same selection would move —
// which is what makes this pass usable as that delete's denominator.
//
// The phase is "scanning" throughout: nothing is being changed, and a UI that
// showed a progress bar labelled "working" for a measurement would be lying
// about what could be lost by cancelling it (nothing).
func Size(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string, crossMounts bool, emit Emit) (wproto.JobResult, error) {
	res, err := scanTrees(ctx, r, plat, paths, crossMounts, emit, scanLimits{}, false)
	out := wproto.JobResult{Files: res.files, Dirs: res.dirs, Bytes: res.bytes}
	if err != nil {
		return out, err
	}
	return out, nil
}
