package fsops

// Size is the folder-size probe, and the same counting pass is what gives a
// recursive delete its denominator (the pre-scan in delete_tree.go). Both are
// the walk with a visitor that adds up what it sees and removes nothing.

import (
	"context"
	"errors"
	"math"
	"os"
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

	// incomplete says something the scan met was not counted for a reason that
	// is not the bound: a subdirectory it could not read, a tree deeper than
	// maxWalkDepth, a network mount it would not touch, or a root path it could
	// not reach at all. The numbers are then a floor, exactly as capped makes
	// them, but for a reason no bound would have prevented.
	//
	// It is recorded even for a QUIET scan, because quiet means "do not tell the
	// job about this", not "do not remember that it happened". The distinction
	// matters to a caller that PERSISTS a total — the trash sidecar, which has to
	// say "unknown" rather than record a plausible fraction of a tree as its
	// size. A caller that only shows a live denominator (Size, and the delete
	// pre-scan) already documents that its totals are what could be read, and
	// ignores this.
	incomplete bool

	// rootInfo is the fstat of the DESCRIPTOR the scan opened for the first root
	// it visited (Visitor.Opened), kept so that a caller can prove afterwards
	// that the tree it counted is the object it is still acting on. Only the
	// trash measurement reads it, and that one scans exactly one path.
	//
	// It deliberately does NOT come from the root WalkItem's Info. That is an
	// lstat of a PATHNAME, taken before the directory is opened, so a name
	// re-pointed in between would be described by one object and enumerated from
	// another — and the comparison that exists to catch exactly that would then
	// be made against the wrong half.
	rootInfo os.FileInfo
}

// addBytes accumulates one item's size, and refuses to wrap doing it.
//
// A sparse file may declare any length the filesystem allows, and nothing bounds
// how many times a tree can name one: a handful of hard links to a single 4 EiB
// sparse file overflows an int64 sum. A wrapped total is the one failure a size
// must not have, because it is SMALLER than the truth and entirely plausible — a
// delete's denominator would run backwards, and a trash sidecar would persist
// the lie for good. When the sum would no longer fit, the scan stops as though
// it had hit its bound; capped is what every caller already reads as "there is
// no usable total here".
//
// A negative size is refused for the same reason. The kernel never reports one,
// so a FileInfo that does is not describing anything this can add up.
func (res *scanResult) addBytes(n int64) bool {
	if n < 0 || res.bytes > math.MaxInt64-n {
		return false
	}
	res.bytes += n
	return true
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
// protect is the never-write component rule this pass applies (F10). A delete's
// pre-scan passes ProtectWrite so its denominator counts exactly what the delete
// will go on to remove; Size passes ProtectSnapshots, which skips .zfs and still
// counts @Recycle.
func scanTrees(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string,
	crossMounts bool, emit Emit, lim scanLimits, quiet bool, protect Protect) (scanResult, error) {

	var res scanResult
	var since int64
	opts := WalkOptions{CrossMounts: crossMounts, Protect: protect}

	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		v := Visitor{
			Opened: func(it WalkItem, info os.FileInfo) error {
				if it.Depth == 0 && res.rootInfo == nil {
					res.rootInfo = info
				}
				// A counting pass refuses nothing: the hook exists here only to
				// take the root's real identity (scanResult.rootInfo).
				return nil
			},
			Pre: func(it WalkItem) error {
				if it.Mount {
					// A mount point the walk did not descend into is one whose
					// contents were not counted — and, worse for anything that
					// persists the number, a mount OVER a populated directory hides
					// files that are on THIS filesystem and would move with a rename.
					// The item itself is still counted, as decision 9 says it must
					// be; what is recorded is that the total is a floor.
					res.incomplete = true
				}
				if it.isDir() {
					res.dirs++
				} else {
					res.files++
					if !res.addBytes(it.Info.Size()) {
						// Past what an int64 can hold. Stopping here is the same
						// answer the bound gives, and for the same reason: what
						// remains is a floor and not a total.
						res.capped = true
						return errScanCapped
					}
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
		// The hook is always installed, quiet or not: quiet decides whether the
		// job is TOLD about a per-item failure, never whether the scan remembers
		// that one happened. Without that distinction an unreadable subdirectory
		// or a tree past maxWalkDepth came back as a complete-looking total.
		v.Warn = func(apiPath string, err error) {
			res.incomplete = true
			if !quiet {
				emit.warnErr(apiPath, err)
			}
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
			// carries on with the rest of the selection — but nothing under it
			// was counted, so the totals are a floor whether or not anybody was
			// listening.
			res.incomplete = true
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
//
// What it reports is what it could COUNT. A subdirectory the user cannot read
// is a warning beside the number rather than the end of the job, so the total
// can be a floor — scanResult.incomplete records exactly that, and Size does not
// act on it on purpose: the warnings are shown next to the figure, and a size
// job that answered "unknown" because one file in a million was unreadable would
// be less useful than the floor plus the reason. A caller that PERSISTS the
// number instead of showing it (the trash sidecar) reads the flag and says
// "unknown" (trashSizeOf).
//
// A CAPPED scan is different from an incomplete one and is always reported.
// Size asks for no bound at all, so the only thing that can stop it early is the
// byte total outgrowing an int64 (addBytes) — at which point the scan ends
// where it stands, including for any selected path it had not reached yet. The
// number that comes back is then a floor with nothing in the reply to say so,
// which is exactly the shape of a lie a Properties panel would render as fact.
// So the reason goes out as a warning (warnScanCapped), which the worker folds
// into JobResult.Warnings.
//
// ".zfs" is skipped even though this pass writes nothing (F10): a snapshot
// directory holds the whole history of a share, so counting it would answer a
// question nobody asked with a number nobody could use. "@Recycle" is counted —
// it is an ordinary directory whose bytes are really there, and decision 10 only
// forbids WRITING to it.
// maxEntries bounds the walk, and zero is the unbounded default above. It is
// there for the one caller that measures in order to DECIDE something rather
// than to display it: the permissions pre-scan, which runs inside a 15-second
// request and must not turn an enormous tree into a timed-out POST (M3 Astra
// round-1 finding 10). A walk that hits the bound stops where it stands, reports
// what it counted so far, and says Capped — and a capped measurement is not a
// count, so the caller reads the whole answer as "unknown" rather than as the
// number it happens to carry.
func Size(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string,
	crossMounts bool, maxEntries int64, emit Emit) (wproto.JobResult, error) {

	lim := sizeScanLimits
	if maxEntries > 0 && (lim.maxEntries <= 0 || maxEntries < lim.maxEntries) {
		// The tighter of the two wins. sizeScanLimits is unbounded in production
		// and is only ever narrowed by a test, so "the smaller bound" is the rule
		// that keeps both honest.
		lim.maxEntries = maxEntries
	}
	res, err := scanTrees(ctx, r, plat, paths, crossMounts, emit, lim, false, ProtectSnapshots)
	out := wproto.JobResult{Files: res.files, Dirs: res.dirs, Bytes: res.bytes, Capped: res.capped}
	if err != nil {
		return out, err
	}
	if res.capped {
		warnScanCapped(emit)
	}
	return out, nil
}

// sizeScanLimits is what Size bounds its pass by: nothing. A user who asked for
// a folder's size asked for the real number, and the only stop is the overflow
// guard inside the counter.
//
// It is a variable rather than a literal so that this package's tests can reach
// the capped branch, which otherwise needs a tree whose declared bytes do not
// fit in an int64 — four exabytes of sparse files, which no filesystem here will
// create (the same reason trashScanMaxEntries is one). Production never assigns
// to it.
var sizeScanLimits scanLimits

// scanCappedCode is the warning code a job reports when its counting pass
// stopped before the end of the tree. It is one code for both users of the pass
// — the folder-size probe and the recursive delete's pre-scan — because it is
// one fact about the same walk: the totals are a floor.
const scanCappedCode = "capped"

// warnScanCapped says so, once per job rather than once per item.
//
// The path is empty on purpose: nothing about this is a failure of any
// particular file, and naming the first selected root would invite a UI to
// blame it. A warning with no path publishes its code and its sentence, which is
// what the front-end shows beside the total.
func warnScanCapped(emit Emit) {
	emit.warn("", scanCappedCode,
		"the scan stopped at its limit, so these totals are a floor and not the whole tree", 0)
}
