package fsops

// The recursive chmod and chown (m3-contract §4): JobChmod and JobChown, one
// engine with two verbs.
//
// Partial success is the NORMAL outcome here, not a failure. On a real NAS a
// recursive chmod over a share meets thousands of files owned by other users,
// and the kernel refuses every one of them (INV-2); a job that stopped at the
// first EPERM would be useless. So every refusal is one skipped entry plus a
// warning and the walk carries on, and the result says what was changed, what
// was skipped and why.
//
// Two orderings are load bearing.
//
//   - Directories are changed in POST, after their children. Taking the search
//     bit off a directory — or handing it to another owner — is exactly what
//     stops the descent into it, and a pre-order walk would have locked itself
//     out of the tree it was in the middle of changing. The walk holds
//     descriptors, but every openat below one is still checked against the mode
//     that is there NOW.
//   - The pre-scan runs before anything is changed, so the denominator describes
//     the tree as the user selected it rather than as the job is leaving it.
//
// There is no undo. Nothing is rolled back on cancellation, the result says so,
// and the dialog says so before the job starts.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// warnUnchanged is the per-entry warning code for an entry the kernel changed
// DIFFERENTLY from what was asked — a setgid silently dropped for a non-member,
// a setuid cleared by a change of owner, an aclmode=groupmask chmod landing on
// other bits. The call succeeded; what is being reported is that the result is
// not the request (contract §3.4).
const warnUnchanged = "unchanged"

// modeScanMaxEntries bounds the recursive pre-scan, alongside the 30 s deadline
// every pre-scan in this package takes (backend plan §3). It is a variable for
// the same reason sizeScanLimits is: reaching the real bound needs half a
// million files, which no test is going to create. Production never assigns
// to it.
var modeScanMaxEntries int64 = scanMaxEntries

// ChmodOptions are the per-job knobs of a recursive chmod. Files and Dirs are
// separate specs because "apply to files only" is a ZERO MASK on the other half
// (§1.2), which is also why neither has a zero value that means anything else.
type ChmodOptions struct {
	Files       perm.ModeSpec
	Dirs        perm.ModeSpec
	Recursive   bool
	CrossMounts bool
}

// ChownOptions are the same for a recursive chown. -1 leaves that half alone.
type ChownOptions struct {
	UID         int
	GID         int
	Recursive   bool
	CrossMounts bool
}

// ChmodTree applies a mode change to each path, and — when Recursive — to
// everything under it.
//
// A recursive request that SETS setuid, setgid or sticky is refused outright as
// fsx.ErrBadName (§1.3). Setting setuid across a tree is the single most
// effective way to make a NAS exploitable and no legitimate workflow needs it in
// one call; CLEARING them recursively is the cleanup that does get needed, and
// stays.
func ChmodTree(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string, o ChmodOptions, emit Emit) (wproto.JobResult, error) {
	if o.Recursive && (o.Files.SetsSpecial() || o.Dirs.SetsSpecial()) {
		return wproto.JobResult{}, fmt.Errorf(
			"a recursive change may clear setuid, setgid and sticky but never set one: %w", fsx.ErrBadName)
	}
	j := &modeJob{
		r: r, plat: plat, emit: emit,
		files: o.Files, dirs: o.Dirs,
		uid: -1, gid: -1,
		recursive: o.Recursive, cross: o.CrossMounts,
		linkGuard: rootWorker(),
	}
	return j.run(ctx, paths)
}

// ChownTree changes ownership of each path, and — when Recursive — of
// everything under it. It is always an lchown, so a symlink in the tree has its
// own ownership changed and is never followed.
func ChownTree(ctx context.Context, r fsx.Root, plat *platform.Platform, paths []string, o ChownOptions, emit Emit) (wproto.JobResult, error) {
	j := &modeJob{
		r: r, plat: plat, emit: emit,
		chown:     true,
		uid:       o.UID,
		gid:       o.GID,
		recursive: o.Recursive, cross: o.CrossMounts,
		linkGuard: rootWorker(),
	}
	return j.run(ctx, paths)
}

// modeJob carries one job's specs and counters.
type modeJob struct {
	r    fsx.Root
	plat *platform.Platform
	emit Emit
	res  wproto.JobResult

	chown       bool
	files, dirs perm.ModeSpec
	uid, gid    int
	recursive   bool
	cross       bool

	filesTotal int64
	// refused counts the entries the KERNEL said no to, separately from every
	// other kind of skip. On a shared NAS they are the ORDINARY outcome — a
	// recursive chmod over a share meets thousands of files owned by other users
	// — so a result that lumped them in with real failures would read as a
	// disaster instead of as a Tuesday. res.Skipped is the total; this says how
	// many of it were the kernel's verdict.
	refused int64

	// linkGuard is true when this worker runs as root, which is the only case in
	// which the hardlink rule in applyRef bites. It is read once, at job start:
	// a worker's credentials are fixed at fork time and cannot change under it.
	linkGuard bool
}

// rootWorker reports whether this process is uid 0 — an administrator session's
// worker, the one identity the kernel refuses nothing. os.Geteuid returns -1 on
// Windows, where there is no such identity and nothing to guard against.
func rootWorker() bool { return os.Geteuid() == 0 }

// linkCountOf reads an entry's link count, which is what says an inode has another
// name somewhere. A FileInfo the platform cannot decompose reports 0, which this
// reads as "not multiply linked" — the same degradation every other stat detail
// accepts off Linux (INV-2).
func linkCountOf(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	_, _, nlink, ok := statDetail(fi)
	if !ok {
		return 0
	}
	return nlink
}

func (j *modeJob) run(ctx context.Context, paths []string) (wproto.JobResult, error) {
	if j.recursive {
		for _, p := range paths {
			clean, err := fsx.Clean(p)
			if err != nil {
				return j.res, err
			}
			if apiDepth(clean) <= 1 {
				// The one hard refusal M3 adds, and it applies to every session
				// including root (§4.5, ui-ux §4.5 item 2). There is no recursive
				// chmod of "/" or of "/share" that anybody means, and a
				// confirmation would only be a slower way of saying yes to it.
				return j.res, fmt.Errorf(
					"%q is too near the root of the filesystem to change recursively: %w", clean, fsx.ErrProtected)
			}
		}
		lim := scanLimits{deadline: time.Now().Add(scanMaxDuration), maxEntries: modeScanMaxEntries}
		scan, err := scanTrees(ctx, j.r, j.plat, paths, j.cross, j.emit, lim, true, ProtectWrite)
		if err != nil {
			return j.res, err
		}
		if scan.capped {
			j.filesTotal = -1
			warnScanCapped(j.emit)
		} else {
			j.filesTotal = scan.files + scan.dirs
		}
	} else {
		j.filesTotal = int64(len(paths))
	}

	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			j.finish()
			return j.res, err
		}
		if err := j.one(ctx, p); err != nil {
			j.finish()
			return j.res, err
		}
	}
	j.finish()
	return j.res, nil
}

// one handles a single selected path.
func (j *modeJob) one(ctx context.Context, p string) error {
	clean, err := fsx.Clean(p)
	if err != nil {
		j.fail(p, err)
		return nil
	}
	// F10 applied to the SELECTED root: the walker only ever sees components it
	// reaches by recursion, so a job rooted at .zfs or @Recycle was never shown
	// the component at all.
	if reason, hit := neverWritePath(clean); hit {
		j.refuse(clean, neverWriteErr(clean, reason))
		return nil
	}
	parent, ref, name, tg, err := canonicalLeaf(j.r, clean)
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	if err != nil {
		j.fail(clean, err)
		return nil
	}
	if ref == nil {
		j.refuse(tg.api, fmt.Errorf("%q is the root of the tree: %w", tg.api, fsx.ErrBadName))
		return nil
	}
	// A mount point at the ROOT of the selection is deliberately NOT refused.
	//
	// The refusal that belongs here is delete's, and its reason does not
	// transfer: unlinking a mount point empties the volume mounted on it. A mode
	// change unlinks nothing, so this is the copy engine's case rather than the
	// delete engine's — and on QuTS hero every share IS its own dataset mount
	// (and a QTS share is a bind mount of one), so refusing meant that a
	// recursive chmod of any share came back "changed 0 of 48102 items; 1
	// skipped" after a pre-scan that had already counted the whole tree, and
	// after a level-2 confirmation for a job that did nothing (round-2 review,
	// P2). The selected root is changed and descended; CHILD mounts are still
	// governed by the walker's crossing rule (mayCrossInto and CrossMounts),
	// which is where decision 9 actually lives.
	if j.recursive && ref.fi.Mode()&fs.ModeSymlink != 0 {
		// A recursive change of a symlink is refused for BOTH verbs. chmod
		// cannot touch a link at all; chown could — it is always an lchown — but
		// "apply to this folder and everything in it" over a link would change
		// exactly one inode and report "re-owned 1 of 1 items", which reads as a
		// recursive success and is not one (round-2 review, P2). The routes
		// resolve a recursive root to its target; a link that reaches here is
		// told, not silently obeyed. A NON-recursive chown of a link keeps its
		// lchown semantics (§1.4), below.
		j.refuse(tg.api, fmt.Errorf(
			"%q is a symlink, and a recursive change does not follow one; open the folder it points at and change that: %w",
			tg.api, fsx.ErrUnsupported))
		return nil
	}

	if !j.recursive || !ref.fi.IsDir() {
		j.applyRef(tg.api, parent, name, ref, true)
		return nil
	}

	// The root has to be ENUMERABLE, which an O_PATH reference is not, so it is
	// re-opened through the held parent and proved to be the same object before
	// a single entry is read (reopenDir).
	held, err := reopenDir(parent, name, ref)
	if err != nil {
		j.fail(tg.api, err)
		return nil
	}
	return walkFrom(ctx, j.r, j.plat, held, tg.api, ref.fi,
		WalkOptions{CrossMounts: j.cross, Mutating: false, Protect: ProtectWrite},
		Visitor{
			Pre: j.pre,
			Post: func(it WalkItem) error {
				if it.Depth == 0 {
					// The root's own parent descriptor is the one this
					// function holds; the walk never had it.
					j.applyRef(it.Path, parent, name, ref, true)
					return nil
				}
				j.applyEntry(it)
				return nil
			},
			Warn: func(apiPath string, err error) { j.fail(apiPath, err) },
		})
}

// pre changes everything that is not a directory. Directories wait for post,
// after their children, so that removing a search bit cannot lock the walk out
// of the tree it is changing.
func (j *modeJob) pre(it WalkItem) error {
	if it.Mount {
		j.refuse(it.Path, fmt.Errorf("%q is a mount point and was left alone: %w", it.Path, fsx.ErrProtected))
		return fs.SkipDir
	}
	if it.Depth == 0 || it.isDir() {
		return nil
	}
	j.applyEntry(it)
	return nil
}

// applyEntry pins one entry of the directory the walk is standing in and
// changes it through that descriptor. The name is looked up relative to the
// held parent, never through a rebuilt pathname.
func (j *modeJob) applyEntry(it WalkItem) {
	if it.parent == nil {
		j.fail(it.Path, fmt.Errorf("%q has no open parent to address it through: %w", it.Path, fsx.ErrUnsupported))
		return
	}
	ref, err := itemRefIn(it.parent, it.Name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Unlinked between the walk and here: an ordinary race in a live
			// directory, and there is nothing left to change.
			return
		}
		j.fail(it.Path, err)
		return
	}
	defer ref.close()
	j.applyRef(it.Path, it.parent, it.Name, ref, false)
}

// applyRef is the whole per-entry decision: which spec applies, whether this
// kind of entry is touched at all, the syscall, and the diff between what was
// asked and what the kernel did.
//
// named says the USER picked this entry, rather than the recursion reaching it.
// The hardlink rule below turns on that distinction and on nothing else.
func (j *modeJob) applyRef(apiPath string, parent *dirRef, name string, ref *itemRef, named bool) {
	before := ref.fi
	isDir := before.IsDir()
	if !named && j.linkGuard && !isDir && linkCountOf(before) > 1 {
		// A root worker will not change a multiply-linked file it merely walked
		// into (round-2 review, P2).
		//
		// A hardlink is not a copy and not a reference — it is the inode itself
		// under a second name, and the mode belongs to the inode. So anybody who
		// can create a file in a share can link one of the daemon's own files
		// into it (on QTS the config and the logs live on the same data volume,
		// and the protected-path table protects a PATH, not an inode), wait for
		// an administrator to run "apply 0777 to this folder and everything in
		// it", and collect a world-writable copy of something the guard would
		// never have let them name.
		//
		// The refusal is deliberately narrow. It applies only when this worker is
		// root — a non-root worker cannot chmod an inode it does not own, so the
		// kernel already refuses the attack and adding a rule of our own would
		// only refuse users their own hardlinks (INV-2) — and only to entries the
		// recursion REACHED. An entry the user named is one the guard saw, and
		// naming it is exactly what the warning tells them to do.
		//
		// The cost is stated rather than hidden: a tree of rsync --link-dest
		// backups is almost entirely multiply-linked, so an admin's recursive
		// chmod over one now skips nearly all of it and says so, per entry.
		j.refuse(apiPath, fmt.Errorf(
			"%q is hard-linked elsewhere, so changing it here would change it wherever else it is named; "+
				"change it by naming it directly: %w", apiPath, fsx.ErrUnsupported))
		return
	}
	if j.chown {
		after, err := chownHeld(parent, name, ref, j.uid, j.gid)
		if err != nil {
			j.fail(apiPath, err)
			return
		}
		j.changed(apiPath, isDir, perm.ModeSpec{}, before, after)
		return
	}
	if before.Mode()&fs.ModeSymlink != 0 {
		// Linux has no lchmod, and a recursive walk never reaches through a
		// link (§1.4). One skipped entry with a reason, and on.
		j.refuse(apiPath, fmt.Errorf("%q is a symlink and Linux cannot change a symlink's mode: %w",
			apiPath, fsx.ErrUnsupported))
		return
	}
	spec := j.files
	if isDir {
		spec = j.dirs
	}
	if !spec.Touches() {
		// "Apply to folders only" (or files only): this entry was never in
		// scope. It is counted as skipped by policy — which is what makes
		// changed + skipped add up to the pre-scan's total — and warns about
		// nothing, because nothing went wrong.
		j.res.Skipped++
		return
	}
	after, err := chmodHeld(parent, name, ref, spec.Apply(perm.Bits(before.Mode())))
	if err != nil {
		j.fail(apiPath, err)
		return
	}
	j.changed(apiPath, isDir, spec, before, after)
}

// changed books one successful change and reports any difference between what
// was asked and what the inode became.
func (j *modeJob) changed(apiPath string, isDir bool, spec perm.ModeSpec, before, after os.FileInfo) {
	if isDir {
		j.res.Dirs++
	} else {
		j.res.Files++
	}
	if diffs := perm.DiffOf(spec, j.uid, j.gid, modeEntry(before), modeEntry(after)); len(diffs) > 0 {
		j.emit.warn(apiPath, warnUnchanged, diffSentence(diffs), 0)
	}
	j.emit.prog(wproto.Prog{
		Files:      j.res.Files + j.res.Dirs,
		FilesTotal: j.filesTotal,
		Current:    []byte(apiPath),
		Phase:      wproto.PhaseWorking,
	})
}

// modeEntry is the smallest fsx.Entry perm.DiffOf reads: the octal mode and the
// two ids. A recursive job compares thousands of these, so it builds nothing it
// does not need — the full entry (names, symlink targets, id lookups) belongs to
// the single-item reply, which has one of them.
func modeEntry(fi os.FileInfo) fsx.Entry {
	var e fsx.Entry
	if fi == nil {
		return e
	}
	e.Mode = fsx.ModeOctal(fi.Mode())
	if uid, gid, _, ok := statDetail(fi); ok {
		e.UID, e.GID = uid, gid
	}
	return e
}

// diffSentence renders a per-entry diff for a warning frame. It is one line and
// it names fields and values only — the path travels in Warn.Path.
func diffSentence(diffs []perm.Diff) string {
	parts := make([]string, 0, len(diffs))
	for _, d := range diffs {
		parts = append(parts, d.Field+" is "+d.Got+", not "+d.Want)
	}
	return "the kernel did not apply this as asked: " + strings.Join(parts, "; ")
}

// fail books a per-item failure: a warning frame, a skip, and — when it was the
// kernel's own refusal — a mark on the counter the result sentence reports
// separately.
func (j *modeJob) fail(apiPath string, err error) {
	if errors.Is(err, fs.ErrPermission) {
		j.refused++
	}
	j.emit.warnErr(apiPath, err)
	j.res.Skipped++
}

// refuse books one of this package's own refusals — a mount point, a
// never-write component, a symlink a chmod cannot touch. It is not the kernel's
// verdict, so it does not count towards the refused total; it is still a skip.
func (j *modeJob) refuse(apiPath string, err error) {
	j.emit.warnErr(apiPath, err)
	j.res.Skipped++
}

// finish writes the sentence the Operations panel shows. It is path-free and it
// says the numbers partial success needs: what was changed, out of how many,
// how many were skipped, and how many of those skips were the kernel refusing
// rather than a policy or a failure (§4.2).
func (j *modeJob) finish() {
	verb := "changed"
	if j.chown {
		verb = "re-owned"
	}
	done := j.res.Files + j.res.Dirs
	if j.filesTotal < 0 {
		j.res.Detail = fmt.Sprintf("%s %d items; %d skipped (%d refused by the kernel)",
			verb, done, j.res.Skipped, j.refused)
		return
	}
	j.res.Detail = fmt.Sprintf("%s %d of %d items; %d skipped (%d refused by the kernel)",
		verb, done, j.filesTotal, j.res.Skipped, j.refused)
}

// apiDepth counts the components of an already-cleaned API path: 0 for "/", 1
// for "/share", 2 for "/share/Public".
func apiDepth(apiPath string) int {
	return len(splitRel(strings.TrimPrefix(apiPath, "/")))
}
