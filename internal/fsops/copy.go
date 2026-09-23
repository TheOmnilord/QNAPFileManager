package fsops

// The M2-B copy/move engine: one engine, two job kinds (contract §1.1).
//
// A move is a copy with two extra properties, not a different operation. It
// tries renameat2 per source root first — instant, atomic, and the kernel's
// decision rather than this package's (INV-2) — and falls back to copy, verify,
// delete only when the kernel says EXDEV, or when the shape of the destination
// makes a rename impossible (a directory merging into an existing directory of
// the same name). On QuTS hero that fallback is the ordinary case: every shared
// folder is its own dataset, so a move between two shares of ONE pool is EXDEV.
//
// Four rules fix the shape of everything below.
//
//   - **The source is deleted only when its copy was clean.** Zero warnings and
//     zero skips for that root, and the source is still the object the copy
//     started from. Anything else leaves both copies and says so (a "kept"
//     warning). A cancelled move leaves both copies too. Never delete before
//     the copy is verified — backend plan §2.6, and the one failure mode this
//     feature must not have.
//   - **Both trees are walked on held descriptors.** The source is the walk's
//     own dirRefs (walk.go, and WalkItem.parent is the descriptor a visitor
//     reads through); the destination is opened ONCE, up front, and every
//     entry below it is created with mkdirat/openat relative to a descriptor
//     this process is holding. No pathname is re-resolved after its directory
//     was opened — the trash hardening's rule (PLAN.md §2.7), and here it also
//     guards the CHOWN at the far end of it.
//   - **A per-item failure is a warning, never the end of the job.** EACCES on
//     one file of a million is reported and the copy carries on, exactly as the
//     recursive delete does. The error return is for the things that stop a
//     job: cancellation, a destination that cannot be opened at all, and the
//     one refusal that is made before anything is written (no space).
//   - **Nothing here decides policy.** The protected-path table, the read-only
//     toggle, the confirmation ladder and the guard's OpCreate/OpDelete checks
//     on both spellings live in the root front-end, before the RPC (INV-1). The
//     refusals made here are the ones only the worker can make: the identity of
//     the destination against the source (§1.7), the kernel's own errnos, and
//     the never-write components the recursion reaches (F10).
//
// One cost is worth naming up front. A cross-filesystem MOVE reads both sides
// once more before it deletes anything: every regular file is compared with its
// copy byte for byte (contentMatches). That is roughly three reads and one
// write per byte instead of two and one. A copy pays none of it — it deletes
// nothing — and a move that renames pays none of it either, because there is no
// copy to check. What it buys is the difference between design §2.6 as written
// ("copy, VERIFY, then delete") and deleting an original on the strength of
// metadata that anybody with write access to the destination can leave looking
// exactly right.
//
// One class of attack is closed by CONSTRUCTION rather than by a check, and it
// is worth saying where. Everything this engine creates at the destination is
// made where nobody else can reach it: a regular file with no name at all
// (O_TMPFILE), published by linking the finished inode into place; a directory
// or a symlink inside a PRIVATE staging directory — this worker's, 0700, empty,
// and carrying no ACL that lets anybody else CHANGE what is in it (stagingIn) —
// renamed into its final name with RENAME_NOREPLACE once it is proved, owned
// and ready. So there is no window in which a half-made object stands anywhere
// an attacker can substitute for it, which matters most where a check cannot
// reach: an ACL granting a stranger access rides along invisibly on a directory
// that satisfies kind, creator, emptiness, mode and group, and a chown strips
// none of it. The proofs all stay as defence in depth, for the fallbacks and
// for anything the rename cannot speak for.
//
// Two things disqualify a destination from being staged in at all, and they
// are different in kind. One is its own ACL passing something down that stops
// one generation later (NO_PROPAGATE_INHERIT): what is built in a staging
// directory there and renamed out would not carry what a directory created at
// the destination would have carried, and a rename recomputes nothing — so the
// object is built at its final name instead, which is the inheritance the
// destination actually describes. The other is a substitution: this job made a
// private directory and could not open it, or opened something that was not it.
// That is evidence of interference rather than an environment, and it refuses
// the entry — otherwise an attacker could pick the weaker path simply by
// racing the staging directory away.
//
// The ACL rule is about WRITE and only write. Substituting means creating,
// renaming or removing an entry, so an inherited ACE that grants a group read,
// list or execute on the staging directory is harmless — it shows them a name
// and a half-made object whose finished permissions they were going to be given
// anyway — while one that grants ADD_FILE, ADD_SUBDIRECTORY, DELETE_CHILD,
// DELETE, WRITE_ACL or WRITE_OWNER is the attack itself. Refusing on read too
// would have refused every share whose dataset hands new directories an
// inherited read entry, which is most of them (acl_linux.go).
//
// Where a private staging directory cannot be had, the answer depends on WHY.
// A destination other users may legitimately write — a group-writable share,
// which is what a share is — gets everything built at its final name under the
// proofs above, and the job says once that the swap protection is reduced
// (`shared_destination`); refusing there would refuse the ordinary case. A
// destination only this worker can write, or a sticky one where the kernel will
// not let anybody else take an entry of ours, gets the same treatment and no
// remark, because there is nobody to hide from. Only the suspicious answer
// refuses the entry outright (`unverified`): the private directory this job
// made was not the one it opened, or its ACL could not be read at all.
//
// Residuals, in one place, each explained where it lives:
//
//   - A rewrite of the published copy inside its own publication tick is
//     indistinguishable by timestamps; the writer needs write access to the
//     copy, which is the access they had to the source (destClockSettled).
//   - The same shape on the source side during a plain COPY: an equal-length
//     rewrite inside the tick the read happened in, of a file small enough to
//     be read inside one tick. A move settles before it reads and does not have
//     it (copyFile).
//   - A destination whose timestamps are coarser than the source's can fail to
//     settle inside the bound, which reports the entry unverifiable and keeps
//     its source rather than risking it (settled).
//   - Two-syscall windows the kernel offers no way to close: the lstat that
//     matches an entry and the unlinkat that removes it, and the check that a
//     name still means our inode and the renameat that publishes it. Linux has
//     neither unlink-by-descriptor nor rename-by-descriptor (§2.4-class;
//     deleteRecorded, publish).
//   - A cleanup that finds a stranger at its name removes nothing, which leaves
//     this job's own partial file under whatever name it was renamed to
//     (unlinkIfOurs). It is the named path's residual only: an unnamed file has
//     no name for anybody to take and nothing to clean up.
//   - Where O_TMPFILE is unavailable — an old kernel, a filesystem without it,
//     or no /proc for the linkat that publishes one — a file is created under a
//     name, and between that creation and the chown that follows it anybody who
//     can reach the name can open the empty file and keep the descriptor. That
//     is the window the unnamed path closes by construction, and it stays open
//     on the fallback (openUnnamed, unnamedOK). Off Linux the same, and there
//     nothing chowns at all.
//   - A destination other users may write gets no private staging directory, so
//     a directory or a symlink stands under its final name for the instant
//     between being created and being opened, and the proofs are stat-based
//     again rather than structural: an empty directory of this worker's uid,
//     the expected group, a mode no wider and a named-user ACL riding along
//     invisibly would pass. It needs a local user with write access to the
//     destination actively racing the job, the job says once that the
//     protection is reduced (`shared_destination`), and File Station offers no
//     protection here at all (stagingIn, sharedDestination).
//   - A filesystem mounted `grpid` (`bsdgroups`) gives every new entry the
//     containing directory's group with no setgid bit to announce it, and the
//     created-group proof refuses there rather than adopting something it
//     cannot explain. QTS mounts neither its ext4 volumes nor its ZFS datasets
//     that way, and the failure keeps the user's data (createdInGroup).
//   - A local process holding a writable MAP_SHARED mapping of a source file
//     can change a page after it has been compared, and a page written through
//     a mapping updates no timestamp the kernel will let anyone observe in
//     time. Linux has no mandatory locking to borrow, so there is nothing a
//     file manager — or mv, or cp — can do about it; it also requires a local
//     process actively mapping the very file being moved, which is not the
//     shape of any of the attacks above.
//
// What is deliberately given up: io.CopyBuffer with an explicit buffer rather
// than *os.File's ReadFrom, so copy_file_range and sendfile are not used. The
// contract asks for a cancellation check and a byte count per buffer (§1.6),
// and a copy that cannot be stopped — or that reports nothing for four minutes
// while the kernel moves 40 GB — is the wrong trade for a file manager whose
// every long job is cancellable.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

const (
	// copyBufSize is the transfer buffer, from contract §1.6. It is also the
	// cancellation granularity and the progress granularity: one context check
	// and one byte count per megabyte moved.
	copyBufSize = 1 << 20

	// maxKeepBothTries bounds the "keep both" name search. A hundred "(2)",
	// "(3)"… candidates is already far past the point where a human meant this,
	// and an unbounded search is an lstat loop a directory of collisions can
	// hold open forever.
	maxKeepBothTries = 100

	// maxExistsWarnings bounds the ONE warning a copy can produce per file as a
	// matter of routine: "it was already there and the policy is skip". Every
	// other warning in this file is exceptional and is reported however many
	// there are, exactly as the delete reports its per-item failures — but
	// merging a large folder under `skip` is an ordinary thing to ask for, and
	// it would otherwise put one frame on the socket per file for a job that is
	// behaving perfectly. Past the bound the skips are still COUNTED, so
	// JobResult.Skipped is the whole number and a move still keeps its source;
	// only the individual frames stop, once, with a note saying so. The bound is
	// the wire's own warning cap, because that is how many the terminal result
	// could have carried anyway.
	maxExistsWarnings = wproto.WarnCap

	// maxTrackedDirs bounds the set of destination directory identities a job
	// keeps (copier.made). It is a SEPARATE number from maxVerifiedEntries, and
	// the two must not be conflated: this set is a security check that FAILS
	// CLOSED — exhausting it stops the root, because a job that cannot
	// recognise its own output could copy it back into itself — while the copy
	// record below is a memory bound whose exhaustion only means the source is
	// kept. They also count different things: one entry per destination
	// DIRECTORY here, one per ENTRY there, which in an ordinary tree differ by
	// a factor of fifty or more. Sharing a bound made the security refusal fire
	// first on any tree that reached either.
	maxTrackedDirs = 1_000_000

	// maxVerifiedEntries bounds the record a move keeps of what it copied
	// (copiedDir). A million entries is about a hundred megabytes of record in
	// a worker that is serving one user, and it is two orders of magnitude past
	// any move anybody makes from a file manager. Past it the copy still
	// completes and the SOURCE IS KEPT: removing a tree because a record that
	// was never finished did not contradict it is exactly the mistake the
	// record exists to prevent.
	maxVerifiedEntries = 1_000_000

	// copyTmpPrefix and copyTmpSuffix name the file an OVERWRITE is written to
	// before it is renamed over its target (§1.3). It is a dot-name so a
	// listing hides it, and it carries eight random hex digits so two copies
	// running at once in one directory cannot collide.
	copyTmpPrefix = ".qfm-copy-"
	copyTmpSuffix = ".part"
)

// Warning codes this engine reports. They join the delete's vocabulary
// (not_empty, no_trash, capped) rather than replacing it; the front-end's
// actionMessage turns them into sentences.
const (
	// warnExists: the destination already has this name and the policy is skip
	// — including the "moving something into the directory it is already in"
	// no-op the route refuses lexically (§1.7).
	warnExists = "exists"
	// warnConflict: a type mismatch (a file over a folder, a folder over a
	// file, a symlink over anything else), or a keep-both search that ran out of
	// names. Refused under every policy.
	warnConflict = "conflict"
	// warnUnsupported: a fifo, a socket or a device node. There is nothing to
	// copy — the bytes are not in the filesystem — so it is skipped (§1.6).
	warnUnsupported = "unsupported"
	// warnKept: a move whose copy was not clean, so the source was left in
	// place. The message says how many items could not be copied.
	warnKept = "kept"
	// warnOwnerUnset: the entry was created but the chown after it failed. The
	// entry stays; the root does not count as clean.
	warnOwnerUnset = "owner_unset"
	// warnTimesUnset: the entry was created but its modification time could not
	// be reproduced. Same treatment: the copy is not faithful, so a move keeps
	// its source.
	warnTimesUnset = "times_unset"
	// warnChanged: the source was written to while it was being copied, so what
	// landed at the destination is as much as was read and not the file the
	// scan measured.
	warnChanged = "changed"
	// warnTooMany: the job created more destination folders than it can keep
	// the identity of, so the check that stops it copying its own output back
	// into itself has stopped working and the root was refused (remember).
	warnTooMany = "too_many"
	// warnUnverified: the entry was copied, but the change time it was recorded
	// with could not be proved to be in the past of the filesystem's own clock,
	// so a later in-place rewrite would be indistinguishable from it. The copy
	// is at the destination; the source is not removed on a record like that.
	warnUnverified = "unverified"
	// warnNoSpace: the destination has less room than this job needs. It is a
	// job-level refusal before anything is written; it is only a per-item
	// warning when an earlier root of the same job has already been moved.
	warnNoSpace = "no_space"
	// warnSharedDest: the destination is a directory other users may write, so
	// this job could not build inside a private directory of its own and built
	// at final names instead (sharedDestination). It is said ONCE per job, it
	// names no entry, and it is about the place rather than about anything that
	// failed — every object is created and proved exactly as before.
	warnSharedDest = "shared_destination"
)

// Copy copies — or, with move set, moves — each source into one destination
// directory.
//
// It runs in three phases. The bounded pre-scan (the same 30 s / 500 000-entry
// cap the delete uses) gives progress its denominator and the free-space check
// its number; the transfer itself is phase "working"; and the delete of a
// move's sources is phase "finishing".
//
// Three of CopyOptions' fields are accepted and not acted on, and it is worth
// being explicit about which. PreserveMode: the creation mode is always the
// source's permission bits under the umask and no chmod is ever issued (§1.5),
// so there is nothing for a flag to select. PreserveTimes: always honoured —
// the wire field is a bool with omitempty, so "false" and "absent" are the same
// bytes and the contract says an absent value means true (see setTimes).
// FollowSymlinks: a symlink is always recreated as the link it is and never
// followed (§1.6), which is what keeps "copy this folder" from reaching through
// a link into /etc; a follow mode would need its own design, not a flag.
//
// The error return is reserved for what stops the whole job: the context being
// cancelled, a destination directory that cannot be opened or is not a
// directory, an unusable conflict policy, and fsx.ErrNoSpace — which is refused
// before a single byte is written. Everything else is a warning against the
// item it happened to, and the counts that come back are real: nothing is ever
// rolled back, and a cancelled job reports exactly what it managed to do.
func Copy(ctx context.Context, r fsx.Root, plat *platform.Platform, req wproto.CopyReq, move bool, emit Emit) (wproto.JobResult, error) {
	c := &copier{
		r:          r,
		plat:       plat,
		emit:       emit,
		move:       move,
		cross:      req.Opts.CrossMounts,
		filesTotal: -1,
		bytesTotal: -1,
	}
	if err := c.setPolicy(req.Opts.Conflict); err != nil {
		return c.res, err
	}
	c.setOwnership(req.Opts.As)

	if err := c.openDest(ctx, string(req.DstDir)); err != nil {
		return c.res, err
	}
	defer c.dst.close()
	// The container's own staging directory outlives every root, so it is
	// removed here rather than by unwind. Each destination directory's own goes
	// with that directory (dropStage).
	defer c.dropStages()

	srcs := c.sources(req.Src)
	if len(srcs) == 0 {
		return c.res, nil
	}
	if err := c.scan(ctx, srcs); err != nil {
		return c.res, err
	}
	// A copy knows up front that every byte has to be written, so the refusal
	// is made once, before anything is created. A move does not: a root that
	// renames writes nothing, and refusing a same-filesystem move because the
	// volume is nearly full would be a bug. Its check is deferred to the first
	// root that actually falls back to copying (ensureSpace).
	if !move {
		if err := c.ensureSpace(c.bytesTotal); err != nil {
			return c.res, err
		}
	}

	for i := range srcs {
		if err := ctx.Err(); err != nil {
			return c.res, err
		}
		if err := c.one(ctx, srcs[i]); err != nil {
			return c.res, err
		}
	}
	if c.kept > 0 {
		c.res.Detail = fmt.Sprintf("%d of %d sources were kept because their copy was not clean", c.kept, len(srcs))
	}
	// Asked once more before reporting success. The per-root loop checks the
	// context at the top of each iteration, which says nothing about a
	// cancellation that arrived while the LAST root was finishing — and a job
	// that returns a nil error is reported by the worker as ordinary
	// completion, so a CancelJob that landed a moment too late looked like the
	// job having simply finished. Whatever was done is still reported; what
	// changes is that the caller is told it was stopped.
	if err := ctx.Err(); err != nil {
		return c.res, err
	}
	return c.res, nil
}

// source is one selected root and what the pre-scan found under it.
type source struct {
	api  string
	scan scanResult
}

// copier carries one copy or move job.
type copier struct {
	r    fsx.Root
	plat *platform.Platform
	emit Emit

	move     bool
	cross    bool
	conflict string
	// as is the owner every entry a COPY creates is chowned to (§1.4). It is
	// nil for a move, for a non-root worker, and when the route did not ask.
	as *Owner
	// keepOwner is the move-by-copy rule: reproduce each entry's own uid and
	// gid, which is what the rename this fell back from would have done. Only
	// the root worker can, so only the root worker does.
	keepOwner bool

	// dst is the destination directory, opened once and held for the whole job
	// (§1.7). dstAPI is its resolved API path and dstJail the handle it was
	// opened through.
	dst     *dirRef
	dstAPI  string
	dstJail fsx.Jail
	// dstID is the destination's own identity, taken from the held descriptor.
	// The source walk compares every directory it meets against it, so a
	// destination that is moved INTO the source while the job runs is caught
	// where it is met rather than only where the job started.
	dstID    inodeKey
	dstHasID bool
	// madeFull records that the set below could not take another identity, so
	// every remaining root of this job is refused too rather than run without
	// the protection it provides.
	madeFull bool
	// made is the identity of EVERY destination directory this job has created
	// or adopted, and the source walk refuses to descend into any of them.
	//
	// The container and its ancestry are not enough. A freshly created
	// /dst/a — a directory this job made, that no check had ever heard of —
	// renamed into /src/a/z while the walk was running put the copy's own
	// output inside the tree being copied, and it recursed into it until the
	// volume was full. Anything this job wrote is something it must not then
	// read back.
	made map[inodeKey]struct{}
	// ancestry is the destination and every directory above it, by identity, so
	// a source directory that is one of them is refused before anything is
	// created (§1.7). It is re-collected per root, from the held destination
	// descriptor, because the chain above a held fd is not itself held: the
	// pre-scan may run for thirty seconds, and anybody who can move the
	// destination can change what is above it in that time.
	ancestry []inodeKey

	res        wproto.JobResult
	filesTotal int64
	bytesTotal int64
	// warns counts every warning this job reported. The worker keeps its own
	// ledger for the terminal frame; this one exists so the counters here can
	// be read back per root.
	warns int64
	// contentWarns counts the subset of those warnings that mean something of
	// the source is NOT at the destination (contentWarning). It, and not warns,
	// is what a move's delete-the-source decision reads: "zero content
	// warnings and zero skips FOR THIS ROOT".
	contentWarns int64
	// kept counts the move sources left in place because their copy was not
	// clean, for the job's Detail.
	kept int
	// existsWarns counts the routine "already at the destination" skips, which
	// are bounded on the wire (maxExistsWarnings) and never in the result.
	existsWarns int
	// touched records that something has been created, renamed or removed, so
	// a late refusal knows whether it can still be the job's own error.
	touched bool

	// clockSeen is the latest instant this job has observed each FILESYSTEM's
	// own inode clock to have reached, keyed by device (settled). A record on
	// that filesystem older than its entry needs no further proof. It is per
	// filesystem and not per job because two filesystems round timestamps
	// differently, and a reading from one says nothing about the other.
	clockSeen map[uint64]time.Time

	// unnamed says whether this destination can give the job files with no
	// name that it can then publish by link (unnamedOK). It is asked once and
	// remembered, because the answer belongs to the destination filesystem and
	// the destination never crosses one.
	unnamed unnamedState

	// stages holds the private staging directory of each destination directory
	// this job has built something in, keyed by the held descriptor it belongs
	// to (stagingIn). Each is removed when its directory is finished with
	// (dropStage), before that directory's timestamps are reproduced.
	stages map[*dirRef]*staging
	// sharedWarned records that this job has already said, once, that its
	// destination is one other users can write (sharedDestination).
	sharedWarned bool

	// buf is the transfer buffer, allocated once per job rather than once per
	// file: a megabyte per file over a million files is a gigabyte of garbage.
	// cmp is its opposite number, allocated only when a hard-linked file has to
	// be compared with its copy (sameBytes).
	buf []byte
	cmp []byte

	// frames is the stack of destination directories currently open, one per
	// depth of the source walk. See unwind.
	frames []destFrame
	// pending is a destination directory whose placement Pre has decided and
	// whose creation is waiting for the source descriptor Opened supplies.
	pending pendingDir
	// srcRootParent is the held parent of the root currently being copied. It is
	// where every SOURCE clock reading is taken, for the reason destClockSettled
	// gives: never in a directory whose modification time this job reproduces.
	srcRootParent *dirRef

	// ledger is what this root actually copied, recorded entry by entry so the
	// move's delete can remove exactly that and nothing else (copiedDir).
	// ledgerCount bounds its size and ledgerFull says the bound was hit, at
	// which point the source is kept rather than removed unverified.
	ledger      *copiedDir
	ledgerCount int
	ledgerFull  bool
}

// copiedDir and copiedEntry are the record of what a copy really put at the
// destination, kept so that the delete half of a move can be a verified removal
// of exactly those objects rather than a fresh walk of a pathname.
//
// The reason is the failure this replaced. Re-walking the source by name at
// delete time removes whatever is there NOW: a file written into the tree after
// its sibling was copied is deleted having never reached the destination, and a
// directory component swapped for a symlink between the copy and the delete
// sends the removal somewhere else entirely. Neither is a race that can be
// argued away — both were reproduced. So the copy writes down what it moved,
// and the delete proves each entry is still that before unlinking it.
//
// The cost is memory: roughly a hundred bytes plus a name per entry, bounded by
// maxVerifiedEntries. Past the bound the source is KEPT, with a warning saying
// the tree was too large to verify — the conservative direction, because the
// alternative is deleting a user's data on the strength of a record that was
// never made.
type copiedDir struct {
	// id is the source directory's identity at the moment the copy descended
	// into it.
	id     inodeKey
	haveID bool
	// mode, uid and gid are what the copy reproduced at the destination, taken
	// from the descriptor the walk enumerated. They are required to be
	// unchanged before anything inside the directory is removed: a source
	// directory tightened 0755 -> 0700, or chowned, after its copy was made is
	// the same hole the per-file record closed, one level up — the restriction
	// the user had just applied would be dropped and the original deleted.
	mode      fs.FileMode
	uid, gid  int
	haveOwner bool
	// dstName, dstID and haveDstID name the directory this one was copied INTO,
	// so the delete can reopen it from the held destination above it and prove
	// it is the one this job created (openRecordedDest). It is only ever needed
	// when something below has to be compared byte for byte.
	dstName   string
	dstID     inodeKey
	haveDstID bool
	// entries are its children, in the order they were copied. A directory's
	// own record carries the sub-directory's copiedDir.
	entries []copiedEntry
}

type copiedEntry struct {
	// name is the SOURCE name, which is what the delete unlinks. It can differ
	// from the destination name: "keep both" renames at the destination only.
	name string
	kind kind
	// recorded separates "this entry was copied" from the zero value. Without
	// it the two would be told apart by the identity, which is exactly what a
	// platform with no inode numbers cannot supply.
	recorded bool
	// id, size, mtime and ctime are what the entry was when it was copied. All
	// of them have to still hold before it is unlinked.
	//
	// ctime is the one that cannot be forged. A file rewritten in place with
	// the same number of bytes, and its mtime put back with utimensat, matched
	// identity, size and modification time and was deleted as though nothing
	// had happened — the reviewer's probe. st_ctim moves on every write, every
	// chmod, every chown and every utimensat, and no interface lets an
	// unprivileged process move it back.
	id        inodeKey
	haveID    bool
	size      int64
	mtime     time.Time
	ctime     time.Time
	haveCtime bool
	// nlink is how many names the inode had when it was copied. More than one
	// means the change time this entry recorded will be moved by THIS JOB's own
	// unlink of a sibling link, so timestamps cannot prove it and the bytes are
	// compared instead (contentMatches).
	nlink uint64
	// mode, uid and gid are the source's permissions and ownership when it was
	// copied, compared independently of the change time.
	//
	// They have to be their own fields because ctime is exempted wherever this
	// job moved it itself: a chmod 0644 -> 0600 (or a chown) of the source
	// AFTER the copy leaves identity, size, modification time and even the
	// bytes matching, so a hard-linked file was deleted and its copies left
	// world-readable — a restriction the user had just applied, dropped.
	mode      fs.FileMode
	uid, gid  int
	haveOwner bool
	// dstName, dstID and haveDstID name the copy this job published, so that
	// comparison has something to open and something to prove it by.
	dstName   string
	dstID     inodeKey
	haveDstID bool
	// dstSize, dstMtime and dstCtime are the published copy's own state, read
	// back after everything that touches it — the chown, the times and, for an
	// overwrite, the rename. Identity, kind and length alone let a destination
	// rewritten in place with the same number of bytes pass, and the source was
	// then deleted with the copy holding somebody else's contents.
	dstSize      int64
	dstMtime     time.Time
	dstCtime     time.Time
	haveDstCtime bool
	// link is a symlink's target text, compared as well as its identity: a link
	// is small enough that reading it again costs nothing and it is the one
	// part of a symlink that is its content.
	link string
	// dir is the sub-record for a directory entry.
	dir *copiedDir
}

// destFrame is one destination directory the copy is writing into.
//
// It exists because a directory's modification time can only be set AFTER its
// children have been written — writing a child is what moved it — so the
// directory has to be held until the walk leaves it, and something has to
// notice when it does. Walk's Post hook is not that something: a directory the
// walk could not open, and a mount point it would not enter, both get a Pre and
// never a Post. The stack is unwound by depth instead, which is correct for
// every one of those cases and for cancellation as well.
type destFrame struct {
	parent  *dirRef     // the directory this one was created in, held by the frame below
	name    string      // its name inside parent
	dir     *dirRef     // the held destination directory
	api     string      // its destination API path, for warnings
	srcInfo os.FileInfo // the source directory's lstat, for the times
	srcAPI  string      // the SOURCE directory's API path, for warnings
	// srcDir is the HELD descriptor of the source directory this frame
	// reproduces, so its state can be re-proved without naming it. The root's
	// is the one walkFrom was handed; every other frame's arrives with the
	// first child enumerated out of it (WalkItem.parent, captured in
	// ancestorUnchanged).
	srcDir  *dirRef
	created bool // false when an existing directory was merged into
	// changed says the source directory this frame reproduces stopped being
	// the object that was recorded, part way through its own contents. The
	// rest of it is not copied and the reason is reported once (pre).
	changed bool
	// rec is the record of what was copied out of the SOURCE directory this
	// frame corresponds to, for the move's verified delete (copiedDir).
	rec *copiedDir
}

// setPolicy fixes the conflict policy for the job. An empty policy is skip, as
// the wire says (§1.3); anything else is a request this engine will not guess
// at, and the route's 422 is the front-end half of the same refusal.
func (c *copier) setPolicy(conflict string) error {
	switch conflict {
	case "", wproto.ConflictSkip:
		c.conflict = wproto.ConflictSkip
	case wproto.ConflictOverwrite, wproto.ConflictRename:
		c.conflict = conflict
	default:
		return fmt.Errorf("%q is not a conflict policy: %w", conflict, fsx.ErrBadName)
	}
	return nil
}

// setOwnership decides what this job does about the owner of what it creates
// (§1.4, and the ownership review's findings B/D: chown only, never chmod).
//
// A copy applies CopyOptions.As to every created entry, which is how an
// administrator's root worker makes content owned by the real signed-in user
// instead of by root. A move that falls back to copy+delete reproduces each
// entry's OWN uid and gid instead — that is what the rename it could not make
// would have done — and ignores As entirely.
//
// Both are the root worker's alone. The kernel refuses a non-root process that
// chowns an inode to another uid (EPERM), so a non-root worker that tried would
// produce one warning per file for something it was never going to achieve;
// refusing to try is the same answer, once, and INV-2 is unharmed because the
// only thing not attempted is a call whose outcome the kernel has already
// fixed. os.Geteuid reports -1 on Windows, so the dev loop never chowns either.
func (c *copier) setOwnership(as *wproto.CreateAs) {
	if os.Geteuid() != 0 {
		return
	}
	if c.move {
		c.keepOwner = true
		return
	}
	if as != nil {
		// Mode is deliberately not carried across: no path here chmods.
		c.as = &Owner{UID: as.UID, GID: as.GID}
	}
}

// openDest resolves the destination directory and holds it open for the whole
// job (§1.7).
//
// The final component IS followed: "copy into /share/Public" means the dataset
// that share symlink points at, which is how QTS builds its whole layout. What
// comes back is a descriptor, and every entry the job creates is created
// relative to it — so a rename of the destination mid-job moves the whole copy
// with it rather than redirecting it somewhere else.
func (c *copier) openDest(ctx context.Context, dst string) error {
	clean, err := fsx.Clean(dst)
	if err != nil {
		return err
	}
	// F10, applied to the one path this job writes through. The guard refuses
	// these too; the worker refuses them as well because it is the process that
	// sees every path below them.
	if reason, hit := neverWritePath(clean); hit {
		return neverWriteErr(clean, reason)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tg, err := resolve(c.r, clean, true)
	if err != nil {
		return err
	}
	d, err := openPathRef(tg.jail, tg.rel)
	if err != nil {
		return err
	}
	fi, err := d.stat()
	if err != nil {
		d.close()
		return err
	}
	if !fi.IsDir() {
		d.close()
		return fmt.Errorf("%q is not a directory: %w", clean, fsx.ErrBadName)
	}
	c.dst, c.dstAPI, c.dstJail = d, tg.api, tg.jail
	c.dstID, c.dstHasID = inodeOf(fi)
	c.ancestry = destAncestry(tg.jail, d)
	return nil
}

// refreshAncestry re-reads the chain above the destination from the held
// descriptor.
//
// It is called per root, immediately before that root's placement is decided
// and its first entry is created, and never once at the start of the job. The
// destination itself is held and cannot be substituted — but nothing holds what
// is ABOVE it, and a bounded pre-scan may run for thirty seconds. A user who
// controls both ends moves the destination into the source during the scan; the
// held fd follows it, a snapshot of the old ancestry does not, and the walk then
// copies its own output until the volume is full. Re-asking costs a handful of
// openats per root against a job that is about to move a filesystem.
func (c *copier) refreshAncestry() {
	c.ancestry = destAncestry(c.dstJail, c.dst)
	if fi, err := c.dst.stat(); err == nil {
		c.dstID, c.dstHasID = inodeOf(fi)
	}
}

// meetsDestination reports that a directory the source walk has reached IS the
// destination, or one of the directories above it.
//
// It is the same question insideSource asks of a selected root, asked again of
// every directory the walk meets — because the answer can become true after the
// job started, and because a `true` that arrives late is an unbounded recursion
// rather than a wrong number.
func (c *copier) meetsDestination(fi os.FileInfo) bool {
	k, ok := inodeOf(fi)
	if !ok {
		return false
	}
	if c.dstHasID && k == c.dstID {
		return true
	}
	if _, ours := c.made[k]; ours {
		return true
	}
	for _, a := range c.ancestry {
		if a == k {
			return true
		}
	}
	return false
}

// remember records a destination directory this job created or adopted, so the
// source walk will refuse to descend into it if it turns up inside the tree
// being copied.
//
// It is bounded by the same number as the copy record: past it new directories
// stop being remembered, and the container-and-ancestry check — which no rename
// can evade, because the container is held — carries on alone. A job with a
// million destination directories has other problems.
// It FAILS CLOSED. The bound used to stop new directories being remembered and
// let the job carry on, which is the worst of both: past it the self-copy
// protection was simply absent, silently, on exactly the enormous job where an
// unbounded recursion costs the most. A directory this job cannot track is a
// directory it will not write under — the root stops, and for a move that means
// the source is kept, because a stopped root is not a clean one.
func (c *copier) remember(dir *dirRef) error {
	fi, err := dir.stat()
	if err != nil {
		return err
	}
	k, ok := inodeOf(fi)
	if !ok {
		if inodeIdentity {
			// This platform has identities and this one could not be read: a
			// measurement that failed, which is a refusal.
			return errUntracked
		}
		// Off Linux there are no identities at all, so there is no set to keep
		// and nothing to fail closed about; the lexical containment check is
		// the whole protection there, as it is for every other identity test in
		// this file (INV-2).
		return nil
	}
	if c.made == nil {
		c.made = make(map[inodeKey]struct{}, 64)
	}
	if _, already := c.made[k]; !already && len(c.made) >= trackedDirBound {
		c.madeFull = true
		return errUntracked
	}
	c.made[k] = struct{}{}
	return nil
}

// errNotOurs says a directory this job had just created turned out not to be
// the one it made, so nothing may be written into it. It abandons the subtree;
// the caller reports it as `changed`.
var errNotOurs = errors.New("fsops: what was just created is not this job's")

// errUntracked stops a root whose destination directories can no longer all be
// remembered. It never leaves this file; copyTree turns it into a warning
// against the root.
var errUntracked = errors.New("fsops: more destination folders than this job can track safely")

// sources cleans the selected paths, dropping the ones this job will not touch
// with a warning against each.
func (c *copier) sources(raw [][]byte) []source {
	out := make([]source, 0, len(raw))
	for _, b := range raw {
		p := string(b)
		clean, err := fsx.Clean(p)
		if err != nil {
			c.skip(p, err)
			continue
		}
		if reason, hit := neverWritePath(clean); hit {
			c.skip(clean, neverWriteErr(clean, reason))
			continue
		}
		out = append(out, source{api: clean})
	}
	return out
}

// scan counts what is about to be moved, one root at a time and under one
// shared bound.
//
// Per root rather than in a single call because a move needs each root's own
// totals: a root that RENAMES is never walked again, so the only numbers the
// progress can credit it with are the ones the scan found.
//
// The bound is the delete's (30 s, 500 000 entries) and it is shared across the
// roots rather than granted afresh to each, so a selection of fifty folders
// cannot scan for twenty-five minutes. Past it the totals are -1 and the UI
// shows an indeterminate bar, which is the same answer a delete gives.
func (c *copier) scan(ctx context.Context, srcs []source) error {
	lim := scanLimits{deadline: time.Now().Add(scanMaxDuration), maxEntries: scanMaxEntries}
	var files, dirs, bytes int64
	capped := false

	for i := range srcs {
		if err := ctx.Err(); err != nil {
			return err
		}
		rl := lim
		if lim.maxEntries > 0 {
			rl.maxEntries = lim.maxEntries - (files + dirs)
			if rl.maxEntries <= 0 {
				capped = true
				break
			}
		}
		// The per-root scan restarts its own counters, so the progress it emits
		// is offset by what the earlier roots already contributed; without that
		// the bar would run backwards at every root boundary.
		doneFiles, doneBytes := files, bytes
		off := Emit{Prog: func(p wproto.Prog) {
			p.Files += doneFiles
			p.Bytes += doneBytes
			c.emit.prog(p)
		}}
		res, err := scanTrees(ctx, c.r, c.plat, []string{srcs[i].api}, c.cross, false, off, rl, true, ProtectWrite)
		if err != nil {
			return err
		}
		srcs[i].scan = res
		if res.capped || bytes > math.MaxInt64-res.bytes {
			// Either the bound stopped this root, or the byte total has
			// outgrown an int64 (a tree of sparse files can declare that). Both
			// mean the same thing to everything downstream: what follows is a
			// floor and not a total.
			capped = true
		}
		files += res.files
		dirs += res.dirs
		if !capped {
			bytes += res.bytes
		}
	}

	if capped {
		warnScanCapped(c.emit)
		c.filesTotal, c.bytesTotal = -1, -1
		return nil
	}
	c.filesTotal, c.bytesTotal = files+dirs, bytes
	return nil
}

// ensureSpace refuses a job that cannot fit, before it writes anything (§1.9).
//
// need is what the CALLER is about to write, and getting that right is the
// whole of the question. A copy asks once, up front, for the whole selection,
// because every byte of it is going to be written. A move asks per root, at the
// moment that root falls back to copying, for that root's own scanned bytes —
// because the roots it renamed wrote nothing at all, and charging their size
// against the free space refused a one-kilobyte cross-dataset move that
// happened to be selected alongside a hundred-gigabyte same-filesystem one.
//
// One fstatfs per call, on the descriptor the destination is already held on. A
// filesystem that will not answer (no fstatfs off Linux, a zero block size) is
// not a refusal: the kernel's own ENOSPC is still there, and inventing a limit
// this app cannot measure is the wrong half of INV-2.
func (c *copier) ensureSpace(need int64) error {
	if need <= 0 {
		// Nothing to write, or a capped scan whose total is not a total. There
		// is no honest comparison to make.
		return nil
	}
	avail, ok, err := statfsAvail(c.dst)
	if err != nil || !ok {
		return nil
	}
	if avail < uint64(need) {
		return fmt.Errorf("%q has %d bytes free and this needs %d: %w",
			c.dstAPI, avail, need, fsx.ErrNoSpace)
	}
	return nil
}

// statfsAvail is the free-space measurement, as a variable so a test can put a
// number in front of it: filling a real filesystem to provoke the refusal is
// not something a unit test may do, and the branch it guards is the one that
// decides whether a 40 GB copy starts at all. Production never assigns to it.
var statfsAvail = fsStatfs

// renameRoot is the move's first attempt, as a variable for the same reason:
// EXDEV needs two filesystems, and the CI ZFS job is the only place that has
// two. A test forces the fallback path by returning it. Production never
// assigns to it.
var renameRoot = func(dst, srcParent *dirRef, fromName, toName string, noReplace bool) error {
	return dst.renameFromDir(srcParent, fromName, toName, noReplace)
}

// setEntryTimes stamps a created entry, as a variable so a test can fail it.
// utimensat does not fail on a healthy filesystem and cannot be provoked into
// it, and the rule behind it is one that must not silently invert: a move whose
// only complaint is a timestamp still deletes its source (contentWarning).
// Production never assigns to it.
var setEntryTimes = utimesEntry

// verifyTrace, when set, is told the ordered steps a test cannot otherwise
// observe: "root-recorded" once a root's destination has been created and its
// record taken from one fstat, with the walk about to take its own; then, for a
// move's verified delete, "delete" before any entry of a root is judged and per
// regular file "settle" when the change-time proof is about to be made and
// "compare" when the bytes are about to be read.
//
// It exists because the ORDER of those two is the property two rounds of review
// turned on — settling after the comparison proves only that the tick had
// ended by then — and an order is not something a filesystem can be asked about
// afterwards. Every attempt to infer it from outcomes instead staged a
// condition that changed what the engine did, which is how the fixture ended up
// testing recency rather than ordering. So the order is observed directly.
//
// It is nil in production and costs one nil check per verified file.
var verifyTrace func(step string)

func traceVerify(step string) {
	if verifyTrace != nil {
		verifyTrace(step)
	}
}

// mkdirForCopy creates a destination directory, as a variable so a test can
// take the name away again in the instant between the mkdirat and the openat
// that follows it — the window the directory's provenance check exists for, and
// one a test cannot otherwise reach. Production never assigns to it.
var mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
	return d.mkdir(name, mode)
}

// aclFactsOf reads a directory's ACLs, as a variable so a test can say what
// they contain — a filesystem with the ACL of the day on it is not something a
// test can conjure, and what the engine DOES with the answer is the
// security-relevant half. Production never assigns to it.
var aclFactsOf = aclFactsFor

// openUnnamedFile creates the unnamed file a copy is written into, as a
// variable so a test can make a filesystem that has no O_TMPFILE: the fallback
// is a whole path of its own — the file is created under a name, with the
// disclosure window that implies — and it has to be exercised. Production never
// assigns to it.
var openUnnamedFile = openUnnamed

// ledgerObserved is handed a root's record once its copy is finished, as a
// variable so a test can assert what was written down rather than infer it: a
// plain copy must record the per-DIRECTORY state its ancestor checks need and
// not one entry per file, and "it did not keep a million proofs" is not
// something an outcome shows. Production never assigns to it.
var ledgerObserved func(rec *copiedDir)

// setEntryOwner installs the owner on something this job created, as a variable
// so a test can fail one: what a failed chown must cost is an ENTRY — or, for a
// directory, a whole subtree that is never written into — and there is no other
// way to make the kernel refuse a chown this worker is allowed to make.
// Production never assigns to it.
var setEntryOwner = chownEntry

// mkdirForStaging creates the private staging directory, as a variable so a
// test can take the name away again in the instant between the mkdirat and the
// openat that follows it — the window the staging directory's own proof exists
// for, and the one case that still refuses to build anything. It is separate
// from mkdirForCopy so that a test staging a substitution of a COPIED directory
// does not have to reckon with the staging directory's creation as well.
// Production never assigns to it.
var mkdirForStaging = func(d *dirRef, name string, mode os.FileMode) error {
	return d.mkdir(name, mode)
}

// symlinkAtSeam creates a symlink at the destination, as a variable so a test
// can take the name away again in the instant between the creation and the pin
// that proves it — the window the link's provenance check exists for, and one a
// test cannot otherwise reach. Production never assigns to it.
var symlinkAtSeam = symlinkAt

// openForCopy opens a source file for reading, as a variable so a test can
// change the file in the window between the walk's lstat and the open — the
// window the metadata-from-the-descriptor rule exists for, and one a test
// cannot otherwise reach. Production never assigns to it.
var openForCopy = func(d *dirRef, name string, flags int, perm os.FileMode) (*os.File, error) {
	return d.openFile(name, flags, perm)
}

// persistDir flushes a destination directory's entries to stable storage, as a
// variable so a test can observe WHEN it is called — the property that matters
// is that every one of them happens before the first original is unlinked, and
// an order is not something a filesystem can be asked about afterwards — and so
// a test can fail one. Production never assigns to it.
var persistDir = fsyncDir

// copyStream moves the bytes of one file, as a variable so a test can fail in
// the middle of one: the property that matters for `overwrite` is that a
// failure half way leaves the ORIGINAL destination untouched and no temporary
// behind, and there is no other way to observe it. Production never assigns.
var copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, src, buf)
}

// ---- one selected root ------------------------------------------------------

// one handles a single selected source: the refusals only the worker can make,
// then either a rename (a move on one filesystem) or a copy.
func (c *copier) one(ctx context.Context, s source) error {
	// The leaf is kept literal: a symlink named for a copy is the link, not the
	// thing it points at.
	tg, err := resolve(c.r, s.api, false)
	if err != nil {
		c.skip(s.api, err)
		return nil
	}
	parentRel, name := splitFinal(tg.rel)
	if tg.rel == "." || tg.rel == "" || name == "" || name == "." {
		c.skipCode(s.api, "bad_request",
			fmt.Sprintf("%q is the root of the tree and has no name to copy under", s.api), 0)
		return nil
	}
	// The source's PARENT is opened once and held for the whole of this root:
	// the rename is made from it, the entries are read through it, and the
	// verified delete unlinks through it. Nothing about this root ever resolves
	// a pathname again — which is what stops a directory component being
	// swapped for a symlink between the copy and the delete and sending the
	// removal into /etc.
	srcParent, err := openPathRef(tg.jail, parentRel)
	if err != nil {
		c.skip(s.api, err)
		return nil
	}
	defer srcParent.close()
	c.srcRootParent = srcParent
	defer func() { c.srcRootParent = nil }()

	// Held for the rest of this root: past the copy, past the verification, and
	// past the delete decision. A stat would have been a snapshot of a name —
	// the inode it described can be unlinked and its (dev, ino) handed straight
	// to a file somebody else creates — and this reference is what the identity
	// check before the source delete is made against. It is opened through the
	// held parent, so it is an entry of THAT directory and not of whatever the
	// parent's name means by now.
	ref, err := itemRefIn(srcParent, name)
	if err != nil {
		c.skip(s.api, err)
		return nil
	}
	defer ref.close()

	fi := ref.fi
	srcAPI := tg.api
	k := kindOf(fi)
	if k == kindSpecial {
		c.skipCode(srcAPI, warnUnsupported,
			fmt.Sprintf("%q is a %s, which has no contents to copy", srcAPI, fsx.TypeString(fi.Mode())), 0)
		return nil
	}

	osPath, oerr := c.r.OS(srcAPI)
	if oerr != nil {
		osPath = ""
	}
	if c.move && mountPointAt(c.r, c.plat, tg, fi, osPath) {
		// The same refusal the delete makes, and for the same reason: a move
		// ends in a delete, and emptying a mount point unmounts a volume by
		// removing everything on it. A COPY of a mount point is fine and is
		// allowed — it reads, it does not remove (§1.8).
		c.skipCode(srcAPI, "protected",
			fmt.Sprintf("%q is a mount point, so it can be copied but not moved", srcAPI), 0)
		return nil
	}
	// Re-asked here, per root and from the held destination descriptor, rather
	// than once when the job started: the pre-scan may have run for thirty
	// seconds and an earlier root's copy for much longer, and the chain above
	// the destination is not something this process holds.
	c.refreshAncestry()
	if k == kindDir && c.insideSource(srcAPI, fi) {
		c.skipCode(srcAPI, "invalid_target",
			fmt.Sprintf("%q is the destination or contains it, so copying it there would never end", srcAPI), 0)
		return nil
	}

	p, ok := c.placeRoot(srcParent, ref, srcAPI, name, k)
	if !ok {
		return nil
	}

	if c.move && p.act != actMerge {
		done, err := c.tryRename(srcParent, srcAPI, name, fi, s, p)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}

	// From here it is a copy, whichever job kind asked for it — which is also
	// where the output-tracking refusal belongs. A rename walks nothing and
	// creates no directory, so it cannot copy its own output back into itself
	// and it is not refused for a set an earlier root exhausted; only a job
	// about to WALK needs that protection, and the set is job-wide, so every
	// copying root after the one that filled it would run without it.
	if c.madeFull {
		c.untracked(srcAPI)
		return nil
	}

	// A move charges
	// only THIS root's bytes, because the roots it renamed wrote nothing; a
	// copy was charged for the whole selection before the loop started.
	if c.move {
		if err := c.ensureSpace(rootBytes(s.scan)); err != nil {
			if !c.touched {
				// Nothing has been created, renamed or removed yet, so this is
				// still the job's own refusal and the front-end reports it as
				// one rather than as a per-item warning.
				return err
			}
			c.skipCode(srcAPI, warnNoSpace, err.Error(), 0)
			return nil
		}
	}
	c.touched = true

	warnsBefore, skipsBefore := c.contentWarns, c.res.Skipped
	c.ledger = &copiedDir{}
	c.ledger.id, c.ledger.haveID = inodeOf(fi)
	c.ledgerCount, c.ledgerFull = 0, false

	if k == kindDir {
		err = c.copyTree(ctx, srcParent, srcAPI, name, ref, p)
	} else {
		err = c.copyEntry(ctx, srcParent, name, fi, srcAPI, c.dst, c.dstAPI, p, c.ledger)
	}
	if err != nil {
		return err
	}
	if ledgerObserved != nil {
		ledgerObserved(c.ledger)
	}
	if !c.move {
		return nil
	}
	return c.finishMove(ctx, srcParent, srcAPI, name, ref, k,
		c.contentWarns-warnsBefore, c.res.Skipped-skipsBefore)
}

// rootBytes is what one root will write, or 0 when its scan could not say. A
// capped scan's total is a floor rather than a total, and a floor is not
// something to refuse a job on.
func rootBytes(scan scanResult) int64 {
	if scan.capped {
		return 0
	}
	return scan.bytes
}

// placeRoot decides what a selected root becomes inside the destination, and
// reports false when it becomes nothing.
//
// The one case the per-entry rule cannot express is the destination being the
// source's OWN parent. Under `rename` that is the "duplicate this" gesture and
// makes a "(2)" beside it. Under everything else it is a no-op at best: a move
// there moves nothing (the route refuses it with `exists`), a skip skips, and
// an overwrite would write a file over itself — or, for a directory, merge a
// tree into itself, which is an unbounded recursion. So all three are refused
// here, together, rather than left to the general rule.
//
// "The same directory" is decided by IDENTITY and not by spelling, which is the
// half a lexical test cannot do. Bind-mount /alias onto /real and the two names
// are one directory: moving /alias/a into /real passed the lexical check, merged
// into /real/a — the source itself — copied every file over itself and then
// deleted both spellings. So the held source parent and the held destination are
// compared as objects, and so is the existing destination entry against the
// source root: if dest/<name> IS the source, there is nothing to copy and
// everything to lose.
func (c *copier) placeRoot(srcParent *dirRef, ref *itemRef, srcAPI, name string, k kind) (placed, bool) {
	sameDir := fsx.Parent(srcAPI) == c.dstAPI
	if !sameDir {
		if same, known := sameHeldDir(srcParent, c.dst); known && same {
			sameDir = true
		}
	}
	if !sameDir {
		// dest/<name> may be the source root itself under another spelling,
		// which is the merge-into-itself the bind-mount case produced. The
		// identity is taken from the held reference on one side and from a
		// lookup through the held destination on the other.
		if dfi, err := c.dst.lstat(name); err == nil {
			a, aok := inodeOf(ref.fi)
			b, bok := inodeOf(dfi)
			if aok && bok && a == b {
				c.skipCode(srcAPI, "invalid_target", fmt.Sprintf(
					"%q and %q are the same object under two names, so there is nothing to copy",
					srcAPI, fsx.Join(c.dstAPI, name)), 0)
				return placed{}, false
			}
		}
	}

	var p placed
	switch {
	case sameDir && c.conflict == wproto.ConflictRename:
		p = c.freeName(c.dst, name, k)
	case sameDir:
		c.skipCode(srcAPI, warnExists,
			fmt.Sprintf("%q is already in %q, so there was nothing to do", name, c.dstAPI), 0)
		return placed{}, false
	default:
		p = c.place(c.dst, name, k)
	}
	switch {
	case p.err != nil:
		c.skip(fsx.Join(c.dstAPI, name), p.err)
		return placed{}, false
	case p.act == actSkip:
		c.skipCode(srcAPI, p.code, p.msg, 0)
		return placed{}, false
	}
	return p, true
}

// tryRename is the move's first attempt (§1.1): renameat2 straight into the
// held destination descriptor. It reports whether the root is finished.
//
// RENAME_NOREPLACE unless the policy is `overwrite` AND both ends are
// non-directories, which is the only pairing where replacing is what was asked
// for and is atomic. EXDEV is not a failure — it is the answer the whole
// copy-then-delete fallback exists for, and it is the kernel's to give: the
// front-end's pre-flight only ever PREDICTED it (§1.2).
func (c *copier) tryRename(srcParent *dirRef, srcAPI, name string, fi os.FileInfo, s source, p placed) (bool, error) {
	// The name is proved to still be the object that was pinned, immediately
	// before the rename. Holding the parent does not pin the CHILD name, and
	// everything between the pin and here — collecting the destination's
	// ancestry, searching for a free keep-both name — takes syscalls: a probe
	// replaced the pinned regular file with a directory in that window and the
	// unrelated directory was moved, reported as a clean one-file move. What is
	// left is the adjacent-syscall residual this package documents everywhere
	// else: Linux has no rename-by-descriptor.
	if same, known := sameNamedObject(srcParent, name, fi); known && !same {
		c.skipCode(srcAPI, warnChanged,
			fmt.Sprintf("%q is not the item that was selected any more, so it was left alone", srcAPI), 0)
		return true, nil
	}
	err := renameRoot(c.dst, srcParent, name, p.name, p.act != actOverwrite)
	switch {
	case err == nil:
		c.touched = true
		c.countRenamed(s.scan, fi, fsx.Join(c.dstAPI, p.name))
		return true, nil
	case isCrossDevice(err):
		// Two filesystems. Copy, verify, then delete.
		return false, nil
	case errors.Is(err, fs.ErrExist):
		// Something took the name between the lookup and the rename. Refusing
		// is the only safe answer: the alternative is deciding a conflict
		// policy against an object nobody has looked at.
		c.skipCode(srcAPI, warnExists,
			fmt.Sprintf("%q appeared at the destination while %q was being moved", p.name, srcAPI), fsx.Errno(err))
		return true, nil
	default:
		c.skip(srcAPI, err)
		return true, nil
	}
}

// countRenamed credits a renamed root with what the pre-scan found under it.
//
// Without this a move of a five-thousand-file folder that the kernel completed
// in one syscall would report "1 of 5 003 items done" and stop there, because
// the tree was never walked. When the scan could not count it, one item is all
// this job honestly knows about.
func (c *copier) countRenamed(scan scanResult, fi os.FileInfo, dstPath string) {
	if !scan.capped && scan.files+scan.dirs > 0 {
		c.res.Files += scan.files
		c.res.Dirs += scan.dirs
		c.res.Bytes += scan.bytes
	} else if fi.IsDir() {
		c.res.Dirs++
	} else {
		c.res.Files++
		c.res.Bytes += fi.Size()
	}
	c.progress(dstPath, wproto.PhaseWorking)
}

// insideSource reports that the destination is the source directory itself or
// lies underneath it (§1.7).
//
// Both halves are asked. The lexical test on the RESOLVED paths catches the
// ordinary spellings and the symlinked ones — resolve() has already followed
// every link on both — and the identity test catches what a lexical test cannot
// see at all: a bind mount, or a rename that happened between the request and
// this moment. Getting this wrong is not a wrong answer, it is a recursion that
// fills the volume, so it is worth two questions.
// The identity half is meetsDestination, the same predicate the walk asks of
// every directory it meets, rather than a second copy of it: "the destination
// is inside this directory" and "this directory is the destination or one of
// its ancestors" are one question, and two implementations of it would drift.
func (c *copier) insideSource(srcAPI string, fi os.FileInfo) bool {
	return fsx.IsWithin(c.dstAPI, srcAPI) || c.meetsDestination(fi)
}

// ---- the copy itself --------------------------------------------------------

// sameHeldDir reports whether two HELD directory descriptors refer to one and
// the same directory, and whether the question could be answered here at all.
//
// It is the identity behind "the destination is the directory this already
// lives in". Two names for one directory are ordinary on a NAS — QTS builds its
// share layout out of bind mounts — and no comparison of spellings can see it.
func sameHeldDir(a, b *dirRef) (same, known bool) {
	afi, aerr := a.stat()
	bfi, berr := b.stat()
	if aerr != nil || berr != nil {
		return false, false
	}
	ak, aok := inodeOf(afi)
	bk, bok := inodeOf(bfi)
	if !aok || !bok {
		return false, false
	}
	return ak == bk, true
}

// copyTree copies a selected directory and everything under it.
//
// The destination directory for the root is created (or merged into) before the
// walk starts, so the walk's visitor never has to think about depth 0, and the
// stack of held destination directories is unwound whatever the walk does —
// including when it is cancelled half way down.
func (c *copier) copyTree(ctx context.Context, srcParent *dirRef, srcAPI, srcName string,
	ref *itemRef, p placed) error {

	fi := ref.fi
	// The source root is opened from the HELD parent and proved to be the inode
	// that was pinned, and the walk is then started on that descriptor
	// (walkFrom). Walk would have resolved the pathname again, which is the one
	// place this engine still named something twice: rename a component to a
	// symlink between the pin and the walk and the traversal — and, for a move,
	// the delete that follows it — would have gone somewhere else entirely.
	srcDir, err := srcParent.child(srcName)
	if err != nil {
		c.skip(srcAPI, err)
		return nil
	}
	if same, known := sameHeldObject(srcDir, fi); !known || !same {
		srcDir.close()
		c.skipCode(srcAPI, warnChanged, fmt.Sprintf(
			"%q is not the folder it was a moment ago, so nothing was copied from it", srcAPI), 0)
		return nil
	}
	// Everything the destination reproduces about this directory comes from the
	// descriptor that is about to be enumerated — walkFrom is handed this very
	// one — and not from the stat taken of its name beforehand. Nested
	// directories get the same treatment from Visitor.Opened (makePending).
	if enumerated, serr := srcDir.stat(); serr == nil {
		fi = enumerated
	}

	dir, created, err := c.makeDir(c.dst, c.dstAPI, p.name, fi, p.act == actMerge)
	if err != nil {
		srcDir.close()
		switch {
		case errors.Is(err, errUntracked):
			c.untracked(srcAPI)
		case errors.Is(err, errNotOurs):
			c.notOurs(fsx.Join(c.dstAPI, p.name), err)
		case errors.Is(err, errOwnerUnset):
			c.ownerRefused(fsx.Join(c.dstAPI, p.name), err)
		case errors.Is(err, errNoStaging):
			c.noStaging(fsx.Join(c.dstAPI, p.name))
		default:
			c.skip(fsx.Join(c.dstAPI, p.name), err)
		}
		return nil
	}
	recordDirState(c.ledger, fi)
	// The record and the destination were both made from one fstat of the held
	// source root; the walk is about to take its own, and opened() requires the
	// two to agree. This is the window between them (verifyTrace).
	traceVerify("root-recorded")
	c.ledger.dstName = p.name
	if dfi, serr := dir.stat(); serr == nil {
		c.ledger.dstID, c.ledger.haveDstID = inodeOf(dfi)
	}
	c.frames = append(c.frames, destFrame{
		parent:  c.dst,
		name:    p.name,
		dir:     dir,
		api:     fsx.Join(c.dstAPI, p.name),
		srcInfo: fi,
		srcAPI:  srcAPI,
		srcDir:  srcDir,
		created: created,
		rec:     c.ledger,
	})
	defer c.unwind(0)

	err = walkFrom(ctx, c.r, c.plat, srcDir, srcAPI, fi, WalkOptions{
		CrossMounts: c.cross,
		// ProtectWrite rather than ProtectSnapshots, and for both job kinds: a
		// ".zfs" holds the whole history of a share and "@Recycle" is
		// firmware-private (decision 10), so neither is something to reproduce
		// at the destination — and for a move both are also a delete this app
		// never makes. It is a mutating protection level, which also makes the
		// walk fail closed on a mount the kernel will not name (B4).
		Protect: ProtectWrite,
	}, Visitor{
		Pre: func(it WalkItem) error { return c.pre(ctx, it) },
		// Opened gives the fstat of the descriptor the walk is about to
		// ENUMERATE, which is the identity a verified delete has to be made
		// against: the WalkItem's own Info is an lstat taken before the open,
		// and between the two a name can be re-pointed. The record and the
		// containment check are both taken from here for that reason (the same
		// distinction the trash's sidecar takes its identity from).
		Opened: func(it WalkItem, info os.FileInfo) error { return c.opened(it, info) },
		Warn:   func(apiPath string, err error) { c.skip(apiPath, err) },
	})
	if errors.Is(err, errCopyIntoItself) {
		c.skipCode(srcAPI, "invalid_target", fmt.Sprintf(
			"%q now contains %q, so the copy was stopped before it could copy its own output",
			srcAPI, c.dstAPI), 0)
		return nil
	}
	if errors.Is(err, errUntracked) {
		c.untracked(srcAPI)
		return nil
	}
	if errors.Is(err, errSourceChanged) {
		c.skipCode(srcAPI, warnChanged, fmt.Sprintf(
			"%q changed between its copy being created and being recorded, so nothing was copied from it", srcAPI), 0)
		return nil
	}
	return err
}

// untracked reports a root stopped because the job can no longer keep track of
// the folders it is creating — the fail-closed half of remember.
func (c *copier) untracked(srcAPI string) {
	c.skipCode(srcAPI, warnTooMany, fmt.Sprintf(
		"%q has more folders than this job can track safely (%d), and copying without that check could copy its own output back into itself",
		srcAPI, trackedDirBound), 0)
}

// errCopyIntoItself stops a root whose walk met the destination inside it. It
// never leaves this file: copyTree turns it into an invalid_target warning
// against the root.
var errCopyIntoItself = errors.New("fsops: the destination is inside the tree being copied")

// opened records the identity of a source directory from the descriptor the
// walk actually opened, and refuses the root if that descriptor turns out to be
// the destination.
//
// The check has to be here and not only at the start. The ancestry is re-read
// per root, but a root can take twenty minutes, and the destination can be
// moved into the source at any point during it — at which point the walk would
// reach the copy's own output and descend into it until the volume is full.
func (c *copier) opened(it WalkItem, info os.FileInfo) error {
	if c.meetsDestination(info) {
		// Refused HERE rather than at the next Pre, which is what the hook
		// being able to return an error buys: not one entry of this directory
		// has been read, so not one entry of the copy's own output can be
		// copied back into it.
		return errCopyIntoItself
	}
	// The destination directory is made HERE, from this descriptor's own stat,
	// for everything below the root (the root's was made from the descriptor
	// walkFrom was handed, which is the same thing). info is what the walk is
	// about to enumerate, so the mode it is created with, the owner it is given
	// and the times it ends up with all describe the object whose contents are
	// being reproduced.
	if f := c.frameAt(it.Depth); f != nil && f.rec != nil {
		// A frame is already standing at this depth, which means its
		// destination was created before this hook ran — the ROOT, made by
		// copyTree from its own fstat of this very descriptor. Two fstats of
		// one descriptor describe one inode but not necessarily one STATE: the
		// source root tightened 0755 -> 0700 between them left the destination
		// created 0755 while the record said 0700, so a private child added
		// before enumeration was disclosed and the delete approved anyway. The
		// two readings have to agree or the root is abandoned.
		if !sameDirState(f.rec, info) {
			return errSourceChanged
		}
		return nil
	}
	if p := c.pending; p.set && p.depth == it.Depth {
		c.pending = pendingDir{}
		if err := c.makePending(p, info); err != nil {
			if errors.Is(err, errUntracked) {
				// Not a per-item failure: the protection this job relies on has
				// stopped working, so the root stops with it.
				return err
			}
			// No frame is pushed, so every child's Pre finds its parent missing
			// and skips — the failure is reported once, here, and the whole
			// subtree is abandoned with it.
			switch {
			case errors.Is(err, errNotOurs):
				c.notOurs(fsx.Join(p.parentAPI, p.dstName), err)
			case errors.Is(err, errOwnerUnset):
				c.ownerRefused(fsx.Join(p.parentAPI, p.dstName), err)
			case errors.Is(err, errNoStaging):
				c.noStaging(fsx.Join(p.parentAPI, p.dstName))
			default:
				c.skip(fsx.Join(p.parentAPI, p.dstName), err)
			}
		}
	}
	return nil
}

// errSourceChanged stops a root whose source directory was not the same object,
// in the same state, when its destination was created and when the record of it
// was taken. It never leaves this file.
var errSourceChanged = errors.New("fsops: the source changed between being created for and being recorded")

// pendingDir is a destination directory whose placement has been decided and
// whose creation is waiting for the source descriptor that decides its mode,
// its owner and its times.
type pendingDir struct {
	set       bool
	depth     int
	parent    *dirRef
	parentAPI string
	parentRec *copiedDir
	srcAPI    string
	srcName   string
	dstName   string
	merge     bool
}

// makePending creates the destination directory a Pre hook decided on, using
// the fstat of the descriptor the walk opened for its source.
func (c *copier) makePending(p pendingDir, info os.FileInfo) error {
	dir, created, err := c.makeDir(p.parent, p.parentAPI, p.dstName, info, p.merge)
	if err != nil {
		return err
	}
	sub := &copiedDir{dstName: p.dstName}
	recordDirState(sub, info)
	if dfi, serr := dir.stat(); serr == nil {
		sub.dstID, sub.haveDstID = inodeOf(dfi)
	}
	c.recordEntry(p.parentRec, copiedEntry{name: p.srcName, kind: kindDir, dir: sub})
	c.frames = append(c.frames, destFrame{
		parent:  p.parent,
		name:    p.dstName,
		dir:     dir,
		api:     fsx.Join(p.parentAPI, p.dstName),
		srcInfo: info,
		srcAPI:  p.srcAPI,
		created: created,
		rec:     sub,
	})
	return nil
}

// sameHeldObject reports whether a held directory is the object a FileInfo
// describes, and whether the question could be answered here at all.
func sameHeldObject(d *dirRef, want os.FileInfo) (same, known bool) {
	fi, err := d.stat()
	if err != nil {
		return false, false
	}
	a, aok := inodeOf(fi)
	b, bok := inodeOf(want)
	if aok && bok {
		return a == b, true
	}
	if inodeIdentity {
		// This platform has identities and one of them is missing: a
		// measurement that failed, which is a refusal and not a shrug.
		return false, true
	}
	// Off Linux there is no identity to compare at all. Refusing there would
	// stop every copy of a folder on the dev box, and the openat that produced
	// this descriptor was still O_NOFOLLOW|O_DIRECTORY relative to the held
	// parent — which is the containment that matters (INV-2).
	return true, true
}

// frameAt is the destination frame for one depth of the source walk, or nil.
func (c *copier) frameAt(depth int) *destFrame {
	if depth < 0 || depth >= len(c.frames) {
		return nil
	}
	return &c.frames[depth]
}

// pre is the copy's visitor: one source item, one destination entry.
//
// The destination stack is unwound to this item's depth FIRST, which is what
// finalises and closes every directory the walk has just left. Doing it here
// rather than in a Post hook is deliberate — see destFrame.
func (c *copier) pre(ctx context.Context, it WalkItem) error {
	// Any placement the previous item left waiting is stale: its directory was
	// never opened, so it was never created.
	c.pending = pendingDir{}
	if it.Depth == 0 {
		// The root's destination was made by copyTree before the walk started.
		return nil
	}
	c.unwind(it.Depth)
	if len(c.frames) < it.Depth {
		// The parent's destination could not be made, and that failure has
		// already been reported. Repeating it once per descendant would bury
		// the one warning that says what actually went wrong.
		if it.isDir() {
			return fs.SkipDir
		}
		return nil
	}
	parent := &c.frames[it.Depth-1]
	if !c.ancestorUnchanged(it) {
		if it.isDir() {
			return fs.SkipDir
		}
		return nil
	}

	if it.Mount {
		// A mount point the walk was not allowed to descend into. Creating an
		// empty directory in its place would be a lie — it would look like the
		// mount point and hold none of its contents — so it is skipped whole
		// and the reason is said (§1.8, decision 9).
		c.skipCode(it.Path, "protected",
			fmt.Sprintf("%q is a mount point this job may not enter, so it was not copied", it.Path), 0)
		return fs.SkipDir
	}

	k := kindOf(it.Info)
	if k == kindSpecial {
		c.skipCode(it.Path, warnUnsupported,
			fmt.Sprintf("%q is a %s, which has no contents to copy", it.Path, fsx.TypeString(it.Info.Mode())), 0)
		return nil
	}
	if k == kindDir && c.meetsDestination(it.Info) {
		// The destination has arrived inside the source since this job started.
		// Refused here, before a destination directory is created for it, and
		// again from the opened descriptor (opened) for the case where the name
		// was re-pointed between the two.
		return errCopyIntoItself
	}

	p := c.place(parent.dir, it.Name, k)
	if p.err != nil {
		c.skip(fsx.Join(parent.api, it.Name), p.err)
		if k == kindDir {
			return fs.SkipDir
		}
		return nil
	}
	if p.act == actSkip {
		c.skipCode(it.Path, p.code, p.msg, 0)
		if k == kindDir {
			return fs.SkipDir
		}
		return nil
	}

	if k == kindDir {
		// NOT created here. A directory's mode, owner and times have to come
		// from the descriptor the walk is about to ENUMERATE, not from the
		// lstat that classified its name: a directory chowned to somebody else
		// in between would otherwise have its former owner reproduced over the
		// new owner's contents, which is the file case of round 7 one level up.
		// opened() has that descriptor and makes it there.
		c.pending = pendingDir{
			set:       true,
			depth:     it.Depth,
			parent:    parent.dir,
			parentAPI: parent.api,
			parentRec: parent.rec,
			srcAPI:    it.Path,
			srcName:   it.Name,
			dstName:   p.name,
			merge:     p.act == actMerge,
		}
		return nil
	}
	if it.parent == nil {
		// Unreachable: every item below depth 0 was enumerated from a held
		// directory. Said out loud rather than dereferenced on faith.
		c.skipCode(it.Path, warnUnsupported, "the directory this item was read from is no longer held", 0)
		return nil
	}
	return c.copyEntry(ctx, it.parent, it.Name, it.Info, it.Path, parent.dir, parent.api, p, parent.rec)
}

// ancestorUnchanged re-proves the SOURCE directories an item is being copied
// out of — the whole held chain from the root down to the directory it was
// enumerated from — immediately before that item is copied, and reports whether
// the copy may go on.
//
// The state of a directory was proved once — when its destination was created
// and its record taken (opened, makePending) — and a directory with a thousand
// entries, or one entry that takes ten minutes, is then copied on the strength
// of that single reading. The owner tightening 0755 -> 0700 during a long file,
// and replacing a not-yet-visited sibling's contents while they were at it, had
// the sibling copied into a destination directory still standing at 0755: a
// restriction applied before the data was read, and undone by this job after it
// was applied. The same reading also decides whether a MOVE may delete, so the
// window is a delete decision as well as a disclosure.
//
// So it is asked per entry, of the held descriptors the walk enumerated — never
// of a name — and it is the same comparison the records were made with:
// identity, permissions and ownership (sameDirState).
//
// The WHOLE chain, and not only the immediate parent, which is round 14's
// first finding: copying /src/a/sub, a tightened 0755 -> 0700 while a file in
// sub was being read left every later file in sub copied into a destination
// still standing at 0755, because only sub was ever asked about. Restricting a
// directory restricts everything under it, so proving the leaf proves nothing.
//
// One fstat per ancestor per entry — the simplest form that is actually
// correct. Trees are shallow beside the openat, the read and the write that
// follow each entry (a ten-deep tree pays ten fstats of open descriptors
// against a megabyte of copying), so nothing is batched and no window is
// traded away for it.
//
// The descriptors are the walk's own, captured as they arrive: the root's is
// the one walkFrom was handed, and every other frame's is the WalkItem.parent
// of the first child enumerated out of it — which, by the time an item at depth
// D is reached, has filled in every frame from 0 to D-1.
//
// A change abandons the REST of that subtree rather than the whole root: what
// was already copied was copied from a state that was proved at the time, and
// it stays. The root is not clean afterwards, so a move keeps its source. The
// reason is reported once, against the source directory that changed, and
// everything after it goes quietly (destFrame.changed) — one warning per
// directory, not one per file.
func (c *copier) ancestorUnchanged(it WalkItem) bool {
	if it.Depth <= 0 || it.Depth > len(c.frames) {
		return true
	}
	if parent := &c.frames[it.Depth-1]; parent.srcDir == nil {
		// The descriptor this item was enumerated from IS its parent frame's
		// source directory, and this is the first time anything has been seen
		// out of it.
		parent.srcDir = it.parent
	}
	// Shallowest first: a change high up is the one that explains everything
	// below it, and it is the one to report.
	for i := 0; i < it.Depth; i++ {
		f := &c.frames[i]
		if f.changed {
			// Already found, already reported.
			return false
		}
		if f.srcDir == nil {
			// Unreachable: every frame below this item's depth has had a child
			// enumerated out of it. Skipped rather than dereferenced on faith.
			continue
		}
		fi, err := f.srcDir.stat()
		if err == nil && sameDirState(f.rec, fi) {
			continue
		}
		f.changed = true
		c.skipCode(f.srcAPI, warnChanged, fmt.Sprintf(
			"%q changed while it was being copied, so the rest of it was left alone", f.srcAPI), 0)
		return false
	}
	return true
}

// The change-time settling bounds (round-3 adversarial finding 1).
const (
	// ctimeRecent is how young a recorded change time has to be before it is
	// worth proving anything about it. An inode whose ctime is older than this
	// cannot collide with a write made now, whatever the clock's granularity.
	ctimeRecent = 2 * time.Second
	// ctimeWaitStep and ctimeWaitTries bound the wait for the filesystem's
	// clock to move past a recorded change time. A few milliseconds covers a
	// jiffies-granular kernel (4 ms at HZ=250, 10 ms at HZ=100); past the bound
	// the entry is reported unverifiable rather than waited on forever.
	ctimeWaitStep  = 5 * time.Millisecond
	ctimeWaitTries = 10
)

// settled proves that a recorded change time lies strictly in the PAST of the
// filesystem's own clock, so that any later write to that inode is
// distinguishable from the state that was recorded.
//
// It exists because ctime equality is only as strong as the kernel's timestamp
// granularity, and QTS's kernels are jiffies-granular: two updates inside one
// tick carry the SAME ctime. Copy a file that was written moments ago, rewrite
// it in place with the same number of bytes and put its mtime back before the
// tick advances, and identity, size, mtime and ctime all still matched — no
// privileges needed, and the move then deleted the original.
//
// The clock is read in the right filesystem's own timestamp space, which is the
// only space the comparison means anything in: a destination tick passing a
// recorded source ctime proves nothing when the two filesystems round
// differently — a source that stores whole seconds passes instantly against a
// nanosecond destination, while a rewrite anywhere inside that second keeps the
// same ctime. So a source proof is read on the source side and a destination
// proof on the destination side.
//
// WHICH directory matters as much as which filesystem, because creating a file
// changes a directory's own modification time. The two used are the ones this
// job is already modifying and whose timestamps it does not reproduce: the
// destination CONTAINER the user picked (c.dst — the job creates the root's
// copy in it) and the source root's PARENT (c.srcRootParent — a move unlinks
// the root from it). Never a directory this job created at the destination and
// then restored the source's time on: a scratch there silently undid the very
// timestamp the copy had just reproduced. Both are on the same filesystem as
// the tree they stand for, with one stated exception: with CrossMounts on, a
// source sub-mount's entries are proved on the source ROOT's filesystem, which
// is the same kernel clock at a possibly different rounding. The destination
// never crosses, so it has no such case.
//
// It costs no permission this job does not already need: only a MOVE settles,
// and a move is going to unlink from that very directory. When the scratch
// cannot be created at all — a source directory that is read-only to this
// worker, a full filesystem — there is no proof to be had and the entry is
// reported unverifiable rather than copied on an assumption.
//
// time.Now() is only a pre-filter, for records too old to be at risk however
// coarse the clock is.
//
// The reading is cached per filesystem. Once a filesystem's clock has been seen
// past some instant, every record on it older than that is settled without
// asking again — so a move of a hundred thousand files costs at most one
// scratch per tick, and a tree that was not written to in the last two seconds
// costs none at all.
//
// One note on where the scratch lands: it is created and unlinked inside a
// directory the walk may be part way through enumerating. The name is unique
// and short-lived, and if a later getdents ever returned it the walk's own lstat
// would find it gone and drop it, which is a race the walk already handles.
func (c *copier) settled(dir *dirRef, ct time.Time, have bool) bool {
	if !have {
		// Nothing to protect: matchesRecord already refuses a record with no
		// change time on a platform that has them.
		return true
	}
	if time.Since(ct) > ctimeRecent {
		return true
	}
	dev, hasDev := devOfDir(dir)
	if hasDev && c.clockSeen[dev].After(ct) {
		return true
	}
	for try := 0; ; try++ {
		now, err := fsClockAt(dir)
		if err != nil {
			// No clock to read here, and no number to invent.
			return false
		}
		if hasDev && now.After(c.clockSeen[dev]) {
			if c.clockSeen == nil {
				c.clockSeen = make(map[uint64]time.Time, 2)
			}
			c.clockSeen[dev] = now
		}
		if now.After(ct) {
			return true
		}
		if try >= ctimeWaitTries {
			return false
		}
		time.Sleep(ctimeWaitStep)
	}
}

// devOfDir is the device a held directory is on, which is what the clock cache
// is keyed by: one filesystem, one clock, one rounding.
func devOfDir(d *dirRef) (uint64, bool) {
	if d == nil {
		return 0, false
	}
	fi, err := d.stat()
	if err != nil {
		return 0, false
	}
	k, ok := inodeOf(fi)
	if !ok {
		return 0, false
	}
	return k.dev, true
}

// settleResult is what settleSource concluded.
type settleResult int

const (
	// settleOK: the source's change time is provably in the past of the
	// filesystem's clock and has not moved since it was taken. Everything that
	// happens to the file from now on lands in a later tick.
	settleOK settleResult = iota
	// settleUnverifiable: the clock would not advance inside the bound.
	settleUnverifiable
	// settleChanged: the file was written to while this was being established,
	// which is a real change and not a granularity problem.
	settleChanged
)

// settleSource establishes, BEFORE a single byte of the file is read, that the
// state about to be copied is one a later change can be told apart from.
//
// The order is the whole of it, and it is what the first version got wrong: it
// settled AFTER the copy, which proved only that the tick had ended by then. A
// rewrite that happened between the read and the end of that same tick — same
// length, mtime restored — left the recorded change time untouched, so the
// delete matched it and removed a file whose contents were newer than the copy
// at the destination. Waiting first inverts that: the clock is past the
// baseline before anything is read, so every subsequent write necessarily lands
// in a later tick and is caught at delete time, including one that races the
// read itself.
//
// The second fstat closes the gap the wait itself opens. If the change time
// moved while this was waiting, that is a real write rather than a granularity
// problem; the baseline is taken again once, and a second move is reported as a
// change rather than waited on indefinitely.
//
// Only a MOVE pays for this. A copy never reads its record back, so waiting on
// a clock — or refusing a file over one — would be cost and noise for a job
// that deletes nothing. Symlinks do not need it either: a symlink's content
// cannot be rewritten in place at all, so replacing one allocates a new inode
// that the identity check catches, and its target text is compared outright.
func (c *copier) settleSource(srcDir *dirRef, src *os.File, base os.FileInfo) (os.FileInfo, settleResult) {
	return c.settleObserved(srcDir, base, src.Stat)
}

// settleObserved is the proof itself, over any object that can be described
// again: wait for the filesystem's clock to pass the observed change time, then
// look once more and require that it has not moved.
//
// It is one function because there are two callers and they must not drift.
// The other is the hard-link re-baselining (rebaseline), which adopts a change
// time this job's own unlink produced — a value that lies in the CURRENT tick
// and is therefore exactly as forgeable as a fresh record was: rewrite the
// remaining sibling with the same length and its mtime put back, inside that
// same tick, and the rebased value still matched. A baseline that has not been
// settled is not a baseline.
//
// There is no retry, and that is deliberate. Taking the new state as a fresh
// baseline and settling THAT looks harmless — the newer state is the one that
// would be copied — but it means a writer can keep the job waiting and, worse,
// it makes "settled" mean "settled at some instant the writer chose". One
// observation, the clock proof, one confirming observation: a change in between
// is a file being written to, and a file being written to is not one this job
// moves.
func (c *copier) settleObserved(dir *dirRef, base os.FileInfo, again func() (os.FileInfo, error)) (os.FileInfo, settleResult) {
	ct, have := changeTimeOf(base)
	if !c.settled(dir, ct, have) {
		return nil, settleUnverifiable
	}
	after, err := again()
	if err != nil {
		return nil, settleChanged
	}
	if !sameChangeTime(base, after) {
		return nil, settleChanged
	}
	return after, settleOK
}

// sameChangeTime reports whether two descriptions of one inode carry the same
// change time. An answer that cannot be given is "no": on a platform with
// change times, a missing one is a measurement that failed.
func sameChangeTime(a, b os.FileInfo) bool {
	at, aok := changeTimeOf(a)
	bt, bok := changeTimeOf(b)
	if !aok || !bok {
		return !inodeIdentity
	}
	return at.Equal(bt)
}

// fsClockAt reads one filesystem's current inode-timestamp value, by creating
// and immediately unlinking a scratch file through the held directory
// descriptor it is given.
//
// It is a variable so a test can drive the settling loop: making a real kernel
// hand out two identical change times on demand is not something a test can do,
// and the branch behind it decides whether a move deletes anything. Production
// never assigns to it.
var fsClockAt = func(d *dirRef) (time.Time, error) {
	name, err := clockTmpName()
	if err != nil {
		return time.Time{}, err
	}
	f, err := d.openFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return time.Time{}, err
	}
	fi, serr := f.Stat()
	// Removed only while the name still refers to the file this created — the
	// same rule every other cleanup here follows (unlinkIfOurs). The descriptor
	// is held across the check and the unlink, so the identity being compared
	// cannot be recycled underneath it. A stranger at the name is left alone
	// and nothing is said: the name is an unguessable dot-name that existed for
	// microseconds, so finding one occupied means somebody is watching this
	// directory, and a warning per clock reading would be noise on a job that
	// has real things to report.
	if serr == nil {
		if same, known := sameNamedObject(d, name, fi); !known || same {
			_ = d.unlink(name, false)
		}
	} else {
		_ = d.unlink(name, false)
	}
	_ = f.Close()
	if serr != nil {
		return time.Time{}, serr
	}
	ct, ok := changeTimeOf(fi)
	if !ok {
		return time.Time{}, fsx.ErrUnsupported
	}
	return ct, nil
}

// clockTmpName is an unguessable hidden name for the scratch file, in the same
// family as the overwrite temporaries so anything that ever leaks is
// recognisable as this app's.
func clockTmpName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return copyTmpPrefix + hex.EncodeToString(b[:]) + ".clock", nil
}

// ledgerBound is maxVerifiedEntries as a variable, for the same reason
// sizeScanLimits and trashScanMaxEntries are variables: reaching it for real
// needs a million-entry tree, and the branch behind it decides whether a move
// deletes anything at all. Production never assigns to it.
var ledgerBound = maxVerifiedEntries

// trackedDirBound is maxTrackedDirs as a variable, for the same reason and
// separately: a test has to be able to exhaust the security set without
// exhausting the copy record, and the other way round, because the two have
// opposite consequences. Production never assigns to it.
var trackedDirBound = maxTrackedDirs

// recordEntry writes one copied entry into the record its parent directory
// keeps, and notices when the record has grown past what this worker will hold.
//
// Past the bound nothing more is written down and ledgerFull is set, which makes
// the move KEEP its source: a delete that cannot prove what it is removing is
// not a delete this app makes.
func (c *copier) recordEntry(rec *copiedDir, e copiedEntry) {
	if !c.move {
		// A plain copy deletes nothing, so it never reads this back — and
		// keeping it cost a few hundred bytes per entry for as long as the job
		// ran: a million-file copy carried hundreds of megabytes of proofs
		// nothing would ever ask for. The per-DIRECTORY records (copiedDir)
		// stay whichever kind of job this is: the ancestor re-check compares
		// against them on every entry, and they are one per directory rather
		// than one per file.
		return
	}
	if rec == nil || c.ledgerFull {
		return
	}
	if c.ledgerCount >= ledgerBound {
		c.ledgerFull = true
		return
	}
	c.ledgerCount++
	rec.entries = append(rec.entries, e)
}

// makeDir creates (or adopts) one destination directory and holds it open.
//
// The mode is the source's permission bits and nothing else: setuid, setgid and
// sticky are never propagated, and the umask and the destination's own
// inherited ACL or setgid bit apply exactly as they would for `cp` without -p
// (§1.5). No chmod is ever issued, here or anywhere else in this file.
//
// A merged directory is NOT chowned and its times are NOT touched: it was
// already there, it is somebody's, and this job created nothing.
func (c *copier) makeDir(parent *dirRef, parentAPI, name string, srcInfo os.FileInfo, merge bool) (*dirRef, bool, error) {
	created := false
	// The name it is CREATED under, which on Linux is never the name it will
	// end up with: an unguessable one in the same directory, renamed into place
	// once the directory is proved, owned and ready to be written into.
	//
	// That is round 14 adversarial's third finding, and it is the one that
	// stops the game rather than scoring another point in it. Every check here
	// answers "is what I opened the thing I just made" — kind, creator,
	// emptiness, mode subset, group, setgid — and an attacker who can write the
	// destination can always try to satisfy them: an existing empty directory
	// with our uid, the expected gid and an allowed mode passes every one of
	// them, and a named-user ACL granting them r-x rides along invisibly,
	// because a chown strips no ACL and this engine has no portable way to read
	// one. Nobody can substitute what nobody can name. The checks stay as
	// defence in depth for the fallback and for anything the rename cannot
	// speak for.
	openName := name
	staged := ""
	// where is the directory the object is BUILT in: the private staging
	// directory when there is one, and the destination itself when there is
	// not and nobody else could interfere with it either.
	where := parent
	if !merge {
		st := c.stagingIn(parent, parentAPI)
		switch {
		case st.dir != nil:
			t, terr := copyTmpName()
			if terr != nil {
				return nil, false, terr
			}
			staged, openName, where = t, t, st.dir
		case st.state == stageRefused:
			// The private directory this job made was not the one it opened.
			// It does not go on building here.
			return nil, false, errNoStaging
		}
		// EEXIST is deliberately NOT tolerated here. The placement said this
		// name was free; something took it in between, and adopting whatever
		// that is would decide a conflict policy against an object nobody has
		// looked at. The caller reports it as `exists` and moves on — the same
		// answer the move's rename gives when it loses the same race. With a
		// staged name the EEXIST that matters comes from the RENAME instead,
		// and says the same thing.
		if err := mkdirForCopy(where, openName, srcInfo.Mode().Perm()); err != nil {
			return nil, false, err
		}
		created = true
	}
	dir, err := where.childPath(openName)
	if err != nil {
		if staged != "" {
			// Nothing has been opened, so there is no descriptor to prove the
			// name with — but the name is this process's own unguessable one,
			// a moment old, inside a directory only this job can reach.
			_ = where.unlink(staged, true)
		}
		return nil, false, err
	}
	if !created {
		// An ADOPTED directory: the only question is the crossing one, and
		// nothing here may be removed whatever the answer — it is the user's
		// own directory, not this job's.
		if crossesInto(parent, dir) {
			dir.close()
			return nil, false, fmt.Errorf(
				"%q is a mount point at the destination and this job does not write across one: %w",
				fsx.Join(parentAPI, name), fsx.ErrProtected)
		}
	}
	if created {
		// Proved on EVERY path, root or not, chown or not, and a failure
		// ABANDONS the subtree rather than carrying on into it. None of these
		// failures removes what it found, staged name or not: each one says
		// "this is not the object I created", and removing somebody else's
		// directory on the strength of that is the second half of the same
		// mistake (unlinkIfOurs says it at greater length).
		//
		// Tying this to the chown was a hole with no privileges in it. A 0700
		// source directory holding 0644 files, copied into a shared
		// non-sticky destination: another user replaces the freshly created
		// directory with their own 0777 one before it is opened, and the
		// non-root path — which never chowns, so never checked — copied the
		// contents straight into it. The root path did notice the foreign
		// owner, and then descended anyway because owner_unset was only a
		// warning. Nothing may be written into a directory this job cannot
		// prove it made.
		if perr := c.provenance(dir, kindDir); perr != nil {
			dir.close()
			return nil, false, errors.Join(errNotOurs, perr)
		}
		// And its permissions may not be WIDER than the ones asked for. Kind,
		// owner and emptiness all pass for an existing empty root-owned 0755
		// directory slid over the name of a 0700 one — see modeNoWiderThan.
		if merr := modeNoWiderThan(dir.f, srcInfo.Mode().Perm(), inheritedSetgid(where)); merr != nil {
			dir.close()
			return nil, false, errors.Join(errNotOurs, merr)
		}
		// And it has to be in the GROUP the kernel would have given it. Kind,
		// creator, emptiness and mode-subset all pass for an existing empty
		// root-owned 0750 directory in another group slid over the name inside
		// a setgid destination — and with no `As` gid to correct it, the
		// contents then land in that group. See createdInGroup.
		//
		// The expectation comes from `where` — the directory it was actually
		// created in — which is the staging directory when there is one. That
		// is exactly why the staging directory lives INSIDE the destination
		// and not off in the container: it inherits the destination's group
		// and setgid bit, so what is built in it gets the group the
		// destination dictates, and this check means the same thing either way.
		if fi, serr := dir.stat(); serr != nil {
			dir.close()
			return nil, false, errors.Join(errNotOurs, serr)
		} else if gerr := createdInGroup(where, fi); gerr != nil {
			dir.close()
			return nil, false, errors.Join(errNotOurs, gerr)
		}
		// Now that it is proved to be this job's own, the crossing question:
		// a mount placed over it puts the copy on another filesystem, with the
		// crossing rule switched off and the free-space check describing a
		// filesystem the bytes never reach. A successful mkdir proves nothing
		// about the descriptor opened after it.
		//
		// This one DOES remove what it found, unlike the proofs above: those
		// say "not mine", and this one says "mine, and somewhere I may not
		// write". If the removal fails because it really is a mount point,
		// there was never anything this process could do about it and the
		// leftover is named out loud.
		if crossesInto(parent, dir) {
			if rerr := c.dropCreated(where, dir, openName); rerr != nil {
				c.warn(fsx.Join(parentAPI, name), warnChanged, fmt.Sprintf(
					"%q could not be removed after it turned out to be a mount point, so an empty folder was left behind: %v",
					fsx.Join(parentAPI, name), rerr), fsx.Errno(rerr))
			}
			dir.close()
			return nil, false, fmt.Errorf(
				"%q is a mount point at the destination and this job does not write across one: %w",
				fsx.Join(parentAPI, name), fsx.ErrProtected)
		}
		// The chown follows the proof, never precedes it: root handing a
		// foreign directory to another user is not a mistake that can be
		// undone (ownership review finding A).
		//
		// A failure here ABANDONS the subtree; it is not a warning to carry on
		// past. The file path has always worked that way (copyFile installs the
		// owner on the empty file and publishes nothing if it cannot), and a
		// directory is the same disclosure one level up: root moving alice's
		// tree into a setgid `public` destination creates each directory
		// root:public, and copying children into one whose chown failed hands
		// every member of that group what was alice's. The empty directory is
		// removed again, so nothing is left standing that a later merge could
		// adopt.
		if uid, gid, want := c.ownerFor(srcInfo); want {
			if cerr := setEntryOwner(where, openName, dir.f, uid, gid); cerr != nil {
				c.rmdirIfOurs(where, dir, openName)
				dir.close()
				return nil, false, errors.Join(errOwnerUnset, cerr)
			}
		}
		// Proved, owned and empty: NOW it takes the name the copy will use,
		// out of the staging directory and into the destination in one
		// renameat2. RENAME_NOREPLACE, so a stranger who took the name since
		// the placement was made is not replaced — the EEXIST that comes back
		// is the same answer the mkdir used to give, and the caller reports it
		// as `exists`. Both ends are held descriptors on one filesystem: the
		// staging directory is inside the destination, and the destination
		// never crosses a mount.
		if staged != "" {
			if rerr := parent.renameFromDir(where, staged, name, true); rerr != nil {
				c.rmdirIfOurs(where, dir, staged)
				dir.close()
				return nil, false, rerr
			}
			// The descriptor followed the rename, as a descriptor does; the
			// SPELLING has to be told. Nothing here resolves it — every
			// operation on this handle is relative to the descriptor — but it
			// is what error messages are written from, and a warning naming a
			// temporary nobody has ever seen would be a lie.
			dir.rel = relJoin(parent.rel, name)
		}
	}
	if rerr := c.remember(dir); rerr != nil {
		dir.close()
		return nil, false, rerr
	}
	c.res.Dirs++
	c.progress(fsx.Join(parentAPI, name), wproto.PhaseWorking)
	return dir, created, nil
}

// crossesInto reports that a directory just adopted at the destination is on a
// different mount from the directory it was found in.
//
// It asks the DESCRIPTORS, through the same identityFor the walk makes its own
// crossing decisions with — the statx mount id where the kernel gives one,
// st_dev otherwise. The mount id is what matters: two bind mounts of one device
// share a st_dev, and a device comparison alone would walk straight into one.
func crossesInto(parent, child *dirRef) bool {
	return identityFor(child).differsFrom(identityFor(parent))
}

// provenance is leafProvenance's whole rule applied to a directory this copy
// has just created: the right kind, owned by this worker, AND EMPTY.
//
// Emptiness is the half that actually proves creation, and leaving it out was a
// real hole: a uid match says only that root owns it, and in a parent an
// attacker can write, a pre-existing root-owned directory holding private data
// renamed over the fresh name between the mkdirat and the openat satisfies kind
// and owner and would then be chowned away to the requested user. A brand-new
// directory has no entries; a directory with entries is not the one we made.
//
// The read descriptor is opened as "." relative to the held O_PATH handle
// (enumerable), so the question is asked of that inode and the name is never
// resolved again.
func (c *copier) provenance(dir *dirRef, want kind) error {
	fi, err := dir.stat()
	if err != nil {
		return err
	}
	if cerr := createdByUs(fi, want); cerr != nil {
		return cerr
	}
	if want != kindDir {
		return nil
	}
	f, err := enumerable(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("the new folder already has %q in it, so it is not the one that was just created: %w",
			names[0], fsx.ErrUnsupported)
	}
	return nil
}

// createdByUs proves, on a FileInfo of a held descriptor alone, that an entry is
// the right kind and belongs to this worker. For a directory it is half the
// proof; see provenance for the other half.
func createdByUs(fi os.FileInfo, want kind) error {
	if fi == nil {
		return fmt.Errorf("what was just created cannot be described: %w", fsx.ErrUnsupported)
	}
	if kindOf(fi) != want {
		return fmt.Errorf("what was just created is a %s: %w", kindName(kindOf(fi)), fsx.ErrUnsupported)
	}
	uid, _, _, ok := statDetail(fi)
	if ok && uid != os.Geteuid() {
		return fmt.Errorf("what was just created is owned by uid %d and not by this worker: %w", uid, fsx.ErrUnsupported)
	}
	return nil
}

// createdInGroup proves that a freshly created destination entry is in the
// group the KERNEL would have put it in, which is the half of "we made this"
// that a uid comparison cannot express.
//
// The attack it answers has no privileges in it. Root copies into a shared,
// non-sticky, SETGID destination owned root:private: every entry created there
// comes out root:private, and `As` — when the job has one at all — need not
// carry a gid (-1 leaves the group alone). Another user renames an existing
// empty root-owned 0750 root:public directory over the fresh name. Creator uid
// passes (root did own it), emptiness passes (it is empty), mode-subset passes
// (0750 is no wider than 0750), and the private tree is then copied into a
// directory every member of `public` can read.
//
// The expectation is the kernel's own rule: a new entry takes the containing
// directory's group when that directory carries S_ISGID, and the worker's
// effective gid otherwise. Nothing else is accepted — a mismatch means the
// object is not the one this job created, whatever else agrees about it.
//
// Residual, stated rather than guessed at: a filesystem mounted `grpid`
// (`bsdgroups`) gives every new entry the parent's group with no setgid bit to
// announce it, and this check would refuse there. QTS mounts neither its ext4
// volumes nor ZFS datasets that way, and the failure is a refusal that keeps
// the user's data rather than one that loses it.
//
// Off Linux there are no uids or gids to read, so there is nothing to compare
// (INV-2).
func createdInGroup(parent *dirRef, fi os.FileInfo) error {
	if !inodeIdentity {
		return nil
	}
	want, setgid, ok := expectedGroup(parent)
	if !ok {
		return fmt.Errorf("the group a new entry here would be given could not be read: %w", fsx.ErrUnsupported)
	}
	_, gid, _, got := statDetail(fi)
	if !got {
		return fmt.Errorf("what was just created has no group this worker can read: %w", fsx.ErrUnsupported)
	}
	if gid != want {
		return fmt.Errorf("what was just created is in group %d where the kernel would have made it %d, so it is not the one this job created: %w",
			gid, want, fsx.ErrUnsupported)
	}
	// Under a setgid parent a new DIRECTORY carries the bit onwards, and its
	// absence is as good a sign of a substitution as a wider mode is. Round 14
	// adversarial's second finding turns on exactly that: a non-root worker
	// whose primary group is `public`, copying into a setgid `private`
	// destination, could have an empty directory of its own uid, gid `private`
	// and mode 0755 — but no setgid bit — swapped in, and every file created
	// inside it afterwards then came out `public`. modeNoWiderThan only ever
	// rejected EXTRA bits, so a missing one went unnoticed.
	//
	// Files never inherit it (S_ISGID on a regular file means something else
	// entirely, and this engine never asks for it), so the requirement is the
	// directory's alone.
	if setgid && fi.IsDir() && fi.Mode()&fs.ModeSetgid == 0 {
		return fmt.Errorf("what was just created does not carry the setgid bit this destination passes down, so it is not the one the kernel made: %w",
			fsx.ErrUnsupported)
	}
	return nil
}

// expectedGroup is the group the kernel gives an entry created in a held
// directory — the directory's own group when it is setgid, the worker's
// effective group otherwise — and whether that directory is setgid at all.
func expectedGroup(parent *dirRef) (gid int, setgid, ok bool) {
	if parent == nil {
		return 0, false, false
	}
	fi, err := parent.stat()
	if err != nil {
		return 0, false, false
	}
	if fi.Mode()&fs.ModeSetgid != 0 {
		_, g, _, got := statDetail(fi)
		return g, true, got
	}
	return os.Getegid(), false, true
}

// errOwnerUnset says a destination directory was created but could not be given
// its owner, so nothing may be written into it. It never leaves this file:
// makeDir's callers turn it into an owner_unset skip against the subtree.
var errOwnerUnset = errors.New("fsops: the created folder could not be given its owner")

// rmdirIfOurs removes a destination directory this job created and then
// abandoned — by NAME, as rmdir must be, but only after the name has been proved
// to still be the held descriptor. A directory somebody substituted in the
// meantime is not this job's to remove.
// dropCreated removes a directory this job created and proved, reporting why it
// could not where that fails — a mount over it is the case that exists, and an
// unremovable mount point is not something any process can tidy away.
func (c *copier) dropCreated(parent, dir *dirRef, name string) error {
	want, ok := heldIdentity(dir)
	if ok {
		fi, err := parent.lstat(name)
		if err != nil {
			return err
		}
		if k, kok := inodeOf(fi); !kok || k != want {
			return errors.New("it is not the directory that was created any more")
		}
	} else if inodeIdentity {
		return errors.New("it could not be identified")
	}
	return parent.unlink(name, true)
}

func (c *copier) rmdirIfOurs(parent, dir *dirRef, name string) {
	if name == "" {
		// Nothing was staged: the directory is at its final name and removing
		// it is not this function's business.
		return
	}
	want, ok := heldIdentity(dir)
	if !ok {
		if inodeIdentity {
			// The platform has identities and this one could not be read: no
			// proof, no removal.
			return
		}
		_ = parent.unlink(name, true)
		return
	}
	fi, err := parent.lstat(name)
	if err != nil {
		return
	}
	if k, kok := inodeOf(fi); !kok || k != want {
		return
	}
	_ = parent.unlink(name, true)
}

// copyEntry copies one non-directory into a destination directory this job is
// holding open.
func (c *copier) copyEntry(ctx context.Context, srcDir *dirRef, srcName string, fi os.FileInfo,
	srcPath string, dstDir *dirRef, dstDirAPI string, p placed, rec *copiedDir) error {

	if kindOf(fi) == kindLink {
		return c.copyLink(srcDir, srcName, fi, srcPath, dstDir, dstDirAPI, p, rec)
	}
	return c.copyFile(ctx, srcDir, srcName, fi, srcPath, dstDir, dstDirAPI, p, rec)
}

// copyLink recreates a symlink: readlinkat, then symlinkat, and never a step
// through the link itself (§1.6). The target text is reproduced byte for byte,
// so a link that pointed outside the tree still points outside it and one that
// was relative stays relative.
// The metadata of the new link is set through a descriptor and never through
// its name. That is finding 3 of the first review, and it was a real hole: an
// fchownat(AT_SYMLINK_NOFOLLOW) by NAME chowns whatever occupies the name, so a
// user who can write the (non-sticky) destination directory had only to rename
// a root-owned 0600 file over the new link between the symlinkat and the chown
// to be handed it. So the link is pinned with O_PATH|O_NOFOLLOW relative to the
// held destination directory, proved to be a symlink this worker owns, and only
// then chowned and stamped — by AT_EMPTY_PATH on that descriptor.
func (c *copier) copyLink(srcDir *dirRef, srcName string, fi os.FileInfo,
	srcPath string, dstDir *dirRef, dstDirAPI string, p placed, rec *copiedDir) error {

	// The SOURCE link is pinned before anything is read from it, and both its
	// target and its metadata come from that descriptor — never from the lstat
	// that classified the name, and never from a second lookup of the name. A
	// link replaced in between would otherwise have its old owner and times
	// reproduced onto a copy of its new target.
	srcRef, err := itemRefIn(srcDir, srcName)
	if err != nil {
		c.skip(srcPath, err)
		return nil
	}
	defer srcRef.close()
	if inodeIdentity && !sameFileState(srcRef.fi, fi) {
		c.skipCode(srcPath, warnChanged,
			fmt.Sprintf("%q changed between being listed and being read, so it was left alone", srcPath), 0)
		return nil
	}
	fi = srcRef.fi

	target, err := readlinkRef(srcRef, srcDir, srcName)
	if err != nil {
		c.skip(srcPath, err)
		return nil
	}
	// Built where nobody else can reach it and renamed into place, for the
	// reason stagingIn gives at length: what nobody can name, nobody can
	// substitute. The pin and its proofs stay exactly where they were.
	where, name, err := c.buildIn(dstDir, dstDirAPI, p)
	if err != nil {
		c.buildFailed(fsx.Join(dstDirAPI, p.name), err)
		return nil
	}
	if err := symlinkAtSeam(where, name, target); err != nil {
		c.skip(fsx.Join(dstDirAPI, p.name), err)
		return nil
	}
	dstPath := fsx.Join(dstDirAPI, p.name)

	// Pinned immediately, before anything is set on it, and then PROVED — every
	// time, whether or not an owner is being applied.
	//
	// Tying that proof to the chown was a hole with no privileges in it: on the
	// ordinary non-root path nothing chowned, so nothing checked, and anybody
	// able to write the destination directory had only to replace the fresh
	// link between the symlinkat and the pin. The replacement's inode then
	// became the recorded identity and its target was never looked at, so
	// "link -> good" was published as "link -> bad", the original was deleted,
	// and the job reported success.
	//
	// A symlink has no meaningful mode to compare — Linux reports 0777 for
	// every one of them and honours none of it — so the subset check the file
	// and directory paths make has nothing to say here.
	//
	// The three questions are the whole of it: is this a symlink, did this
	// worker make it (its owner is this euid — on a non-root worker that is the
	// user's own uid, which still proves the link is ours and not somebody
	// else's), and does it point where the source pointed. The target is read
	// from the pinned descriptor, never by name.
	pin, perr := itemRefIn(where, name)
	if pin != nil {
		defer pin.close()
	}
	if perr != nil {
		c.skip(dstPath, perr)
		return nil
	}
	if cerr := createdByUs(pin.fi, kindLink); cerr != nil {
		// Nothing is unlinked: what is at the name is not this job's.
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was replaced as it was created, so nothing was published for it: %v", dstPath, cerr), 0)
		return nil
	}
	// The group the kernel would have given it, for the same reason and with
	// the same answer as everywhere else this job creates something
	// (createdInGroup). A link has no mode to compare, so this and the creator
	// are the whole of what a stat can say about where it came from.
	if gerr := createdInGroup(where, pin.fi); gerr != nil {
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was replaced as it was created, so nothing was published for it: %v", dstPath, gerr), 0)
		return nil
	}
	if made, rerr := readlinkRef(pin, where, name); rerr != nil || made != target {
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q does not point where %q does, so nothing was published for it", dstPath, srcPath), 0)
		return nil
	}
	if uid, gid, want := c.ownerFor(fi); want {
		if cerr := setEntryOwner(where, name, refFD(pin), uid, gid); cerr != nil {
			c.ownerUnset(dstPath, cerr)
		}
	}
	// A symlink needs no settling: its content cannot be rewritten in place,
	// so replacing one allocates a new inode that the identity check catches,
	// and its target text is compared at delete time — read from a descriptor
	// on both sides, never from a name.
	c.setTimes(where, name, refFD(pin), true, fi, dstPath)
	if err := c.publish(where, dstDir, name, p.name, pin.fi, kindLink, dstPath, p.act == actOverwrite); err != nil {
		return nil
	}
	c.recordEntry(rec, c.entryRecord(srcName, kindLink, fi, fi.Size(), target, p.name, publishedState(dstDir, p.name, pin.fi)))
	c.res.Files++
	c.res.Bytes += fi.Size()
	c.progress(dstPath, wproto.PhaseWorking)
	return nil
}

// entryRecord is what the delete will have to find again: the identity, the
// size and the modification time the entry had when it was copied, plus a
// symlink's target text.
func (c *copier) entryRecord(name string, k kind, fi os.FileInfo, size int64, link string,
	dstName string, published os.FileInfo) copiedEntry {

	e := copiedEntry{name: name, kind: k, recorded: true, size: size, mtime: fi.ModTime(), link: link, dstName: dstName}
	e.id, e.haveID = inodeOf(fi)
	e.ctime, e.haveCtime = changeTimeOf(fi)
	e.mode = fi.Mode()
	if uid, gid, nlink, ok := statDetail(fi); ok {
		e.nlink = nlink
		e.uid, e.gid, e.haveOwner = uid, gid, true
	}
	if published != nil {
		e.dstID, e.haveDstID = inodeOf(published)
		e.dstSize = published.Size()
		e.dstMtime = published.ModTime()
		e.dstCtime, e.haveDstCtime = changeTimeOf(published)
	}
	return e
}

// publishedState reads back what this job actually left at the destination,
// after everything that touches it: the bytes, the owner, the times and — for
// an overwrite — the rename, every one of which moves the change time. It is
// the state copyStillThere will require to be unchanged before the source is
// removed.
//
// The identity is checked against the descriptor the bytes went through, so a
// name that means something else by now is not recorded as this job's copy.
func publishedState(dstDir *dirRef, name string, wrote os.FileInfo) os.FileInfo {
	fi, err := dstDir.lstat(name)
	if err != nil {
		return nil
	}
	a, aok := inodeOf(fi)
	b, bok := inodeOf(wrote)
	if aok && bok && a != b {
		return nil
	}
	return fi
}

// copyFile copies one regular file through two held descriptors.
//
// `overwrite` is write-to-temp-then-rename-over and never a truncate in place
// (§1.3). That is the whole difference between "the copy failed and you still
// have your file" and "the copy failed and your file is now half the other
// one": renameat replaces atomically, so a reader sees the old file or the new
// one, and every failure path below throws the half-written copy away and
// leaves the original exactly as it was — which, on the unnamed path, is
// nothing more than closing a descriptor (discard).
func (c *copier) copyFile(ctx context.Context, srcDir *dirRef, srcName string, fi os.FileInfo,
	srcPath string, dstDir *dirRef, dstDirAPI string, p placed, rec *copiedDir) error {

	src, err := openForCopy(srcDir, srcName, copyReadFlags, 0)
	if err != nil {
		c.skip(srcPath, err)
		return nil
	}
	defer src.Close()
	sfi, err := src.Stat()
	if err != nil {
		c.skip(srcPath, err)
		return nil
	}
	if !sfi.Mode().IsRegular() {
		// The name became something else between the walk's lstat and this
		// open. The descriptor is what counts, and it says do not read this.
		c.skipCode(srcPath, warnUnsupported,
			fmt.Sprintf("%q is a %s, which has no contents to copy", srcPath, fsx.TypeString(sfi.Mode())), 0)
		return nil
	}
	if same, known := sameObject(fi, sfi); known && !same {
		c.skipCode(srcPath, warnChanged,
			fmt.Sprintf("%q was replaced between being listed and being opened, so it was left alone", srcPath), 0)
		return nil
	}
	if err := clearNonblock(src); err != nil {
		c.skip(srcPath, err)
		return nil
	}

	// Settled BEFORE a byte is read, and before anything is created for it
	// (settleSource). Proving it afterwards proved only that the tick had
	// ended: a same-length rewrite with its mtime restored, made between the
	// read and the end of that tick, kept the recorded change time and the
	// newer file was then deleted with the older bytes standing at the
	// destination. An entry that cannot be settled is not copied at all, so
	// nothing is published for it and there is nothing to undo.
	if c.move {
		settledFi, res := c.settleSource(c.srcRootParent, src, sfi)
		switch res {
		case settleUnverifiable:
			c.skipCode(srcPath, warnUnverified, fmt.Sprintf(
				"%q was written to so recently that a later change to it could not be told apart, so it was not moved",
				srcPath), 0)
			return nil
		case settleChanged:
			c.skipCode(srcPath, warnChanged, fmt.Sprintf(
				"%q is being written to, so it was not moved", srcPath), 0)
			return nil
		}
		// The state proved settled is the state that gets copied and recorded.
		sfi = settledFi
	}

	dstPath := fsx.Join(dstDirAPI, p.name)
	asked := sfi.Mode().Perm()

	// Created with NO NAME where the kernel will do it (O_TMPFILE), and linked
	// into place only once it is complete, owned and proved. Round 14
	// adversarial's first finding is what that answers: installing the owner on
	// the empty file closed the window for anyone who had not opened it YET,
	// but a file created at its final name is openable the instant it exists,
	// and a descriptor somebody already holds survives every chown that
	// follows. Root moving alice's 0640 into a setgid `public` directory made
	// it root:public 0640 under its real name; a member of `public` opening it
	// in that instant read everything written into it afterwards. An inode with
	// no name cannot be opened by anybody.
	//
	// Where O_TMPFILE is unavailable the file is created under a name as it
	// always was, and that window is the residual this file's header records
	// for the fallback.
	unnamed := false
	var dst *os.File
	// where the file is built and the name it will be given: the destination
	// itself for an unnamed one — it has no name to protect until the link —
	// and otherwise whatever buildIn decides.
	where, name := dstDir, ""
	if c.unnamedOK() {
		if f, uerr := openUnnamedFile(dstDir, asked); uerr == nil {
			n, nerr := c.createName(p)
			if nerr != nil {
				_ = f.Close()
				c.skip(dstPath, nerr)
				return nil
			}
			dst, unnamed, name = f, true, n
		}
	}
	if !unnamed {
		w, n, berr := c.buildIn(dstDir, dstDirAPI, p)
		if berr != nil {
			c.buildFailed(dstPath, berr)
			return nil
		}
		where, name = w, n
		dst, err = where.openFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, asked)
		if err != nil {
			c.skip(dstPath, err)
			return nil
		}
	}

	// Both of these happen on the EMPTY file, before a byte of anybody's data
	// is in it.
	//
	// The mode is checked because a file may never end up with permissions
	// WIDER than the ones asked for: O_CREAT narrows by the umask and by a
	// default ACL and never widens, so a wider mode means this is not the file
	// this job thinks it created.
	//
	// The owner is installed here rather than after the copy, and that is the
	// whole of round 12's second finding: root moving alice's 0640 file into a
	// setgid `public` directory created it root:public 0640, and the ENTIRE
	// copy then ran before the chown — so for as long as it took, every member
	// of `public` could read it, or open a descriptor and keep reading it
	// afterwards. It is the same chown, done while the file is still empty. A
	// chown that fails now costs an empty file and a warning; one that failed
	// later cost a disclosure.
	//
	// The GROUP is checked with it, and for the reason createdInGroup gives one
	// level up: a file takes its group from the destination directory when that
	// directory is setgid, so a file that came out in another group is not the
	// one the kernel was asked for and its contents are not going into it. One
	// fstat answers both questions.
	empty, serr := dst.Stat()
	if serr != nil {
		c.discard(where, name, unnamed, nil, dstPath)
		_ = dst.Close()
		c.skip(dstPath, serr)
		return nil
	}
	if merr := modeSubset(empty.Mode(), asked, 0); merr != nil {
		c.discard(where, name, unnamed, empty, dstPath)
		_ = dst.Close()
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was not created as this job asked, so nothing was written into it: %v", dstPath, merr), 0)
		return nil
	}
	if gerr := createdInGroup(where, empty); gerr != nil {
		c.discard(where, name, unnamed, empty, dstPath)
		_ = dst.Close()
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was not created as this job asked, so nothing was written into it: %v", dstPath, gerr), 0)
		return nil
	}
	if uid, gid, want := c.ownerFor(sfi); want {
		if cerr := setEntryOwner(where, name, dst, uid, gid); cerr != nil {
			c.discard(where, name, unnamed, empty, dstPath)
			_ = dst.Close()
			c.skipCode(dstPath, warnOwnerUnset, fmt.Sprintf(
				"%q could not be given its owner, so nothing was written into it: %v", dstPath, cerr), 0)
			return nil
		}
	}

	if c.buf == nil {
		c.buf = make([]byte, copyBufSize)
	}
	base := c.res.Bytes
	w := &countWriter{w: dst, ctx: ctx, tick: func(n int64) {
		c.progressBytes(dstPath, base+n)
	}}
	n, cerr := copyStream(w, plainReader{src}, c.buf)

	if cerr != nil {
		// Nothing half-written survives: the temporary of an overwrite AND the
		// partial file of a plain create are both removed, so a failed copy
		// never leaves something that looks like a complete file. The removal
		// is by identity, never by name alone — see unlinkIfOurs.
		// The descriptor stays OPEN across the identity check and the unlink:
		// while this job holds it the inode cannot be freed, so its number
		// cannot be handed to a stranger's file at the same name and the check
		// cannot be fooled into removing one.
		partial, _ := dst.Stat()
		c.discard(where, name, unnamed, partial, dstPath)
		_ = dst.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.copyFailed(dstPath, cerr)
		return nil
	}

	// The verification, and it is a GATE rather than a remark. io.CopyBuffer
	// returns a short count with no error when the source is truncated
	// underneath it, so the old shape warned "changed" and then renamed the
	// temporary over the destination anyway — an intact file replaced by one
	// byte of a file that no longer exists. A destination that does not have
	// the size the source had when it was opened has not been copied: the
	// partial goes away, nothing is published, and the entry counts as a
	// failure like any other.
	dfi, serr := dst.Stat()
	switch {
	case serr != nil:
		// No fstat, so no identity: nothing is removed, and the warning names
		// what was left behind rather than unlinking on a guess.
		c.discard(where, name, unnamed, nil, dstPath)
		_ = dst.Close()
		c.skip(dstPath, serr)
		return nil
	case dfi.Size() != sfi.Size():
		c.discard(where, name, unnamed, dfi, dstPath)
		_ = dst.Close()
		c.skipCode(srcPath, warnChanged, fmt.Sprintf(
			"%q was %d bytes when it was opened and %d arrived, so it is being written to and was not copied",
			srcPath, sfi.Size(), dfi.Size()), 0)
		return nil
	}

	// The owner comes from sfi — the fstat of the descriptor the bytes were
	// READ from, after the settle — and never from the lstat that classified the
	// name. A file chowned to another user between the two, and given private
	// contents with it, would otherwise be reproduced with its OLD owner and the
	// new contents, and then have its source deleted: a disclosure.
	// And the SOURCE has to be what it was when the read started. A destination
	// of the right length is not the same as a faithful copy: read "AA" of
	// "AAAA", let somebody rewrite the file to "BBBB", read the rest, and
	// "AABB" is exactly four bytes long and is neither version. Under overwrite
	// that was published over an intact destination, so the destination held
	// neither the old file nor the new one — a COPY losing data, with no move
	// involved and no warning.
	//
	// Residual, stated honestly: a move settles before it reads, so any rewrite
	// lands in a later tick and moves the change time. A plain COPY does not
	// settle — it deletes nothing, so the cost is not warranted — which leaves
	// one case open there: an equal-length rewrite made inside the same clock
	// tick as the read, of a file small enough to be read inside one tick.
	sAfter, serr := src.Stat()
	if serr != nil || !sameFileState(sfi, sAfter) {
		c.discard(where, name, unnamed, dfi, dstPath)
		_ = dst.Close()
		c.skipCode(srcPath, warnChanged, fmt.Sprintf(
			"%q was written to while it was being read, so nothing was published for it", srcPath), 0)
		return nil
	}

	// Before the close, so futimens acts on the descriptor the bytes went
	// through rather than on a name that could mean something else by then.
	c.setTimes(where, name, dst, false, sfi, dstPath)

	// Flushed BEFORE anything is published. On a buffered network filesystem
	// the writes all "succeed" and the error — EIO, EDQUOT — surfaces at close;
	// with the rename already done, the close-error branch then unlinked the
	// published file and NEITHER version survived. fsync is where a delayed
	// write error is supposed to appear, so it is asked here, while there is
	// still nothing published to lose. It also settles the copy's own change
	// time, which the record depends on.
	//
	// The cost is one fsync per file. ext4 and ZFS both take it in their
	// stride, and a move that skipped it would be trading the user's only
	// remaining copy against it.
	if serr := dst.Sync(); serr != nil {
		c.discard(where, name, unnamed, dfi, dstPath)
		_ = dst.Close()
		c.copyFailed(dstPath, serr)
		return nil
	}

	// Published while the descriptor is STILL OPEN, and closed only afterwards.
	// That ordering is the whole of it: the check that the name still refers to
	// what this job wrote compares inode numbers, and an inode number is only
	// meaningful while somebody holds the inode. Closing first let a
	// destination writer unlink the temporary, watch this job's close release
	// the last reference, and have the freed number handed straight back to a
	// file they created at the same name — at which point the identity check
	// agreed and the rename published their contents over an intact file.
	// An unnamed file gets its name HERE, with everything already done to it:
	// the bytes, the owner, the times, the flush. For a direct create that
	// linkat IS the publication — atomic, and EEXIST if somebody took the name
	// in the meantime, which is the answer the O_EXCL create used to give. For
	// an overwrite it lands under the unguessable temporary name and publish
	// renames it over the target exactly as before.
	if unnamed {
		if lerr := linkUnnamed(dst, where, name); lerr != nil {
			_ = dst.Close()
			// There is nothing to clean up: an inode nobody named and nobody
			// can reach goes away with the descriptor.
			c.skip(dstPath, lerr)
			return nil
		}
	}
	if err := c.publish(where, dstDir, name, p.name, dfi, kindRegular, dstPath, p.act == actOverwrite); err != nil {
		_ = dst.Close()
		return nil
	}
	if err := dst.Close(); err != nil {
		// Reported and left ALONE. The data was flushed before publication, so
		// a failure surfacing only now is one this job cannot attribute — and
		// unlinking the published name over it was how a delayed NFS error
		// destroyed the last copy of a file whose original the move was about
		// to delete. The entry is not recorded either, so a move keeps its
		// source: both copies stand and the warning says why.
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was published but its filesystem reported an error closing it, so the original was kept: %v",
			dstPath, err), 0)
		return nil
	}

	// Recorded from the fstat of the descriptor the bytes were READ through,
	// not from the lstat that classified the name: that is the object this copy
	// actually reproduced, and it is the one the delete has to find again.
	c.recordEntry(rec, c.entryRecord(srcName, kindRegular, sfi, sfi.Size(), "", p.name, publishedState(dstDir, p.name, dfi)))
	c.res.Files++
	c.res.Bytes += n
	c.progress(dstPath, wproto.PhaseWorking)
	return nil
}

// publish renames the temporary of an overwrite over its target, after proving
// that the temporary's NAME still refers to the inode this job wrote.
//
// The proof is the third finding of the second review, and the attack is
// pretty: everything up to here addresses the held descriptor, so an attacker
// who can write the destination directory unlinks the temporary during a long
// copy and creates an empty file under the same name. The writes and the size
// verification all succeed — on the inode nobody can see any more — and the
// rename then publishes the attacker's file under the user's name, after which
// a move deletes the source. So the name is looked up once more through the
// held destination descriptor and compared with the fstat of the descriptor the
// bytes went through.
//
// A stranger's file at that name is NOT removed: it is not this job's, and
// unlinking it would be the second half of the same mistake. The entry fails as
// a content warning, which keeps a move's source.
//
// Residual: Linux has no rename-by-descriptor, so between this check and the
// renameat the name could be re-pointed once more. It is a §2.4-class residual
// and it is now two adjacent syscalls wide, with nothing in between.
// It is asked for the direct-create path too, where name and final are the same
// string and there is no rename to make. The hole is identical there and the
// reviewer's version of it only named the temporary: unlink the freshly created
// file and put another one at its name, and every write lands on an inode
// nobody can reach while the name holds somebody else's file — which a move
// would then count as copied and delete the source for.
// The TARGET's kind is re-checked too, and for the same class of reason. place
// refuses a mismatch under every policy — a file over a folder, a symlink over
// a file — but it decided that before a transfer that can run for minutes, and
// renameat replaces whatever it finds. An existing regular file swapped for a
// symlink (or a directory) during the write would have been renamed over,
// turning a refusal into a silent replacement of something the policy said to
// leave alone. So the final name is looked up once more and has to be absent,
// or still the kind the placement was made against.
func (c *copier) publish(from, dstDir *dirRef, name, final string, wrote os.FileInfo, want kind, dstPath string, replace bool) error {
	if same, known := sameNamedObject(from, name, wrote); known && !same {
		c.skipCode(dstPath, warnChanged, fmt.Sprintf(
			"%q was replaced while it was being written, so nothing was published under that name", dstPath), 0)
		return errNotPublished
	}
	if from == dstDir && name == final {
		// Created under its own name: there was never anything to rename, and
		// the check above is the whole of the publication.
		return nil
	}
	if tfi, terr := dstDir.lstat(final); terr == nil && kindOf(tfi) != want {
		c.unlinkIfOurs(from, name, wrote, dstPath)
		c.skipCode(dstPath, warnConflict, fmt.Sprintf(
			"%q became a %s while it was being written, and this job does not replace one kind with another",
			dstPath, kindName(kindOf(tfi))), 0)
		return errNotPublished
	}
	// Only an OVERWRITE replaces. Everything else was placed against a name
	// that was free, and RENAME_NOREPLACE is what keeps that true all the way
	// to the publication: a stranger who took the name while this was being
	// written gets an EEXIST back, which the caller reports as `exists` — the
	// same answer the O_EXCL create used to give when it lost the same race.
	//
	// Both ends are held descriptors, and `from` is the private staging
	// directory whenever there is one — which is inside the destination, so
	// this is one renameat2 on one filesystem either way.
	if err := dstDir.renameFromDir(from, name, final, !replace); err != nil {
		c.unlinkIfOurs(from, name, wrote, dstPath)
		c.skip(dstPath, err)
		return errNotPublished
	}
	return nil
}

// discard throws away a destination file that will not be published: nothing at
// all when it never had a name, and unlinkIfOurs when it did.
//
// An unnamed file is the easy half of the case this whole cleanup path exists
// for. There is no name for anybody to have taken, nothing to identify before
// removing, and nothing left behind when this process closes the descriptor —
// which the caller does immediately afterwards.
func (c *copier) discard(dir *dirRef, name string, unnamed bool, ours os.FileInfo, dstPath string) {
	if unnamed {
		return
	}
	c.unlinkIfOurs(dir, name, ours, dstPath)
}

// unnamedOK reports whether this job can create files with no name and publish
// them by link, and finds out once.
//
// The probe is one create-link-unlink in the destination container the user
// picked, which is the directory this engine already uses for its clock scratch
// (settled) and whose timestamps it does not reproduce. It answers two
// questions no errno at the wrong moment could: whether the destination
// filesystem implements O_TMPFILE, and whether /proc is mounted for the linkat
// that publishes one. Finding out on the first real file instead would mean
// discovering half way through a copy that the bytes just written cannot be
// given a name.
//
// A `no` is not a failure: the file is created under a name as this engine
// always did, with the window that leaves recorded in the header's residuals.
func (c *copier) unnamedOK() bool {
	if c.unnamed != unnamedUnknown {
		return c.unnamed == unnamedYes
	}
	c.unnamed = unnamedNo
	f, err := openUnnamedFile(c.dst, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	name, nerr := copyTmpName()
	if nerr != nil {
		return false
	}
	if lerr := linkUnnamed(f, c.dst, name); lerr != nil {
		return false
	}
	_ = c.dst.unlink(name, false)
	c.unnamed = unnamedYes
	return true
}

// unlinkIfOurs removes a name this job created, and ONLY while that name still
// refers to the object this job created.
//
// Every cleanup path goes through it, which is the point of it being one
// function: a failed copy, a cancelled one, a failed verification, a failed
// close and a failed rename all used to unlink by name alone, and the reviewer
// reproduced the consequence. A process that renames our in-progress file aside
// and saves an unrelated file under the same name — an editor writing out, a
// download completing — had that file deleted by our tidying up.
//
// When the name is somebody else's, nothing is unlinked and the warning says
// so. Our own inode, now living under whatever name it was renamed to, is the
// residual that warning names: this process cannot find it again, and hunting
// for it would mean searching a directory by identity for something an attacker
// controls.
//
// ours == nil means the object could not be described at all (its fstat
// failed), which is the same answer: no proof, no unlink.
func (c *copier) unlinkIfOurs(dir *dirRef, name string, ours os.FileInfo, dstPath string) {
	if ours == nil {
		c.warn(dstPath, warnChanged, fmt.Sprintf(
			"%q could not be identified while it was being cleaned up, so nothing was removed under that name", dstPath), 0)
		return
	}
	if same, known := sameNamedObject(dir, name, ours); known && !same {
		c.warn(dstPath, warnChanged, fmt.Sprintf(
			"%q was replaced while it was being written; the file now at that name belongs to somebody else and was left alone", dstPath), 0)
		return
	}
	_ = dir.unlink(name, false)
}

// staging is the private directory this job builds things in inside one
// destination directory, and the answer to whether that destination could give
// it one at all.
type staging struct {
	// dir and name are the staging directory itself, nil when this destination
	// could not provide a private one.
	dir  *dirRef
	name string
	// state says what to do when there is no staging directory.
	state stageState
}

// stageState is what a destination directory offers a job that wants to build
// something in it.
type stageState int

const (
	// stageReady: a private staging directory was made and proved.
	stageReady stageState = iota
	// stageOpen: no staging directory, and none is needed — nobody but this
	// worker can put anything in this destination, or the kernel will not let
	// them take an entry of ours out of it (a sticky directory).
	stageOpen
	// stageShared: no staging directory, because this destination is one other
	// users may legitimately write. Objects are built at their final names
	// under every proof this engine has, and the job says once that the
	// protection is reduced.
	stageShared
	// stageRefused: something was wrong with the staging directory itself —
	// not the object we made, or an ACL that could not be read. Nothing is
	// built here at all.
	stageRefused
)

// stageFail says why a staging directory could not be used.
type stageFail int

const (
	// stageProved: it can.
	stageProved stageFail = iota
	// stageUnproved: what was opened is not what was created, or the ACL could
	// not be read or understood. This is the suspicious one.
	stageUnproved
	// stageWritable: it is the object this job created, and this destination
	// hands out write access to other people. Nothing is wrong; the place is
	// just shared.
	stageWritable
	// stageUnmade: it could not be created or opened at all — a read-only or
	// full destination, which whatever is built next will report properly.
	stageUnmade
)

// stageMode is the staging directory's permissions: this worker and nobody
// else. It is required exactly, not as a subset — a directory that came out
// with anything else is not the one this job asked the kernel for.
const stageMode = 0o700

// stagingIn returns the private directory to build things in inside dst, or nil
// when this destination cannot provide one.
//
// This is round 15's first finding, and it is what finally takes the guessing
// out of "is what I opened the thing I just made". An unguessable name in a
// LISTABLE directory is still a name: a readdir loop — or one inotify watch —
// sees it appear, and the window between the mkdir and the openat that follows
// is enough to rename something else onto it. What can be substituted there is
// not a joke either: an empty directory of this worker's own uid and gid, mode
// no wider than asked, carrying a named-user ACL that grants the attacker r-x.
// Every stat check this engine makes passes, a chown strips no ACL, and the
// copy proceeds into a directory somebody else can read.
//
// Inside a directory that is ours, empty, 0700 and carries no ACL naming
// anybody, nobody else can create, rename or even look. So provenance of what
// is built there holds BY CONSTRUCTION, and the stat proofs — which all stay —
// become defence in depth rather than the whole defence.
//
// It is created inside the destination directory the object will end up in,
// not once per job in the container, and that is deliberate: a new entry takes
// its group from the directory it is created in when that directory is setgid,
// and its inherited ACL likewise. Staging everything in one place would give
// every copied directory the container's group instead of the group the
// destination the user picked dictates, which is §1.5's "exactly as cp without
// -p would" written off. One mkdir, one getxattr and one rmdir per destination
// directory is the price of keeping that true.
//
// When it cannot be had, the caller's fallbacks are in makeDir and copyLink:
// build at the final name where nobody else could interfere anyway (open), and
// otherwise refuse the entry rather than build it somewhere watchable.
func (c *copier) stagingIn(parent *dirRef, parentAPI string) *staging {
	if s, ok := c.stages[parent]; ok {
		return s
	}
	s := &staging{}
	if c.stages == nil {
		c.stages = make(map[*dirRef]*staging)
	}
	c.stages[parent] = s
	if !stagedCreate {
		// The dev loop cannot stage anything — a dirRef here is a pathname, so
		// nothing can be renamed out from under it — and it cannot read an ACL
		// either. It builds at the final name as this engine always did, which
		// is the same documented degradation as every other identity question
		// off Linux (INV-2). The NAS and the CI Linux jobs take the real path.
		s.state = stageOpen
		return s
	}
	// The destination's OWN ACLs, read once: they decide both whether staging
	// there would quietly change what the copied objects inherit, and — when
	// there is no staging — whether anybody else could interfere with objects
	// built at their final names.
	pf, perr := aclFactsOf(parent)
	if perr != nil {
		// A destination whose ACLs cannot be read is not one to reason about.
		// It is not evidence of interference either, so it is not a refusal:
		// it is the shared answer, with everything still proved.
		pf = aclFacts{otherWriter: true, noPropagate: true}
	}
	why := stageUnmade
	var dir *dirRef
	var name string
	if !pf.noPropagate {
		dir, name, why = c.makeStaging(parent, pf)
	}
	switch {
	case why == stageProved:
		s.dir, s.name, s.state = dir, name, stageReady
	case why == stageUnproved:
		// The suspicious one, and the only one that refuses: this job made a
		// directory and what it opened was not it, or its ACL could not be
		// read at all. Somewhere that happens is not somewhere to build.
		s.state = stageRefused
	case c.othersCanWrite(parent, pf):
		// Nothing suspicious: the staging directory carries an inherited write
		// entry, or could not be made at all, and this destination is one other
		// users may legitimately write. Everything is built at its final name,
		// under every proof this engine has, and the job says so once.
		s.state = stageShared
		c.sharedDestination()
	default:
		// No private place, and nobody to hide from either: whatever stopped
		// the staging directory (an inherited entry, a full disk) says nothing
		// about a destination only this worker can put things in.
		s.state = stageOpen
	}
	return s
}

// makeStaging creates and proves one staging directory, and says why not when
// it could not.
func (c *copier) makeStaging(parent *dirRef, pf aclFacts) (*dirRef, string, stageFail) {
	name, err := stageTmpName()
	if err != nil {
		return nil, "", stageUnmade
	}
	if merr := mkdirForStaging(parent, name, stageMode); merr != nil {
		return nil, "", stageUnmade
	}
	dir, oerr := parent.childPath(name)
	if oerr != nil {
		// The mkdir SUCCEEDED and the open did not. Somebody took the name
		// this job had just created — renamed it away, or put a symlink or a
		// file there — which is interference and not an environment. Falling
		// back to building at final names here would let an attacker CHOOSE
		// the weaker path by racing the staging directory, so this refuses.
		// Nothing is removed: what is at that name now is not ours.
		return nil, "", stageUnproved
	}
	if why := c.stagingProved(parent, dir, pf); why != stageProved {
		if why != stageUnproved {
			// Proved to be the directory this job made — it is simply not
			// private enough — so it is this job's to take away again. An
			// UNPROVED one is somebody else's and is left exactly where it is,
			// like every other object this engine cannot prove it created.
			c.rmdirIfOurs(parent, dir, name)
		}
		dir.close()
		return nil, "", why
	}
	return dir, name, stageProved
}

// stagingProved is the whole of what makes a staging directory private: it is
// the object this job just made, it is empty, it is on the same filesystem as
// the directory it was made in, its permissions are exactly this worker's, and
// no ACL names anybody else.
// Everything up to the ACL is "is this the object I just made": a failure
// there is a substitution, and it refuses. The ACL is the one question that can
// fail because of the ENVIRONMENT rather than because of an attacker — a share
// whose dataset hands new directories an inherited write entry is an ordinary
// share, not an attack — so that answer is told apart from the rest.
func (c *copier) stagingProved(parent, dir *dirRef, pf aclFacts) stageFail {
	if crossesInto(parent, dir) {
		return stageUnproved
	}
	if perr := c.provenance(dir, kindDir); perr != nil {
		return stageUnproved
	}
	fi, serr := dir.stat()
	if serr != nil {
		return stageUnproved
	}
	if inodeIdentity && fi.Mode().Perm() != stageMode {
		return stageUnproved
	}
	// The setgid bit a setgid parent passes down is expected; nothing else is.
	if merr := modeSubset(fi.Mode(), stageMode, inheritedSetgid(parent)); merr != nil {
		return stageUnproved
	}
	if gerr := createdInGroup(parent, fi); gerr != nil {
		return stageUnproved
	}
	facts, aerr := aclFactsOf(dir)
	switch {
	case aerr != nil:
		// An ACL this job cannot read is one it cannot reason about.
		return stageUnproved
	case !inheritedFrom(facts, pf):
		// What it will pass DOWN did not come from the destination. That is
		// round 17's finding and the last shape of the substitution: a planted
		// directory that is empty, ours, 0700 and in the right group, carrying
		// a default ACL — or an inheritable ACE — of somebody else's, which
		// every object built inside it would inherit and keep through the
		// rename that publishes it. Nothing here is written into; it is left
		// exactly where it was found.
		return stageUnproved
	case facts.otherWriter:
		return stageWritable
	}
	return stageProved
}

// othersCanWrite reports whether anybody but this worker could create something
// in a destination directory — by mode, or through an ACL that names somebody.
//
// Where nobody can, the substitution this staging exists to prevent has nobody
// to make it, and building at the final name is as safe as building anywhere.
// The answer is deliberately crude: any named ACL entry counts, because judging
// what a named entry is actually allowed to do means reproducing the kernel's
// own evaluation, which is the thing INV-2 forbids.
func (c *copier) othersCanWrite(parent *dirRef, facts aclFacts) bool {
	fi, err := parent.stat()
	if err != nil {
		return true
	}
	if fi.Mode()&fs.ModeSticky != 0 {
		// A sticky directory: others may add names of their own, but only the
		// owner of an entry may remove or rename it. The substitution this is
		// about — taking the name of something this job just created — is one
		// the kernel refuses there, which is exactly what /tmp's bit is for.
		return false
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return true
	}
	return facts.otherWriter
}

// dropStage removes the staging directory of one destination directory, if it
// has one. It runs BEFORE that directory's modification time is reproduced
// (unwind), because removing an entry from a directory is a change to it.
func (c *copier) dropStage(parent *dirRef) {
	s, ok := c.stages[parent]
	if !ok {
		return
	}
	delete(c.stages, parent)
	if s.dir == nil {
		return
	}
	c.rmdirIfOurs(parent, s.dir, s.name)
	s.dir.close()
}

// dropStages removes every staging directory this job still holds — the
// container's, and any a frame did not get to (a cancelled walk). A staging
// directory left behind by a crash is an empty dot-named directory this job's
// successor will not touch; it is not in the way of anything.
func (c *copier) dropStages() {
	for parent := range c.stages {
		c.dropStage(parent)
	}
}

// stageTmpName is a hidden, unguessable name for a staging directory.
func stageTmpName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return copyTmpPrefix + hex.EncodeToString(b[:]) + stageSuffix, nil
}

// stageSuffix ends the name of a staging directory, so that what is left behind
// by a crash says what it was.
const stageSuffix = ".stage"

// errNoStaging says a destination directory can be written by somebody else and
// could not give this job a private place to build in, so nothing was built
// there. It never leaves this file.
var errNoStaging = errors.New("fsops: the destination could not provide a private staging directory")

// unnamedState is the once-per-job answer to "can this destination make files
// with no name", asked by unnamedOK.
type unnamedState int

const (
	unnamedUnknown unnamedState = iota
	unnamedYes
	unnamedNo
)

// errNotPublished says the caller has already reported why. It never leaves
// this file.
var errNotPublished = errors.New("fsops: the entry was not published")

// sameNamedObject reports whether name, looked up through a held directory,
// still refers to the object want describes.
func sameNamedObject(dir *dirRef, name string, want os.FileInfo) (same, known bool) {
	fi, err := dir.lstat(name)
	if err != nil {
		return false, true
	}
	a, aok := inodeOf(fi)
	b, bok := inodeOf(want)
	if aok && bok {
		return a == b, true
	}
	// Off Linux there is no identity to compare; the check is not made there
	// and the CI Linux jobs are where it is (INV-2).
	return true, inodeIdentity
}

// createName is the name an entry is CREATED under. For an overwrite that is
// an unguessable temporary, which publish then renames over the target; for
// everything else it is the entry's own final name, and publish makes no rename
// at all — but still proves the name refers to what was written.
func (c *copier) createName(p placed) (string, error) {
	if p.act != actOverwrite {
		return p.name, nil
	}
	return copyTmpName()
}

// buildIn decides WHERE an entry is built and under what name: inside the
// private staging directory under an unguessable one, or — where nobody else
// could interfere with the destination anyway — in the destination itself under
// the name the placement chose.
//
// It is the shape of round 15's first finding for the things that have no
// unnamed form: a symlink, and a regular file on a filesystem with no
// O_TMPFILE. A directory goes through the same decision inside makeDir, which
// has more to do with the answer.
func (c *copier) buildIn(dstDir *dirRef, dstDirAPI string, p placed) (*dirRef, string, error) {
	st := c.stagingIn(dstDir, dstDirAPI)
	if st.dir != nil {
		name, err := copyTmpName()
		if err != nil {
			return nil, "", err
		}
		return st.dir, name, nil
	}
	if st.state == stageRefused {
		return nil, "", errNoStaging
	}
	name, err := c.createName(p)
	if err != nil {
		return nil, "", err
	}
	return dstDir, name, nil
}

// buildFailed reports an entry that was never built, with the reason belonging
// to whichever half of buildIn refused.
func (c *copier) buildFailed(dstPath string, err error) {
	if errors.Is(err, errNoStaging) {
		c.noStaging(dstPath)
		return
	}
	c.skip(dstPath, err)
}

// copyTmpName is a hidden, unguessable name inside the destination directory.
// It is created with O_EXCL, so two jobs writing into one directory cannot
// collide even if the eight random digits somehow did.
func copyTmpName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return copyTmpPrefix + hex.EncodeToString(b[:]) + copyTmpSuffix, nil
}

// copyFailed reports a transfer that did not complete, naming the quota when
// that is what stopped it. EDQUOT and ENOSPC both classify as no_space, and the
// advice they need is not the same one: "delete something" against "ask for
// more quota" (§1.9).
func (c *copier) copyFailed(dstPath string, err error) {
	if isQuota(err) {
		c.warn(dstPath, warnNoSpace,
			fmt.Sprintf("copying %q stopped because this user's quota is full, not the disk: %v", dstPath, err),
			fsx.Errno(err))
		c.res.Skipped++
		return
	}
	c.skip(dstPath, err)
}

// setTimes reproduces an entry's modification and access times (§1.5).
//
// CopyOptions.PreserveTimes is accepted and currently always honoured: the wire
// field is a bool with omitempty, so "false" and "absent" are the same bytes,
// and the contract says an omitted value means true. Preserving unconditionally
// is the only reading of that which does not depend on the sender; if a
// "reset the times" mode is ever wanted it needs its own wire field rather than
// an ambiguous one.
func (c *copier) setTimes(dstDir *dirRef, name string, f *os.File, link bool, srcInfo os.FileInfo, dstPath string) {
	mtime := srcInfo.ModTime()
	atime := mtime
	if at, ok := accessTimeOf(srcInfo); ok {
		atime = at
	}
	if err := setEntryTimes(dstDir, name, f, link, atime, mtime); err != nil {
		c.warn(dstPath, warnTimesUnset,
			fmt.Sprintf("%q was copied but its modification time could not be reproduced: %v", dstPath, err),
			fsx.Errno(err))
	}
}

// ownerFor answers who a freshly created entry should belong to (§1.4).
func (c *copier) ownerFor(srcInfo os.FileInfo) (uid, gid int, want bool) {
	if c.as != nil {
		return c.as.UID, c.as.GID, true
	}
	if !c.keepOwner {
		return 0, 0, false
	}
	u, g, _, ok := statDetail(srcInfo)
	if !ok {
		return 0, 0, false
	}
	return u, g, true
}

// ownerUnset reports a chown that failed on an entry that WAS created. The
// entry stays — removing somebody's freshly copied data because its owner could
// not be set would be the worse answer — and the root stops counting as clean,
// so a move keeps its source.
func (c *copier) ownerUnset(dstPath string, err error) {
	c.warn(dstPath, warnOwnerUnset,
		fmt.Sprintf("%q was created but its owner could not be set: %v", dstPath, err), fsx.Errno(err))
}

// noStaging reports an entry this job would not build because the private place
// it tried to build in was not the one it had just created (stagingIn).
//
// It is `unverified` rather than a kernel error, and it says what it means:
// something took the directory this job made, so the engine could not put
// itself in a position to prove what it was making and made nothing. It is NOT
// the answer for an ordinary shared destination — see sharedDestination.
func (c *copier) noStaging(dstPath string) {
	c.skipCode(dstPath, warnUnverified, fmt.Sprintf(
		"%q could not be created where nobody else can interfere with it while it is being made, so it was not created",
		dstPath), 0)
}

// sharedDestination says, once per job, that the destination is one other users
// can write, so the job built at final names instead of inside a private
// directory of its own.
//
// It is a remark and not a failure: every object is still created, pinned and
// proved exactly as it was before staging existed — kind, creator, emptiness,
// mode subset, group, setgid, identity, ownership installed while it is still
// empty, and files still unnamed where the kernel allows it. What is reduced is
// the guarantee that a directory cannot be SWAPPED for another between being
// created and being opened, which needs a local user with write access to the
// destination actively racing the job.
//
// Refusing instead would have refused the normal case: a NAS share is
// group-writable, which is the whole point of a share. File Station offers no
// protection here at all.
func (c *copier) sharedDestination() {
	if c.sharedWarned {
		return
	}
	c.sharedWarned = true
	c.warn("", warnSharedDest,
		"The destination can be written by other users, so protection against a folder being swapped in during the copy is reduced.", 0)
}

// ownerRefused reports a destination DIRECTORY whose chown failed. Unlike
// ownerUnset this is a skip and not a remark: nothing was copied into it, so
// the subtree is counted as not copied and a move keeps its source (makeDir).
func (c *copier) ownerRefused(dstPath string, err error) {
	c.skipCode(dstPath, warnOwnerUnset, fmt.Sprintf(
		"%q could not be given its owner, so nothing was copied into it: %v", dstPath, err), fsx.Errno(err))
}

// ---- the destination stack --------------------------------------------------

// unwind finalises and closes every held destination directory at or below the
// given depth, deepest first. It is what applies a directory's modification
// time, which can only be right once its children have stopped changing it.
func (c *copier) unwind(depth int) {
	for len(c.frames) > depth {
		f := c.frames[len(c.frames)-1]
		c.frames = c.frames[:len(c.frames)-1]
		if f.dir == nil {
			continue
		}
		// The staging directory goes FIRST, before the timestamps: removing an
		// entry from a directory changes that directory, and stampDir is about
		// to reproduce the source's modification time on it.
		c.dropStage(f.dir)
		if f.created && f.srcInfo != nil {
			c.stampDir(f)
		}
		c.persist(f)
		f.dir.close()
	}
}

// persist flushes one destination directory's ENTRIES to stable storage, as a
// frame is finished with and while its descriptor is still open — which is
// post-order, deepest first, because that is the order unwind pops them in.
//
// It is for a MOVE, and only for a move. A copy that is not durable yet loses
// nothing a power cut has not already taken from the page cache; a move goes on
// to unlink the originals, and an unlink is a metadata operation the filesystem
// journals. Cross-filesystem, the destination names — the files, the symlinks,
// the directories this job created — were never fsync'd at all, so a crash
// between the copy and the next journal commit could land with the source
// entries gone and the destination entries never written. The file CONTENTS are
// already safe (copyFile fsyncs each one before publishing it); what this adds
// is the namespace that points at them.
//
// The cost is one fsync per destination directory per moved root, plus one for
// the destination container (finishMove). A renaming move — the same-filesystem
// case, which is most of them — never gets here at all: a rename is one
// journaled operation and there is no window between a copy and a delete to
// lose anything in.
//
// A failure is a warning, which makes the root unclean, which keeps the source:
// the copy may well be fine, and it is not this job's place to decide that the
// user's only other copy should go on the strength of an fsync the filesystem
// would not make.
func (c *copier) persist(f destFrame) {
	if !c.move || f.dir == nil {
		return
	}
	if err := persistDir(f.dir); err != nil {
		c.warn(f.api, warnKept, fmt.Sprintf(
			"%q could not be flushed to disk, so the original was kept: %v", f.api, err), fsx.Errno(err))
	}
}

// stampDir reproduces a created destination directory's modification time —
// through its own DESCRIPTOR, not through its name.
//
// A directory's times can only be set once its children have stopped changing
// them, so this happens at the end of a subtree that may have taken minutes;
// naming it again there was the one metadata step still trusting a lookup. A
// destination directory renamed aside and replaced under its name while its
// children were being copied had the REPLACEMENT stamped and the copy left with
// the wrong time.
//
// The held handle is an O_PATH one (openPathRef), so a readable descriptor for
// the same inode is opened from it — openat(fd, ".") — and futimens'd. Where
// that cannot be had, the name is proved to still be this directory immediately
// before the by-name form, which is the best a platform with no fd-based
// utimensat can do.
//
// Off Linux the descriptor is opened and then ignored: os.Root has no
// Chtimes-by-descriptor, so the stamp is by name there whatever this does, and
// there is no identity to prove the name with either. That is the dev box's
// documented degradation (INV-2); the CI Linux jobs and the NAS take the
// descriptor path.
func (c *copier) stampDir(f destFrame) {
	if rd, err := enumerable(f.dir); err == nil {
		defer rd.Close()
		c.setTimes(f.parent, f.name, rd, false, f.srcInfo, f.api)
		return
	}
	if want, ok := heldIdentity(f.dir); ok {
		fi, err := f.parent.lstat(f.name)
		if err != nil {
			c.warn(f.api, warnTimesUnset, fmt.Sprintf(
				"%q could not be found again to reproduce its modification time", f.api), 0)
			return
		}
		if k, kok := inodeOf(fi); !kok || k != want {
			c.warn(f.api, warnTimesUnset, fmt.Sprintf(
				"%q was replaced while its contents were being copied, so nothing of it was stamped", f.api), 0)
			return
		}
	}
	c.setTimes(f.parent, f.name, nil, false, f.srcInfo, f.api)
}

// ---- conflict policy --------------------------------------------------------

// kind is the coarse type a conflict is decided on. It is four values rather
// than fs.FileMode because the rule is about what may stand in for what: a
// directory merges with a directory, a symlink replaces a symlink, and every
// other pairing is a mismatch that is refused under every policy (§1.3).
type kind int

const (
	kindDir kind = iota
	kindLink
	kindRegular
	kindSpecial
)

func kindOf(fi os.FileInfo) kind {
	if fi == nil {
		return kindSpecial
	}
	m := fi.Mode()
	switch {
	case m.IsDir():
		return kindDir
	case m&fs.ModeSymlink != 0:
		return kindLink
	case m.IsRegular():
		return kindRegular
	}
	return kindSpecial
}

// action is what to do about a name at the destination.
type action int

const (
	actCreate    action = iota // nothing is there (or a free "(2)" name was found)
	actMerge                   // a directory of the same name: descend into it
	actOverwrite               // write a temporary and rename it over what is there
	actSkip                    // leave both ends alone and say why
)

// placed is one decided name.
type placed struct {
	name string
	act  action
	// code and msg describe an actSkip this engine decided.
	code string
	msg  string
	// err is a lookup that failed, reported with the kernel's own
	// classification rather than one of this file's codes.
	err error
}

// place decides what the entry called name, of kind k, becomes inside dstDir
// (§1.3).
//
// Directories always merge, whatever the policy: "copy A into B" where B
// already has an A means putting A's contents alongside what is there, and no
// file manager has ever meant "delete B/A first". Everything else is the
// policy's to decide, and only between two entries of the SAME kind — a file
// over a folder, a folder over a file and a symlink over anything else are all
// refused, because none of them is a replacement, they are a destruction.
func (c *copier) place(dstDir *dirRef, name string, k kind) placed {
	fi, err := dstDir.lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return placed{name: name, act: actCreate}
		}
		return placed{name: name, err: err, act: actSkip}
	}
	dk := kindOf(fi)
	if k == kindDir && dk == kindDir {
		return placed{name: name, act: actMerge}
	}
	if k != dk {
		return placed{name: name, act: actSkip, code: warnConflict, msg: fmt.Sprintf(
			"%q is already a %s at the destination and this is a %s, so nothing was changed",
			name, kindName(dk), kindName(k))}
	}
	switch c.conflict {
	case wproto.ConflictOverwrite:
		return placed{name: name, act: actOverwrite}
	case wproto.ConflictRename:
		return c.freeName(dstDir, name, k)
	}
	return placed{name: name, act: actSkip, code: warnExists,
		msg: fmt.Sprintf("%q already exists at the destination and was skipped", name)}
}

// freeName is "keep both": the first of name (2), name (3) … that nothing
// answers to, bounded at maxKeepBothTries.
func (c *copier) freeName(dstDir *dirRef, name string, k kind) placed {
	for n := 2; n < 2+maxKeepBothTries; n++ {
		// Bounded by NAME_MAX, like every other generated component (round 7
		// adversarial). Without it the candidate was simply 259 bytes long and
		// the create failed with ENAMETOOLONG — reported, but as the kernel's
		// complaint about a name this engine had built rather than as the
		// refusal it is.
		cand, ok := keepBothWithin(name, k == kindDir, n)
		if !ok {
			return placed{name: name, act: actSkip, code: warnConflict, msg: fmt.Sprintf(
				"%q is too long for a \"keep both\" name to be made from it", name)}
		}
		_, err := dstDir.lstat(cand)
		if errors.Is(err, fs.ErrNotExist) {
			return placed{name: cand, act: actCreate}
		}
		if err != nil {
			return placed{name: name, err: err, act: actSkip}
		}
	}
	return placed{name: name, act: actSkip, code: warnConflict, msg: fmt.Sprintf(
		"%q and the next %d names after it are all taken at the destination", name, maxKeepBothTries)}
}

// keepBothName builds the nth "keep both" candidate: "report (2).pdf".
//
// The extension is whatever follows the LAST dot of the basename, and there is
// none for a directory (a folder called "backup.2024" is not a file with a
// ".2024" extension) nor for a dotfile whose only dot is the leading one
// (".bashrc (2)", never ". (2)bashrc"). A name with an interior dot is treated
// as having an extension however it starts, so ".tar.gz" becomes ".tar (2).gz".
func keepBothName(name string, isDir bool, n int) string {
	stem, ext := splitKeepBoth(name, isDir)
	return stem + " (" + strconv.Itoa(n) + ")" + ext
}

// splitKeepBoth is keepBothName's stem/extension split, on its own so that the
// bounded form below can rebuild the name at a different length.
func splitKeepBoth(name string, isDir bool) (stem, ext string) {
	if !isDir {
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			return name[:i], name[i:]
		}
	}
	return name, ""
}

// maxNameBytes is NAME_MAX: the kernel's own limit on ONE path component, in
// BYTES rather than characters. Every Linux filesystem this app runs on
// enforces it, and a name that exceeds it is not a long name — it is ENAMETOOLONG.
const maxNameBytes = 255

// keepBothWithin is keepBothName bounded by what the kernel will accept (M2-C
// review round 7 adversarial).
//
// " (2)" is four bytes, and a name may already be all 255 of them. Appending
// regardless produced a 259-byte component, and what happened next depended on
// who was creating it: the upload's linkat failed with ENAMETOOLONG after the
// whole body had been transferred, and an ARCHIVE — which creates nothing and
// so is told nothing — wrote the member happily and left the failure for the
// user's unzip, on a file they had already waited for. Neither is a thing to
// discover at the end.
//
// So the stem is shortened to make room, on a rune boundary, and the EXTENSION
// is never touched: it is what tells the user (and their desktop) what the file
// is, and four bytes of stem are worth less than that. The suffix carries n, so
// two different attempts can never shorten to the same string — and every
// caller re-checks the candidate against what is already taken in any case.
//
// false means there is no room at all: an extension so long that the suffix
// alone does not fit beside it. The caller reports that rather than inventing a
// name, because a name it invented would be one the user did not ask for.
func keepBothWithin(name string, isDir bool, n int) (string, bool) {
	if cand := keepBothName(name, isDir, n); len(cand) <= maxNameBytes {
		return cand, true
	}
	stem, ext := splitKeepBoth(name, isDir)
	suffix := " (" + strconv.Itoa(n) + ")"
	room := maxNameBytes - len(suffix) - len(ext)
	if room < 1 {
		return "", false
	}
	if stem = truncateAtRune(stem, room); stem == "" {
		return "", false
	}
	return stem + suffix + ext, true
}

// truncateAtRune cuts a string to at most max BYTES without splitting a rune.
//
// A Linux filename is an arbitrary byte string, so this cannot assume valid
// UTF-8: what it guarantees is that a multi-byte sequence which IS there is not
// cut in half — a half rune renders as U+FFFD and turns a shortened name into
// an unreadable one. Bytes that are not part of any sequence are cut wherever
// the limit falls, which is the only thing that can be done with them.
func truncateAtRune(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// kindName is the word a warning uses for a kind.
func kindName(k kind) string {
	switch k {
	case kindDir:
		return "folder"
	case kindLink:
		return "symlink"
	case kindRegular:
		return "file"
	}
	return "special file"
}

// ---- the move's second half -------------------------------------------------

// finishMove decides whether a copied root's source may be removed (§1.1).
//
// Three things have to hold before anything is unlinked. The copy has to have
// been CLEAN — zero CONTENT warnings and zero skips for this root, so there is
// nothing at the destination that is missing, truncated or unowned. The record
// of what was copied has to be complete. And the source root has to still be
// the object the copy started from, which is what the held O_PATH reference is
// for.
//
// "Content" is the word doing the work, and contentWarning is where it is
// defined: a warning that says something of the source is not at the
// destination vetoes this, and the one warning that says only "a timestamp
// could not be reproduced" does not.
//
// When any of them fails both copies stay and the job says so. That is the
// whole design rule of a move here: never delete before the copy is verified.
//
// The root-level identity check is a fast fail and NOT the proof. The proof is
// per entry, in deleteRecorded: a tree can take twenty minutes to copy, and
// "the root is still the same directory" says nothing at all about the file
// somebody added to it two levels down while that was happening.
func (c *copier) finishMove(ctx context.Context, srcParent *dirRef, srcAPI, name string,
	ref *itemRef, k kind, warns, skips int64) error {

	switch {
	case warns > 0 || skips > 0:
		c.keep(srcAPI, warns+skips)
		return nil
	case c.ledgerFull:
		c.keepBecause(srcAPI, fmt.Sprintf(
			"%q holds more than %d items, which is more than this worker can record and verify, so the original was kept",
			srcAPI, ledgerBound))
		return nil
	}
	now, err := itemRefIn(srcParent, name)
	if err != nil {
		c.keep(srcAPI, 0)
		return nil
	}
	defer now.close()
	if same, known := sameObject(ref.fi, now.fi); known && !same {
		c.keep(srcAPI, 0)
		return nil
	}

	// The destination CONTAINER, last of the namespace: it holds the name of
	// this root's copy, and every directory below it was flushed as the walk
	// left it (persist). Nothing of the source is removed until all of it is on
	// stable storage.
	if serr := persistDir(c.dst); serr != nil {
		c.keepBecause(srcAPI, fmt.Sprintf(
			"%q was copied but %q could not be flushed to disk, so the original was kept: %v",
			srcAPI, c.dstAPI, serr))
		return nil
	}
	traceVerify("persisted")

	// Announced before a single entry is judged, so a test can stage its
	// condition at a point the engine defines rather than at whichever entry
	// enumeration happened to hand over first (verifyTrace).
	traceVerify("delete")
	kept, err := c.deleteRecorded(ctx, srcParent, c.dst, srcAPI, name, k, c.ledger, nil)
	if err != nil {
		return err
	}
	if kept {
		c.kept++
	}
	return nil
}

// keep records a move source that was left in place, with the count of what
// could not be copied.
func (c *copier) keep(srcAPI string, failures int64) {
	c.kept++
	if failures > 0 {
		c.warn(srcAPI, warnKept, fmt.Sprintf(
			"%q was copied but %d items could not be, so the original was kept", srcAPI, failures), 0)
		return
	}
	c.warn(srcAPI, warnKept, fmt.Sprintf(
		"%q changed while it was being copied, so the original was kept", srcAPI), 0)
}

// keepBecause is keep with the reason spelled out.
func (c *copier) keepBecause(srcAPI, msg string) {
	c.kept++
	c.warn(srcAPI, warnKept, msg, 0)
}

// deleteRecorded removes the source of a move — and only what this job actually
// copied, proved entry by entry, through descriptors this process is holding.
//
// It replaced a recursive delete by pathname, and it is worth being exact about
// what that could do, because both of these were reproduced:
//
//   - a file written into the tree AFTER its directory was copied was deleted
//     without ever having reached the destination, and the job reported no
//     warning at all, because a delete by name removes whatever is there now;
//   - a directory component renamed to a symlink between the copy and the
//     delete sent the removal somewhere else: moving /share/Public/stage/passwd
//     as root, with "stage" swapped for a link to /etc after the root identity
//     check, unlinked /etc/passwd.
//
// So nothing here resolves a pathname. Every level is opened with openat from
// the descriptor above it (O_DIRECTORY|O_NOFOLLOW, so a symlink is refused by
// the kernel rather than followed), its identity is checked against the record
// before the walk descends, and an entry is unlinked only when its current
// lstat still matches what was written down when it was copied: the same
// (dev, ino), the same kind, the same size, the same modification time, and for
// a symlink the same target text. Anything that does not match, and anything
// that was not recorded at all, is left where it is and said out loud.
//
// Directories are removed post-order and only when they are empty by then, so a
// subtree that kept anything keeps its parents too, up to the root — which is
// the honest outcome: the move did not finish, and both copies stay.
//
// The progress is this job's, in phase "finishing" (§1.10).
//
// The residual: between the lstat that matches an entry and the unlinkat that
// removes it, the name could be re-pointed once more. Linux has no
// unlink-by-descriptor to close that; it is the same accepted residual every
// two-syscall sequence in this package has (PLAN.md §2.4), and it is now the
// only one left here — the directory chain above it is held, not re-resolved.
func (c *copier) deleteRecorded(ctx context.Context, parent, dstParent *dirRef, apiPath, name string,
	k kind, rec *copiedDir, chain []srcLevel) (kept bool, err error) {

	if cerr := ctx.Err(); cerr != nil {
		return true, cerr
	}
	if k != kindDir {
		return c.deleteRecordedEntry(ctx, parent, dstParent, apiPath, rootEntryRecord(name, k, rec))
	}

	dir, derr := parent.childPath(name)
	if derr != nil {
		c.keepEntry(apiPath, derr.Error())
		return true, nil
	}
	defer dir.close()
	if !stillTheRecorded(dir, rec) {
		c.keepEntry(apiPath, fmt.Sprintf("%q is not the folder that was copied any more, so it was kept", apiPath))
		return true, nil
	}
	held, heldKnown := heldIdentity(dir)

	// The matching destination directory, always. Nothing is removed from the
	// source until its copy has been found at the destination and proved to be
	// the one this job published — for a directory that is this openat, for
	// everything inside it one lstat each (copyStillThere). Without it an
	// ordinary file's source was unlinked on its own state alone, so deleting a
	// published copy while later siblings were still being written took its
	// source with it and the job reported success.
	if dstParent == nil {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q has no reachable copy at the destination to check against, so it was kept", apiPath))
		return true, nil
	}
	dstDir, oerr := openRecordedDest(dstParent, rec)
	if oerr != nil {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: its copy is no longer at the destination, so it was kept (%v)", apiPath, oerr))
		return true, nil
	}
	defer dstDir.close()

	// This directory, added to the chain of ancestors every removal below it is
	// judged against. A fresh slice per level: depth-sized, once per directory.
	levels := make([]srcLevel, len(chain)+1)
	copy(levels, chain)
	levels[len(chain)] = srcLevel{dir: dir, rec: rec, api: apiPath}

	keptBelow, abandoned := false, false
	for _, e := range rec.entries {
		if cerr := ctx.Err(); cerr != nil {
			return true, cerr
		}
		// Before EVERY removal, not once before the loop. Emptying a directory
		// takes as long as its contents take — a single byte comparison of a
		// large file can run for minutes — and the reading that approved the
		// delete was taken before all of it. A directory tightened 0755 -> 0700
		// or chowned during that window had every remaining child removed and
		// then itself, on a judgement its owner had already withdrawn. It costs
		// one fstat of a descriptor this process is holding per entry.
		//
		// And the whole ANCESTOR CHAIN with it, not only this directory, which
		// is round 15's second finding: tightening /src/a while the comparison
		// of a file inside /src/a/sub was running stopped nothing, because the
		// recursion carried no record of anything above itself. Restricting a
		// directory restricts everything under it, so proving the innermost one
		// proves nothing. The copy side answers the same question the same way
		// (ancestorUnchanged).
		//
		// What was already removed was removed on a state proved at the time;
		// the REST is kept, the directory is not rmdir'd, and the parents keep
		// with it.
		if !c.levelsUnchanged(levels) {
			keptBelow, abandoned = true, true
			break
		}
		childAPI := fsx.Join(apiPath, e.name)
		if e.kind == kindDir {
			below, err := c.deleteRecorded(ctx, dir, dstDir, childAPI, e.name, kindDir, e.dir, levels)
			if err != nil {
				return true, err
			}
			keptBelow = keptBelow || below
			continue
		}
		below, eerr := c.deleteRecordedEntry(ctx, dir, dstDir, childAPI, e)
		if eerr != nil {
			return true, eerr
		}
		if below {
			keptBelow = true
		}
	}

	if abandoned {
		// The directory stopped being the one that was recorded. It is not
		// removed, whatever is or is not left in it by now.
		return true, nil
	}

	// This directory and every ancestor once more, immediately before the
	// rmdir. The per-entry check above runs before each REMOVAL, so the last
	// child's comparison — which can run for as long as that file is big — has
	// no iteration after it to notice anything: a one-file directory chowned or
	// tightened during it was removed on a reading taken before the change,
	// with the destination left under the old mode and owner. The check below
	// asks about the NAME; this one asks about the objects.
	if !c.levelsUnchanged(levels) {
		return true, nil
	}

	// The name is proved once more, immediately before the rmdir. The identity
	// check above was made before the children were removed, and emptying a
	// directory takes as long as it takes: a process that renames it aside and
	// creates an empty replacement under the old name in that window had the
	// REPLACEMENT removed, silently. rmdir takes a name and there is no
	// rmdir-by-descriptor, so the name is looked up once more and has to still
	// be this directory.
	if !c.nameStillIs(parent, name, held, heldKnown, apiPath) {
		return true, nil
	}

	// The directory itself, last, and only if it is empty by now. ENOTEMPTY
	// with nothing kept below means entries appeared after the copy — they were
	// never at the destination, and they are not this job's to remove.
	if uerr := parent.unlink(name, true); uerr != nil {
		switch {
		case errors.Is(uerr, fs.ErrNotExist):
			return keptBelow, nil
		case isNotEmpty(uerr) && !keptBelow:
			c.keepEntry(apiPath, fmt.Sprintf(
				"%q has entries in it that were added after it was copied, so it was kept", apiPath))
		case !isNotEmpty(uerr):
			c.keepEntry(apiPath, uerr.Error())
		}
		return true, nil
	}
	c.progress(apiPath, wproto.PhaseFinishing)
	return keptBelow, nil
}

// srcLevel is one source directory of the delete's chain: the descriptor this
// process holds for it and the record the copy made of it.
type srcLevel struct {
	dir *dirRef
	rec *copiedDir
	api string
}

// levelsUnchanged re-proves every source directory a removal is about to happen
// inside — the whole chain from the root down, shallowest first — and reports
// whether it may go ahead.
//
// One fstat of a held descriptor per level per removal. The shallowest change
// is the one reported, because it is the one that explains everything below it.
func (c *copier) levelsUnchanged(levels []srcLevel) bool {
	for _, l := range levels {
		if stillTheRecorded(l.dir, l.rec) {
			continue
		}
		c.keepEntry(l.api, fmt.Sprintf(
			"%q changed while its contents were being removed, so the rest of it was kept", l.api))
		return false
	}
	return true
}

// rootEntryRecord describes a selected root that is not a directory, from the
// record the copy made for it. With no record there is no proof, and an entry
// with no identity never matches.
func rootEntryRecord(name string, k kind, rec *copiedDir) copiedEntry {
	if rec != nil && len(rec.entries) == 1 {
		return rec.entries[0]
	}
	return copiedEntry{name: name, kind: k}
}

// deleteRecordedEntry removes one non-directory, and reports whether it was
// KEPT instead.
func (c *copier) deleteRecordedEntry(ctx context.Context, parent, dstDir *dirRef, apiPath string, e copiedEntry) (kept bool, err error) {
	if !e.recorded {
		// Nothing was written down for this entry, so it was never copied and
		// there is no proof to act on. An unverified delete is not one this
		// makes.
		c.keepEntry(apiPath, fmt.Sprintf("%q was not recorded as copied, so it was kept", apiPath))
		return true, nil
	}
	// The clock proof comes FIRST, before anything is stat'ed. It reads the
	// filesystem's clock and may wait for a tick to end, and a stat taken
	// before that wait describes a moment that has already passed: a copy
	// truncated or unlinked, or a source rewritten, while the wait was running
	// was then judged on figures from before it. Everything below is read
	// after. It costs nothing repeated — the reading is cached per filesystem,
	// so a root pays it once or not at all.
	if !c.destClockSettled(dstDir, e, apiPath) {
		return true, nil
	}
	fi, err := parent.lstat(e.name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Somebody else removed it. A move whose source is already gone got
			// what it asked for.
			return false, nil
		}
		c.keepEntry(apiPath, err.Error())
		return true, nil
	}
	if !c.matchesRecord(fi, e) {
		c.keepEntry(apiPath, fmt.Sprintf("%q changed since it was copied, so it was kept", apiPath))
		return true, nil
	}
	if e.kind == kindLink {
		// A symlink's content is its target text, and it costs one readlink to
		// prove it is still the one that was reproduced.
		if target, rerr := readlinkIn(parent, e.name); rerr != nil || target != e.link {
			c.keepEntry(apiPath, fmt.Sprintf("%q changed since it was copied, so it was kept", apiPath))
			return true, nil
		}
	}
	// The copy has to still be there, and be the one this job published. This
	// is the cheap half of what a hard link pays in full: one lstat against the
	// identity taken at publication, and the length for a file.
	if !c.copyStillThere(dstDir, e, apiPath) {
		return true, nil
	}
	if e.kind == kindRegular {
		// EVERY regular file is proved by its CONTENT before its source is
		// removed. See contentMatches.
		stable, cerr := c.contentMatches(ctx, parent, dstDir, e)
		if cerr != nil {
			if ctx.Err() != nil {
				// A cancelled comparison is the JOB stopping, not this entry
				// failing. Propagated so the worker reports a cancelled job
				// with its partial counts rather than a tree of warnings.
				return true, cerr
			}
			c.keepEntry(apiPath, fmt.Sprintf("%q was not compared with its copy, so it was kept: %v", apiPath, cerr))
			return true, nil
		}
		if stable == nil {
			c.keepEntry(apiPath, fmt.Sprintf(
				"%q is not byte for byte what was copied to the destination, so it was kept", apiPath))
			return true, nil
		}
		// The comparison took as long as the file is big, so the name is proved
		// once more against the state the comparison ended on — which the
		// settle inside contentMatches made distinguishable from anything
		// written since.
		if !c.stillTheComparedFile(parent, e.name, stable, apiPath) {
			return true, nil
		}
	}
	if err := parent.unlink(e.name, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
		c.keepEntry(apiPath, err.Error())
		return true, nil
	}
	c.progress(apiPath, wproto.PhaseFinishing)
	return false, nil
}

// copyStillThere proves that the copy this job published is still at the
// destination and is still the object that was published.
//
// It is asked of EVERY recorded entry before its source is removed — files,
// symlinks and, through openRecordedDest, directories. Checking only the source
// side was the round-8 finding: deleting a published file while the job was
// still copying its siblings left the record describing a source that was
// perfectly intact, so the source was removed and the job reported a clean move
// with the data gone from both ends.
//
// A file's length is compared as well as its identity, because a truncation
// leaves the inode alone. The bytes are not, except for the hard-linked case
// that has to read them anyway (contentMatches) — reading every file back would
// double the cost of every move to catch a destination somebody is actively
// sabotaging, which is not the trade this makes.
func (c *copier) copyStillThere(dstDir *dirRef, e copiedEntry, apiPath string) bool {
	if dstDir == nil {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q has no reachable copy at the destination to check against, so it was kept", apiPath))
		return false
	}
	fi, err := dstDir.lstat(e.dstName)
	if err != nil {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: its copy is no longer at the destination, so it was kept", apiPath))
		return false
	}
	if kindOf(fi) != e.kind || !sameRecordedInode(fi, e.dstID, e.haveDstID) {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: what is at the destination is no longer the copy this job made, so it was kept", apiPath))
		return false
	}
	if e.kind != kindRegular {
		if e.kind == kindLink {
			// A symlink's content is its target, and the COPY's target is
			// compared here as well as the source's (which the caller does).
			// Identity alone was not enough: a link replaced at the destination
			// between its creation and its publication would have had the
			// replacement's inode recorded, and identity would then agree with
			// itself for ever. Read from a pinned descriptor, never by name.
			pin, perr := itemRefIn(dstDir, e.dstName)
			if perr != nil {
				c.keepEntry(apiPath, fmt.Sprintf(
					"%q: its copy at the destination could not be read, so it was kept", apiPath))
				return false
			}
			defer pin.close()
			// The pin is a fresh lookup of the name, so it is put through the
			// record before its target is believed — the same rule every other
			// baseline in the delete path follows.
			if !publishedMatches(pin.fi, e) {
				c.keepEntry(apiPath, fmt.Sprintf(
					"%q: what is at the destination is no longer the copy this job made, so it was kept", apiPath))
				return false
			}
			made, rerr := readlinkRef(pin, dstDir, e.dstName)
			if rerr != nil || made != e.link {
				c.keepEntry(apiPath, fmt.Sprintf(
					"%q: its copy at the destination no longer points where it did, so it was kept", apiPath))
				return false
			}
			return true
		}
		// A directory is proved by identity alone (openRecordedDest); what is
		// IN it is proved entry by entry.
		return true
	}
	if fi.Size() != e.dstSize {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: its copy at the destination is %d bytes and not %d, so it was kept", apiPath, fi.Size(), e.dstSize))
		return false
	}
	if !fi.ModTime().Equal(e.dstMtime) {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: its copy was changed at the destination, so it was kept", apiPath))
		return false
	}
	return c.copyUnchanged(fi, e, apiPath)
}

// destClockSettled proves that the filesystem's clock has passed the change
// time recorded for a published copy, BEFORE anything is stat'ed for the
// decision that rests on it.
//
// The settle is made here, at the delete, and not at publication — a deliberate
// departure from the round-9 finding's wording, for cost, and with the same
// guarantee. The record's change time C is fixed at publication either way, and
// a rewrite is detected exactly when its own change time differs from C, which
// is to say whenever it falls outside C's tick. What the proof has to establish
// is that C's tick has ENDED BEFORE THE COMPARISON IS TRUSTED — otherwise a
// rewrite happening right now would still read C — and that is precisely what
// asking here establishes. Asking at publication instead would have settled per
// FILE: every published copy has a change time newer than the last reading, so
// the per-filesystem cache never hits, and on a coarse-timestamp kernel — the
// whole reason any of this exists — each file would additionally SLEEP until
// its tick ended. Here, one reading settles every copy published before it, so
// a move pays at most one scratch per root, and none at all for a root that
// took longer than ctimeRecent.
//
// The residual either way: a rewrite of the published copy inside its own
// publication tick is indistinguishable by timestamps; the writer needs write
// access to the copy, which is the access they had to the source.
func (c *copier) destClockSettled(dstDir *dirRef, e copiedEntry, apiPath string) bool {
	if e.kind != kindRegular || !e.haveDstCtime {
		// A symlink is proved by its target text and a directory by its
		// identity, neither of which a clock has anything to say about. A
		// record with no change time at all is judged by copyUnchanged.
		return true
	}
	if c.settled(c.dst, e.dstCtime, true) {
		return true
	}
	c.keepEntry(apiPath, fmt.Sprintf(
		"%q: the destination's clock could not be shown to have passed its copy, so it was kept", apiPath))
	return false
}

// copyUnchanged is the half of the destination check that catches a rewrite IN
// PLACE: same inode, same length, modification time restored. Only the change
// time moves under that, and it is only worth anything because destClockSettled
// has already shown — before this stat was taken — that the clock has passed it.
func (c *copier) copyUnchanged(fi os.FileInfo, e copiedEntry, apiPath string) bool {
	if !e.haveDstCtime {
		// No change time was recorded. On a platform that has them that is a
		// measurement that failed; where there are none, size and modification
		// time are all there has ever been (INV-2).
		if inodeIdentity {
			c.keepEntry(apiPath, fmt.Sprintf(
				"%q: its copy at the destination cannot be proved unchanged, so it was kept", apiPath))
			return false
		}
		return true
	}
	now, ok := changeTimeOf(fi)
	if !ok || !now.Equal(e.dstCtime) {
		c.keepEntry(apiPath, fmt.Sprintf(
			"%q: its copy was changed at the destination, so it was kept", apiPath))
		return false
	}
	return true
}

// stillTheComparedFile re-proves a name against the state a byte comparison
// ended on, immediately before the unlink that follows it.
//
// The comparison reads a whole file, which for a large one is a long time to
// hold an opinion about a name. Nothing in it addresses the name — both ends
// are descriptors — so the unlink afterwards was the one step still trusting a
// lookup made before all of it. Re-proving costs one lstat, and it is only
// meaningful because the state it compares against was settled: a write since
// then necessarily moved the change time.
func (c *copier) stillTheComparedFile(parent *dirRef, name string, compared os.FileInfo, apiPath string) bool {
	fi, err := parent.lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Gone already; there is nothing left to remove and nothing to warn
			// about.
			return true
		}
		c.keepEntry(apiPath, err.Error())
		return false
	}
	if sameFileState(fi, compared) {
		return true
	}
	c.keepEntry(apiPath, fmt.Sprintf(
		"%q changed while it was being compared with its copy, so it was kept", apiPath))
	return false
}

// sameFileState reports whether two descriptions are the same object in the
// same state: identity, length, modification time and change time. It is the
// whole of what a stat can say, used where a long operation has just happened
// and the question is whether anything at all moved.
func sameFileState(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	ka, aok := inodeOf(a)
	kb, bok := inodeOf(b)
	switch {
	case aok && bok:
		if ka != kb {
			return false
		}
	case inodeIdentity:
		return false
	}
	if a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	return sameChangeTime(a, b)
}

// contentMatches compares a source file with the copy this job made of it, byte
// for byte, and it is the proof for EVERY regular file whose original a move is
// about to remove.
//
// Timestamps cannot carry that weight, and two rounds of review were the
// demonstration. For a HARD-LINKED file they cannot even try: two names for one
// inode share one change time, so removing the first link moves the value the
// second was recorded with, and every scheme for carrying that value forward
// produces a baseline inside the current tick that a same-length rewrite with
// the modification time restored matches exactly. And for an ORDINARY file the
// record is no better than the moment it was taken: somebody with write access
// to the destination — its owner, or a group member where the source mode was
// group-writable — who replaces already-written bytes BEFORE publication has
// their version recorded as the baseline, and no timestamp scheme can see a
// write that happened before the baseline existed.
//
// Design §2.6 says copy, VERIFY, then delete. Verify means the bytes.
//
// Both ends are addressed through descriptors this job is holding, and both are
// proved to be the objects that were recorded before a byte is compared: the
// source by the identity in the record, the destination by the identity taken
// when it was published. The comparison itself checks the context once per
// megabyte, like the copy.
//
// It replaced the re-baselining entirely rather than standing beside it, and
// then replaced the timestamp proof for ordinary files too: two proofs for one
// question is how they drift.
// The comparison itself is not the proof — a comparison is only ever a
// statement about the instant each block was read. A writer who modifies a
// block AFTER sameBytes has passed it changes neither the inode nor the length,
// and the last link would have been removed with newer bytes than the
// destination ever received.
//
// So the order is exactly the order copyFile uses before it reads anything, and
// through the same function (settleSource): fstat the source, settle — the tick
// containing that baseline must have ENDED — confirm it is unchanged, and only
// then read. Settling AFTERWARDS was not the same thing and was the round-7
// finding: on a coarse-timestamp filesystem this job's own unlink of the first
// link gives the survivor a current-tick change time, a writer modifies already
// compared bytes and restores the modification time inside that same tick, and
// a settle that runs after the fact leaves the change time equal on both sides
// of the comparison. With the settle first, every write after that point lands
// in a later tick and the post-compare fstat sees it.
//
// Both descriptors are then fstat'ed again, and nothing is trusted unless size,
// modification time and change time are unchanged on BOTH ends.
//
// It returns the post-compare description of the source when the file is
// proved, nil when it is not, and an error only for things that stopped the
// comparison — the context being cancelled among them.
func (c *copier) contentMatches(ctx context.Context, parent, dstDir *dirRef, e copiedEntry) (os.FileInfo, error) {
	if dstDir == nil {
		return nil, errors.New("the folder it was copied into could not be reopened")
	}
	// Announced before the baseline is taken, not after it: the step names the
	// window between the caller's own check of the name and the fstat that
	// becomes this comparison's baseline.
	traceVerify("settle")

	src, err := parent.openFile(e.name, copyReadFlags, 0)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	sfi, err := src.Stat()
	if err != nil {
		return nil, err
	}
	// Against the WHOLE record, not just the inode. A baseline accepted on
	// identity alone was the round-13 finding: a chmod or a chown landing after
	// the caller matched the name and before this fstat became the newer state,
	// every later check compared against THAT, and the source was deleted with
	// the destination left under the old mode. Every fstat that becomes a
	// baseline for a delete goes through the same comparison the caller made.
	if !sfi.Mode().IsRegular() || !c.matchesRecord(sfi, e) {
		return nil, nil
	}
	// Settled BEFORE a byte is read, exactly as copyFile settles before it
	// reads, and through the same function.
	settled, res := c.settleSource(c.srcRootParent, src, sfi)
	switch res {
	case settleUnverifiable:
		return nil, errors.New("its change time could not be shown to be in the past of the filesystem's own clock")
	case settleChanged:
		return nil, errors.New("it is being written to")
	}
	// The settled state becomes the baseline everything below compares against,
	// so it is put through the record as well. settleObserved has already
	// required its change time to be unchanged, which a chmod or a chown would
	// have moved — this is the belt to that pair of braces, and costs no
	// syscall.
	if !c.matchesRecord(settled, e) {
		return nil, nil
	}
	sfi = settled

	dst, err := dstDir.openFile(e.dstName, copyReadFlags, 0)
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	dfi, err := dst.Stat()
	if err != nil {
		return nil, err
	}
	// The destination's baseline gets the same treatment against the record
	// taken when it was published — the caller's copyStillThere checked the
	// NAME, and this is the descriptor.
	if !dfi.Mode().IsRegular() || !publishedMatches(dfi, e) {
		return nil, nil
	}
	if dfi.Size() != sfi.Size() {
		return nil, nil
	}
	if err := clearNonblock(src); err != nil {
		return nil, err
	}
	if err := clearNonblock(dst); err != nil {
		return nil, err
	}

	traceVerify("compare")
	same, err := c.sameBytes(ctx, src, dst)
	if err != nil {
		return nil, err
	}
	if !same {
		return nil, nil
	}

	sAfter, err := src.Stat()
	if err != nil {
		return nil, err
	}
	dAfter, err := dst.Stat()
	if err != nil {
		return nil, err
	}
	if !sameFileState(sfi, sAfter) || !sameFileState(dfi, dAfter) {
		return nil, nil
	}
	return sAfter, nil
}

// sameRecordedInode reports whether a description matches a recorded identity.
// Where the platform has no identities at all the answer is yes, which is the
// same degradation every other identity test here accepts — and this path is
// unreachable off Linux in any case, because nothing there reports a link count.
func sameRecordedInode(fi os.FileInfo, want inodeKey, have bool) bool {
	k, ok := inodeOf(fi)
	if ok && have {
		return k == want
	}
	return !inodeIdentity
}

// sameBytes compares two open files a megabyte at a time, checking the context
// between buffers as the copy does.
func (c *copier) sameBytes(ctx context.Context, a, b *os.File) (bool, error) {
	if c.buf == nil {
		c.buf = make([]byte, copyBufSize)
	}
	if c.cmp == nil {
		c.cmp = make([]byte, copyBufSize)
	}
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		na, aerr := io.ReadFull(a, c.buf)
		nb, berr := io.ReadFull(b, c.cmp)
		if na != nb || !bytes.Equal(c.buf[:na], c.cmp[:nb]) {
			return false, nil
		}
		endA := errors.Is(aerr, io.EOF) || errors.Is(aerr, io.ErrUnexpectedEOF)
		endB := errors.Is(berr, io.EOF) || errors.Is(berr, io.ErrUnexpectedEOF)
		switch {
		case aerr == nil && berr == nil:
			continue
		case endA && endB:
			return true, nil
		case aerr != nil && !endA:
			return false, aerr
		case berr != nil && !endB:
			return false, berr
		}
		// One ended and the other did not, which the size check should already
		// have caught; either way they are not the same file.
		return false, nil
	}
}

// openRecordedDest reopens the destination directory a recorded source
// directory was copied into, from the held destination above it, and proves it
// is the one that was created.
func openRecordedDest(dstParent *dirRef, rec *copiedDir) (*dirRef, error) {
	if rec.dstName == "" {
		return nil, errors.New("no destination name was recorded")
	}
	d, err := dstParent.childPath(rec.dstName)
	if err != nil {
		return nil, err
	}
	fi, serr := d.stat()
	if serr != nil {
		d.close()
		return nil, serr
	}
	if !sameRecordedInode(fi, rec.dstID, rec.haveDstID) {
		d.close()
		return nil, errors.New("the folder it was copied into is not the one that was created")
	}
	return d, nil
}

// heldIdentity is the identity of a directory this process is holding.
func heldIdentity(d *dirRef) (inodeKey, bool) {
	fi, err := d.stat()
	if err != nil {
		return inodeKey{}, false
	}
	return inodeOf(fi)
}

// nameStillIs proves that a name in a held directory still refers to a given
// object, immediately before an operation that can only take a name.
func (c *copier) nameStillIs(parent *dirRef, name string, want inodeKey, have bool, apiPath string) bool {
	if !have {
		return !inodeIdentity
	}
	fi, err := parent.lstat(name)
	if err != nil {
		// Gone already, or unreadable: either way there is nothing here this
		// job may remove on the strength of a check it could not make.
		return errors.Is(err, fs.ErrNotExist)
	}
	k, ok := inodeOf(fi)
	if ok && k == want {
		return true
	}
	c.keepEntry(apiPath, fmt.Sprintf(
		"%q was replaced while its contents were being removed, so what is there now was left alone", apiPath))
	return false
}

// stillTheRecorded reports that a held directory is the one the copy descended
// into. Where identity cannot be read at all (off Linux) the answer is no, so
// the dev loop keeps a moved source rather than removing it unverified.
// Permissions and ownership are required to be unchanged as well as the
// identity, and for the reason the per-file record has them: a directory
// tightened 0755 -> 0700, or chowned, after its copy was made would otherwise
// be removed with the destination left under the OLD mode — a restriction
// dropped at the moment the user applied it. They are checked HERE, at the
// start of the post-order delete, before a single entry inside has been
// touched, so a mismatch keeps the whole subtree.
//
// Its modification time is deliberately not among them, and that is a departure
// from the finding's wording worth stating. A directory's mtime is a function
// of its ENTRIES, and every entry is already proved individually; requiring it
// would mean that one file added to a folder by somebody else during a move
// keeps that folder's entire subtree, where today the entries that were
// verifiably copied are removed and the new file, its parents and the reason
// are reported (TestMoveDeletesOnlyWhatItVerifiablyCopied pins exactly that).
// It would also make a timestamp block a delete, which is the thing round 5
// ruled out: timestamps are not data. Mode and ownership are.
func stillTheRecorded(dir *dirRef, rec *copiedDir) bool {
	if rec == nil {
		return false
	}
	fi, err := dir.stat()
	if err != nil {
		return false
	}
	if fi.Mode() != rec.mode {
		return false
	}
	uid, gid, _, owned := statDetail(fi)
	if owned != rec.haveOwner || (owned && (uid != rec.uid || gid != rec.gid)) {
		return false
	}
	if !rec.haveID {
		// On Linux a directory the copy could not identify is one the delete
		// will not descend into. Off Linux nothing has an identity at all, and
		// refusing there would mean a move on the dev box never removed
		// anything; the confinement is os.Root's and the per-entry checks still
		// apply.
		return !inodeIdentity
	}
	k, ok := inodeOf(fi)
	return ok && k == rec.id
}

// matchesRecord is the per-entry proof: the same object, the same kind, the
// same length, the same modification time. Identity alone would not see a file
// rewritten in place, and size and time alone would not see one replaced by
// another of the same shape.
func (c *copier) matchesRecord(fi os.FileInfo, e copiedEntry) bool {
	if !e.recorded || kindOf(fi) != e.kind {
		return false
	}
	if e.haveID {
		k, ok := inodeOf(fi)
		if !ok || k != e.id {
			return false
		}
	} else if inodeIdentity {
		// This platform HAS identities and this entry has none, which is not a
		// platform limitation but a measurement that failed. Refuse.
		return false
	}
	if fi.Size() != e.size {
		return false
	}
	if !fi.ModTime().Equal(e.mtime) {
		return false
	}
	// Permissions and ownership, on their own rather than through the change
	// time — which is exempted for a hard-linked entry precisely because this
	// job moved it itself, so a chmod or a chown made after the copy would
	// otherwise have been invisible and the source removed with its copies left
	// under the OLD permissions.
	if fi.Mode() != e.mode {
		return false
	}
	uid, gid, _, ok := statDetail(fi)
	if ok != e.haveOwner || (ok && (uid != e.uid || gid != e.gid)) {
		return false
	}
	if e.nlink > 1 {
		// A hard-linked inode's change time was moved by this job's own unlink
		// of one of its other links, so it cannot be the proof here. The bytes
		// are, and contentMatches reads them.
		return true
	}
	// The change time, where the platform has one. On Linux a record without it
	// is a measurement that failed, and the entry is not removed on the
	// strength of the three fields a writer CAN control.
	now, cok := changeTimeOf(fi)
	if !e.haveCtime {
		return !inodeIdentity
	}
	if !cok {
		return false
	}
	return now.Equal(e.ctime)
}

// keepEntry reports one source entry that was not removed. It is a warning
// rather than a skip: the entry reached the destination (or was never this
// job's to touch), and JobResult.Skipped counts what did not.
func (c *copier) keepEntry(apiPath, msg string) {
	c.warn(apiPath, warnKept, msg, 0)
}

// ---- plumbing ---------------------------------------------------------------

// countWriter is the destination end of a file copy: it counts the bytes, it
// reports them, and it is where the job notices that it has been cancelled.
//
// It deliberately implements nothing but io.Writer. An *os.File would have been
// accepted by io.CopyBuffer through its ReadFrom, which hands the whole
// transfer to the kernel (copy_file_range) and ignores both the buffer and
// every chance to stop — see this file's header for why that is not the trade
// to make here.
type countWriter struct {
	w    io.Writer
	ctx  context.Context
	n    int64
	tick func(int64)
}

func (w *countWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	if w.tick != nil {
		w.tick(w.n)
	}
	return n, err
}

// plainReader hides the source's own WriteTo for the same reason countWriter
// hides ReadFrom: io.CopyBuffer prefers either of them over the buffer it was
// given, and this copy wants the loop.
type plainReader struct{ r io.Reader }

func (p plainReader) Read(b []byte) (int, error) { return p.r.Read(b) }

// progress reports one completed item. The rate limiting is the worker's
// (see Emit).
func (c *copier) progress(apiPath, phase string) {
	c.emit.prog(wproto.Prog{
		Files:      c.res.Files + c.res.Dirs,
		FilesTotal: c.filesTotal,
		Bytes:      c.res.Bytes,
		BytesTotal: c.bytesTotal,
		Current:    []byte(apiPath),
		Phase:      phase,
	})
}

// progressBytes reports part of one file, so a single 40 GB file is not a
// motionless bar for four minutes.
func (c *copier) progressBytes(apiPath string, bytes int64) {
	c.emit.prog(wproto.Prog{
		Files:      c.res.Files + c.res.Dirs,
		FilesTotal: c.filesTotal,
		Bytes:      bytes,
		BytesTotal: c.bytesTotal,
		Current:    []byte(apiPath),
		Phase:      wproto.PhaseWorking,
	})
}

// contentWarning reports whether a warning code means that something of the
// SOURCE is not at the destination — which is the only question the move's
// delete-the-source decision is entitled to ask (finishMove).
//
// The distinction matters because "clean" is not "quiet". These codes are
// content, and every one of them means the destination is missing something the
// source had:
//
//	unsupported  a fifo, socket or device node that was not reproduced
//	conflict     a type mismatch, or a keep-both search with no name left
//	exists       an entry skipped because the destination already had one
//	changed      the source was rewritten mid-copy, so what landed is not it
//	no_space     a write that ran out of room or quota
//	owner_unset  the entry is there but belongs to the wrong user — ownership
//	             is part of what the rename this fell back from WOULD have
//	             preserved, so a copy that lost it has not reproduced the source
//	protected    a mount point or a never-write component that was not entered
//	<any errno>  a per-item kernel failure, classified by fsx.Code
//
// And exactly two codes are not:
//
//	times_unset         a modification time that could not be reproduced
//	shared_destination  the destination is one other users may write
//
// A timestamp is metadata ABOUT the data, not the data. A move that copied
// every byte, every directory, every symlink and every owner, and could only
// not stamp one mtime, has moved the user's files; refusing to remove the
// source over it would leave two copies of a terabyte behind and make the user
// clean up by hand after a job that worked. The warning is still reported —
// the copy is not perfect and the job says so — it just does not veto the
// delete.
//
// shared_destination is the same kind of statement one level up: it describes
// the PLACE, not an entry. Nothing about it says an entry failed — every object
// was created, pinned and proved exactly as it is anywhere else — so vetoing
// the delete over it would mean a move into an ordinary group-writable share
// never removing its source, which is every share on the NAS.
//
// The default is deliberately the other way: any code this function does not
// name, including anything a later change adds, counts as content and keeps the
// source. Failing closed here costs disk space; failing open costs data.
func contentWarning(code string) bool {
	return code != warnTimesUnset && code != warnSharedDest
}

// count books one warning against the ledgers: the total, and the subset that
// can stop a move from deleting its source.
func (c *copier) count(code string) {
	c.warns++
	if contentWarning(code) {
		c.contentWarns++
	}
}

// warn reports a per-item failure and counts it.
func (c *copier) warn(apiPath, code, msg string, errno int) {
	c.count(code)
	c.emit.warn(apiPath, code, msg, errno)
}

// warnErr reports a per-item failure the kernel decided, classified with the
// one error vocabulary the whole app speaks. Every such failure is content: the
// kernel refused something the copy was told to reproduce.
func (c *copier) warnErr(apiPath string, err error) {
	c.count(fsx.Code(err))
	c.emit.warnErr(apiPath, err)
}

// skip reports an item that was not copied, with the kernel's classification.
func (c *copier) skip(apiPath string, err error) {
	c.warnErr(apiPath, err)
	c.res.Skipped++
}

// skipCode reports an item this engine decided not to copy, with its own code.
//
// The routine "already there" case is bounded (maxExistsWarnings): the skip is
// always counted and always makes the root unclean, and only the per-item
// frames stop once there have been enough of them to make the point.
func (c *copier) skipCode(apiPath, code, msg string, errno int) {
	c.res.Skipped++
	if code != warnExists {
		c.warn(apiPath, code, msg, errno)
		return
	}
	c.existsWarns++
	switch {
	case c.existsWarns < maxExistsWarnings:
		c.warn(apiPath, code, msg, errno)
	case c.existsWarns == maxExistsWarnings:
		c.warn("", code, fmt.Sprintf(
			"%d items were already at the destination and were skipped; the rest are counted but not listed",
			maxExistsWarnings), 0)
	default:
		// Counted so the move's delete-the-source decision still sees it, but
		// not put on the socket.
		c.count(code)
	}
}

// notOurs reports a destination directory this job created and then could not
// prove it had made, so nothing was written into it.
func (c *copier) notOurs(dstPath string, err error) {
	c.skipCode(dstPath, warnChanged, fmt.Sprintf(
		"%q was replaced as it was created, so nothing was copied into it: %v", dstPath, err), 0)
}

// recordDirState writes down what a source directory was when the walk opened
// it — its identity and the permissions and ownership the copy is reproducing —
// so the delete can require them unchanged before it removes anything inside.
//
// Everything comes from the fstat of the descriptor the walk ENUMERATES, never
// from the lstat of its name, for the reason makePending gives.
//
// Its modification time is deliberately NOT among them; see stillTheRecorded.
func recordDirState(rec *copiedDir, info os.FileInfo) {
	if rec == nil || info == nil {
		return
	}
	rec.id, rec.haveID = inodeOf(info)
	rec.mode = info.Mode()
	if uid, gid, _, ok := statDetail(info); ok {
		rec.uid, rec.gid, rec.haveOwner = uid, gid, true
	}
}

// modeNoWiderThan requires a freshly created object's permissions to be a
// SUBSET of the ones this job asked for.
//
// Creation only ever narrows: the umask removes bits, a POSIX default ACL caps
// the result at the requested mode, and neither can add one. So a wider mode is
// not a filesystem being generous, it is evidence that the object is not the one
// this job created — which is exactly how a substituted directory got past a
// provenance check that asked only about kind, owner and emptiness. Root copying
// a 0700 folder of 0644 files into a shared non-sticky destination had an
// existing empty root-owned 0755 directory slid over the name; every other test
// passed, the chown left it 0755, and private files landed in a directory
// anybody could search.
//
// parentSetgid says the containing directory carries S_ISGID, in which case the
// kernel gives the new directory one too and it is expected. No other special
// bit is ever asked for by this engine, so any of them is a refusal.
//
// It is a Linux check. Off Linux the mode a stat reports is a synthetic
// approximation — Go reports 0777 for every directory on Windows — so comparing
// it would refuse every copy on the dev box (INV-2).
func modeNoWiderThan(f *os.File, asked fs.FileMode, extra fs.FileMode) error {
	if !inodeIdentity {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return modeSubset(fi.Mode(), asked, extra)
}

// modeSubset is modeNoWiderThan's comparison, over a FileInfo the caller has.
func modeSubset(got, asked, extra fs.FileMode) error {
	if !inodeIdentity {
		return nil
	}
	if wider := got.Perm() &^ asked.Perm(); wider != 0 {
		return fmt.Errorf("it is mode %o where at most %o was asked for: %w",
			got.Perm(), asked.Perm(), fsx.ErrUnsupported)
	}
	if special := got & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky) &^ extra; special != 0 {
		return fmt.Errorf("it carries %v, which this job never asks for: %w", special, fsx.ErrUnsupported)
	}
	return nil
}

// inheritedSetgid reports the special bits a newly created directory may
// legitimately carry because its parent passed them down: setgid, and nothing
// else.
func inheritedSetgid(parent *dirRef) fs.FileMode {
	if parent == nil {
		return 0
	}
	fi, err := parent.stat()
	if err != nil {
		return 0
	}
	return fi.Mode() & fs.ModeSetgid
}

// sameDirState reports whether a description matches what was recorded for a
// source directory: identity, permissions and ownership.
func sameDirState(rec *copiedDir, info os.FileInfo) bool {
	if rec == nil || info == nil {
		return false
	}
	if info.Mode() != rec.mode {
		return false
	}
	uid, gid, _, ok := statDetail(info)
	if ok != rec.haveOwner || (ok && (uid != rec.uid || gid != rec.gid)) {
		return false
	}
	k, kok := inodeOf(info)
	if kok && rec.haveID {
		return k == rec.id
	}
	return !inodeIdentity
}

// publishedMatches reports whether a description of the copy at the destination
// is the one this job published: kind, identity, length, modification time and
// change time, all as recorded at publication.
//
// It is copyStillThere's comparison, over a description the caller already has.
// copyStillThere asks it of the NAME; contentMatches asks it of the descriptor
// it then reads, because a baseline is only worth what it was checked against.
func publishedMatches(fi os.FileInfo, e copiedEntry) bool {
	if fi == nil || kindOf(fi) != e.kind {
		return false
	}
	if !sameRecordedInode(fi, e.dstID, e.haveDstID) {
		return false
	}
	if fi.Size() != e.dstSize || !fi.ModTime().Equal(e.dstMtime) {
		return false
	}
	now, ok := changeTimeOf(fi)
	if !e.haveDstCtime {
		return !inodeIdentity
	}
	return ok && now.Equal(e.dstCtime)
}
