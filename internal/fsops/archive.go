package fsops

// The M2-C archive download (contract §2): the selected trees, streamed as one
// zip or tar.gz into a writer the worker never owns the other end of.
//
// Nothing is written to disk. The worker replies to OpArchive with the read end
// of a pipe and then walks the trees into the write end, so the archive exists
// only as bytes in flight between this process and the browser. That is what
// makes an archive of a 200 GB share possible on a NAS with a full volume, and
// it is why every decision below is about what to do when the stream, rather
// than the filesystem, is the thing that fails.
//
// Four rules fix the shape.
//
//   - Every byte is read as the user, through the walk's own held descriptors.
//     A file is opened with openat relative to the directory the walk is
//     standing in (O_NOFOLLOW), never by a pathname rebuilt from its name, for
//     the reason the copy engine gives: the names come from one directory's
//     getdents, and the bytes must come from that same directory.
//   - A symlink is an ENTRY, never a way in. It is recorded as a symlink member
//     whose content is its target text — a zip entry with mode 0120000, a tar
//     TypeSymlink — so unzipping reproduces the link instead of silently
//     copying whatever it pointed at, possibly from outside the selection.
//   - A per-item failure never ends the archive. An unreadable file, an
//     unreadable subdirectory, a fifo that has no bytes to archive: each is
//     recorded as a line in a final ERROR.txt member and the walk carries on,
//     which is the same rule the recursive delete and the copy follow.
//   - A FATAL failure ends it WITHOUT the trailer. Cancellation, or a write
//     error on the stream that is not simply the reader going away, appends
//     ERROR.txt best-effort and then closes the pipe without the central
//     directory (zip) or the end-of-archive blocks (tar). A truncated archive is
//     what unzip and tar both report as damaged, which is the only honest way to
//     tell somebody holding a half-downloaded file that it is half a file
//     (design §2.11). Finishing the trailer over a failed stream would hand them
//     a well-formed archive that silently lacks their data.
//
// The reader going away is NOT a failure. The browser cancelling a download
// closes its end, our writes get EPIPE, and the walk stops quietly: there is
// nobody to report to and nothing was lost.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// Archive formats. They are the wire's spellings (ArchiveReq.Format).
const (
	ArchiveZip = "zip"
	ArchiveTGZ = "tgz"
)

const (
	// archiveBufSize is the transfer buffer, and with it the cancellation
	// granularity: one context check per megabyte, exactly as the copy engine
	// does it and for the same reason.
	archiveBufSize = 1 << 20

	// maxArchiveRoots bounds one archive's selection. It is the route's own
	// maxJobRoots repeated here, because the worker does not trust a request to
	// carry its own limits.
	maxArchiveRoots = 1000

	// maxArchiveNotes bounds the ERROR.txt member. A tree where every file is
	// unreadable would otherwise build a note per file in memory, which is the
	// one place an archive of four million files could run a 1 GB NAS out of
	// memory. Past the bound the notes are still COUNTED and the last line says
	// how many were not listed.
	maxArchiveNotes = 1000

	// maxArchiveMembers bounds how many members one archive may hold.
	//
	// It is a MEMORY bound and it is the zip format's, not this code's:
	// archive/zip keeps one header per member in RAM until Close writes the
	// central directory, so an archive of a four-million-file share would
	// accumulate hundreds of megabytes of headers inside a worker on a NAS with
	// one gigabyte of it — and be killed by the OOM reaper half way through a
	// download nobody could explain (M2-C review round 1 adversarial, finding
	// 1).
	//
	// The same bound is applied to tar, which has no such table and needs none.
	// One rule is worth more than the memory it costs nothing to save: "an
	// archive stops at two hundred thousand items" is a sentence a user can be
	// told, and a limit that depended on the format they picked is one they
	// would meet by accident. Past it the archive ends TRUNCATED, with the
	// reason in ERROR.txt and no trailer, so the client's unzip says so rather
	// than reporting a complete archive that quietly holds a fraction of a tree.
	maxArchiveMembers = 200_000

	// maxArchiveMetadata bounds the same memory in BYTES, because the member
	// count alone does not (M2-C review round 2 adversarial, finding 1).
	//
	// What archive/zip retains per member is a header STRUCT plus the member's
	// NAME, and a name on Linux may be 255 bytes per component and 4096 in
	// total. A hundred and ninety-nine thousand empty files with four-kilobyte
	// paths sit comfortably under the item bound and still retain more than a
	// gigabyte — and the session allows two producers at once, so twice that.
	// Sixty-four megabytes is roughly two hundred thousand ordinary names, so
	// an archive of real files meets the item bound first and this one never;
	// an archive of pathological ones meets this one and stops.
	maxArchiveMetadata = 64 << 20

	// archiveHeaderOverhead is what one member costs besides its name: the
	// central-directory record the format writes (46 bytes), the zip.FileHeader
	// Go keeps for it, and the slice entry that points at it. It is rounded
	// generously UP, because the number it protects is a worker's whole memory
	// and being wrong in the other direction is an OOM kill nobody can explain.
	archiveHeaderOverhead = 256

	// archiveNotesName is the member that carries what went wrong. It is at the
	// end of the archive so that a reader who extracted everything else finds it
	// last, and it is plain text so that double-clicking it explains itself.
	//
	// It is a WANTED name rather than a fixed one. A user may perfectly well
	// select a file of their own called ERROR.txt, and two members of one name
	// is an archive whose extraction replaces one with the other — the user's
	// file overwritten by a diagnostic, or the diagnostic hiding their file. So
	// the notes go through the same collision-free allocator the selected roots
	// go through (archiver.reserve), and they are allocated LAST: the user's own
	// file keeps its name, and it is the diagnostic that becomes "ERROR (2).txt"
	// (M2-C review round 1, finding 3).
	archiveNotesName = "ERROR.txt"
)

// storeExtensions are the file extensions that are already compressed, from
// contract §2.2. Deflating them costs CPU on a 1.7 GHz ARM and produces a
// LARGER member, so they are stored.
var storeExtensions = map[string]bool{
	".zip": true, ".gz": true, ".tgz": true, ".7z": true, ".rar": true,
	".mp4": true, ".mkv": true, ".jpg": true, ".jpeg": true, ".png": true,
	".heic": true, ".mp3": true, ".flac": true, ".aac": true, ".ogg": true,
	".webm": true, ".webp": true, ".avif": true,
}

// archiveClock names the archive of a multi-root selection, as a variable so a
// test can assert the whole name. Production never assigns to it.
var archiveClock = time.Now

// archiveMemberCap is maxArchiveMembers as a variable, so a test can reach the
// bound without building a tree of two hundred thousand files. Production never
// assigns to it.
var archiveMemberCap = maxArchiveMembers

// archiveMetadataCap is maxArchiveMetadata as a variable, so a test can reach
// the budget without building a tree of four-kilobyte names. Production never
// assigns to it.
var archiveMetadataCap int64 = maxArchiveMetadata

// errArchiveFull says the member bound was reached. It is fatal in the same
// sense a broken stream is — the archive ends without its trailer — but it is
// this app's own decision rather than a failure, so it says so in ERROR.txt in
// its own words.
var errArchiveFull = errors.New("fsops: the archive reached its item limit")

// ArchiveName is the file name the download should be offered under (§2.1).
//
// One selected item names the archive after itself; several name it after the
// day, because there is no honest single name for "these fourteen things". The
// base name is refused and replaced when it carries anything a
// Content-Disposition header would have to escape — a quote, a backslash, a
// control byte — since the front-end builds that header out of this string and
// a filename is an arbitrary byte string on Linux.
func ArchiveName(paths []string, format string) string {
	ext := ".zip"
	if format == ArchiveTGZ {
		ext = ".tar.gz"
	}
	if len(paths) == 1 {
		if base, ok := archiveBase(paths[0]); ok {
			return base + ext
		}
	}
	return "archive-" + archiveClock().Format("2006-01-02") + ext
}

// archiveBase is the base name of one selected path, or false when it is not a
// name a download header can carry.
func archiveBase(p string) (string, bool) {
	base := fsx.Base(p)
	switch base {
	case "", "/", ".", "..":
		return "", false
	}
	for i := 0; i < len(base); i++ {
		if c := base[i]; c < 0x20 || c == 0x7f || c == '"' || c == '\\' || c == '/' {
			return "", false
		}
	}
	return base, true
}

// ArchiveCheck validates an archive request and returns the name the download
// should carry, WITHOUT opening the pipe or walking anything.
//
// It exists because of the order §2.2 fixes: the worker replies OK — with the
// pipe's read end — before it has archived a single byte, so everything that
// could have been an honest error frame has to be decided first. A selection
// holding a path the user cannot reach is a 404, not a zip file whose only
// member is ERROR.txt.
// ArchivePlan is what ArchiveCheck proved, carried to the producer that streams
// the archive (M2-C review round 13).
//
// It exists because the two halves are separated by the whole download. The
// authorization, the guard and this check all finish before the first byte
// leaves; the roots after the first are opened minutes later, while earlier
// members are still streaming. Re-resolving them then was the hole: an
// administrator archiving a large file followed by /safe/config.json could,
// during the stream, rename /safe away and leave a symlink to the daemon's own
// configuration directory in its place. The later resolution walked the
// replacement parent — refuseRoot is a mount and snapshot rule, not the web
// guard — and the protected file went into the archive.
//
// So every root's identity is recorded here, before anything is written, and
// compared when the producer reaches it. What is NOT done is holding a
// descriptor per root: a ticket-sized selection is thousands of them, and a
// worker that held thousands of open descriptors for the length of a download
// would be a different bug. The identity is the M2-B ledger's answer applied to
// a stream: record what was proved, prove it again before acting, and refuse
// the entry — never follow the replacement — when it no longer matches.
type ArchivePlan struct {
	// Name is the file name the download should be offered under.
	Name []byte
	// roots is one entry per requested path, in the order they were requested,
	// so the producer can find a root by index without re-parsing anything.
	roots []archiveRoot
}

// archiveRoot is one selected path as it was when the archive was authorized.
type archiveRoot struct {
	// api is the requested spelling, cleaned — what messages name.
	api string
	// resolved is the API path resolve() produced, and rel the jail-relative
	// one. The producer re-opens THIS, never the requested spelling: the
	// symlinks QTS builds its shares out of were followed once, under the
	// user's own traversal permissions, and following them again would be a
	// second, different resolution.
	resolved string
	rel      string
	// id is the root's own identity, from an O_PATH open of the exact resolved
	// path, and parentID its directory's. Both are compared before the producer
	// descends: the parent catches "the directory this was in was replaced",
	// which is the shape of the attack, and the root itself catches "the entry
	// was replaced inside a directory that did not change".
	//
	// They are objectIDs and not bare inode numbers, because the gap they span
	// is the whole download and an inode number freed inside it can be handed
	// back to the next thing created at that name (round 14 adversarial).
	id       objectID
	parentID objectID
}

// archiveOpenRoot opens a selected directory for enumeration, as a variable so
// a test can substitute another directory in the instant between the lstat that
// classified the root and the openat that enumerates it (round 14). That window
// is two adjacent syscalls wide and nothing else can stage it; it is the same
// reason mkdirForCopy is a variable. Production never assigns to it.
var archiveOpenRoot = func(d *dirRef, name string) (*dirRef, error) { return d.child(name) }

// archiveBetweenRoots is called before each root is archived, as a variable so
// a test can substitute a directory in the window the producer actually has:
// between finishing one root and starting the next. Nothing else can stage
// that, because it is a window between two syscall sequences in another
// goroutine. Production never assigns to it.
var archiveBetweenRoots func(index int)

func ArchiveCheck(ctx context.Context, r fsx.Root, plat *platform.Platform, req wproto.ArchiveReq) (*ArchivePlan, error) {
	switch req.Format {
	case ArchiveZip, ArchiveTGZ:
	default:
		return nil, fmt.Errorf("%q is not an archive format this app writes: %w", req.Format, fsx.ErrBadName)
	}
	if len(req.Paths) == 0 {
		return nil, fmt.Errorf("an archive needs at least one item: %w", fsx.ErrBadName)
	}
	if len(req.Paths) > maxArchiveRoots {
		return nil, fmt.Errorf("an archive of %d items is more than the %d this worker will take: %w",
			len(req.Paths), maxArchiveRoots, fsx.ErrBadName)
	}
	clean := make([]string, 0, len(req.Paths))
	plan := &ArchivePlan{roots: make([]archiveRoot, 0, len(req.Paths))}
	for _, raw := range req.Paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := fsx.Clean(string(raw))
		if err != nil {
			return nil, err
		}
		// Before the resolve, for the reason archiver.root gives: this check is
		// what stops a root inside a dead network mount from parking the whole
		// request inside an lstat (round 2 adversarial, finding 2). It runs on
		// THIS side of the reply, so it is an honest error frame rather than a
		// truncated archive.
		if rerr := refuseRootPath(r, plat, p, ProtectSnapshots); rerr != nil {
			return nil, rerr
		}
		// Opened as the user with the leaf kept literal — a symlink named for an
		// archive is archived as the link — and following nothing on the way.
		root, err := checkedRoot(r, p)
		if err != nil {
			return nil, err
		}
		plan.roots = append(plan.roots, root)
		clean = append(clean, p)
	}
	plan.Name = []byte(ArchiveName(clean, req.Format))
	return plan, nil
}

// checkedRoot records what one selected path IS, so the producer can prove it
// is still that later.
//
// The root's own identity comes from an O_PATH open of the exact resolved path
// — openItemRef, which opens the final component with O_NOFOLLOW and fstats the
// descriptor, so the answer describes the object rather than whatever the name
// means a moment afterwards. The parent's comes from the held directory
// descriptor for the same reason.
func checkedRoot(r fsx.Root, requested string) (archiveRoot, error) {
	// The walk follows NOTHING (round 14 adversarial): the route sends the
	// spelling its own guarded resolution produced, and a second following
	// resolution here would walk whatever the tree says now — recording the
	// identity of the replacement, which the producer would then "prove"
	// perfectly.
	parent, ref, _, tg, err := canonicalLeaf(r, requested)
	if err != nil {
		return archiveRoot{}, err
	}
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	out := archiveRoot{api: requested, resolved: tg.api, rel: tg.rel}
	if ref == nil {
		// The jail base: there is no parent this process may open, and the base
		// is the one directory nobody can rename out from under the handle.
		fi, serr := statAt(tg.jail, tg.rel)
		if serr != nil {
			return archiveRoot{}, serr
		}
		out.id = objectIDOf(nil, fi)
		return out, nil
	}
	out.parentID = objectIDOf(parent.f, parentIdentityOf(parent))
	out.id = objectIDOf(refFD(ref), ref.fi)
	return out, nil
}

// ArchiveResult is what became of one archive, for the record the front-end
// audits (adversarial finding 6).
//
// It exists because a pipe cannot carry an outcome. A stream that ended because
// the walk was cancelled, hit its item bound or failed mid-way closes exactly
// the way a complete one does — clean EOF — so a front-end that recorded "ok"
// on EOF was recording a truncated download as a successful one. Truncated is
// the one bit that matters: it says the trailer was deliberately NOT written,
// which is what makes the client's unzip report a damaged file.
type ArchiveResult struct {
	// Bytes is how much was written into the stream.
	Bytes int64
	// Truncated says the archive ends without its trailer.
	Truncated bool
	// Reason is a short sentence for the log and the audit record. It is empty
	// exactly when the archive is complete.
	Reason string
}

// Archive writes the selected trees into w as one archive. It does NOT close w,
// and the type says so.
//
// That is a rule about ORDER rather than about ownership (M2-C review round 2).
// Closing the write end is what lets the front-end see EOF, and EOF is what
// makes it ask the worker for this archive's verdict. While this function
// closed the pipe itself, the close happened before the worker had recorded the
// outcome — so a front-end that asked the instant it saw EOF was told the
// worker had no record, and audited a completed download as unknown. The caller
// records the result FIRST and closes the write end afterwards, which makes the
// window impossible rather than unlikely (internal/worker/archive.go).
//
// The error return is for the caller's log, not for the client: by the time
// anything here can fail the reply has long gone and the client is reading
// bytes. What the client sees is the archive — complete, or truncated with an
// ERROR.txt in it. The ArchiveResult is what the front-end audits, and it is
// filled in on every path including the failures.
func Archive(ctx context.Context, r fsx.Root, plat *platform.Platform, req wproto.ArchiveReq, plan *ArchivePlan, w io.Writer) (ArchiveResult, error) {
	sw := &sinkWriter{w: w}
	sink, err := newArchiveSink(req.Format, sw)
	if err != nil {
		return ArchiveResult{Truncated: true, Reason: err.Error()}, err
	}
	a := &archiver{
		r:    r,
		plat: plat,
		ctx:  ctx,
		sink: sink,
		sw:   sw,
		opts: WalkOptions{CrossMounts: req.CrossMounts, Protect: ProtectSnapshots},
		used: map[string]bool{},
		plan: plan,
	}
	roots := 0
	if plan != nil {
		roots = len(plan.roots)
	}
	for i := 0; i < roots; i++ {
		if a.done() {
			break
		}
		if archiveBetweenRoots != nil {
			archiveBetweenRoots(i)
		}
		a.root(i)
	}
	err = a.finish()
	return a.result(), err
}

// result is the verdict this archive ended with.
func (a *archiver) result() ArchiveResult {
	res := ArchiveResult{Bytes: a.sw.n}
	switch {
	case a.fatal != nil:
		res.Truncated = true
		res.Reason = a.fatal.Error()
	case a.sw.broken:
		// The client stopped reading. What they have is not a whole archive,
		// and saying so is the difference between an audit record that reads
		// "cancelled" and one that reads "ok" over half a download.
		res.Truncated = true
		res.Reason = "the client stopped reading before the archive was finished"
	}
	return res
}

// archiver is one running archive.
type archiver struct {
	r    fsx.Root
	plat *platform.Platform
	ctx  context.Context
	sink archiveSink
	sw   *sinkWriter
	opts WalkOptions

	buf []byte
	// plan is what ArchiveCheck proved about every selected root, before the
	// first byte left. The producer re-opens and re-proves; it never resolves.
	plan *ArchivePlan

	// used is the set of member-name prefixes already taken, so that two
	// selected roots called "photos" do not produce one unextractable archive.
	used map[string]bool

	// members counts what has been added, against maxArchiveMembers, and
	// metaBytes what those members will cost in retained header memory.
	members   int
	metaBytes int64
	// seq is the allocator's last resort: a counter that cannot collide,
	// because a name built from it is checked against the same set (finding 7).
	seq int

	notes    []string
	noteMore int
	// fatal is the first thing that ended the archive rather than one member:
	// cancellation, or a stream failure that is not the reader leaving.
	fatal error
}

// done reports that there is no point going on: the stream is dead, or
// something fatal already happened.
func (a *archiver) done() bool {
	if a.fatal != nil || a.sw.broken {
		return true
	}
	if err := a.ctx.Err(); err != nil {
		a.fatal = err
		return true
	}
	return false
}

// note records a per-item failure for the ERROR.txt member. It never stops the
// archive.
func (a *archiver) note(apiPath, msg string) {
	if len(a.notes) >= maxArchiveNotes {
		a.noteMore++
		return
	}
	if apiPath != "" {
		msg = apiPath + ": " + msg
	}
	a.notes = append(a.notes, msg)
}

// fail records a stream failure. EPIPE and a closed pipe are the reader going
// away, which is not a failure at all — the download was cancelled and there is
// nobody left to tell.
func (a *archiver) fail(err error) {
	if err == nil || a.fatal != nil {
		return
	}
	if readerGone(err) {
		a.sw.broken = true
		return
	}
	a.fatal = err
}

// root archives the selected path the plan recorded at index i.
//
// It does NOT resolve anything. The path was resolved once, before the first
// byte left, under the user's own traversal permissions — and resolving it
// again now would be a second, different answer, arrived at while the earlier
// members of this very archive were streaming (M2-C review round 13). What
// happens instead is that the recorded resolution is re-opened and its identity
// compared: same parent, same entry, or the root is skipped.
func (a *archiver) root(i int) {
	if a.plan == nil || i < 0 || i >= len(a.plan.roots) {
		// Unreachable: Archive iterates the plan's own roots. Said out loud
		// because the alternative to a plan entry is a fresh resolution, and
		// that is the thing this design exists to never do.
		a.note("", "this item was not checked before the archive started, so it was not archived")
		return
	}
	e := a.plan.roots[i]
	clean := e.api
	// BEFORE anything is opened: a root inside a dead network mount would park
	// this producer inside an lstat nothing can interrupt (round 2 adversarial,
	// finding 2), and the mount table answers by name with no syscall at all.
	if err := refuseRootPath(a.r, a.plat, clean, a.opts.Protect); err != nil {
		a.note(clean, err.Error())
		return
	}
	jail, err := a.r.Open()
	if err != nil {
		a.note(clean, err.Error())
		return
	}
	if e.rel == "." || e.rel == "" {
		a.rootBase(jailPath{jail: jail, rel: e.rel, api: e.resolved}, e)
		return
	}
	parentRel, name := splitFinal(e.rel)
	// Opened without following anything, for the reason checkedRoot gives: an
	// ancestor swapped for a symlink since the check is evidence that the tree
	// changed, never a path to follow (round 14 adversarial).
	parent, err := openCanonicalDir(jail, parentRel, clean)
	if err != nil {
		a.note(clean, err.Error())
		return
	}
	defer parent.close()
	// The parent first, because that is the half the attack moves: rename the
	// authorized directory away and leave a symlink — or another real directory
	// — where it was. A pathname walk cannot tell the difference and an inode
	// can.
	if !a.stillTheCheckedObject(objectIDOf(parent.f, parentIdentityOf(parent)), e.parentID, clean,
		"the folder holding it") {
		return
	}
	// The leaf is PINNED and judged on that descriptor: an lstat is a lookup by
	// name, and everything below acts on an object.
	ref, err := itemRefIn(parent, name)
	if err != nil {
		a.note(clean, err.Error())
		return
	}
	defer ref.close()
	if !a.stillTheCheckedObject(objectIDOf(refFD(ref), ref.fi), e.id, clean, "it") {
		return
	}
	info := ref.fi
	if err := refuseRoot(a.r, a.plat, clean, e.resolved, a.opts.Protect); err != nil {
		// The refusals the walker makes for every child, made for the root as
		// well (adversarial finding 4). It is one selected item's failure, not
		// the archive's: the rest of the selection is still archived and the
		// reason goes into ERROR.txt.
		a.note(clean, err.Error())
		return
	}
	prefix := a.reserve(fsx.Base(e.resolved), info.IsDir())

	switch {
	case info.IsDir():
		held, err := archiveOpenRoot(parent, name)
		if err != nil {
			a.note(clean, err.Error())
			return
		}
		// Proved AGAIN, on the descriptor that will actually be enumerated
		// (M2-C review round 14). The lstat above is a lookup by name and the
		// open below is another one: between them the directory can be renamed
		// away and a different REAL directory left at the name — O_NOFOLLOW
		// refuses a symlink and has nothing to say about that — and neither
		// a.tree nor walkFrom would have compared the descriptor to anything.
		// The whole of the replacement would then have been archived under the
		// selected root's name with nothing anywhere to say so. It is the rule
		// copyTree already follows: the object that is acted on is the object
		// that was proved, and a stat taken a syscall earlier is not it.
		if !a.stillTheCheckedObject(objectIDOf(held.f, parentIdentityOf(held)), e.id, clean, "it") {
			held.close()
			return
		}
		// walkFrom CONSUMES the descriptor: it closes it when the enumeration
		// is done, exactly as it closes every directory it opens itself.
		a.tree(held, e.resolved, info, prefix)
	case info.Mode()&fs.ModeSymlink != 0:
		if !a.room(prefix) {
			return
		}
		a.symlink(parent, name, clean, info, prefix)
	case info.Mode().IsRegular():
		if !a.room(prefix) {
			return
		}
		a.file(parent, name, clean, info, prefix)
	default:
		a.note(clean, fmt.Sprintf("a %s has no contents to archive and was skipped", fsx.TypeString(info.Mode())))
	}
}

// rootBase archives the jail base itself, which is the one path with no parent
// this process may open. It exists for the dev loop's -jail root and for an
// unjailed archive of "/".
func (a *archiver) rootBase(tg jailPath, e archiveRoot) {
	info, err := statAt(tg.jail, tg.rel)
	if err != nil {
		a.note(e.api, err.Error())
		return
	}
	if !a.stillTheCheckedObject(objectIDOf(nil, info), e.id, e.api, "it") {
		return
	}
	if rerr := refuseRoot(a.r, a.plat, e.api, e.resolved, a.opts.Protect); rerr != nil {
		a.note(e.api, rerr.Error())
		return
	}
	held, err := openDirRef(tg.jail, tg.rel)
	if err != nil {
		a.note(e.api, err.Error())
		return
	}
	// On the descriptor that will be enumerated, not on the stat above (round
	// 14). The jail base is the one directory nobody can rename out from under
	// the handle, so this can only ever succeed here — it is written the same
	// way as the branch above so that the two cannot drift apart.
	if !a.stillTheCheckedObject(objectIDOf(held.f, parentIdentityOf(held)), e.id, e.api, "it") {
		held.close()
		return
	}
	a.tree(held, e.resolved, info, a.reserve(fsx.Base(e.resolved), true))
}

// stillTheCheckedObject compares what is there now with what ArchiveCheck
// proved, and refuses the root when they differ (M2-C review round 13).
//
// A mismatch is never followed and never archived: the note says the item
// changed, and the rest of the selection carries on. That is the whole of the
// rule — the producer's job is to archive what was authorized, and something
// else standing at the same name is not that, whatever it is.
//
// An identity that could not be READ is treated as a mismatch where the
// platform has identities at all (sameRecordedInode's rule): no proof, no
// archive. Off Linux there are none, and the comparison is not made — the same
// INV-2 degradation every identity check in this package accepts.
func (a *archiver) stillTheCheckedObject(got, want objectID, apiPath, what string) bool {
	if got.same(want) {
		return true
	}
	a.note(apiPath, fmt.Sprintf(
		"%s changed between the moment this archive was authorized and the moment it was reached, so it was not archived", what))
	return false
}

// parentIdentityOf is the held directory's own stat, or nil when it cannot be
// described — which sameRecordedInode reads as "no proof" on a platform that
// has identities.
func parentIdentityOf(d *dirRef) os.FileInfo {
	fi, err := d.stat()
	if err != nil {
		return nil
	}
	return fi
}

// reserve picks the member-name prefix one root's contents live under, and
// makes sure no two roots share one.
//
// The prefix is the root's own base name, so an archive of /share/Public/Photos
// extracts as "Photos/…" — the path relative to the selected root's PARENT
// (§2.2), which is what every file manager's "compress" produces. Two selected
// roots with the same base name get the copy engine's keep-both names, because
// an archive with two different "photos/" trees in it is one nobody can extract
// without losing half of it.
// A name is never handed out twice, whatever happens. The keep-both search is
// bounded like the copy engine's, but where the copy engine can refuse the
// entry and say so, an archive that gave up and returned a name already in use
// would write a SECOND member at that path — and extracting it would replace one
// of the two files with the other, silently (adversarial finding 7). So past the
// bound the allocator falls back to a counter, which cannot collide because
// every candidate is checked against the same set and the set is finite.
func (a *archiver) reserve(base string, isDir bool) string {
	switch base {
	case "", "/", ".", "..":
		base = "archive"
	}
	if !a.used[base] {
		a.used[base] = true
		return base
	}
	for n := 2; n < 2+maxKeepBothTries; n++ {
		cand, ok := keepBothWithin(base, isDir, n)
		if !ok {
			break
		}
		if !a.used[cand] {
			a.used[cand] = true
			return cand
		}
	}
	for {
		a.seq++
		// Bounded like everything else: a member whose name exceeds NAME_MAX
		// extracts to ENAMETOOLONG, and an archive that cannot be extracted is
		// not an archive (round 7 adversarial). Where even a suffix will not fit
		// beside the extension, a generated name is used instead — short by
		// construction, unique because the loop checks it, and better than a
		// member the user cannot unpack.
		cand, ok := keepBothWithin(base, isDir, a.seq+maxKeepBothTries+1)
		if !ok {
			cand = fmt.Sprintf("archive-item-%d", a.seq)
		}
		if !a.used[cand] {
			a.used[cand] = true
			return cand
		}
	}
}

// room reserves one member against BOTH bounds — the item count and the bytes
// of metadata the format will retain for it — and reports whether there was
// room. Reaching either ends the archive the way a fatal failure does:
// ERROR.txt, no trailer, and a client whose unzip says the file is damaged.
//
// The name is what makes the second bound necessary: it is the variable part of
// what is retained, and it is the part an attacker (or a badly behaved backup
// tool) controls.
func (a *archiver) room(name string) bool {
	if a.members >= archiveMemberCap {
		if a.fatal == nil {
			a.fatal = fmt.Errorf("%w: it stopped after %d entries", errArchiveFull, a.members)
		}
		return false
	}
	cost := int64(len(name)) + archiveHeaderOverhead
	if a.metaBytes+cost > archiveMetadataCap {
		if a.fatal == nil {
			a.fatal = fmt.Errorf("%w: it stopped after %d entries whose names alone needed %d bytes of memory",
				errArchiveFull, a.members, a.metaBytes)
		}
		return false
	}
	a.members++
	a.metaBytes += cost
	return true
}

// tree walks one selected directory on held descriptors and writes every entry
// under it. held is consumed by the walk.
func (a *archiver) tree(held *dirRef, rootAPI string, info os.FileInfo, prefix string) {
	v := Visitor{
		Pre: func(it WalkItem) error {
			if a.done() {
				// The only thing that stops a walk from inside a visitor, and
				// the only thing that should: the stream is gone.
				return errArchiveStopped
			}
			a.item(it, a.memberName(prefix, rootAPI, it))
			return nil
		},
		Warn: func(apiPath string, err error) { a.note(apiPath, err.Error()) },
	}
	err := walkFrom(a.ctx, a.r, a.plat, held, rootAPI, info, a.opts, v)
	switch {
	case err == nil, errors.Is(err, errArchiveStopped):
	case a.ctx.Err() != nil:
		a.fail(a.ctx.Err())
	default:
		a.note(rootAPI, err.Error())
	}
}

// errArchiveStopped ends a walk whose stream has gone. It never leaves this
// file.
var errArchiveStopped = errors.New("fsops: the archive stream ended")

// memberName is the path of one item relative to its root's PARENT, with
// forward slashes and the bytes the kernel gave (§2.2).
//
// It is derived from the walk's own Path — which was built by joining each
// name onto its parent as the walk descended — rather than rebuilt from the
// item's name, so a non-UTF-8 filename survives into the archive exactly as it
// is on the disk.
func (a *archiver) memberName(prefix, rootAPI string, it WalkItem) string {
	if it.Path == rootAPI {
		return prefix
	}
	rel := strings.TrimPrefix(it.Path, rootAPI)
	if rel == it.Path {
		// The walk left the subtree, which it cannot: name the item under the
		// prefix anyway rather than placing it outside the root it belongs to.
		return prefix + "/" + it.Name
	}
	if !strings.HasPrefix(rel, "/") {
		// rootAPI was "/" — the jail base — so the trim took the separator with
		// it rather than leaving one.
		rel = "/" + rel
	}
	return prefix + rel
}

// item writes one thing the walk reached.
func (a *archiver) item(it WalkItem, name string) {
	if !a.room(name) {
		return
	}
	switch {
	case it.isDir():
		if err := a.sink.addDir(name, it.Info); err != nil {
			a.fail(err)
		}
	case it.Info.Mode()&fs.ModeSymlink != 0:
		if it.parent == nil {
			a.note(it.Path, "a symlink at the root of a walk has no directory to read it through")
			return
		}
		a.symlink(it.parent, it.Name, it.Path, it.Info, name)
	case it.Info.Mode().IsRegular():
		if it.parent == nil {
			a.note(it.Path, "a file at the root of a walk has no directory to read it through")
			return
		}
		a.file(it.parent, it.Name, it.Path, it.Info, name)
	default:
		a.note(it.Path, fmt.Sprintf("a %s has no contents to archive and was skipped", fsx.TypeString(it.Info.Mode())))
	}
}

// symlink records a link as a link.
//
// The link is PINNED first and its target read from that descriptor, which is
// the same rule the directory branch follows and the one copyLink follows
// (round 14): the entry was classified by an lstat, and a readlinkat by name
// afterwards would read whatever link is at that name now — so the member could
// carry one link's metadata and another link's target. An O_PATH handle for the
// link itself settles it, and the identity check is what says the two lookups
// found one object.
func (a *archiver) symlink(dir *dirRef, name, apiPath string, info os.FileInfo, member string) {
	ref, err := itemRefIn(dir, name)
	if err != nil {
		a.note(apiPath, err.Error())
		return
	}
	defer ref.close()
	if same, known := sameObject(info, ref.fi); known && !same {
		a.note(apiPath, "it was replaced between being listed and being read, and was skipped")
		return
	}
	target, err := readlinkRef(ref, dir, name)
	if err != nil {
		a.note(apiPath, err.Error())
		return
	}
	// The metadata comes from the pinned descriptor too, for the same reason
	// the target does.
	if err := a.sink.addSymlink(member, ref.fi, target); err != nil {
		a.fail(err)
	}
}

// file copies one regular file's bytes into the archive.
//
// The descriptor decides, not the name. The walk classified the entry with an
// lstat; between that and this open the name could be anything, so the open is
// O_NOFOLLOW|O_NONBLOCK (a fifo would otherwise park the worker inside open(2)
// where no deadline reaches it) and the fstat that follows is what says whether
// there are bytes here to archive at all.
func (a *archiver) file(dir *dirRef, name, apiPath string, info os.FileInfo, member string) {
	f, err := dir.openFile(name, copyReadFlags, 0)
	if err != nil {
		a.note(apiPath, err.Error())
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		a.note(apiPath, err.Error())
		return
	}
	if !fi.Mode().IsRegular() {
		a.note(apiPath, fmt.Sprintf("it became a %s between being listed and being read, and was skipped",
			fsx.TypeString(fi.Mode())))
		return
	}
	if same, known := sameObject(info, fi); known && !same {
		a.note(apiPath, "it was replaced between being listed and being read, and was skipped")
		return
	}
	if err := clearNonblock(f); err != nil {
		a.note(apiPath, err.Error())
		return
	}

	size := fi.Size()
	w, err := a.sink.addFile(member, fi, size)
	if err != nil {
		a.fail(err)
		return
	}
	n, rerr, werr := a.copyInto(w, f, size)
	if werr != nil {
		a.fail(werr)
		return
	}
	if n < size {
		// The header has already promised this many bytes, and a tar member
		// short of its header is a broken archive rather than a short file. The
		// remainder is padded with zeros and the truth goes in ERROR.txt.
		if err := a.sink.padFile(size - n); err != nil {
			a.fail(err)
			return
		}
	}
	switch {
	case rerr != nil:
		a.note(apiPath, fmt.Sprintf("only %d of %d bytes could be read: %v", n, size, rerr))
	case n != size:
		a.note(apiPath, fmt.Sprintf("it was %d bytes when it was opened and %d could be read, so it is being written to", size, n))
	}
}

// copyInto moves at most limit bytes, checking the context once per buffer.
//
// It returns the read failure and the WRITE failure separately, because they
// mean opposite things: one file that cannot be read is a note, and a stream
// that cannot be written is the end of the archive.
func (a *archiver) copyInto(dst io.Writer, src io.Reader, limit int64) (n int64, rerr, werr error) {
	if a.buf == nil {
		a.buf = make([]byte, archiveBufSize)
	}
	for n < limit {
		if err := a.ctx.Err(); err != nil {
			return n, nil, err
		}
		chunk := a.buf
		if rest := limit - n; rest < int64(len(chunk)) {
			chunk = chunk[:rest]
		}
		read, err := src.Read(chunk)
		if read > 0 {
			wrote, wErr := dst.Write(chunk[:read])
			n += int64(wrote)
			if wErr != nil {
				return n, nil, wErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil, nil
			}
			return n, err, nil
		}
	}
	return n, nil, nil
}

// finish closes the archive: the trailer when the stream is sound, and no
// trailer at all when it is not.
func (a *archiver) finish() error {
	if a.sw.broken {
		// The reader went away. Nothing to report and nobody to report it to.
		return nil
	}
	if a.fatal == nil {
		if err := a.ctx.Err(); err != nil {
			a.fatal = err
		}
	}
	if a.fatal != nil {
		// Best effort, in this order: say what went wrong, then close WITHOUT
		// the trailer so the client's unzip reports a truncated file (§2.2).
		if errors.Is(a.fatal, errArchiveFull) {
			a.notes = append(a.notes, fmt.Sprintf(
				"this archive stopped after %d items, which is the most one download may hold; the rest of the selection is not in it",
				a.members))
		} else {
			a.notes = append(a.notes, "the archive was stopped before it was complete: "+a.fatal.Error())
		}
		_ = a.sink.addText(a.reserve(archiveNotesName, false), []byte(a.notesText()))
		_ = a.sink.flush()
		return a.fatal
	}
	if len(a.notes) > 0 {
		if err := a.sink.addText(a.reserve(archiveNotesName, false), []byte(a.notesText())); err != nil {
			a.fail(err)
			if a.fatal != nil {
				return a.fatal
			}
			return nil
		}
	}
	if err := a.sink.finish(); err != nil {
		a.fail(err)
		return a.fatal
	}
	return nil
}

func (a *archiver) notesText() string {
	var b strings.Builder
	b.WriteString("Some items could not be added to this archive.\n\n")
	for _, n := range a.notes {
		b.WriteString(n)
		b.WriteByte('\n')
	}
	if a.noteMore > 0 {
		fmt.Fprintf(&b, "\n…and %d more, not listed.\n", a.noteMore)
	}
	return b.String()
}

// sinkWriter is the archive's end of the pipe: it counts, and it remembers
// whether the far end simply went away.
type sinkWriter struct {
	w      io.Writer
	n      int64
	broken bool
}

func (sw *sinkWriter) Write(p []byte) (int, error) {
	n, err := sw.w.Write(p)
	sw.n += int64(n)
	if err != nil && readerGone(err) {
		sw.broken = true
	}
	return n, err
}

// readerGone reports that a write failed because the other end of the pipe is
// closed — the browser cancelling a download, or the front-end giving up on a
// client that disconnected. It is not a failure of this archive.
func readerGone(err error) bool {
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrClosed)
}

// archiveSink is the format-specific half: zip or tar+gzip, with the same five
// operations and the one difference that matters — a tar member's length is
// promised in its header and a zip member's is not.
type archiveSink interface {
	addDir(name string, fi os.FileInfo) error
	addSymlink(name string, fi os.FileInfo, target string) error
	// addFile opens a member and returns the writer for its content. size is
	// what the header promises; the caller must write exactly that many bytes
	// or pad the difference with padFile.
	addFile(name string, fi os.FileInfo, size int64) (io.Writer, error)
	padFile(missing int64) error
	addText(name string, body []byte) error
	// flush pushes what has been written so far out of the format's own
	// buffering, WITHOUT writing a trailer. It is what makes the truncated
	// archive of a failed job actually reach the client: both archive/zip and
	// compress/gzip buffer, so a stream abandoned without it would simply stop
	// several kilobytes earlier and the final ERROR.txt would never be seen.
	flush() error
	// finish writes the trailer. It is NOT called for an archive that failed.
	finish() error
}

func newArchiveSink(format string, w io.Writer) (archiveSink, error) {
	switch format {
	case ArchiveZip:
		return &zipSink{zw: zip.NewWriter(w)}, nil
	case ArchiveTGZ:
		gz := gzip.NewWriter(w)
		return &tarSink{gz: gz, tw: tar.NewWriter(gz)}, nil
	}
	return nil, fmt.Errorf("%q is not an archive format this app writes: %w", format, fsx.ErrBadName)
}

// storedMethod picks Store for something already compressed and Deflate for
// everything else (§2.2).
func storedMethod(name string) uint16 {
	if storeExtensions[strings.ToLower(path.Ext(name))] {
		return zip.Store
	}
	return zip.Deflate
}

type zipSink struct {
	zw *zip.Writer
}

// header builds one zip member's header from the entry's own lstat.
//
// NonUTF8 is set from the bytes rather than from a guess: a Linux filename is
// an arbitrary byte string, and marking one that is not UTF-8 with the
// language-encoding flag would tell every unzip on earth to decode it as UTF-8
// and produce U+FFFD. Unset, the bytes are handed over raw and the extractor
// applies whatever it does for legacy names — which is the only thing it can do
// with bytes that are not text in any encoding we know.
func zipHeader(name string, fi os.FileInfo, method uint16) *zip.FileHeader {
	h := &zip.FileHeader{Name: name, Method: method, NonUTF8: !utf8.ValidString(name)}
	if fi != nil {
		h.SetMode(fi.Mode())
		h.Modified = fi.ModTime()
	}
	return h
}

func (z *zipSink) addDir(name string, fi os.FileInfo) error {
	// A zip reader decides a member is a directory from its name ending in a
	// slash, and nothing else.
	_, err := z.zw.CreateHeader(zipHeader(name+"/", fi, zip.Store))
	return err
}

func (z *zipSink) addSymlink(name string, fi os.FileInfo, target string) error {
	w, err := z.zw.CreateHeader(zipHeader(name, fi, zip.Store))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(target))
	return err
}

func (z *zipSink) addFile(name string, fi os.FileInfo, size int64) (io.Writer, error) {
	// size is not carried into the header on purpose: archive/zip writes a data
	// descriptor after every member and puts the REAL lengths in it, and decides
	// Zip64 from what was actually written. A declared length here would be a
	// promise this code cannot keep for a file somebody is still writing to.
	_ = size
	return z.zw.CreateHeader(zipHeader(name, fi, storedMethod(name)))
}

// padFile has nothing to do for a zip: the member's real length is written into
// its data descriptor after the content, so a file that turned out shorter than
// its stat is simply a shorter member.
func (z *zipSink) padFile(int64) error { return nil }

// addText writes the notes member STORED rather than deflated, and that is not
// an optimisation: a deflated member's bytes sit inside the compressor until
// the entry is closed, and the entry is only closed by the next member or by
// the trailer — neither of which a truncated archive has. Stored, the bytes
// reach the buffered writer at once and flush can push them to the client.
func (z *zipSink) addText(name string, body []byte) error {
	h := &zip.FileHeader{Name: name, Method: zip.Store, Modified: archiveClock()}
	h.SetMode(0o644)
	w, err := z.zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func (z *zipSink) flush() error  { return z.zw.Flush() }
func (z *zipSink) finish() error { return z.zw.Close() }

type tarSink struct {
	gz *gzip.Writer
	tw *tar.Writer
}

// tarHeader builds one member's header from the entry's own lstat, through
// archive/tar's own constructor so that the mode, the times and (on Linux) the
// uid and gid come from the same place a tar(1) would take them.
func tarHeader(name string, fi os.FileInfo, link string) (*tar.Header, error) {
	h, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return nil, err
	}
	h.Name = name
	if fi.IsDir() {
		h.Name = name + "/"
	}
	// Neither the uid/gid names nor the "format" are ours to guess; what matters
	// is that a member's declared size is exactly what follows it.
	return h, nil
}

func (t *tarSink) addDir(name string, fi os.FileInfo) error {
	h, err := tarHeader(name, fi, "")
	if err != nil {
		return err
	}
	h.Size = 0
	return t.tw.WriteHeader(h)
}

func (t *tarSink) addSymlink(name string, fi os.FileInfo, target string) error {
	h, err := tarHeader(name, fi, target)
	if err != nil {
		return err
	}
	// A tar symlink carries its target in the header and has no content at all.
	h.Typeflag = tar.TypeSymlink
	h.Linkname = target
	h.Size = 0
	return t.tw.WriteHeader(h)
}

func (t *tarSink) addFile(name string, fi os.FileInfo, size int64) (io.Writer, error) {
	h, err := tarHeader(name, fi, "")
	if err != nil {
		return nil, err
	}
	h.Size = size
	if err := t.tw.WriteHeader(h); err != nil {
		return nil, err
	}
	return t.tw, nil
}

// padFile fills out a member whose file turned out shorter than its header
// promised. A tar stream has no length that can be corrected afterwards, so the
// choice is between padding and a broken archive; the ERROR.txt member says
// which file it happened to.
func (t *tarSink) padFile(missing int64) error {
	zeros := make([]byte, 32<<10)
	for missing > 0 {
		n := int64(len(zeros))
		if missing < n {
			n = missing
		}
		if _, err := t.tw.Write(zeros[:n]); err != nil {
			return err
		}
		missing -= n
	}
	return nil
}

func (t *tarSink) addText(name string, body []byte) error {
	h := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		ModTime:  archiveClock(),
		Typeflag: tar.TypeReg,
	}
	if err := t.tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := t.tw.Write(body)
	return err
}

// flush ends the current member's padding and pushes the gzip stream's own
// buffer out, without either trailer. A gzip stream that stops without its
// final CRC and length is what gunzip reports as unexpected EOF, which is
// exactly the message a half-downloaded archive should produce.
func (t *tarSink) flush() error {
	if err := t.tw.Flush(); err != nil {
		return err
	}
	return t.gz.Flush()
}

// finish writes tar's end-of-archive blocks and then flushes and ends the gzip
// stream. Neither is called for an archive that failed, which is what makes the
// truncation visible to the client.
func (t *tarSink) finish() error {
	if err := t.tw.Close(); err != nil {
		return err
	}
	return t.gz.Close()
}
