package wproto

import (
	"encoding/json"

	"qnapfilemanager/internal/fsx"
)

// Limits are the front-end's caps, handed to the worker at hello time so the
// worker can refuse oversized work itself rather than trusting each request.
type Limits struct {
	ListMax      int   `json:"listMax"`
	MaxTextBytes int64 `json:"maxTextBytes"`
}

// HelloReq is the first frame on a new worker connection.
type HelloReq struct {
	// JailRoot is the -jail directory, empty in production. It is applied
	// inside the worker, so nothing above it can address a path outside.
	JailRoot string `json:"jailRoot,omitempty"`
	// Umask is applied by the worker to itself; QTS's default is 0022.
	Umask  uint32 `json:"umask"`
	Limits Limits `json:"limits"`
}

// HelloResp lets the parent confirm it got the identity it asked for. The
// worker reports what the kernel actually gave it, not what it was told.
type HelloResp struct {
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Groups  []int  `json:"groups,omitempty"`
	PID     int    `json:"pid"`
	Version string `json:"version,omitempty"`
}

type ListReq struct {
	Dir  []byte          `json:"d"`
	Opts fsx.ListOptions `json:"o"`
}

type ListResp struct {
	Listing fsx.Listing `json:"l"`
}

type StatReq struct {
	Path []byte `json:"p"`
	// Follow stats the target of a symlink instead of the link itself.
	Follow bool `json:"f,omitempty"`
}

type StatResp struct {
	Entry fsx.Entry `json:"e"`
}

// CreateAs asks the worker to chown freshly created content after it is created,
// so an administrator session's root worker can make content owned by the real
// signed-in user — the way File Station does — instead of leaving it root-owned.
// UID or GID of -1 leaves that id as the kernel set it (so GID -1 keeps the
// group the parent's setgid bit supplied, i.e. administrators). A nil *CreateAs
// is the unchanged behaviour: root-owned, umask-applied.
//
// Mode is RESERVED; mkdir does not chmod — group-write/ACL changes are the M3
// permissions feature. An fchmod on the create path could widen a POSIX ACL mask
// or, on a hero dataset with aclmode=discard, drop inherited ACLs without the
// level-2 confirmation PLAN decision 12 requires, and clear the parent's setgid
// bit (findings B/D), so no M1 path applies it. The field is kept so the M2/M3
// create paths (copy, upload, chmod) can carry intent without a wire change.
//
// It is only meaningful for the root worker: a non-root worker asked to chown
// to another uid is refused by the kernel (EPERM), which is why the front-end
// sets it solely for an admin (root) session in an ordinary (guard-normal)
// location (see internal/web/routes_mutate.go).
type CreateAs struct {
	UID  int    `json:"u"`
	GID  int    `json:"g"`
	Mode uint32 `json:"m"` // reserved; mkdir does not chmod (M3 permissions feature)
}

type MkdirReq struct {
	Dir  []byte `json:"d"`
	Name []byte `json:"n"`
	Mode uint32 `json:"m"`
	// Parents creates missing intermediate directories.
	Parents bool `json:"p,omitempty"`
	// As, when non-nil, asks the worker to chown/chmod the created directory to
	// the given owner after creating it (the admin-as-real-user case). nil keeps
	// the current root-owned, umask-applied behaviour.
	As *CreateAs `json:"as,omitempty"`
}

type RenameReq struct {
	From      []byte `json:"f"`
	To        []byte `json:"t"`
	Overwrite bool   `json:"o,omitempty"`
}

type ChmodReq struct {
	Path []byte `json:"p"`
	Mode uint32 `json:"m"`
	// Follow chmods the target of a symlink. A symlink's own mode is
	// meaningless on Linux, so the default is to refuse rather than to
	// silently change the target.
	Follow bool `json:"f,omitempty"`
}

// ChownReq changes ownership. -1 leaves that half alone, matching chown(2).
type ChownReq struct {
	Path []byte `json:"p"`
	UID  int    `json:"u"`
	GID  int    `json:"g"`
	// Follow chowns through a symlink; the default is lchown.
	Follow bool `json:"f,omitempty"`
}

// ChownReq/ChmodReq reply with the post-call Entry so the front-end can diff
// what was asked against what the kernel did (INV-2, and the partial-success
// reporting in PLAN.md decision 12).
type ModeResp struct {
	Entry fsx.Entry `json:"e"`
}

type ReadlinkReq struct {
	Path []byte `json:"p"`
}

// ResolveReq asks the worker to resolve an API path to its canonical spelling
// as the user, so the O_PATH walk enforces the caller's own traversal
// permissions (INV-2) rather than the root front-end resolving symlinks it
// could reach but the user could not. FollowLeaf resolves the whole path (an
// existing directory); when it is false the parent is resolved and the final
// component is kept literal (a named entry to create, rename or delete).
type ResolveReq struct {
	Path       []byte `json:"p"`
	FollowLeaf bool   `json:"l,omitempty"`
}

// ResolveResp carries the canonical API path. It is bytes for the same reason
// every other name here is: a non-UTF-8 Linux filename survives the round trip.
type ResolveResp struct {
	Path []byte `json:"p"`
}

type ReadlinkResp struct {
	Target []byte `json:"t"`
	// Resolved is the fully evaluated target, empty when dangling or looping.
	Resolved []byte `json:"r,omitempty"`
}

// OpenReadReq asks the worker to open a file as the user. The reply carries
// the fd on the frame (NFD:1) plus the stat the front-end needs for
// http.ServeContent. The kernel checks permission at open(2) time; the root
// front-end holding the resulting fd afterwards is intentional and safe,
// because that fd can only be what the user was allowed to open.
type OpenReadReq struct {
	Path []byte `json:"p"`
}

type OpenReadResp struct {
	Entry fsx.Entry `json:"e"`
}

// OpenWriteReq asks the worker to create the upload's file AS THE USER and hand
// back its descriptor (M2-C contract §1): unnamed (O_TMPFILE) where the kernel
// allows, so no name can reach it before Finalize publishes it, else a
// .qfm-upload-<hex>.part created O_EXCL in the destination directory. The
// front-end streams the request body into that descriptor and never creates
// a file itself. Size is the declared length for the free-space check (0 =
// unknown); As is the owner an admin's upload is chowned to, gated by the
// route exactly as mkdir (chown only, never chmod); Mode is ignored — the file
// is created 0644 under the umask and the destination's inherited ACL.
type OpenWriteReq struct {
	Dir      []byte    `json:"d"`
	Name     []byte    `json:"n"`
	Mode     uint32    `json:"m"`
	Size     int64     `json:"s,omitempty"`
	MTime    int64     `json:"mt,omitempty"`
	Conflict string    `json:"c,omitempty"`
	As       *CreateAs `json:"as,omitempty"`
	// DirIdentity is the identity Dir had when the front end authorized this
	// upload. The worker opens the destination only when the file part's
	// headers arrive, and the client controls the gap in between: rename the
	// authorized directory away, put a symlink to somewhere else in its place,
	// then send the body. Binding the open to the inode closes that window —
	// the worker refuses with "changed" when the directory it opens is not the
	// one that was cleared. Nil means the caller could not identify it and no
	// binding is asked for.
	DirIdentity *FSIdentityResp `json:"di,omitempty"`
}

// OpenWriteResp.Tmp is an opaque handle the worker keeps for the open inode
// until Finalize (or its expiry), never a path. The descriptor rides on the
// frame (NFD = 1).
type OpenWriteResp struct {
	Tmp []byte `json:"t"`
}

// FinalizeReq publishes (or discards) an upload the front-end has finished
// streaming.
type FinalizeReq struct {
	Tmp       []byte `json:"t"`
	Final     []byte `json:"f"`
	Mode      uint32 `json:"m"`
	MTimeUnix int64  `json:"mt,omitempty"`
	Conflict  string `json:"c,omitempty"`
	// Discard aborts: unlink the .part and report nothing else.
	Discard bool `json:"x,omitempty"`
}

type FinalizeResp struct {
	Entry fsx.Entry `json:"e"`
	// Path is where the file actually landed, which differs from Final when
	// Conflict was "rename".
	Path []byte `json:"p"`
}

// ArchiveReq is the body of OpArchive (M2-C contract §2): the trees to stream
// as one archive. Format is "zip" or "tgz". The reply carries the pipe's read
// end; the worker walks the trees on held descriptors and writes into the
// write end until it is done, the reader goes away, or a fatal error makes it
// append a final ERROR.txt member and close without the trailer.
type ArchiveReq struct {
	Paths       [][]byte `json:"p"`
	Format      string   `json:"f"`
	CrossMounts bool     `json:"x,omitempty"`
}

// ArchiveResp names the archive the front-end should offer for download, and
// identifies the producer so its outcome can be asked for afterwards.
type ArchiveResp struct {
	Name []byte `json:"n"`
	// ID names this archive's producer inside the worker, for OpArchiveStatus.
	// It is empty only from a worker too old to have one.
	ID string `json:"id,omitempty"`
}

// ArchiveStatusReq asks what became of one archive (OpArchiveStatus).
type ArchiveStatusReq struct {
	ID string `json:"id"`
}

// ArchiveStatusResp is the producer's verdict.
//
// Done is false while it is still writing, which is the honest answer to a
// front-end that asks too early. Truncated says the client's copy is NOT the
// whole archive: the walk was stopped by a fatal failure, by cancellation or by
// the member bound, and the trailer was deliberately not written — so an
// audit record must say "truncated" rather than "ok" however cleanly the pipe
// ended. Error carries the reason for a log; it is never shown verbatim.
type ArchiveStatusResp struct {
	Done      bool   `json:"d"`
	Truncated bool   `json:"t,omitempty"`
	Bytes     int64  `json:"b,omitempty"`
	Error     string `json:"e,omitempty"`
}

// SearchReq is the body of a JobSearch (M2-C contract §3). Query is a
// case-insensitive substring of the entry name, or a path.Match pattern when
// Glob is set. The caps are sent by the route and clamped by the worker.
type SearchReq struct {
	Roots       [][]byte `json:"r"`
	Query       string   `json:"q"`
	Glob        bool     `json:"g,omitempty"`
	Hidden      bool     `json:"h,omitempty"`
	CrossMounts bool     `json:"x,omitempty"`
	Kind        string   `json:"k,omitempty"` // "" | "any" | "file" | "dir"
	MaxHits     int      `json:"mh,omitempty"`
	MaxVisited  int64    `json:"mv,omitempty"`
	MaxDuration int64    `json:"md,omitempty"` // seconds
}

// TextReq reads or writes a small text file whole. Size is bounded by
// Limits.MaxTextBytes on both sides.
type TextReq struct {
	Path  []byte `json:"p"`
	Write bool   `json:"w,omitempty"`
	Data  []byte `json:"d,omitempty"`
}

type TextResp struct {
	Data []byte `json:"d,omitempty"`
	// Truncated is set when the file was longer than the limit.
	Truncated bool      `json:"t,omitempty"`
	Entry     fsx.Entry `json:"e"`
}

// JobReq starts one long-lived RPC. Progress and per-item warnings come back
// on the same request ID until a terminal ok or err frame closes it.
type JobReq struct {
	JobID string          `json:"j"`
	Kind  string          `json:"k"`
	Body  json.RawMessage `json:"b"`
}

// CancelReq is a separate, immediate RPC on its own ID; the worker looks the
// work up in its own tables and cancels the context it runs under.
type CancelReq struct {
	// JobID cancels a long-running job (M2).
	JobID string `json:"j,omitempty"`
	// ReqID cancels one in-flight request by the frame ID it was sent with.
	// The front-end sends this the moment a caller's context is done, because
	// unregistering the caller stops nobody: a worker whose request context was
	// never cancelled keeps its slot — and, for a fifo or a directory on a
	// wedged mount, its blocked syscall — long after the browser has gone.
	ReqID uint64 `json:"r,omitempty"`
}

// CopyOptions are the per-job knobs shared by copy and move. They live here
// rather than in fsx because fsx carries no mutation code; internal/fsops will
// consume this type as given.
type CopyOptions struct {
	Conflict       string `json:"conflict,omitempty"`
	PreserveMode   bool   `json:"preserveMode,omitempty"`
	PreserveTimes  bool   `json:"preserveTimes,omitempty"`
	FollowSymlinks bool   `json:"followSymlinks,omitempty"`
	// CrossMounts allows the walk to descend into mounts of the same storage
	// domain — "include mounted sub-folders" in the UI. It never permits
	// /proc, /sys, /dev, tmpfs, USB disks, other pools or network mounts.
	CrossMounts bool `json:"crossMounts,omitempty"`
	// As is the owner for every entry a COPY creates — the same chown-only rule
	// as MkdirReq.As (never chmod; GID -1 = inherit), gated by the front-end the
	// same way: only for an admin operating as root, only when both spellings of
	// the destination directory classify "normal". Ignored for a move, which
	// preserves the source owner when the worker's euid is 0 — what the rename
	// would have done (M2-B contract §1.4).
	As *CreateAs `json:"as,omitempty"`
}

// CopyReq is the body of a JobCopy and of a JobMove: one engine, two kinds
// (M2-B contract §1.1). A move tries renameat2 per source first and falls back
// to copy, verify, then delete the source — and deletes a root's source only
// when that root copied with zero warnings and zero skips.
//
// Conflict is ConflictSkip (the default when empty), ConflictOverwrite or
// ConflictRename ("keep both": "name (2).ext"). It applies to non-directory
// entries; directories always merge. PreserveTimes: the route always sends it;
// the engine treats an omitted value as true. PreserveMode is accepted and
// ignored — the creation mode is srcMode&0777 under the umask and the
// destination's inherited ACL, and no chmod is ever issued (§1.5).
type CopyReq struct {
	Src    [][]byte    `json:"s"`
	DstDir []byte      `json:"d"`
	Opts   CopyOptions `json:"o"`
}

// FSIdentityReq asks OpFSIdentity about one path — the entry itself, never
// followed, so a symlink answers for the link.
type FSIdentityReq struct {
	Path []byte `json:"p"`
}

// FSIdentityResp is the mount identity of the opened descriptor: the statx
// mount id when the kernel gives one (bind mounts share a st_dev, so the mount
// id is what tells datasets and shares apart — astra-per-user-review §46), and
// st_dev always. Two paths with equal identities rename between each other;
// two with different identities are predicted EXDEV.
type FSIdentityResp struct {
	Mount    uint64 `json:"m,omitempty"`
	HasMount bool   `json:"hm,omitempty"`
	Dev      uint64 `json:"d"`
	Dir      bool   `json:"dir"`
	// Ino names the entry itself rather than the filesystem holding it. Same
	// device and same inode is the same directory, whatever it is now called
	// and whatever a symlink of that name points at today — which is what lets
	// an upload be bound to the directory that was authorized rather than to
	// the pathname that was authorized (M2-C round-13 P1).
	Ino uint64 `json:"i"`
	// Btime is the object's creation time in unix nanoseconds (statx
	// STATX_BTIME), and HasBtime says the filesystem gave one.
	//
	// It exists because device and inode identify an object perfectly while it
	// exists and not at all across a gap, and the gaps here are the client's to
	// choose: it decides when an upload's body arrives, and an archive reaches
	// its later roots minutes after they were authorized. An inode number is
	// freed with its object and may be handed straight back, so somebody who
	// can remove and recreate an entry can loop until the number repeats and
	// the identity check agrees about the wrong object (M2-C round-14
	// adversarial). Birth time is set once at creation and no interface
	// changes it, so a recycled number carries a different one.
	//
	// Where the filesystem does not record it — HasBtime false on EITHER side —
	// the comparison degrades to device and inode, which is what it was before.
	// ext4, XFS, btrfs and ZFS all record it; the degradation is for the ones
	// that do not, and for a kernel too old for statx.
	Btime    int64 `json:"bt,omitempty"`
	HasBtime bool  `json:"hb,omitempty"`
}

// SameInode reports whether two identities name the same ENTRY: the same inode
// on the same device. Same is the weaker question — one filesystem — and the
// two are not interchangeable: every directory on a volume answers Same, and
// only one answers SameInode.
// Birth time is compared as well when both sides have one, because an inode
// number alone is only an identity while the object is alive: freed, it can be
// handed back to the next thing created at that name, and a client that
// controls the gap can make that happen on purpose (round 14 adversarial).
func (a FSIdentityResp) SameInode(b FSIdentityResp) bool {
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Ino == 0 {
		return false
	}
	if a.HasBtime && b.HasBtime {
		return a.Btime == b.Btime
	}
	return true
}

// Same reports whether two identities name one filesystem: by mount id when
// both sides have one, else by device.
func (a FSIdentityResp) Same(b FSIdentityResp) bool {
	if a.HasMount && b.HasMount {
		return a.Mount == b.Mount
	}
	return a.Dev == b.Dev
}

type DeleteReq struct {
	Paths     [][]byte `json:"p"`
	Recursive bool     `json:"r,omitempty"`
	// Trash renames into the nearest .@qfm_trash instead of unlinking.
	Trash bool `json:"t,omitempty"`
	// CrossMounts lets the recursive walk descend into mounts of the same
	// storage domain ("include mounted sub-folders"); see CopyOptions.CrossMounts.
	CrossMounts bool `json:"x,omitempty"`
}

// DeleteOneReq removes a single item (OpDelete, M1): a file, an empty
// directory, or a symlink (the link itself, never its target). A non-empty
// directory comes back as not_empty rather than being recursed into —
// recursive delete and trash are the job-shaped DeleteReq above, in M2.
type DeleteOneReq struct {
	Path []byte `json:"p"`
}

// Prog is a progress update on a running job. The worker coalesces these to
// at most 10 a second or one per 8 MiB, whichever comes first, so a
// million-file delete does not flood the socket.
type Prog struct {
	Files      int64  `json:"f,omitempty"`
	FilesTotal int64  `json:"ft,omitempty"`
	Bytes      int64  `json:"b,omitempty"`
	BytesTotal int64  `json:"bt,omitempty"`
	Current    []byte `json:"c,omitempty"`
	Phase      string `json:"p,omitempty"`
}

// Warn is a per-item failure inside a job: it does not end the job, it is
// collected and reported alongside the result.
type Warn struct {
	Path    []byte `json:"p"`
	Code    string `json:"c"`
	Message string `json:"m"`
	Errno   int    `json:"n,omitempty"`
}

// ---- Jobs (M2) --------------------------------------------------------------
//
// The job kinds themselves (JobDelete, JobSize, JobTrashRestore, ...) live in
// wproto.go beside the ops. The worker dispatches on them; the front-end's
// jobs.Manager sorts them into the byte-mover and metadata semaphore classes
// (design §3). A delete-to-trash is JobDelete with DeleteReq.Trash set; the
// older JobTrash kind is accepted by the worker as the same thing.

// WarnCap bounds JobResult.Warns; beyond it only Warnings counts.
const WarnCap = 100

// JobResult is the body of a job's terminal OK frame. It is also the job's
// durable summary: the worker folds its per-item failures in here (capped),
// so a Warn frame dropped by a slow reader is never a lost record.
type JobResult struct {
	Files   int64 `json:"f"`           // items completed (deleted, sized, restored, copied)
	Bytes   int64 `json:"b"`           // bytes accounted
	Dirs    int64 `json:"d,omitempty"` // directories completed
	Skipped int64 `json:"s,omitempty"` // items skipped by policy or by a per-item failure
	// Warnings is the TOTAL number of per-item failures; Warns carries the
	// first WarnCap of them verbatim.
	Warnings int    `json:"w,omitempty"`
	Warns    []Warn `json:"ws,omitempty"`
	Detail   string `json:"m,omitempty"`
	// Cancelled marks a job that stopped on cancellation. The worker still
	// sends the terminal as an OK frame carrying this partial result — the
	// counts and the folded warnings are the authoritative record of what
	// actually happened, and an Err frame has no body to carry them (M2-A
	// review round 1, finding 7). The pool returns the result together with
	// context.Canceled so the manager keeps the structured partial data.
	Cancelled bool `json:"cancelled,omitempty"`
	// TrashIDs are the trash entry ids ("<unix>-<8hex>") a delete-to-trash job
	// created, in path order, so the UI's Undo can restore exactly those
	// entries instead of guessing from origPath and time (M2-A web review).
	TrashIDs []string `json:"tids,omitempty"`
	// Hits are a search job's matches in walk order, capped by SearchReq.MaxHits
	// (M2-C). Detail says when the cap was hit.
	Hits []fsx.Entry `json:"hits,omitempty"`
}

// SizeReq measures trees: files, directories and bytes under each path.
type SizeReq struct {
	Paths       [][]byte `json:"p"`
	CrossMounts bool     `json:"x,omitempty"`
}

// TrashListReq lists the caller's own trashed items (OpTrashList — a plain
// request, not a job, so the panel opens without a job round-trip).
type TrashListReq struct{}

// TrashItem is one entry under <trash>/<uid>/. ID is the entry directory's
// name ("<unix>-<8hex>"); the original path and stat come from its sidecar.
type TrashItem struct {
	ID       string `json:"i"`
	Name     []byte `json:"n"` // original basename
	OrigPath []byte `json:"o"` // original API path
	Type     string `json:"t"` // "dir" | "file" | "symlink" | ...
	// Size is the bytes of the whole item — the whole tree, for a directory —
	// and -1 when they are not known: the worker's trash-time scan hit its bound,
	// or the sidecar was written by a build that recorded only the directory
	// inode's own size. -1 is "unknown", never "empty", and never a floor.
	Size int64 `json:"s"`
	// Files is how many entries those bytes are: 1 for a single item, and for a
	// directory everything under it including itself. -1 when unknown.
	Files     int64  `json:"f"`
	DeletedAt int64  `json:"d"` // unix seconds
	Trash     []byte `json:"r"` // API path of the .@qfm_trash root holding it
}

type TrashListResp struct {
	Items []TrashItem `json:"items"`
}

// TrashRestoreReq moves items back to their original paths (job kind
// trash-restore). IDs are TrashItem.ID values.
type TrashRestoreReq struct {
	IDs []string `json:"i"`
}

// TrashEmptyReq permanently deletes everything in the caller's own trash
// (job kind trash-empty).
type TrashEmptyReq struct{}
