package wproto

import (
	"encoding/json"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
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

// ChmodReq changes an entry's mode bits. The change travels as a perm.ModeSpec
// (mask + value), never as an absolute mode: a mixed selection, a recursive
// apply over modes nobody has seen, and the three special bits are then all one
// mechanism (m3-contract §1.1).
type ChmodReq struct {
	Path []byte        `json:"p"`
	Spec perm.ModeSpec `json:"s"`
	// Follow is INERT in M3 and is never set by the route.
	//
	// A symlink's own mode is meaningless on Linux (there is no lchmod), so the
	// worker refuses a symlink leaf as unsupported and never follows one. A
	// caller that wants the target changed resolves the path itself and guards
	// the target as a path of its own (contract §1.4), which is what the web
	// route does — so what reaches here is already the object to change. The
	// field is kept so the wire shape does not move under a worker that was
	// built against it.
	Follow bool `json:"f,omitempty"`
	// Expect, when set, is the precondition the route graded on: the ACL state
	// and the filesystem identity Props reported for this object a moment ago.
	// The worker re-probes the held descriptor and refuses `changed` when either
	// has moved (Astra M3 round-1 finding 4) — swapping a non-trivial file over
	// the name between the confirmation and the change would otherwise discard an
	// ACL the user was never warned about. A job grades with ACLUnknown and can
	// promise nothing per entry, so it sends none.
	Expect *ACLExpect `json:"x,omitempty"`
}

// ACLExpect is what the confirmation was graded against (m3-contract §8.1 as
// amended): the per-object ACL state and the identity of the object the state
// was read from.
//
// Both halves are OBSERVATIONS, not grades (Astra M3 round-2 finding 1). The
// route grades an unreadable or unplaceable object pessimistically and still
// sends what Props actually saw, because the worker can only re-prove what was
// seen. An EMPTY State therefore means "nothing was observed", never "this
// object has no ACL".
//
// So the worker reads a request exactly three ways, and nothing else:
//
//   - No expectation at all (nil): nothing is proved. That is a recursive job,
//     which grades no entry individually and can promise nothing about one.
//   - State "": the IDENTITY alone is proved. There is no observation to hold
//     the object to, and re-probing to manufacture one would refuse a change
//     nobody tampered with — the mount probe that decides whether there is a
//     backend to read runs asynchronously after a refresh, so an unplaced mount
//     during Props can be a real backend by the time the chmod arrives.
//   - State non-empty: the identity AND the state are proved, and either moving
//     is `changed`.
//
// The identity half has its own degradation, and it is the mirror of the above:
// where NEITHER side carries an inode, on a platform that has none to carry
// (off Linux, §14), there is nothing to compare and the state alone is proved.
// An expectation with an empty state on such a platform proves nothing, which is
// correct rather than lax — the route sent nothing it had learned, and the
// kernel that decides is not this one (INV-2).
type ACLExpect struct {
	State    string         `json:"s"`
	Identity FSIdentityResp `json:"id"`
}

// ChownReq changes ownership. -1 leaves that half alone, matching chown(2).
type ChownReq struct {
	Path []byte `json:"p"`
	UID  int    `json:"u"`
	GID  int    `json:"g"`
	// Follow chowns through a symlink. Chown is ALWAYS lchown in M3 — a
	// symlink's own ownership is what changes — so a request that sets this is
	// refused as unsupported, leaving exactly one chown semantics to reason
	// about (m3-contract §1.4).
	Follow bool `json:"f,omitempty"`
}

// ChownReq/ChmodReq reply with the pre- and post-call Entry plus the fields the
// kernel did not do as asked, so the caller can show the DIFF (INV-2, and the
// partial-success reporting in PLAN.md decision 12). The worker computes the
// diff because it is the only side holding the pre-call state of the same
// inode, and INV-1 forbids the front end from looking (m3-contract §3.1).
type ModeResp struct {
	Before fsx.Entry   `json:"b"`
	Entry  fsx.Entry   `json:"e"`
	Diffs  []perm.Diff `json:"d,omitempty"`
}

// ChmodJobReq is the recursive/multi-item chmod (m3-contract §9). Files and
// Dirs are separate specs so "apply to files only" is expressed by a zero mask
// rather than by a mode the server would have to interpret; #pSmartX is a
// client-side preset over these two and the server has no smart-X of its own.
type ChmodJobReq struct {
	Paths       [][]byte      `json:"p"`
	Files       perm.ModeSpec `json:"fs"`
	Dirs        perm.ModeSpec `json:"ds"`
	Recursive   bool          `json:"r,omitempty"`
	CrossMounts bool          `json:"x,omitempty"`
}

// ChownJobReq is the recursive/multi-item chown. -1 leaves that half alone.
type ChownJobReq struct {
	Paths       [][]byte `json:"p"`
	UID         int      `json:"u"`
	GID         int      `json:"g"`
	Recursive   bool     `json:"r,omitempty"`
	CrossMounts bool     `json:"x,omitempty"`
}

// PropsReq asks for everything the properties dialog shows about one entry.
type PropsReq struct {
	Path []byte `json:"p"`
	// Target is the symlink's already-RESOLVED, already-GUARDED spelling, and it
	// is the only thing that fills PropsResp.Target (M3 round-3 review).
	//
	// The worker used to resolve the link itself, with a following StatFollow on
	// the leaf. That is a second resolution separated from the route's guard by a
	// gap the client chooses, so a link re-pointed inside it was described from a
	// path the guard had never seen — the round-14 lesson (canonical.go) applied
	// to a read. Now the route resolves it as the user, guards THAT spelling, and
	// sends it here; the worker walks it O_NOFOLLOW per component and refuses a
	// symlink among them as fsx.ErrChanged.
	//
	// Empty means "no target": the link is still fully described, which is what
	// a dangling one — for which the route has no resolved spelling to send —
	// needs (§8.1).
	Target []byte `json:"t,omitempty"`
	// Follow is INERT. It was what asked the worker to resolve the link, and
	// resolving in the worker is precisely what Target replaces; it is kept on
	// the wire so a worker and a front-end of different vintages still speak,
	// and a request that sets it and sends no Target simply gets no target.
	Follow bool `json:"f,omitempty"`
}

// PropsResp is one canonical walk, one fstat, one fstatfs and one xattr probe
// on the held descriptor. The field names are readable rather than terse
// because, unlike every other message here, this one is forwarded to the client
// essentially as it stands (m3-contract §10's properties route).
type PropsResp struct {
	Entry    fsx.Entry      `json:"e"`
	Target   *fsx.Entry     `json:"t,omitempty"`
	FS       FSInfo         `json:"fs"`
	ACL      ACLInfo        `json:"acl"`
	Identity FSIdentityResp `json:"id"`
}

// FSInfo describes the filesystem holding the entry. Avail/Total come from
// fstatfs on the held descriptor, so on a per-share hero dataset they are the
// dataset's numbers; where fstatfs is unavailable they are omitted rather than
// invented (m3-contract §8.2, §14).
type FSInfo struct {
	FSType   string `json:"fsType,omitempty"`
	Mount    string `json:"mount,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Network  bool   `json:"network,omitempty"`
	ReadOnly bool   `json:"readOnly,omitempty"`
	Avail    uint64 `json:"avail,omitempty"`
	Total    uint64 `json:"total,omitempty"`
}

// ACLInfo is the authoritative display copy of an entry's ACL situation:
// which backend the mount has, which xattr answered, the per-entry STATE
// (m3-contract §6.1), and — on ZFS — the dataset and its aclmode.
type ACLInfo struct {
	Backend string `json:"backend,omitempty"`
	Xattr   string `json:"xattr,omitempty"`
	State   string `json:"state,omitempty"`
	Aclmode string `json:"aclmode,omitempty"`
	Dataset string `json:"dataset,omitempty"`
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
	// Capped marks a measurement that stopped at SizeReq.MaxEntries. The counts
	// are then a MINIMUM, not a total, and a caller deciding something from them
	// (the M3 pre-scan) must read the whole answer as "unknown" rather than as
	// the number it happens to carry.
	Capped bool `json:"cp,omitempty"`
	// MountsSkipped counts the local STORAGE mount points a search or a size walk
	// reached and did not enter: another volume or pool, or any storage mount at
	// all with CrossMounts off. The mount point itself is still visited (and a
	// hit if its name matches); only what is under it went unexamined, and a
	// search rooted inside it can look. A mount that is not Storage (/proc, /sys,
	// /dev, a tmpfs) or that the walk could not identify is not counted: nobody
	// can search inside it (Astra r2 on the QKVM fix). It is a count, not a list,
	// so the frame stays bounded however many shares a tree holds, and omitempty
	// keeps an older peer's frames byte-identical.
	MountsSkipped int64 `json:"ms,omitempty"`
	// MountsNetwork counts the NETWORK mounts the walk refused from the mount
	// table alone (NFS, CIFS, FUSE). They are kept apart from MountsSkipped
	// because the advice differs (Astra r1 on the QKVM fix): no search enters a
	// network share, whether by crossing or as its root, so "search inside it"
	// would be a promise the app cannot keep.
	MountsNetwork int64 `json:"mn,omitempty"`
}

// SizeReq measures trees: files, directories and bytes under each path.
type SizeReq struct {
	Paths       [][]byte `json:"p"`
	CrossMounts bool     `json:"x,omitempty"`
	// ReadCross opts this measurement into platform.MayCrossRead (PLAN.md
	// decision 9, amended): from a non-storage parent such as the tmpfs /share
	// the walk may enter a storage volume. The folder-size route sets it when the
	// client asks (Properties does; the Permissions impact estimate does not).
	// The pre-scans that measure in order to confirm a change (permissions,
	// transfer) leave it off, so their count is the one the change will walk.
	ReadCross bool `json:"rx,omitempty"`
	// MaxEntries bounds the walk. Zero is the size job's own default; a caller
	// that is measuring in order to decide something — the M3 permissions
	// pre-scan, which runs inside a 15 s request — passes the contract's 500 000
	// bound so an enormous tree ends the walk instead of the request. A walk that
	// hit the bound answers Capped, and a capped measurement is not a count.
	MaxEntries int64 `json:"me,omitempty"`
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
