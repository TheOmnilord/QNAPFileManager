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

// CreateAs asks the worker to chown (and optionally chmod) freshly created
// content after it is created, so an administrator session's root worker can
// make content owned by the real signed-in user — the way File Station does —
// instead of leaving it root-owned. UID or GID of -1 leaves that id as the
// kernel set it (so GID -1 keeps the group the parent's setgid bit supplied,
// i.e. administrators); Mode 0 leaves the mode the umask produced. A nil
// *CreateAs is the unchanged behaviour: root-owned, umask-applied.
//
// It is only meaningful for the root worker: a non-root worker asked to chown
// to another uid is refused by the kernel (EPERM), which is why the front-end
// sets it solely for an admin (root) session in an ordinary (guard-normal)
// location (see internal/web/routes_mutate.go). It is carried on MkdirReq here
// and reserved for the M2 create paths (copy, upload) as they land.
type CreateAs struct {
	UID  int    `json:"u"`
	GID  int    `json:"g"`
	Mode uint32 `json:"m"`
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

// OpenWriteReq creates <dir>/.qfm-upload-<hex>.part with
// O_WRONLY|O_CREAT|O_EXCL and mode 0600, owned by the worker's uid, and
// returns its fd. The front-end streams the request body into it and never
// creates a file itself.
type OpenWriteReq struct {
	Dir  []byte `json:"d"`
	Name []byte `json:"n"`
	Mode uint32 `json:"m"`
}

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
}

type CopyReq struct {
	Src    [][]byte    `json:"s"`
	DstDir []byte      `json:"d"`
	Opts   CopyOptions `json:"o"`
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
	ID        string `json:"i"`
	Name      []byte `json:"n"` // original basename
	OrigPath  []byte `json:"o"` // original API path
	Type      string `json:"t"` // "dir" | "file" | "symlink" | ...
	Size      int64  `json:"s"`
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
