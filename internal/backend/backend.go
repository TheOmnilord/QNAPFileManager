// Package backend defines the boundary between the root front-end (internal/web)
// and whatever executes filesystem operations on behalf of a user. In production
// the implementation is internal/workerpool, which forwards every call to a
// worker process running with the user's own credentials (PLAN.md INV-1). Tests
// and the Windows dev loop use an in-process implementation.
//
// Paths are API paths: absolute, slash-separated, already passed through
// fsx.Clean. Non-UTF-8 names travel as raw bytes inside the strings; callers
// must not assume valid UTF-8.
package backend

import (
	"context"
	"io"
	"os"
	"strconv"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// Principal is the resolved identity a request runs as. Root is true only for
// an administrator session that has explicitly armed root mode; every other
// session carries its own uid, gid and supplementary groups.
type Principal struct {
	User   string
	UID    int
	GID    int
	Groups []int
	Root   bool
}

// Key returns the pool key for this principal: "root" for root mode, otherwise
// the uid. Workers are shared per key, never per session.
func (p Principal) Key() string {
	if p.Root {
		return "root"
	}
	return "uid:" + itoa(p.UID)
}

// Backend executes read-only filesystem operations as a principal. Mutating
// operations are added in M1 (see docs/design/identity-and-hero-plan.md §2.5).
type Backend interface {
	// List returns one page of a directory listing.
	List(ctx context.Context, who Principal, dir string, opts fsx.ListOptions) (fsx.Listing, error)
	// Stat returns a single entry without following the final symlink.
	Stat(ctx context.Context, who Principal, path string) (fsx.Entry, error)
	// Readlink returns the raw target of a symlink.
	Readlink(ctx context.Context, who Principal, path string) (string, error)
	// OpenRead opens a regular file for reading as the principal. The kernel
	// performs the permission check at open time; the caller only streams
	// bytes and must Close the file.
	OpenRead(ctx context.Context, who Principal, path string) (*os.File, fsx.Entry, error)
	// Ping checks that the principal's worker is alive (spawning it if needed).
	Ping(ctx context.Context, who Principal) error
	// Archive streams the requested trees as one zip or tar.gz, produced by
	// the principal's worker into a pipe whose read end is returned (M2-C
	// contract §2). The caller copies it to the response and must Close it —
	// closing early is how a departed client stops the worker's walk.
	Archive(ctx context.Context, who Principal, req wproto.ArchiveReq) (ArchiveStream, wproto.ArchiveResp, error)
	// Props reports everything the properties dialog shows about one entry:
	// the entry, a followed symlink's target, the filesystem, the ACL state and
	// the mount identity — all from ONE canonical walk on a held descriptor
	// inside the worker (M3 contract §8.1). It is a plain read, not a job.
	Props(ctx context.Context, who Principal, req wproto.PropsReq) (wproto.PropsResp, error)
}

// ArchiveStream is an archive being produced: the bytes, and the one question a
// pipe cannot answer.
//
// A stream that ends because the walk was cancelled, hit its item bound or
// failed mid-way closes exactly the way a complete one does — clean EOF — so a
// route that audited "ok" on EOF was recording a truncated download as a
// successful one (M2-C review round 1 adversarial, finding 6). Outcome asks the
// worker that produced it what actually happened, and it is asked AFTER the
// copy loop ends: before that the honest answer is "still producing"
// (ArchiveStatusResp.Done false).
//
// Close releases the worker the producer is running on and must be called
// exactly once, whether the download completed or the client disconnected.
type ArchiveStream interface {
	io.ReadCloser
	// Outcome reports what became of the archive. It may be called before or
	// after Close; after is the ordinary case, because the copy loop is what
	// ends first.
	Outcome(ctx context.Context) (wproto.ArchiveStatusResp, error)
}

// Mutator executes the M1 filesystem mutations as a principal: create a
// directory, rename (or move within the jail), delete a single item. It is a
// separate interface from Backend, not an extension of it, so internal/web
// keeps compiling against Backend alone until the write routes are wired; the
// production *workerpool.Pool satisfies both.
//
// As with Backend, every path is an API path already through fsx.Clean, and
// non-UTF-8 names travel as raw bytes inside the strings. The kernel makes
// every permission decision inside the worker (INV-2); these methods surface
// its errors unchanged, mapped to the shared vocabulary by fsx.Code.
type Mutator interface {
	// Mkdir creates <dir>/<name> and returns the new entry. mode 0 means 0755
	// (less the worker's umask); parents creates missing intermediates. as, when
	// non-nil, asks the worker to chown/chmod the created directory to the given
	// owner after creating it — the admin-as-real-user case (routes_mutate.go);
	// nil keeps the default root-owned, umask-applied create. It is only
	// meaningful for a root (admin) worker, since the kernel refuses a non-root
	// process that chowns to another uid (INV-2).
	Mkdir(ctx context.Context, who Principal, dir, name string, mode os.FileMode, parents bool, as *wproto.CreateAs) (fsx.Entry, error)
	// Rename moves from to to, which may be in different directories. An
	// existing destination is refused unless overwrite is set; a rename across
	// filesystems is fsx.ErrCrossDevice.
	Rename(ctx context.Context, who Principal, from, to string, overwrite bool) error
	// Delete removes one item: a file, an empty directory, or a symlink (the
	// link itself). A non-empty directory is refused (not_empty); recursion and
	// trash are M2.
	Delete(ctx context.Context, who Principal, path string) error
	// Resolve returns the canonical API path for path, resolved as the principal
	// inside the worker so the O_PATH walk enforces the user's own traversal
	// permissions (INV-2) — closing the front-end's static requested-path bypass
	// (round-3 finding 2). followLeaf resolves the whole path (an existing
	// directory, such as mkdir's dir); when it is false the parent is resolved
	// and the final component kept literal (a named entry to create, rename or
	// delete). A component the user cannot search surfaces as the kernel's
	// permission error; a non-existent leaf under !followLeaf is not an error.
	Resolve(ctx context.Context, who Principal, path string, followLeaf bool) (string, error)
	// OpenWrite creates an upload's file as the principal and returns the
	// descriptor to stream into plus the worker's handle for it (M2-C
	// contract §1). The caller must Close the file and then Finalize (or
	// Finalize with Discard) the handle.
	OpenWrite(ctx context.Context, who Principal, req wproto.OpenWriteReq) (*os.File, wproto.OpenWriteResp, error)
	// Finalize publishes or discards an upload the caller has finished
	// streaming: the worker verifies, stamps and links the inode into place
	// under the conflict policy.
	Finalize(ctx context.Context, who Principal, req wproto.FinalizeReq) (wproto.FinalizeResp, error)
	// Chmod applies a mode CHANGE (mask + value) to one entry and reports the
	// pre-call entry, the post-call entry and the fields the kernel did not do
	// as asked. A symlink leaf is refused as unsupported unless Follow is set
	// (M3 contract §1.4); the diff, not an error, is how a silently-dropped
	// setgid or an aclmode=groupmask rewrite is surfaced (§3).
	Chmod(ctx context.Context, who Principal, req wproto.ChmodReq) (wproto.ModeResp, error)
	// Chown changes owner and/or group of one entry; -1 leaves that half
	// alone. It is always an lchown — a symlink's own ownership is what
	// changes — so req.Follow is refused as unsupported in M3.
	Chown(ctx context.Context, who Principal, req wproto.ChownReq) (wproto.ModeResp, error)
}

func itoa(i int) string { return strconv.Itoa(i) }

// Jobs runs the long-lived M2 operations as a principal. A job is ONE RPC:
// progress and per-item warnings arrive in-band through the callbacks until
// the terminal result (identity plan §2.5). Like Mutator it is a separate
// interface, so internal/web compiles against exactly what it uses; the
// production *workerpool.Pool satisfies Backend, Mutator and Jobs.
type Jobs interface {
	// Job runs req to completion under ctx. onProg and onWarn may be nil.
	// Cancelling ctx stops the job (the pool also tells the worker); a
	// cancelled job returns ctx.Err(), and partial work is NOT rolled back —
	// the caller states that fact rather than pretending otherwise (design §3).
	Job(ctx context.Context, who Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error)
	// CancelJob asks the principal's worker to stop jobID promptly. It is a
	// separate, immediate RPC; the Job call itself returns once the worker
	// has actually stopped.
	CancelJob(ctx context.Context, who Principal, jobID string) error
	// TrashList lists the principal's own trashed items: a plain read, not a
	// job, so the trash panel opens without a job round-trip.
	TrashList(ctx context.Context, who Principal) (wproto.TrashListResp, error)
	// FSIdentity reports which filesystem holds path, computed in the
	// principal's worker from a descriptor it opened as the user — never by a
	// root-side pathname lookup (INV-2). The move pre-flight uses it to predict
	// an EXDEV and say so up front (M2-B contract §1.2).
	FSIdentity(ctx context.Context, who Principal, path string) (wproto.FSIdentityResp, error)
}
