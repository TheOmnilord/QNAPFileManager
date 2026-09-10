// Package wproto is the wire protocol between the root front-end and the
// per-user worker processes: the frame codec, the fd-passing helpers, and the
// request and response bodies.
//
// Two properties fix the design (docs/design/identity-and-hero-plan.md §2.5):
//
//   - Every path and name is []byte. encoding/json base64-encodes []byte
//     automatically, so an arbitrary non-UTF-8 Linux filename survives the
//     round trip unchanged — the same problem pathB64 solves at the HTTP layer.
//   - One frame is one sendmsg, so a frame carrying file descriptors in
//     SCM_RIGHTS is always delivered whole.
package wproto

// Op names a request. The vocabulary is closed: an unknown Op is a protocol
// error, not something the worker tries to interpret.
type Op string

const (
	OpHello     Op = "hello" // parent → worker, once: jail root, umask, limits
	OpList      Op = "list"
	OpStat      Op = "stat"
	OpProps     Op = "props"
	OpMkdir     Op = "mkdir"
	OpRename    Op = "rename"
	OpDelete    Op = "delete" // single, non-recursive delete (M1); recursive delete and trash are the job-shaped DeleteReq (M2)
	OpReadlink  Op = "readlink"
	OpResolve   Op = "resolve" // resolve an API path to its canonical spelling, as the user
	OpChmod     Op = "chmod"
	OpChown     Op = "chown"
	OpOpenRead  Op = "openread"
	OpOpenWrite Op = "openwrite"
	OpFinalize  Op = "finalize" // chmod/chtimes/rename the .part into place
	OpText      Op = "text"
	OpJob       Op = "job" // copy|move|delete|size|search|archive|chmod|chown|trash
	OpCancel    Op = "cancel"
	OpPing      Op = "ping"
	OpBye       Op = "bye" // graceful shutdown: finish nothing new, exit
)

// Frame kinds. A request gets exactly one terminal frame (KindOK or KindErr)
// with the same ID; a job may emit any number of KindProg and KindWarn frames
// before it.
const (
	KindReq  = "req"
	KindOK   = "ok"
	KindErr  = "err"
	KindProg = "prog"
	KindWarn = "warn"
)

// Job kinds carried in JobReq.Kind.
const (
	JobCopy    = "copy"
	JobMove    = "move"
	JobDelete  = "delete"
	JobSize    = "size"
	JobSearch  = "search"
	JobArchive = "archive"
	JobChmod   = "chmod"
	JobChown   = "chown"
	JobTrash   = "trash"
)

// Conflict resolutions for a copy, move or upload finalize.
const (
	ConflictSkip      = "skip"
	ConflictOverwrite = "overwrite"
	ConflictRename    = "rename"
)

// Job phases reported in Prog.Phase.
const (
	PhaseScanning  = "scanning"
	PhaseWorking   = "working"
	PhaseFinishing = "finishing"
)

// Err is a failure crossing the socket. Code is the same vocabulary as
// fsx.Code, and Errno carries the raw syscall number so the front-end can be
// specific about EDQUOT versus ENOSPC without parsing a message.
type Err struct {
	Code    string `json:"c"`
	Errno   int    `json:"n,omitempty"`
	Message string `json:"m"`
	Path    []byte `json:"p,omitempty"`
}

func (e *Err) Error() string {
	if e == nil {
		return "<nil>"
	}
	if len(e.Path) > 0 {
		return string(e.Path) + ": " + e.Message + " (" + e.Code + ")"
	}
	return e.Message + " (" + e.Code + ")"
}
