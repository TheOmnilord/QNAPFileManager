
# QNAPFileManager — design delta for QTS-native identity, per-user impersonation, and QuTS hero

Scope: replaces PLAN.md decision 5 (auth), decision 12 (ACLs), decision 9 (one-filesystem), decision 4 (framing), and the "QuTS hero best-effort" open question. Everything else in PLAN.md stands.

Two new invariants govern the whole design:

- **INV-1**: no filesystem-mutating or user-data-reading syscall for a non-admin session ever executes in the root front-end process. The front-end's only filesystem access is metadata needed by the guard (`Lstat`, `EvalSymlinks`, `statfs`, `/proc/self/mountinfo`).
- **INV-2**: permission decisions are made by the Linux kernel, never re-implemented. The app computes *predictions* (to grey out controls) but treats `EACCES`/`EPERM` as the truth and reports it verbatim.

---

## 1. Identity model

### 1.1 What we get from QTS

`authLogin.cgi` gives `authPassed`, `isAdmin`, `authSid`, `errorValue` — and, we hope, `username`. It gives **no uid/gid**. So identity resolution is a second, local step.

```go
package idmap

type Ident struct {
    Name    string
    UID     int
    GID     int      // primary
    Groups  []int    // includes GID, deduped, sorted
    Home    string
    Source  string   // "passwd" | "nss-helper" | "cache"
    Partial bool     // true when supplementary groups could not be enumerated
}

func (m *Map) LookupUser(name string) (Ident, error)   // /etc/passwd + /etc/group
func (m *Map) LookupNSS(ctx context.Context, name string) (Ident, error) // exec fallback
func (m *Map) Resolve(ctx context.Context, name string) (Ident, error)   // passwd, then NSS, then error
```

**Step 1 — pure Go, no cgo.** Extend the already-planned `internal/idmap` parser (§2.14 of the backend plan) with a name→entry index:

- `/etc/passwd` → `name:passwd:uid:gid:gecos:home:shell` gives uid, primary gid, home.
- `/etc/group` → `name:passwd:gid:member,member` gives supplementary groups: every group whose member list contains the username, **plus** the primary gid from passwd (which is usually *not* repeated in `/etc/group`'s member list — forgetting this is the classic bug).
- Reload on `mtime`+`size` change, at most once per second (QTS rewrites these files on user changes). On QTS these are typically symlinks into `/mnt/HDA_ROOT/.config/` — **VERIFY ON NAS** (`ls -l /etc/passwd /etc/group`), because if they are symlinks the mtime we must watch is the *target's*; use `os.Stat`, not `os.Lstat`, for the staleness probe.

This covers every **local** QTS user, which is the overwhelming majority case and the only case for a home NAS.

**Step 2 — domain (AD/LDAP) users.** These do **not** appear in `/etc/passwd`. They are resolved by NSS through `libnss_winbind.so` / QNAP's own module, which is reachable only from a process linked against glibc's NSS — i.e. only with `CGO_ENABLED=1`. Enabling cgo is rejected: it forces a glibc-matched cross-toolchain per architecture, breaks the single-static-binary property, and QTS's glibc version varies by firmware.

The feasible fallback is a **one-shot exec per session**, never per request:

```go
// LookupNSS runs, once, with a 3s timeout and a nil-ish env:
//   id -u <user>   → uid
//   id -g <user>   → primary gid
//   id -G <user>   → space-separated supplementary gids
// Output must be all-numeric; anything else is a hard failure.
```

- Prefer `getent passwd <user>` + `getent group` if `getent` exists (single call, richer). QTS's busybox may not ship `getent`. **VERIFY ON NAS**: `command -v id getent; id -G admin; getent passwd admin`.
- busybox `id` supports `-u/-g/-G` in most builds but **VERIFY ON NAS** — if `-G` is missing, the user is admitted with `Partial: true` and only the primary group, and the UI shows a persistent banner: *"Your group memberships could not be enumerated on this NAS; access to group-shared folders may be denied even where you have rights."* Never silently pretend.
- Cache the result for the life of the session plus 10 minutes. Never re-exec per request — the whole point of the worker architecture is that identity is resolved once.
- Never pass the username to a shell. `exec.CommandContext(ctx, "/bin/id", "-G", name)` with no shell, and reject names containing anything outside `[A-Za-z0-9._@\\-]` before the call (also a good filter against a hostile `NAS_USER` cookie).

**Step 3 — refusal.** If neither path resolves the user to a uid, the session is refused with a specific message. We do **not** fall back to root, ever.

### 1.2 Deciding "admin"

Three signals, and they must agree before we hand out root:

| Signal | Source | Meaning |
|---|---|---|
| `isAdmin == 1` | `authLogin.cgi` response | QTS's own answer — authoritative for *QTS* admin semantics (it accounts for QNAP's delegated-admin roles) |
| `uid == 0` | `/etc/passwd` | On QTS the `admin` account is uid 0. **VERIFY ON NAS** — some firmwares use uid 0, some do not. |
| gid 0 / group `administrators` in `Ident.Groups` | `/etc/group` | QNAP's admin group. **VERIFY ON NAS**: is it named `administrators`, and is its gid 0? |

Rule:

```go
func decideAdmin(a QTSAuth, id Ident, g *idmap.Map) (admin bool, note string) {
    qts   := a.IsAdmin == 1
    local := id.UID == 0 || hasGroupNamed(id, g, "administrators")
    switch {
    case qts && local:  return true, ""
    case qts && !local: return false, "QTS reports admin but the account is not in the administrators group"
    case !qts && local: return false, "account is in administrators but QTS did not report admin"
    default:            return false, ""
    }
}
```

Take the **lower** privilege on disagreement, log the disagreement to the audit log and QuLog at `Warning`, and show it in `/api/diag`. Config `auth.adminRequiresBoth` (default `true`) can be set to `false` to trust `isAdmin` alone, for firmwares where the group name differs — but only after the NAS check answers rows 2 and 3.

**Non-admins are admitted** (requirement A) and simply get a worker with their own credentials. They are not "degraded"; they get exactly the access the kernel gives them.

Admin-only endpoints regardless: `/api/config` (POST), `/api/readonly`, `/api/audit`, `/api/diag`, `/api/fs/trash/empty` for other users' entries, and the systemWrite arming switch.

### 1.3 Session identity binding — a real vulnerability to avoid

The `qtoken` form (`?qtoken=<t>&user=<u>`) validates the **pair**, so binding to the `NAS_USER` cookie is safe.

The `sid` form (`?sid=<s>`) validates only the token. If we then take the identity from the `NAS_USER` cookie, **any authenticated non-admin can set `NAS_USER=admin` in their own browser and be handed a root worker.** Therefore:

- For `sid`, the username **must** come from the `authLogin.cgi` response body (`username` element, or whatever it is on this firmware). **VERIFY ON NAS** whether the response carries a username at all.
- If it does not, the `sid` path is **disabled** and only the `qtoken` path is accepted. Fail closed. This is written as a hard-coded default, not a config option.
- Same for `isAdmin`: if it is only returned on *login* and not on *validation* (PLAN.md open question 3), then cookie SSO grants a **non-admin worker to everyone**, and an admin must additionally re-enter their password once (credential-proxy login) to obtain a root worker. That degradation is correct and is the honest behaviour; the UI says *"Signed in as admin (limited). Confirm your password to act as administrator."*

---

## 2. Impersonation architecture

### 2.1 Why not setuid in-process

`syscall.Setuid` in Go ≥1.16 changes **all** OS threads of the process (via `AllThreadsSyscall`), which is process-global and irreversible once root is dropped — unusable in a concurrent server. The `runtime.LockOSThread` + raw `setresuid` trick is per-thread but the Go runtime may migrate goroutines, spawn new threads that inherit the *original* credentials, and any concurrent `AllThreadsSyscall` clobbers it; the runtime documentation explicitly does not support it. Both are rejected. Impersonation therefore requires a separate process.

### 2.2 The three candidates

| | (i) worker per active user | (ii) worker per job | (iii) helper exec per request |
|---|---|---|---|
| Added latency, warm | ~0.1–0.2 ms (one socketpair round trip) | ~5–15 ms x86 / ~15–40 ms ARM per job (estimates, measure on the NAS) | same fork+exec cost **on every request** |
| Cost of a directory click (~4 API calls) | negligible | negligible (clicks aren't jobs) | +60–160 ms on ARM |
| Streaming (download/upload) | fd passed once, bytes never cross the RPC | same | needs a socket anyway → collapses into (i) |
| Progress for long jobs | in-band frames on the same RPC | in-band, plus process exit as completion | not workable |
| Isolation blast radius | one process per user, lives for minutes | one process per job | smallest |
| Crash containment | one user's in-flight ops fail | one job fails | one request fails |
| Memory | N × Go runtime (~8–15 MB RSS, text/rodata pages shared because it is the same binary) | transient | transient |
| Complexity | RPC + pool + lifecycle | RPC + spawn | arg-passing, quoting hazards, no fd passing |

### 2.3 Recommendation: (i), one long-lived worker per **uid**, with (ii) available for hostile-sized jobs

Key by **uid**, not by session: multiple browser tabs, multiple sessions and the reconnect after a QTS re-login all share one worker. Admin sessions get a worker spawned with **no `Credential`** at all, so it inherits root — the *same code path*, not a bypass. This is worth stating plainly: **there is exactly one way filesystem work happens in this app.** Special-casing root into the front-end would double the code that has to be correct.

A config escape hatch `worker.rootInProcess = false` (default) exists but is documented as unsupported.

Transport: an **anonymous socketpair**, not a named unix socket. `syscall.Socketpair(AF_UNIX, SOCK_STREAM, 0)`; one end becomes `cmd.ExtraFiles[0]` (fd 3 in the child), the other becomes a `*net.UnixConn` in the parent via `net.FileConn`. No filesystem rendezvous means no path to permission, no `/tmp` (which is the QTS RAM disk), no possibility of a second process connecting, and no cleanup on crash.

### 2.4 Spawn

```go
// internal/workerpool
cmd := exec.Command(selfExe, "-worker", "-uid", strconv.Itoa(id.UID))
cmd.Dir  = "/"                       // never hold a cwd on a volume (would block unmount)
cmd.Env  = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=" + safeHome(id), "TZ=" + os.Getenv("TZ")}
cmd.Stdin = devNull
cmd.Stdout, cmd.Stderr = logPipe, logPipe   // drained into the app log with a "worker[uid=1001]" prefix
cmd.ExtraFiles = []*os.File{childEnd}       // → fd 3
cmd.SysProcAttr = &syscall.SysProcAttr{
    Setpgid:   true,                        // signals don't leak from the front-end's group
    Pdeathsig: syscall.SIGKILL,             // best-effort; see below
}
if !admin {
    cmd.SysProcAttr.Credential = &syscall.Credential{
        Uid:    uint32(id.UID),
        Gid:    uint32(id.GID),
        Groups: toU32(id.Groups),            // MUST be explicit and MUST contain GID
    }
}
```

Notes that matter:

- `Credential.Groups` **must** be set explicitly. With `Groups == nil` and `NoSetGroups == false`, Go calls `setgroups(0, nil)`, wiping supplementary groups — the user would silently lose access to every group-shared folder. Include the primary gid in the slice.
- `Pdeathsig` is best-effort only; it is documented as cleared when executing a set-uid binary, and its interaction with `Credential` ordering in `syscall.forkAndExecInChild` is a known grey area — **VERIFY ON NAS** with `kill -9` on the front-end. The *real* guarantee is that the worker's `read` on fd 3 returns EOF when the parent dies, and the worker's main loop exits on EOF unconditionally. Belt and braces.
- The worker sets its own `umask` explicitly at startup (`syscall.Umask(config.worker.umask)`, default `0022`) so created modes are deterministic and don't depend on what App Center's shell left behind.
- The worker sets `debug.SetGCPercent(40)` and a `GOMEMLIMIT` from config so N workers on a 1 GB ARM NAS stay bounded.
- Worker mode is detected in `main()` **before** any HTTP, config, or embed initialisation, so a worker never opens a listener and never reads the config file (whose directory is 0700 root-only and which contains the bcrypt hash — a non-root worker cannot read it anyway, which is the desired property). The worker's configuration arrives as a `Hello` frame on fd 3.

### 2.5 Wire protocol — `internal/wproto`

Framing: `uint32` big-endian length + payload, one `WriteMsgUnix` per frame. Every read on both sides goes through `ReadMsgUnix` so ancillary data is never lost; received fds are pushed onto a queue and a frame declaring `NFD: n` pops `n`. Linux does not merge stream data across a `sendmsg` that carried ancillary data, so an fd-bearing frame is always delivered whole — but the reader is written to tolerate the general case anyway.

Codec: **JSON**, with every path/name field typed `[]byte`. `encoding/json` base64-encodes `[]byte` automatically, which makes the protocol lossless for arbitrary non-UTF-8 Linux filenames — the exact problem PLAN.md already solves with `pathB64` at the HTTP layer. gob would also be lossless and faster, but gob's stateful type-definition stream fights the one-`sendmsg`-per-frame rule needed for `SCM_RIGHTS`. The codec sits behind a `wproto.Codec` interface so it can be swapped if a 5 000-entry listing (~1.5 MB of JSON, ~5–10 ms to encode+decode on ARM — estimate, measure) turns out to matter.

```go
package wproto

type Op string

const (
    OpHello   Op = "hello"     // parent → worker, once: config, jail root, limits
    OpList    Op = "list"
    OpStat    Op = "stat"
    OpProps   Op = "props"
    OpMkdir   Op = "mkdir"
    OpRename  Op = "rename"
    OpReadlink Op = "readlink"
    OpChmod   Op = "chmod"
    OpChown   Op = "chown"
    OpOpenRead  Op = "openread"
    OpOpenWrite Op = "openwrite"
    OpFinalize  Op = "finalize"   // chmod/chtimes/rename the .part into place
    OpText    Op = "text"
    OpJob     Op = "job"          // copy | move | delete | size | search | archive | chmod-r | chown-r | trash
    OpCancel  Op = "cancel"
    OpPing    Op = "ping"
)

type Frame struct {
    ID   uint64          `json:"i"`           // request id; replies and progress echo it
    Kind string          `json:"k"`           // "req" | "ok" | "err" | "prog" | "warn"
    Op   Op              `json:"o,omitempty"`
    NFD  int             `json:"n,omitempty"` // number of fds in SCM_RIGHTS on this frame
    Body json.RawMessage `json:"b,omitempty"`
    Err  *Err            `json:"e,omitempty"`
}

type Err struct {
    Code    string `json:"c"`            // same vocabulary as internal/fsx/errors.go
    Errno   int    `json:"n,omitempty"`  // raw syscall.Errno, so the front-end can be specific
    Message string `json:"m"`
    Path    []byte `json:"p,omitempty"`
}
```

Request bodies (abridged, but complete enough to implement):

```go
type ListReq struct {
    Dir  []byte `json:"d"`
    Opts fsx.ListOptions `json:"o"`
}
type ListResp struct{ Listing fsx.Listing }   // Entry.Name/Path are []byte in the wire form

type StatReq struct{ Path []byte }
type MkdirReq struct{ Dir, Name []byte; Mode uint32 }
type RenameReq struct{ From, To []byte; Overwrite bool }
type ChmodReq struct{ Path []byte; Mode uint32; Follow bool }
type ChownReq struct{ Path []byte; UID, GID int }   // -1 = leave

// Returns an fd on the reply frame (NFD:1) plus the stat the front-end needs
// for ServeContent. The kernel checks permission at open(2) time; the root
// front-end holding the fd afterwards is intentional and safe.
type OpenReadReq  struct{ Path []byte }
type OpenReadResp struct{ Entry fsx.Entry }

// Creates <dir>/.qfm-upload-<hex>.part with O_WRONLY|O_CREAT|O_EXCL, mode 0600,
// owned by the worker's uid. Returns its fd. Front-end streams the body in.
type OpenWriteReq  struct{ Dir, Name []byte; Mode uint32 }
type OpenWriteResp struct{ Tmp []byte }

type FinalizeReq struct {
    Tmp, Final []byte
    Mode       uint32
    MTimeUnix  int64
    Conflict   string   // "skip"|"overwrite"|"rename"
    Discard    bool     // abort: unlink the .part
}

type JobReq struct {
    JobID string          `json:"j"`
    Kind  string          `json:"k"`   // "copy" "move" "delete" "size" "search" "archive" "chmod" "chown" "trash"
    Body  json.RawMessage `json:"b"`   // CopyReq | DeleteReq | SearchOptions | ...
}
type CopyReq   struct{ Src [][]byte; DstDir []byte; Opts fsx.CopyOptions }
type DeleteReq struct{ Paths [][]byte; Recursive, Trash bool }

// Progress frames carry Kind "prog" and the SAME request ID as the JobReq.
type Prog struct {
    Files, FilesTotal int64
    Bytes, BytesTotal int64
    Current           []byte
    Phase             string   // "scanning"|"working"|"finishing"
}
// Per-item failures inside a job are Kind "warn" frames, not terminal errors:
type Warn struct{ Path []byte; Code, Message string; Errno int }
```

**How progress flows back.** A job is *one* long-lived RPC. `workerpool.Call` registers `ID → chan Frame`; the front-end's `jobs.Manager` wrapper drains that channel, turning `prog` frames into `jobs.Progress` updates and `warn` frames into `job.Warnings` (capped at 100 then counted, as already planned), until a terminal `ok` or `err` frame closes the job. No second channel, no correlation problem, and job completion is naturally ordered after the last progress update. The worker coalesces progress to **≤10 frames/s or every 8 MiB**, whichever comes first, so a million-file delete does not flood the socket. `OpCancel{JobID}` is a separate, immediate RPC on its own ID; the worker looks the job up in a `map[string]context.CancelFunc`.

### 2.6 Pool lifecycle

```go
type Pool struct {
    max      int            // config.worker.max, default 8
    idle     time.Duration  // config.worker.idleTimeout, default 10m
    workers  map[int]*Worker  // keyed by uid
}
func (p *Pool) Acquire(ctx context.Context, id idmap.Ident, admin bool) (*Worker, error)
```

- **Spawn**: lazily, on the first filesystem request of a session. `singleflight` on the uid so ten parallel requests from one page load spawn one worker.
- **Idle reaping**: a worker with no in-flight RPC and no running job for `idle` is sent a `bye` frame, then `SIGTERM`, then `SIGKILL` after 5 s. A worker with a running job is **never** reaped.
- **Eviction at `max`**: evict the least-recently-used *idle* worker. If all are busy, `Acquire` returns `ErrWorkerBusy` → HTTP `503` with `Retry-After: 5` and a clear message. Do not queue indefinitely.
- **Crash recovery**: the reader goroutine sees EOF or a decode error → the worker is marked dead, every registered in-flight ID gets a synthetic `err{code:"worker_gone"}`, running jobs move to `failed` with *"the worker process for user X stopped unexpectedly; partial work may remain"*, the stderr tail is attached to the job and to the audit log. The next request respawns. **Restart budget**: 5 restarts per uid per minute; beyond that, `Acquire` fails with `worker_unavailable` for 60 s, so a crash loop cannot fork-bomb the NAS. Every crash writes an `Error` to QuLog.
- **Group changes**: if `/etc/group` changes such that the user's group set differs from the running worker's, the worker is retired at the next idle moment (a running process cannot gain groups). The session shows *"your group memberships changed; reopening"*.
- **Shutdown**: on `SIGTERM` the front-end sends `bye` to all workers, waits up to `QPKG_TIMEOUT` stop seconds, then kills the process group.

### 2.7 Where the guard and audit live

Both stay entirely in the **root front-end**, before the RPC:

```
HTTP handler
  ├─ session → Ident{uid,gid,groups}, admin
  ├─ decode path / pathB64
  ├─ fsx.ResolveParent  (as root — canonicalisation only, no mutation)
  ├─ guard.Check(op, canonicalPath)           ← readOnly, systemWrite, prefix rules, mount points
  ├─ guard.Redeem(confirmToken) if required
  ├─ audit.Write(phase:"intent", actor, uid, admin, op, path)
  ├─ pool.Acquire(uid).Call(ctx, frame)       ← the ONLY place a syscall on user data happens
  └─ audit.Write(phase:"result", code, files, bytes)
```

Two consequences to state honestly:

1. **The guard resolves symlinks as root**, so the front-end can learn that a path exists even when the user cannot traverse to it. The resulting distinction between `403 protected` and `403 permission` is a minor existence oracle. It is accepted and documented in `docs/safety.md`: File Station leaks the same, and the alternative (resolve in the worker, then guard, then act) reintroduces a TOCTOU window that is strictly worse.
2. **Guard rules apply to non-admins too**, even though the kernel would usually stop them anyway. Defence in depth, and it stops the real case of a non-admin deleting something world-writable under `/etc` or `/run`.

INV-1 is enforced by a test, not by discipline alone: a `go list -deps`-based test asserts that `internal/web` does not (transitively) import the mutating half of `internal/fsx`. Split the package so this is checkable: `internal/fsx` (types, `Clean`, `Resolve`, mount/statfs read-only helpers) and `internal/fsops` (everything that writes), with only `internal/worker` importing `internal/fsops`.

### 2.8 Job placement: (ii) as a mode

A "delete 4 million files" job pins one worker for hours and blocks that user's interactive browsing behind the pool's per-worker RPC serialisation. Two mitigations, in order:

- The worker serves RPCs concurrently (one goroutine per request ID) — interactive `List` is not blocked by a running job in the same worker. This is the default and suffices.
- `config.worker.jobsInOwnProcess` (default `false`) switches byte-mover jobs to option (ii): a dedicated worker per job, spawned with the same credentials, reaped on completion. Worth having for the pathological case; not worth being the default.

---

## 3. chmod / chown / ACL as a non-root user

### 3.1 What the kernel will actually do

| Operation | Rule | Failure |
|---|---|---|
| `chmod` | only `euid == st_uid` or `CAP_FOWNER` (root) | `EPERM` |
| `chown` (change uid) | root only (`CAP_CHOWN`) | `EPERM` |
| `chgrp` (change gid) | owner may set the gid to **any group they are a member of**; root may set any | `EPERM` |
| any successful non-root `chown`/`chgrp` | kernel **clears setuid, and clears setgid if the file is group-executable** | silent |
| non-root `chmod` setting setgid where `st_gid ∉ user's groups` | kernel **silently drops** `S_ISGID` | silent, mode differs from requested |
| unlink/rename in a sticky (`+t`) directory | only the file's owner, the directory's owner, or root | `EPERM` |
| ZFS with `aclmode=discard` | `chmod` **destroys** the NFSv4 ACL | succeeds, data-losing |
| QNAP Advanced Folder Permissions / Windows ACL | may deny even where the mode allows | `EACCES` |

The "silently dropped bit" cases are the nastiest, because the call *succeeds* and the result differs from what the user asked for. Therefore **every `Chmod` and `Chown` RPC re-`Lstat`s the target after the call and returns the resulting `Entry`**, and the front-end diffs requested vs. actual. If they differ, the response carries `warnings: ["the setgid bit was not applied: you are not a member of group 'users'"]` and the UI shows it as a warning toast, not a success toast. This is cheap and it removes an entire class of "I set it and it didn't stick" support questions.

### 3.2 Predicting capability, for the UI only

The front-end knows `uid`, `groups` and the entry's `st_uid`, `st_gid`, so it can compute per-entry capability flags and ship them with `Stat`/`Properties`:

```go
type Caps struct {
    Chmod    bool     `json:"chmod"`
    ChownUID bool     `json:"chownUid"`
    ChgrpTo  []int    `json:"chgrpTo"`   // gids the user may set (their own groups), root → nil meaning "any"
    Reason   string   `json:"reason,omitempty"`
}
```

Rules: `Chmod = admin || uid == e.UID`; `ChownUID = admin`; `ChgrpTo = admin ? all : (uid == e.UID ? id.Groups : nil)`.

These are **hints** (INV-2). An ACL, a read-only mount, or an immutable attribute can still produce `EPERM`, and the UI must handle that gracefully rather than treating it as impossible.

### 3.3 UI messaging

- Permissions dialog for a file you don't own: the rwx grid renders **read-only** with a lock affordance and the line *"Owned by `backup` (uid 1003). Only the owner or an administrator can change permissions. You are signed in as `sveinung`."*
- Owner field: a plain sentence, not a disabled dropdown with no explanation — *"Only an administrator can change ownership."* If the session is an admin who chose "act as myself", offer **"Switch to administrator for this action"**, which retires the impersonating worker for that session and re-acquires the root worker. If the session is not an admin, do not offer anything; there is nothing to click.
- Group field: a dropdown listing **only** `Caps.ChgrpTo` resolved to names, with *"You can only assign groups you belong to."*
- Recursive chmod/chown as a non-owner: **partial success is the normal outcome**, not a failure. The job continues past every `EPERM`, collects `warn` frames, and finishes `done` with a summary: *"Changed 412 of 8 003 items. 7 591 are owned by other users and were skipped. 0 other errors."* Plus a "Show skipped items" expander over the first 100. A job that fails wholesale on the first `EPERM` would be useless on a real NAS.
- On QuTS hero, see §4.4 — chmod gets an extra, data-loss-grade warning.

---

## 4. QuTS hero (ZFS) in scope for v1

### 4.1 Volume layout

Known: shared folders are reached at `/share/<Name>` on both platforms, via a symlink in the `/share` tmpfs.

Believed but **VERIFY ON NAS**: on QuTS hero the underlying mount is named `/share/ZFS<n>_DATA` (e.g. `/share/ZFS530_DATA`), analogous to QTS's `/share/CACHEDEV<n>_DATA`; the digits encode pool and volume rather than being a simple counter.

**Do not pattern-match volume roots.** The design already needs `/proc/self/mountinfo`; derive volume roots from it:

```go
// A "volume root" is a mount point that is a direct child of /share
// (path depth 2) whose fstype is a storage filesystem.
// This is correct on QTS (CACHEDEV1_DATA), on hero (ZFS530_DATA),
// and on the legacy HDA_DATA..HDK_DATA layout, with no table to maintain.
```

Keep the `CACHEDEV|ZFS|HDA?-K_DATA|MD\d+_DATA` regex only as a **label** heuristic for the UI's "volume mounts" group, never as a behavioural switch.

### 4.2 Dataset boundaries — the change with the widest blast radius

On QuTS hero **each shared folder is its own ZFS dataset with its own mount point**, so `st_dev` differs between `/share/ZFS530_DATA` and `/share/ZFS530_DATA/Public`, and between any two shares. **VERIFY ON NAS** with `cat /proc/mounts | grep zfs` and `stat -c '%d %n' /share/*_DATA /share/*_DATA/*`.

PLAN.md decision 9 ("every recursive op is one-filesystem") therefore **breaks on hero**: copying `/share/ZFS530_DATA` would copy an empty skeleton and skip every share. Replace `OneFileSystem` with a *storage-domain* rule:

```go
// internal/platform
type FSCaps struct {
    FSType       string // from mountinfo: "ext4","zfs","tmpfs","proc","nfs4","fuse.*", ...
    Storage      bool   // real user-data fs: ext2/3/4, xfs, btrfs, zfs
    Domain       string // "zfs:pool0"  (dataset name up to the first '/')  |  "dev:0x0801"
    Mount        string
    ACLBackend   string // "posix" | "nfs4" | "none"
    ACLXattr     string // "system.posix_acl_access" | "system.nfs4_acl" | ""
    ZFSAclmode   string // "discard"|"groupmask"|"passthrough"|"restricted"|"" (unknown)
    Network      bool   // nfs, cifs, sshfs — never traversed by a recursive job by default
}

type Platform struct {
    Family   string  // "qts" | "quts_hero" | "linux" | "unknown"
    Firmware string
}
func (p *Platform) For(osPath string) FSCaps           // longest-prefix match over mountinfo, 5s cache
func (p *Platform) MayCross(from, to FSCaps) bool
```

`MayCross` = `to.Storage && !to.Network && to.Domain == from.Domain`. On QTS ext4 that is a no-op (one device per volume, so it never fires). On hero it lets a walk descend from a volume root into every dataset **of the same pool** and still refuses `/proc`, `/sys`, `/dev`, tmpfs, USB disks, other pools and network mounts. The property PLAN.md wanted — "no blacklist to maintain" — is preserved, and it is now *data-driven from the mount table*, so one binary serves both platforms with no `isHero` branch in the operation code.

The `CopyOptions` field is renamed `Crossing string // "none" | "domain" | "any"`, default `"domain"`, exposed in the UI as a checkbox *"Include mounted sub-folders"* on the copy/delete/size dialogs, defaulted on for hero and off-by-consequence on QTS.

**EXDEV moves.** On hero, a move between two shares on the same pool is `EXDEV` — a rename cannot cross datasets even within a pool. Move therefore degrades to copy+verify+delete far more often than on QTS. This must not be a surprise at the end of a 40 GB operation:

- The front-end compares `st_dev` of the source and the destination **before submitting the job** (both are cheap root `Lstat`s) and, when they differ, the confirm dialog says up-front: *"Public and Media are separate ZFS datasets, so this move is a copy of 41.2 GB followed by a delete, not an instant rename. It can be cancelled, and a cancelled move leaves both copies."*
- `internal/fsx/errors.go` gains `syscall.EDQUOT → "no_space"` with a distinct message (*"your quota on this share is full"*) — per-user quotas are a real QNAP feature and `statfs` free space does not reflect them, so the pre-flight free-space check can pass and the write still fail.

**Same-device trash.** `TrashRoot` currently walks up until `st_dev` changes. That rule needs no change but its *result* differs by platform, correctly: on QTS it lands on the volume root, on hero on the share's dataset root — which is also where `@Recycle` lives. Restate the rule as **"the nearest enclosing mount point whose `FSCaps.Storage` is true"** and it is right on both.

Because non-admins must be able to trash, the trash directory is created **by the root front-end**, once, on demand, as `<mountRoot>/.@qfm_trash` mode `1777` (sticky), with entries at `<trash>/<uid>/<unix>-<8hex>/`. The sticky bit gives exactly the semantics wanted, enforced by the kernel: a user can move items in, and can only move their own items back out. Creating a 1777 directory inside a share is a security-relevant act — it is audited, mirrored to QuLog, disclosed in the trash panel, and skippable via `config.trash.enabled=false`, in which case delete is always permanent-with-confirmation.

### 4.3 Snapshots

`.zfs/snapshot` is hidden by default (`snapdir=hidden`), so `readdir` will not surface it and walks will not descend into it. If a dataset has `snapdir=visible`, a naive recursive size or copy of a share would traverse every snapshot and report absurd totals.

- Add `.zfs` to a **never-descend, never-write** component set in `internal/guard`, matched on the path *component*, not the prefix (a user's own directory named `.zfs` deeper in a tree is also skipped — acceptable, and warned about).
- Snapshots are read-only at the kernel level, so writes fail with `EROFS`/`EPERM` anyway; the guard just makes the message honest.
- **VERIFY ON NAS**: does QuTS hero expose `.zfs` at all, and does the QTS-side snapshot feature (LVM thin snapshots on ext4) expose anything comparable under a share? If QTS exposes a hidden snapshot directory too, add its name to the same set.

### 4.4 ACLs

| | QTS | QuTS hero |
|---|---|---|
| Backend | POSIX ACL | NFSv4 ACL |
| Detection xattr | `system.posix_acl_access` | `system.nfs4_acl` — **VERIFY ON NAS**; OpenZFS-on-Linux exposes this only in some builds and QNAP ships a fork |
| Pure-Go detect | `syscall.Getxattr(p, name, nil) > 0` | same call, different name |
| `chmod` effect on the ACL | mode is the ACL's base entries; ACL survives | **depends on `aclmode`**: `discard` deletes the ACL, `groupmask` silently reduces it, `passthrough`/`restricted` behave differently again |

So `ACLBackend()` becomes per-mount (`FSCaps.ACLBackend`), probed once per mount by attempting both `Getxattr` names on the mount root and caching the answer. Never a global.

The v1 badge text must be **stronger on hero**, because the mode genuinely is not the truth there:

- QTS/POSIX: *"This item has an extended ACL that this app does not display. The mode below is only the base permission set — editing it will not remove the ACL."* (unchanged)
- Hero/NFSv4: *"This item's real permissions are an NFSv4 ACL. The mode shown is a summary the filesystem derives from it. Changing the mode may **discard or reduce** the ACL, and that cannot be undone from this app."*

And when `FSCaps.ZFSAclmode == "discard"` (or is unknown), a `chmod` on a `HasACL` item is promoted to a **level-2 confirmation** with the real dataset name in the dialog. `ZFSAclmode` is read once per dataset by execing `zfs get -Hp -o value aclmode <dataset>` at mount-table build time — **VERIFY ON NAS** the binary's path (`/sbin/zfs`, `/usr/sbin/zfs`, or a QNAP-specific location) and whether it is callable at all as root. If it is not available, `ZFSAclmode` stays `""` and the pessimistic warning is shown. Never guess `passthrough`.

Editing ACLs remains v2+ for POSIX and v3 for NFSv4, unchanged.

### 4.5 Runtime detection — data-driven

```go
func Detect() *Platform
```

Signals, evaluated in order, all recorded in `/api/diag` so a mismatch is diagnosable:

1. `/proc/self/mountinfo`: any mount with fstype `zfs` → strong hero signal. This is the **only** signal that behaviour depends on, and even then only via `FSCaps`, never via `Family`.
2. `/proc/spl/kstat/zfs` or `/proc/spl` exists → ZFS kernel module loaded.
3. `/etc/config/uLinux.conf`, `[System] Version` — believed to be prefixed `h` on hero (e.g. `h5.1.0`) versus `5.1.0` on QTS. **VERIFY ON NAS** (`/sbin/getcfg System Version`). Used for the *label* in diag and for the docs, not for behaviour.
4. `/sbin/zfs` / `/usr/sbin/zfs` present.
5. `/etc/config/uLinux.conf` exists at all → this is a QNAP NAS rather than a dev box.

`Family` exists purely so the UI and the audit log can say "QuTS hero 5.1.0" and so the NAS checklist can branch. **No operation reads `Family`.** Every operation reads `Platform.For(path)`. That is what makes one binary serve both, and it is testable off-NAS by feeding a synthetic mountinfo file into `Platform` (`platform.FromMountinfo(io.Reader)`), which is how the hero code paths get golden tests on Windows.

---

## 5. QTS-desktop embedding

### 5.1 Own port vs. proxy — the decision is forced

The own-port option (`QPKG_WEB_PORT=8770`, `QPKG_DESKTOP_APP=1`, desktop iframes `http://<host>:8770/`) fails on a modern, correctly configured NAS:

- QTS pushes **Force HTTPS**. An `https://nas/` desktop page cannot iframe `http://nas:8770/` at all — mixed content blocking, no user override inside an iframe.
- Serving TLS ourselves means a **self-signed certificate**, and a certificate interstitial inside an iframe is not clickable-through; the frame just fails silently.
- QTS's cookies are likely `Secure` under Force HTTPS and would never be sent to a plain-HTTP port regardless.
- Same-site *does* ignore port, so `SameSite=Lax` is not the blocker — the scheme is. But scheme is not fixable without a real certificate.

**Recommendation: `QPKG_USE_PROXY="1"` + `QPKG_PROXY_PATH`.** The UI is then served from the QTS origin itself (`https://nas/qnapfilemanager/`), which makes all of the following true at once: QTS cookies arrive first-party, no mixed content, no certificate problem, `frame-ancestors 'self'` is exactly the right CSP, `SameSite=Lax` on our own cookie works, and there is no CORS anywhere. It is also what Tailscale does, for the same reasons.

```sh
QPKG_NAME="QNAPFileManager"
QPKG_DISPLAY_NAME="File Manager"
QPKG_VER="0.1.0"                    # CI overwrites from the git tag
QPKG_AUTHOR="Sveinung"
QPKG_LICENSE="MIT"
QPKG_RC_NUM="198"
QPKG_SERVICE_PROGRAM="QNAPFileManager.sh"
QTS_MINI_VERSION="4.5.0"

# --- QTS desktop embedding ---
QPKG_DESKTOP_APP="1"                 # open in a QTS desktop window, like File Station
QPKG_USE_PROXY="1"                   # QTS Apache reverse-proxies to our loopback port
QPKG_PROXY_PATH="/qnapfilemanager"   # same-origin path on the QTS web port
QPKG_WEBUI="/qnapfilemanager/"       # tile target — MUST match PROXY_PATH, trailing slash
QPKG_WEB_PORT="8770"                 # loopback target of the proxy
QPKG_VISIBLE="1"                     # tile visible to non-admin users     (VERIFY semantics)
QPKG_VOLUME_SELECT="1"
QPKG_TIMEOUT="30,60"                 # stop needs time to drain workers + jobs
QPKG_DIR_ICONS="icons"
```

Listener policy:

- `web.listen = "127.0.0.1:8770"` by **default** — the app is reachable only through the QTS proxy, which is the smallest attack surface for a root daemon.
- `web.breakGlass = {enabled: true, addr: "0.0.0.0:8771", tls: "selfsigned"}` — a second listener that serves **only** the local-bcrypt auth mode. This matters: this is the tool an operator would use to fix a NAS whose Apache or App Center is broken, and it must not depend on the thing it might have to repair. Certificate warnings are acceptable there because it is a top-level tab, not an iframe. The owner should confirm this trade-off; the alternative (single 0.0.0.0 listener) is simpler but exposes the whole app to the LAN.

### 5.2 Prefix handling

**VERIFY ON NAS**: whether QTS's generated Apache rule strips `QPKG_PROXY_PATH` before proxying, and what the rule literally is (`grep -r qnapfilemanager /etc/config/apache* /mnt/HDA_ROOT/.config/`). Tailscale passing an explicit `--prefix=` suggests it does **not** strip. Handle both without needing the answer:

- `QNAPFileManager.sh` reads `QPKG_PROXY_PATH` with `getcfg` and passes `-proxy-prefix /qnapfilemanager` to the daemon.
- The daemon registers its mux at **both** `/` and `/qnapfilemanager/` (`http.StripPrefix`). Whichever way the rule was written, it works.
- Every UI URL is already relative with no leading slash (PLAN.md decision, `ui-ux-safety-plan.md` §5.1), and routing is `location.hash` — so nothing in the UI needs to know the prefix.
- Our session cookie gets `Path=<prefix>/` when a prefix is configured, so it is not offered to every other QTS path on the same origin.
- `X-Frame-Options` is **omitted** entirely; CSP carries `frame-ancestors 'self'` plus any origins in `settings.frameAncestors`.
- `RemoteAddr` will be `127.0.0.1` for every proxied request, which would make the audit log useless. Read `X-Forwarded-For` / `X-Real-IP` **only when `RemoteAddr` is loopback**, take the last hop, and record both in the audit event. **VERIFY ON NAS** which headers QTS's proxy actually sets, and whether it sets `X-Forwarded-Proto` (needed to decide whether our cookie gets `Secure`; if it is absent, infer TLS from the fact that we are behind the proxy plus a config flag).

### 5.3 First-request flow

```
 Browser                    QTS Apache (:443)            qnapfilemanager (127.0.0.1:8770)
    │                             │                                   │
 1. user is signed into the QTS desktop; QTS holds cookies
    NAS_USER=<user>, qtoken=<t>  (or NAS_SID=<s> on older firmware)
    │                             │                                   │
 2. clicks the App Center tile → desktop opens a window whose iframe src is
    https://nas/qnapfilemanager/          ← SAME ORIGIN as the desktop
    │                             │                                   │
 3. GET /qnapfilemanager/  ──────►│   cookies attached (first-party)  │
    │                             │──── proxy, cookies intact ───────►│
    │                             │                                   │ 4. static shell
    │◄────────────────────────────│◄──────────────────────────────────│    (no auth needed)
    │                             │                                   │
 5. app.js: GET api/session ─────►│──────────────────────────────────►│
    │                             │                                   │ 6. qtsauth.FromRequest:
    │                             │                                   │    read NAS_USER + qtoken
    │                             │                                   │    cache key = sha256(cookie)
    │                             │                                   │    miss → single-flight:
    │                             │◄─ GET 127.0.0.1:8080/cgi-bin/ ────│
    │                             │   authLogin.cgi?qtoken=..&user=.. │
    │                             │   (5s, no redirects, ≤64 KiB,     │
    │                             │    lenient XML token walk)        │
    │                             │──► authPassed/isAdmin/authSid ───►│
    │                             │                                   │ 7. authPassed==1?
    │                             │                                   │    idmap.Resolve(user)
    │                             │                                   │      /etc/passwd + /etc/group
    │                             │                                   │      → miss: `id -u/-g/-G` once
    │                             │                                   │    decideAdmin(isAdmin, Ident)
    │                             │                                   │ 8. issue OUR session:
    │                             │                                   │    qfm_sid, HttpOnly,
    │                             │                                   │    SameSite=Lax, Secure,
    │                             │                                   │    Path=/qnapfilemanager/
    │                             │                                   │    bound to sha256(qtoken)
    │◄─── {user, admin, uid, gid, groups, readOnly, csrf, platform} ──│
    │                             │                                   │
 9. GET api/fs/list?path=/share ─►│──────────────────────────────────►│
    │                             │                                   │ 10. pool.Acquire(uid)
    │                             │                                   │     → fork+exec
    │                             │                                   │       qnapfilemanager -worker
    │                             │                                   │       Credential{uid,gid,groups}
    │                             │                                   │       (admin → no Credential)
    │                             │                                   │     guard.Check → audit intent
    │                             │                                   │     RPC OpList over socketpair
    │                             │                                   │     ← kernel enforces perms
    │◄────────────── Listing ─────────────────────────────────────────│     audit result
```

Revalidation: the QTS cookie is re-checked on a 60 s cache and **unconditionally before any write**. If QTS says the token is gone (the user signed out of QTS, or the qtoken rotated), our session is destroyed in place and the UI swaps to a re-auth panel — never a top-level redirect. That coupling is what makes "no separate login" honest rather than a second, longer-lived credential.

Fallback chain when cookies do not arrive (direct break-glass port, a bookmark to the wrong host, a browser blocking the cookie): (a) credential-proxy form → `authLogin.cgi?user=&pwd=`, **no longer requiring `isAdmin=1`** since non-admins are now in scope; (b) the local bcrypt admin. Never a hard fail, and the local account is always the last door.

### 5.4 Must be verified on the NAS (supersedes PLAN.md's list)

1. The literal Apache rule QTS writes for `QPKG_PROXY_PATH`, and whether it strips the prefix.
2. Whether QTS health-checks `QPKG_WEB_PORT` and whether binding it to `127.0.0.1` only is acceptable to App Center.
3. Whether `QPKG_DESKTOP_APP=1` combined with `QPKG_USE_PROXY=1` actually opens a desktop window (rather than a tab), and the resulting iframe `src`.
4. `QPKG_VISIBLE` semantics for non-admin users, and whether a separate per-app permission ("App permission" in App Center) must be granted before non-admins see the tile.
5. Cookie names and attributes (`NAS_USER`, `qtoken`, `NAS_SID`; `Secure`/`HttpOnly`/`SameSite`/`Path`/`Domain`).
6. Whether the `authLogin.cgi` validation response carries a `username` — **if not, the `sid` path stays disabled** (§1.3).
7. Whether `isAdmin` is returned on *validation* or only on *login* (§1.3).
8. `uLinux.conf` keys for the web and SSL ports; `[System] Version` prefix for hero.
9. Which forwarded headers the QTS proxy sets (`X-Forwarded-For`, `-Proto`, `-Prefix`).
10. `id`/`getent` availability and busybox `id -G` support.
11. `admin` uid, `administrators` gid and group name.
12. Hero: `/share/ZFS*_DATA` naming; per-share `st_dev`; `system.nfs4_acl` xattr name; `zfs` binary path; `aclmode` value; `.zfs` visibility.
13. Whether `authLogin.cgi` rate-limits or writes a QuLog event per call (our 60 s cache plus single-flight is sized for a fork-per-call CGI, but a logged event per call would flood QuLog).
14. Whether QuFirewall blocks loopback CGI calls.

---

## 6. Milestone deltas

### Moves earlier

| Was | Now | Why |
|---|---|---|
| QTS auth in M4 | **M0/M1** | Identity *is* the architecture now. The worker boundary cannot be retro-fitted into a finished `fsx` layer; it is a rewrite, not a feature. |
| ACL backend probe in M3 | **M0** | It is part of the per-mount `FSCaps` table that the crossing rule and trash root already need. |
| Mount-table work in M2/M3 | **M0** | `Platform`/`FSCaps` is the foundation for hero support, crossing, trash and EXDEV prediction. |

### Revised milestones

**M0 — Skeleton, platform table, worker spine, browse (was 15%, now ~22%)**
- `internal/platform`: mountinfo parser, `FSCaps`, `Platform.For`, `FromMountinfo(io.Reader)` for tests, hero/QTS detection, ACL-backend probe.
- `internal/idmap` extended: name→`Ident`, `/etc/group` membership, `LookupNSS` exec fallback.
- `internal/wproto` + `internal/worker` + `internal/workerpool`: `Hello`, `List`, `Stat`, `OpenRead`, `Ping`, socketpair framing, `SCM_RIGHTS`, lifecycle (idle, crash, max, restart budget).
- `internal/qtsauth`: cookie extraction, `authLogin.cgi` client, lenient XML, 60 s cache + single-flight, `decideAdmin`.
- Dev/CI identity: `-impersonate <user>` flag spawns a worker as that user without any QTS involvement; `-jail <dir>` unchanged and applies inside the worker.
- Exit: browse the whole NAS **as a chosen non-root user** from a browser, with the kernel doing the permission checks; hero code paths exercised against a synthetic mountinfo and a file-backed ZFS pool in CI.

**M1 — Safety spine + basic ops + first NAS install (was 20%, now ~20%)**
- `guard` (now including the `.zfs` component rule), confirm tokens, readOnly, systemWrite, audit + QuLog with `uid`/`admin`/`worker` fields.
- `Mkdir`, `Rename`, single `Delete`, `OpenWrite`/`Finalize` over RPC.
- `qpkg/` complete with the proxy configuration; **first real install**; NAS checklist items 1–14 answered. The QTS auth path is *verified* here, having been *built* in M0.
- Exit: the guard is real, and the two auth doors (cookie SSO, local break-glass) both work on the NAS.

**M2 — Jobs + transfer (unchanged, ~23%)**
- Job RPC with in-band progress and `warn` frames; cancel; copy/move/delete/size/search/archive; upload via passed fd; download via passed fd + `ServeContent`; per-uid sticky trash; EXDEV pre-flight dialog; crossing checkbox.

**M3 — Permissions + properties (was 15%, now ~17%)**
- chmod/chown over RPC with post-call re-`Lstat` and requested-vs-actual diffing; `Caps` prediction; partial-success recursive jobs; ACL badge with per-backend text; the `aclmode=discard` level-2 confirmation.

**M4 — Polish (was 25%, now ~18%)**
- Non-admin UX pass (empty states, "why is this greyed out"), break-glass TLS listener, a11y/keyboard/narrow, docs (`docs/identity.md` is new and mandatory), tagged v1.0.0.

### New ordering constraints

- `platform` before `fsops` (the crossing rule is a parameter of every walk).
- `workerpool` before any `fsops` caller (INV-1 must hold from the first write, not be retro-fitted).
- `idmap.Resolve` before `qtsauth` can issue a session.

### What can be tested without a NAS

**CI `test-linux-root` job (root on an Ubuntu runner) — the highest-value new tests:**
- `useradd` three fixture users (`alice`, `bob`, `carol`) and two groups (`team`, `other`), `alice` and `carol` in `team`. Build a fixture tree with mixed ownership and modes.
- File `0600 alice:team` → `bob`'s worker gets `EACCES` on `OpenRead`; `alice`'s worker succeeds.
- Dir `0070 root:team` → `carol` can `List` (supplementary group), `bob` cannot. This is the test that catches the `Credential.Groups == nil` bug.
- `chmod` by non-owner → `EPERM`; by owner → ok. `chown` uid by non-root → `EPERM`. `chgrp` to a member group → ok; to a non-member group → `EPERM`.
- setgid silently dropped: request `2755` as a non-member owner, assert the post-call `Lstat` shows `0755` **and** that the response carries the warning.
- Sticky-directory delete: `1777` dir with a file owned by `alice`; `bob`'s worker gets `EPERM` on unlink.
- Recursive chmod over a mixed-ownership tree → job completes `done` with the right changed/skipped counts, not `failed`.
- `SCM_RIGHTS` round trip: `OpenRead` fd is readable in the parent and its `fstat` matches; the fd is not leaked into the *next* worker (check `/proc/<pid>/fd`).
- Crash recovery: `kill -9` the worker mid-`List` → in-flight RPC returns `worker_gone`, next request respawns, restart budget trips after 5.
- Idle reap, LRU eviction at `max`, `bye`-then-`SIGTERM` shutdown ordering.
- Parent death: kill the front-end, assert workers exit within 2 s (validates the EOF path independently of `Pdeathsig`).

**CI ZFS job (`apt-get install zfsutils-linux`, file-backed pool, two datasets mounted under a fake `/share/ZFS1_DATA`):** this is the single most valuable NAS-free test, because it exercises the entire hero delta.
- Per-dataset `st_dev`; `MayCross` allows same-pool crossing and refuses a second pool and a tmpfs.
- `rename` between datasets returns `EXDEV`; the move pre-flight predicts it correctly.
- `TrashRoot` lands on the dataset root, not the pool root.
- `Platform.Detect` reports `zfs` `FSCaps` from real mountinfo.
- `zfs get aclmode` parsing.
- ACL xattr probe is written **tolerantly**, because upstream OpenZFS on Linux may not expose `system.nfs4_acl` while QNAP's fork does — the test asserts "detects whichever is present, reports `none` otherwise", never "asserts nfs4".

**Unprivileged CI (no root):** `unshare -Ur` maps the runner user to uid 0 in a new user namespace with two mapped uids, enough to exercise the pool's spawn/reap/crash logic and the socketpair protocol without a root runner. Useful as the fast pre-merge gate.

**Windows dev box:** `-jail` + an in-process worker running as the developer; every permission-semantics test is `t.Skip`ped, because simulating the kernel's rules would violate INV-2 and would test the simulation rather than the product. `Platform` is fully testable via `FromMountinfo` over golden mountinfo files captured from a real QTS and a real hero NAS (capture them during the M1 install and check them into `testdata/`).

**Not testable off-NAS, and must stay on the checklist:** `authLogin.cgi` response shapes, cookie attributes, the Apache proxy rule, `QPKG_DESKTOP_APP` behaviour, QNAP's Advanced Folder Permissions layer, hero volume naming, busybox `id -G`.

---

### Critical Files for Implementation

- `C:\Dev\QNAPFileManager\PLAN.md` — decisions 4, 5, 9, 12 and the milestone table are superseded by the above; the "must verify on the real NAS" list is replaced by §5.4.
- `C:\Dev\QNAPFileManager\docs\design\backend-packaging-plan.md` — §2.5–2.9 (`CopyOptions.OneFileSystem` → `Crossing`, `ACLBackend()` → per-mount `FSCaps`), §5 (auth), §6.5 (mount rule), §7.1 (`qpkg.cfg`) need rewriting against this design.
- `C:\Dev\QNAPFileManager\docs\design\ui-ux-safety-plan.md` — §5.1's framing table is now the primary path rather than best-effort; the permissions dialog and job-summary sections need the non-owner and partial-success states from §3.3.
- `C:\Dev\QNAPFileManager\docs\research\qts-integration-facts.md` — extend with the identity findings (§1) and the hero facts (§4) as they are verified.
- New, and the three files the implementation actually turns on: `internal/wproto/frame.go` (protocol), `internal/workerpool/pool.go` (lifecycle and INV-1 boundary), `internal/platform/mounts.go` (`FSCaps`, `MayCross`, QTS/hero detection).