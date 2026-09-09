
# QNAPFileManager — Backend, API and Packaging Implementation Plan

**Target repo:** `C:\Dev\QNAPFileManager` (currently empty, not a git repo)
**Reference repo:** `C:\Dev\GitBackup` — every "copy from" path below is absolute and real.

---

## 0. Decisions taken up front

| Question | Decision | Why |
|---|---|---|
| Module name | `qnapfilemanager` (bare, no host prefix) | Mirrors `C:\Dev\GitBackup\go.mod` (`module gitbackup`) |
| Binary name | `qnapfilemanager` | The service script greps `/proc/<pid>/cmdline` for it (see `C:\Dev\GitBackup\qpkg\shared\GitBackup.sh:39-42`); a short name like `qfm` would false-positive |
| Config format | **JSON**, not YAML | Drops `gopkg.in/yaml.v3`. Config here is almost entirely UI-written (password hash, port, toggles); nobody hand-edits it. Leaves exactly one dependency: `golang.org/x/crypto/bcrypt` |
| Auth for v1 | **Own bcrypt login** + a first-run *claim window*; QTS auth added in M4 behind `auth.mode` | Only mode testable on the Windows dev box and in CI; does not depend on undocumented firmware behaviour (§5) |
| Job progress transport | **Polling** `/api/jobs` in v1; SSE endpoint added in M2 as an enhancement with identical JSON | No goroutine-per-tab, trivially testable with `httptest`, immune to any QTS reverse-proxy buffering |
| QPKG web port | **8770** | 8765 is GitBackup's, and it is already bound on this user's NAS and dev box |
| ACLs | v1 = POSIX mode + owner/group, with a **read-only "has extended ACL" badge**; v2 = edit | §2.9 |
| Trash | **Own trash dir per volume**, not QTS `@Recycle` | §2.7 — `@Recycle`'s original-path metadata store is undocumented; writing into it produces entries File Station cannot restore correctly |
| Dev sandbox | A `-jail` flag that reroots every syscall | §7.4 — the single highest-value decision for the dev loop, and it doubles as the test fixture mechanism and a defence-in-depth option in production |

---

## 1. Repo layout

```
C:\Dev\QNAPFileManager\
├─ go.mod                       module qnapfilemanager / go 1.26.0
├─ go.sum
├─ .gitattributes               ← adapt C:\Dev\GitBackup\.gitattributes
├─ .gitignore                   ← adapt C:\Dev\GitBackup\.gitignore
├─ .claude\launch.json          ← adapt C:\Dev\GitBackup\.claude\launch.json
├─ CLAUDE.md                    fresh (carry over gotchas 1,2,3,6,8 verbatim)
├─ README.md  LICENSE           fresh
├─ config.example.json          fresh
├─ dev-config.json              gitignored, created by hand
│
├─ cmd\qnapfilemanager\
│    main.go                    flags, config load, wiring, graceful shutdown
│    main_test.go
│
├─ internal\
│  ├─ fsx\                      ← THE core package. All fresh.
│  │    root.go       Root (the -jail mapping): OS(), API(), Rel()
│  │    path.go       Clean, Resolve, ResolveParent, IsWithin, Base64 name handling
│  │    entry.go      Entry struct + JSON tags
│  │    list.go       List(ctx, Root, dir, ListOptions) (Listing, error)
│  │    stat.go       Stat(ctx, Root, path) (Entry, error); Properties(...)
│  │    stat_linux.go     statDetail(): uid/gid/dev/ino/nlink/atime/ctime
│  │    stat_windows.go   statDetail(): synthesised uid=0/gid=0
│  │    share.go      ShareClass(): /share symlink + RAM-disk rules
│  │    mount.go      Mounts() from /proc/self/mountinfo (cached); IsMountPoint()
│  │    mkdir.go rename.go
│  │    copy.go       Copy, copyFile, copyDir, copySymlink, cross-device
│  │    delete.go     Delete, deleteTree (post-order, one-filesystem)
│  │    walk.go       walk() — own stack-based walker with ctx + dev checks
│  │    chmod.go      Chmod, ChmodRecursive
│  │    chown_unix.go chown_windows.go
│  │    acl_linux.go  HasACL() via syscall.Getxattr; acl_other.go stub
│  │    text.go       ReadText, WriteText
│  │    search.go     Search(ctx, root, SearchOptions, emit func(Entry) bool)
│  │    archive.go    WriteZip, WriteTarGz (streaming)
│  │    upload.go     ReceiveStream, ReceiveMultipart
│  │    trash.go      Trash, TrashList, Restore, EmptyTrash, sweep
│  │    errors.go     Err* sentinels + Code(err) string
│  │    *_test.go     + testtree.go (fixture builder)
│  ├─ guard\          protected paths, read-only mode, confirmation tokens
│  │    guard.go rules.go confirm.go guard_test.go
│  ├─ jobs\           manager.go job.go progress.go manager_test.go
│  ├─ audit\          audit.go (JSON lines + QuLog mirror) audit_test.go
│  ├─ idmap\          idmap.go (/etc/passwd,/etc/group cache) idmap_test.go
│  ├─ qts\            authlogin.go (authLogin.cgi client), ulinux.go (INI reader)
│  ├─ qnap\           ← COPY C:\Dev\GitBackup\internal\qnap\qnap.go verbatim, change Keyword
│  ├─ diskfree\       ← COPY C:\Dev\GitBackup\internal\diskfree\* verbatim
│  ├─ logfile\        ← COPY C:\Dev\GitBackup\internal\logfile\* verbatim
│  ├─ jsonfile\       ← COPY C:\Dev\GitBackup\internal\jsonfile\* verbatim
│  ├─ durable\        ← COPY C:\Dev\GitBackup\internal\durable\* verbatim
│  ├─ config\         config.go (JSON), validate.go, config_test.go
│  └─ web\
│       server.go     Server struct, ListenAndServe, routes
│       routes_fs.go  handleList/Stat/Mkdir/Rename/Delete/Chmod/Chown/Text/...
│       routes_jobs.go handleJobs, handleJobCancel, handleJobStream (SSE, M2)
│       routes_xfer.go handleDownload, handleArchive, handleUpload
│       auth.go       middleware, local login, QTS login (M4)
│       session.go    ← COPY C:\Dev\GitBackup\internal\web\session.go (rename cookie)
│       throttle.go   ← COPY C:\Dev\GitBackup\internal\web\throttle.go verbatim
│       clientip.go   ← COPY C:\Dev\GitBackup\internal\web\clientip.go verbatim
│       selfsigned.go ← COPY C:\Dev\GitBackup\internal\web\selfsigned.go verbatim
│       security.go   headers + checkSameOrigin (adapted, see §4.5)
│       jsonhttp.go   writeJSON, writeErr, apiError
│       static\       index.html  app.js  app.css  icons.svg   (go:embed)
│
├─ qpkg\
│    qpkg.cfg                   ← adapt C:\Dev\GitBackup\qpkg\qpkg.cfg
│    package_routines           ← adapt C:\Dev\GitBackup\qpkg\package_routines
│    shared\QNAPFileManager.sh  ← adapt C:\Dev\GitBackup\qpkg\shared\GitBackup.sh
│    icons\QNAPFileManager.gif / _80.gif / _gray.gif
│
├─ scripts\
│    build-local.ps1            ← adapt C:\Dev\GitBackup\scripts\build-local.ps1
│    make-icons.ps1             ← adapt C:\Dev\GitBackup\scripts\make-icons.ps1
│    make-fakeroot.ps1          fresh — builds testdata\fakeroot for the dev loop
│
├─ testdata\fakeroot\           gitignored, generated
│
├─ docs\
│    qnap-install.md            ← model on C:\Dev\GitBackup\docs\qnap-install.md
│    api.md  safety.md  development.md  nas-checklist.md
│
└─ .github\workflows\build.yml  ← adapt C:\Dev\GitBackup\.github\workflows\build.yml
```

### 1.1 Copy nearly verbatim (with source paths)

| Source | Destination | Change |
|---|---|---|
| `C:\Dev\GitBackup\internal\qnap\qnap.go` | `internal\qnap\qnap.go` | `Keyword = "QNAPFileManager"` only |
| `C:\Dev\GitBackup\internal\diskfree\diskfree_unix.go` (+ windows sibling) | `internal\diskfree\` | none |
| `C:\Dev\GitBackup\internal\logfile\logfile.go` | `internal\logfile\` | none — used for both the app log and `audit.jsonl` |
| `C:\Dev\GitBackup\internal\jsonfile\jsonfile.go`, `internal\durable\*` | same | none — atomic config writes |
| `C:\Dev\GitBackup\internal\web\session.go` | `internal\web\session.go` | `sessionCookie = "qfm_session"`; drop `sessionTTL` to 4 h (root tool) |
| `C:\Dev\GitBackup\internal\web\throttle.go` | same | none |
| `C:\Dev\GitBackup\internal\web\clientip.go` | same | none |
| `C:\Dev\GitBackup\internal\web\selfsigned.go` | same | none — needed if QTS is https-only (§5.4) |
| `C:\Dev\GitBackup\internal\web\server.go:1271-1290` `checkSameOrigin` + the header block at `:665-682` | `internal\web\security.go` | **must diverge** — see §4.5 |
| `C:\Dev\GitBackup\internal\web\server.go:2082-2116` (the `/share` rule) | `internal\fsx\share.go` | **behaviour change** — see §2.2 |
| `C:\Dev\GitBackup\qpkg\shared\GitBackup.sh` | `qpkg\shared\QNAPFileManager.sh` | strip all git/git-lfs/CA env (lines 16-26, 61-70); keep the Install_Path guard, pidfile, `is_running`, startup.log, and the `sleep 2 && is_running` check verbatim |
| `C:\Dev\GitBackup\.github\workflows\build.yml` — the `test`, `test-windows` and `package` jobs, and the pinned-by-commit QDK install at lines 384-402 | `.github\workflows\build.yml` | delete `static-git`, `docker`, `windows`, the git-lfs download and the git smoke assertions |
| `C:\Dev\GitBackup\docs\qnap-install.md` | `docs\qnap-install.md` | structure and the RAM-disk / arch-selection / install-manually / unsigned-warning prose |

### 1.2 Write fresh
`internal/fsx` (all of it), `internal/guard`, `internal/jobs`, `internal/audit`, `internal/idmap`, `internal/qts`, `internal/config`, all of `internal/web/routes_*.go`, `internal/web/static/*`, `cmd/qnapfilemanager/main.go`.

### 1.3 Departures from GitBackup convention, and why

1. **Static assets split into `index.html` + `app.js` + `app.css`** instead of GitBackup's single `internal/web/static/index.html`. This UI is far larger, and a separate `app.js` lets the CSP be `script-src 'self'` with no `'unsafe-inline'` — worth having on a tool that runs as root. Still no npm, still `go:embed`.
2. **JSON config, not YAML** (§0).
3. **`internal/fsx`, not `internal/fs`** — `fs` shadows the `io/fs` import that every file in the package needs.

---

## 2. Filesystem service layer — `internal/fsx`

Every function takes `ctx context.Context` first and `r Root` second. `Root` is the jail mapping (§7.4); in production `Root{"/"}` is the identity.

### 2.0 Path resolution — `path.go`

```go
// Clean normalises an API path: absolute, slash-separated, no "." or "..".
func Clean(p string) (string, error)          // rejects "", relative, NUL bytes, UNC-ish "//host"

// Resolve is Clean plus symlink hardening for READ operations.
func Resolve(r Root, p string) (apiPath, osPath string, err error)

// ResolveParent is what every WRITE operation must use: it EvalSymlinks the
// *parent* directory and re-checks the result against the guard, so a symlink
// /share/x -> /etc/config cannot be used to write into a protected directory.
func ResolveParent(r Root, p string) (parentAPI, parentOS, base string, err error)
```

- `filepath.Clean` on Windows would rewrite `/` to `\`; use `path.Clean` on the API side and convert to an OS path only inside `Root.OS()`.
- Guard checks run on the **resolved** path, never the raw one.
- Residual TOCTOU risk: stdlib has no `openat2`/`RESOLVE_BENEATH`. Documented in `docs/safety.md` as accepted — exploiting it requires an attacker who already has local write access on the NAS.

**Non-UTF-8 filenames.** Linux filenames are arbitrary bytes; `encoding/json` replaces invalid sequences with U+FFFD, so such a name cannot round-trip. Legacy QNAP shares have these. Every `Entry` therefore carries:

```go
NameB64 string `json:"nameB64,omitempty"` // base64url of the raw bytes, set only when !utf8.ValidString(Name)
PathB64 string `json:"pathB64,omitempty"`
```

and **every endpoint that accepts a path also accepts `pathB64`**. `decodePathParam(r *http.Request, name string) (string, error)` in `jsonhttp.go` is the single place that resolves the pair.

### 2.1 `List` — the workhorse

```go
type ListOptions struct {
    ShowHidden     bool   // dotfiles
    ShowVolumeRoots bool  // at /share: reveal CACHEDEV*_DATA etc (see 2.2)
    ResolveLinks   bool   // os.Stat each symlink to learn target type (default true)
    Sort           string // "name"|"size"|"mtime"|"type"
    Desc           bool
    Offset, Limit  int    // Limit defaults to 5000, hard cap 50000
}
type Listing struct {
    Path, Parent string
    Entries      []Entry
    Total        int
    Truncated    bool
    Notes        []string // "on the QTS RAM disk", "mount point", …
    Class        string   // guard classification of the directory itself
}
func List(ctx context.Context, r Root, dir string, o ListOptions) (Listing, error)
```

`Entry` (JSON as shown):

```go
type Entry struct {
    Name, NameB64 string
    Path, PathB64 string
    Type          string    // "dir"|"file"|"symlink"|"fifo"|"socket"|"device"|"other"
    Size          int64     // st_size; for symlinks the link length, not the target's
    Mode          string    // "0755"  (octal, includes setuid/setgid/sticky)
    ModeStr       string    // "drwxr-sr-x"
    UID, GID      int
    User, Group   string    // "" when unresolvable → UI shows the number
    MTime         time.Time // RFC3339
    Nlink         uint64
    IsSymlink     bool
    LinkTarget    string    // raw os.Readlink
    LinkResolved  string    // filepath.EvalSymlinks, "" when dangling/looping
    TargetType    string    // "dir"|"file"|"" when dangling
    Hidden        bool
    HasACL        bool      // §2.9
    MountPoint    bool
    Class         string    // "normal"|"warn"|"protected" from internal/guard
    ShareLink     bool      // §2.2
    VolumeRoot    bool      // §2.2
}
```

Implementation notes:
- `os.ReadDir` returns `DirEntry`; call `e.Info()` (which is `Lstat` data on Linux, already cached by `getdents`) — do **not** `os.Lstat` again per entry, it doubles syscalls on 10k-entry directories.
- Only when `ResolveLinks` and `e.Type()&fs.ModeSymlink != 0` do an extra `os.Stat`. This is the expensive part on `/share`; it is also exactly what GitBackup does at `C:\Dev\GitBackup\internal\web\server.go:2102`.
- uid/gid → name through `idmap` (below), never `os/user` (no bulk API, no "list all users" for the chown picker).
- A directory the daemon cannot read returns `ErrPermission` even as root — that happens on `/proc/<pid>` races; return the error rather than a partial list.

### 2.2 The `/share` rule — a deliberate change from GitBackup

GitBackup at `C:\Dev\GitBackup\internal\web\server.go:2114-2116` **hides** the raw volume mounts at `/share`, showing only the symlinked shares, to match File Station. For this app that is backwards: seeing above and beside the shares is the entire product.

`internal/fsx/share.go`:

```go
// ShareClass tags entries at /share. QTS lays out /share as a small tmpfs
// holding one symlink per registered shared folder (Public -> CACHEDEV1_DATA/Public)
// alongside the raw volume mount points themselves (CACHEDEV1_DATA, and on this
// user's NAS the legacy HDA_DATA … HDK_DATA).
func ShareClass(dir, name string, e fs.DirEntry) (shareLink, volumeRoot bool)

// IsShareRAMDisk reports whether /share is the QTS tmpfs, i.e. the same device
// as /. Reuses diskfree.SameDevice — the same test GitBackup uses.
func IsShareRAMDisk(r Root) bool
```

Behaviour: at `/share`, return **everything**, with `ShareLink`/`VolumeRoot` set. The UI defaults to hiding `VolumeRoot` entries behind a "show volume mounts" toggle, so the default view matches File Station while the capability is one click away.

RAM-disk rule (from `C:\Dev\GitBackup\internal\web\server.go:2138-2141`): creating, uploading, pasting, extracting or trashing **directly into `/share`** is refused with the guard code `ramdisk`, message adapted from `errShareRoot`. Overridable only with an explicit confirmation token (§6.3).

### 2.3 Stat / properties

```go
func Stat(ctx, r, path) (Entry, error)                     // single Lstat, cheap
func Properties(ctx, r, path) (Props, error)               // + free/total on the fs, mount info, ACL flag
// Recursive size is ALWAYS a job — never inline:
jobs.Submit("size", …, func(ctx, p *jobs.Progress) (any, error) { return fsx.TreeSize(ctx, r, path, p) })
type SizeResult struct{ Files, Dirs, Links int64; Bytes, Apparent int64; Skipped []string }
```

`TreeSize` counts `st_blocks*512` as `Bytes` (real occupancy, matches `du`) and `st_size` as `Apparent`; deduplicates hardlinks by `(dev,ino)` in a `map[[2]uint64]struct{}` capped at 2 M entries, beyond which it stops deduplicating and adds a warning.

### 2.4 mkdir / rename

```go
func Mkdir(ctx, r, dir, name string, mode os.FileMode) (string, error)  // mode default 0755, O_EXCL semantics
func MkdirAll(ctx, r, path string, mode os.FileMode) error              // each created level guard-checked
func Rename(ctx, r, from, to string, overwrite bool) error
```
- `name` must be non-empty, must not contain `/` or NUL, must not be `.` or `..` (GitBackup's check at `server.go:2132` covers `/` and `\`; on Linux `\` is a legal filename character, so **do not copy that half**).
- `Rename` refuses when `to` exists unless `overwrite`; `os.Rename` overwrites silently on Linux, so pre-check with `os.Lstat` and accept the race.
- `Rename` across devices returns `ErrCrossDevice` (`syscall.EXDEV` inside `*os.LinkError`) — the API turns that into "use Move instead", and the UI submits a move job.

### 2.5 Copy — `copy.go`

```go
type CopyOptions struct {
    Conflict       string // "skip"|"overwrite"|"rename"  (rename → "name (2).ext")
    PreserveTimes  bool   // default true
    PreserveOwner  bool   // default true (we are root)
    FollowSymlinks bool   // default false → recreate the link
    OneFileSystem  bool   // default true
}
func Copy(ctx context.Context, r Root, src, dstDir string, o CopyOptions, p *jobs.Progress) error
```

Semantics on QTS as root:
- **Walk** with `walk.go` (own explicit stack, not `filepath.WalkDir`): it must check `ctx.Err()` per entry, compare `st_dev` against the top-level source's, and consult `guard` per entry.
- **Regular files**: `os.OpenFile(dst, O_WRONLY|O_CREATE|O_EXCL, srcMode.Perm())` → `io.CopyBuffer` with a 1 MiB buffer wrapped in a `countingWriter` that ticks `p.AddBytes(n)` and checks `ctx.Err()` — a cancel therefore lands within one buffer, not at the end of a 40 GB file. No `Sync()` (a NAS copy of thousands of files would crawl); the caller may request `fsync` via `CopyOptions` later.
- **Order**: content → `os.Lchown` → `os.Chmod` (chown clears setuid/setgid, so chmod must come after) → `os.Chtimes`.
- **Directories**: created 0700 first, then their real mode applied on the way *out* of the subtree, so a mode like 0500 does not block writing children.
- **Symlinks**: `os.Readlink` + `os.Symlink` + `os.Lchown`. There is no `lchmod` on Linux — symlink modes are meaningless and are not copied.
- **Device nodes, FIFOs, sockets**: skipped with `p.Warn("skipped special file %s")`. `mknod` is not reachable without cgo and copying a socket is meaningless.
- **Hardlinks**: not preserved in v1 — a tree with hardlinks is duplicated. Recorded as a warning when `nlink > 1` is seen. (v2: `(dev,ino) → firstDst` map + `os.Link`.)
- **Cross-device**: irrelevant for copy (it is always a read+write), but `OneFileSystem` is what keeps a copy of `/` from descending into `/proc`, `/sys`, `/dev` and every mounted volume.
- **Sparse files**: not detected; a sparse file is materialised. Noted in `docs/safety.md`.
- **Free-space precheck**: before starting, `statfs(dstDir)` vs. the scanned byte total; refuse with `ErrNoSpace` rather than filling a volume. (`internal/diskfree` gains `Avail(path) (uint64, error)` alongside the copied `SameDevice`.)

### 2.6 Move

```go
func Move(ctx, r, src, dstDir string, o CopyOptions, p *jobs.Progress) error
```
`os.Rename` first (instant, same device). On `EXDEV`: full `Copy`, verify it completed without error, **then** `Delete` the source. Never delete before the copy is verified. A cancelled cross-device move leaves both copies and says so.

### 2.7 Delete and trash

```go
func Delete(ctx, r, path string, o DeleteOptions, p *jobs.Progress) error
type DeleteOptions struct{ Recursive, AllowMountPoint bool }
```
- Post-order (`os.Remove` on children before the parent), never `os.RemoveAll` — `RemoveAll` cannot be cancelled, cannot report progress, and happily follows into other filesystems.
- Refuses when the target is a mount point (its `st_dev` differs from its parent's, cross-checked against `/proc/self/mountinfo`) unless `AllowMountPoint`. Unmounting a volume by `rm -rf` is the single worst thing this app could do.
- Never descends into a different device.
- `guard.Check(OpDelete, path)` for the root **and for every entry** during the walk, because a symlinked subtree could reach a protected path — though the walk is `Lstat`-only, so it removes the link, not the target.

**QTS recycle bins — what is actually there, and what we do.**
When *Network Recycle Bin* is enabled for a shared folder, QTS creates `@Recycle` at the root of that shared folder (`/share/CACHEDEV1_DATA/Public/@Recycle`), optionally with a per-user subdirectory. Older/legacy layouts used a single per-volume `Network Recycle Bin 1` directory. The original-path/deleted-at metadata that File Station shows in its Recycle Bin view is held in a firmware-private store whose format is **undocumented**.

Consequence: moving a file into `@Recycle` ourselves creates an entry File Station will list but cannot restore to the right place. So v1 does **not** write into `@Recycle`. Instead:

```go
// TrashRoot walks up from path until st_dev changes (or a /share/*_DATA
// pattern matches) to find the volume root, then returns
// <volumeRoot>/.@qfm_trash. Returns ErrNoTrash when path is not on a volume
// (e.g. /etc/foo) — such deletes are always hard deletes with confirmation.
func TrashRoot(r Root, path string) (string, error)
func Trash(ctx, r, path, actor string) (entryID string, err error)
func TrashList(ctx, r) ([]TrashEntry, error)
func Restore(ctx, r, entryID string) error   // refuses if the original path now exists
func EmptyTrash(ctx, r, olderThan time.Duration, p *jobs.Progress) error
```

Layout: `<volumeRoot>/.@qfm_trash/<unix>-<8 hex>/` containing the moved item plus `meta.json` = `{originalPath, originalPathB64, deletedAt, actor, mode, uid, gid, bytes}`. Because it is on the same device, `Trash` is a single `os.Rename` — instant, no copy, and it fails loudly (`EXDEV`) rather than silently copying if the volume detection is wrong.

`@Recycle` interop is read-only for ever: it is just a normal directory in the listing, shown with a recycle icon.

### 2.8 chmod / chown

```go
func Chmod(ctx, r, path string, mode os.FileMode, o ModeOptions) error
type ModeOptions struct {
    Recursive  bool
    DirsOnly, FilesOnly bool  // the "apply X to folders, Y to files" pattern
    DirMode    os.FileMode    // used when Recursive && DirMode != 0
}
func Chown(ctx, r, path string, uid, gid int, recursive bool) error  // -1 leaves a field alone
```
- Recursive chmod/chown run **as jobs** (a share can hold a million files).
- `Chmod` on a symlink: Linux has no `lchmod`, so `os.Chmod` would silently change the *target's* mode. The service **refuses** chmod on a symlink unless `follow: true` is passed explicitly, and the API says so.
- `Chown` always uses `os.Lchown` (never `os.Chown`) so a symlink's own ownership is what changes.
- `Chown` validates uid/gid against `idmap` and warns (does not refuse) on an unknown id — orphaned uids are normal on a NAS.
- Setuid/setgid/sticky bits are exposed in the API and the UI as three checkboxes; setting setuid on a file outside the guard's "normal" class requires a confirmation token.

### 2.9 ACLs — what is realistically available on QTS

- QTS on ext4 supports **POSIX ACLs**; QuTS hero on ZFS uses **NFSv4 ACLs**. QNAP's "Advanced Folder Permissions" layer stores Windows-style ACLs on top.
- Whether `getfacl`/`setfacl` binaries exist on a bare QTS userland is **not certain** and varies by firmware — it must be checked on the NAS (`command -v getfacl; ls /usr/bin/*facl /sbin/*facl`).
- What *is* reliable without any binary and without cgo: `syscall.Getxattr(path, "system.posix_acl_access", nil)` on Linux returns the attribute size, so the presence of an extended ACL (the `+` in `ls -l`) is detectable in pure Go.

**v1** (`internal/fsx/acl_linux.go`):
```go
func HasACL(osPath string) bool          // Getxattr size > 0 on system.posix_acl_access
func ACLBackend() string                 // "posix"|"nfs4"|"none" — probed once at startup
```
Every `Entry` carries `HasACL`. The properties dialog shows a badge: *"This item has an extended ACL that this app does not display. The mode below is only the base permission set — editing it will not remove the ACL."* That is the honest, non-misleading v1: it never lets a user think mode 0644 is the whole story.

**v2**: parse and serialise the POSIX ACL xattr ourselves. The format is a documented fixed-width struct (4-byte `version=2` header, then 8-byte entries of `u16 tag, u16 perm, u32 id`), so a full ACL editor is achievable in pure Go with no `setfacl` dependency. NFSv4/ZFS ACLs are a separate, larger format — v3 at earliest, and only after confirming which firmware families need it.

### 2.10 Upload

Endpoint accepts **both** shapes, sniffed on `Content-Type`:

```go
// Raw body (preferred; what the UI uses):
//   POST /api/fs/upload?path=<dir>&name=<file>&mtime=<unix>&conflict=rename
//   Content-Type: application/octet-stream, body = the bytes
func ReceiveStream(ctx, r Root, dir, name string, body io.Reader, o UploadOptions) (Entry, error)

// multipart/form-data, for a plain <form> and for multi-file posts:
func ReceiveMultipart(ctx, r Root, dir string, mr *multipart.Reader, o UploadOptions) ([]Entry, error)
```
- Multipart **must** use `r.MultipartReader()`, never `r.ParseMultipartForm` — the latter buffers to the OS temp dir, which on QTS is the RAM disk, so a 10 GB upload would OOM the NAS.
- Temp file is created **in the destination directory** as `.qfm-upload-<16 hex>.part` (mode 0600) so the final `os.Rename` is atomic and same-device. `defer os.Remove(tmp)` guarded by a `done` flag handles aborts.
- Filenames from the client are taken as a single path component: rejected if they contain `/` or NUL; `..` rejected.
- Free-space check on `Content-Length` when present.
- After rename: `os.Chtimes` from `mtime` when supplied; mode 0644 minus umask; owner left as root:administrators (a `defaultUpload.uid/gid` config option can change this — worth having on a NAS where files must be owned by a share user).

### 2.11 Download and archive

```go
GET /api/fs/download?path=…            → http.ServeContent (Range, ETag, If-Modified-Since for free)
GET /api/fs/archive?path=…&items=a,b&format=zip|tgz
```
- `Content-Disposition: attachment; filename="ascii-fallback"; filename*=UTF-8''<pct-encoded>` — the `filename*` form is what makes unicode names arrive intact.
- `ServeContent` needs an `io.ReadSeeker`: pass the `*os.File`. Refuse directories and non-regular files here.
- Archive streams `archive/zip` (or `archive/tar` + `compress/gzip`) straight to the `ResponseWriter`: no `Content-Length`, chunked, flush every ~4 MiB. `archive/zip` promotes to Zip64 automatically for >4 GB.
- **The mid-stream error problem**: once bytes are written the status is 200 and cannot be changed. Mitigation: write a final `ERROR.txt` member into the zip describing what failed, log it, and abandon the gzip/zip trailer so the client's unzip reports a truncated archive rather than silently accepting a partial one.
- Default compression for `zip` is `Store` for entries whose name matches an already-compressed extension list (`.zip .gz .jpg .mp4 .qpkg .iso …`) — on a NAS CPU this roughly triples throughput.
- One-filesystem walk applies here too.

### 2.12 Text read / write

```go
func ReadText(ctx, r, path string, max int64) (TextFile, error)
type TextFile struct{ Content string; Bytes int64; Truncated, Binary bool; Mode, MTime, ETag string }
func WriteText(ctx, r, path, content, expectETag string, o WriteOptions) (Entry, error)
type WriteOptions struct{ Atomic bool /*default true*/; Mode os.FileMode; Create bool }
```
- `max` default 2 MiB (`config.maxTextBytes`), hard cap 16 MiB.
- Binary detection: a NUL byte in the first 8 KiB → `Binary: true`, content withheld.
- `ETag` = `fmt.Sprintf("%d-%d", size, mtime.UnixNano())`; a write with a mismatched `expectETag` returns `409 conflict`. This is the guard against two tabs clobbering `/etc/config/smb.conf`.
- Atomic write = temp in the same dir, chmod+chown to the original's mode/uid/gid, then rename. **Caveat, documented and surfaced in the UI:** rename replaces the inode, so hardlinks break and any xattr/ACL on the original is lost. For files whose `HasACL` is true, or `nlink > 1`, the UI defaults to `Atomic: false` (in-place `O_TRUNC`) and warns about the truncation risk instead. Both trade-offs are real; the choice is made per-file on the evidence.

### 2.13 Search

```go
type SearchOptions struct {
    Root        string
    Query       string   // substring, case-insensitive by default
    Glob        bool     // interpret Query with path.Match instead
    Regex       bool     // regexp.MustCompile, timeout-capped
    MinSize,MaxSize int64
    ModifiedAfter, ModifiedBefore time.Time
    IncludeHidden bool
    OneFileSystem bool   // default true
    MaxHits     int      // default 1000
    MaxVisited  int64    // default 500_000
    MaxDuration time.Duration // default 60s
}
func Search(ctx, r, o SearchOptions, emit func(Entry) bool) (SearchStats, error)
```
Always a job. Skips anything `guard` classifies as no-traverse (`/proc`, `/sys`, `/dev`). Returns `SearchStats{Visited, Hits, Truncated, TruncatedReason}` so the UI can say *"first 1000 of many"* honestly. Content search (grep) is explicitly **out of scope for v1**.

### 2.14 idmap — `internal/idmap`

```go
type Map struct{ … }
func Open(passwdPath, groupPath string) *Map      // "/etc/passwd", "/etc/group"
func (m *Map) User(uid int) string                // "" when unknown
func (m *Map) Group(gid int) string
func (m *Map) Users() []Ident                     // for the chown picker
func (m *Map) Groups() []Ident
```
Own parser, not `os/user`: we need bulk lookup for a 10 000-entry listing and a *list-all* for the picker, which `os/user` does not provide. Reloads when either file's `mtime`+`size` changes (QTS regenerates `/etc/passwd` on user changes), checked at most once a second. Tolerates NIS `+`/`-` compat lines and malformed rows by skipping them. On Windows (`idmap_windows.go` or a runtime branch) it returns empty maps and the UI hides the owner column.

---

## 3. Long-running operations — `internal/jobs`

```go
type Kind string   // "copy" "move" "delete" "size" "archive" "search" "chmod" "chown" "trash" "extract"
type State string  // "queued" "running" "done" "failed" "cancelled"

type Job struct {
    ID        string   `json:"id"`          // 16 hex chars from crypto/rand
    Kind      Kind     `json:"kind"`
    State     State    `json:"state"`
    Title     string   `json:"title"`       // "Copying 3 items to /share/Public"
    Src       []string `json:"src,omitempty"`
    Dst       string   `json:"dst,omitempty"`
    Files     int64    `json:"files"`
    FilesTotal int64   `json:"filesTotal"`  // -1 = indeterminate
    Bytes     int64    `json:"bytes"`
    BytesTotal int64   `json:"bytesTotal"`  // -1 = indeterminate
    Current   string   `json:"current"`
    Rate      int64    `json:"rate"`        // bytes/s, EWMA over 5s
    ETA       int      `json:"eta"`         // seconds, -1 unknown
    Phase     string   `json:"phase"`       // "scanning"|"working"|"finishing"
    Warnings  []string `json:"warnings"`    // capped at 100, then a counter
    Err       string   `json:"error,omitempty"`
    ErrCode   string   `json:"errorCode,omitempty"`
    Actor     string   `json:"actor"`
    StartedAt, UpdatedAt, FinishedAt time.Time
    Result    json.RawMessage `json:"result,omitempty"`
}

type Manager struct{ … }
func New(limits map[Kind]int) *Manager
func (m *Manager) Submit(kind Kind, title string, meta Meta,
        fn func(ctx context.Context, p *Progress) (any, error)) (*Job, error)
func (m *Manager) Get(id string) (Job, bool)
func (m *Manager) List() []Job                 // newest first
func (m *Manager) Cancel(id string) bool
func (m *Manager) Subscribe() (<-chan Job, func())   // used by SSE in M2
func (m *Manager) Reap()                        // called by a 1-minute ticker
```

**Two phases.** `copy`, `move`, `delete` and `archive` run a *scan* first (count files and bytes) so progress has a denominator. The scan is itself capped: 30 s or 500 000 entries, after which `FilesTotal = -1` and the UI shows an indeterminate bar. This avoids the classic failure where scanning a 4 M-file share takes longer than the copy.

**Concurrency**, two independent semaphores so a folder-size probe is never stuck behind a 200 GB copy:
- byte-movers (`copy`, `move`, `archive`, `extract`): **2** — a spinning-disk NAS thrashes beyond that.
- metadata (`delete`, `size`, `search`, `chmod`, `chown`, `trash`): **4**.
- queue depth cap 64 per class; `Submit` returns `ErrQueueFull` beyond that.

**Cancel.** Each job stores its `context.CancelFunc`. `Progress.Step()` returns `ctx.Err()`, and the copy loop's counting writer checks it every buffer. **Partial work is not rolled back** — this is stated in the API response and shown in the UI: *"Cancelled after 412 of 8 003 files. A partial copy remains at /share/Public/x."* Pretending otherwise would be worse than saying it.

**Retention.** Finished jobs are kept for 1 h or the most recent 50, whichever is larger; `Reap()` runs on a ticker. Jobs are in-memory only — a restart loses history, which matches GitBackup's session policy and keeps nothing replayable on disk. The *audit log* is the durable record.

**Transport.**
- v1: `GET /api/jobs` returns the whole list. The UI polls at 500 ms while any job is `queued`/`running`, stops entirely when idle, and pauses on `document.hidden`.
- M2: `GET /api/jobs/stream` — `text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`, one `event: job` per change plus a `:heartbeat` comment every 20 s, `http.ResponseController.Flush()` after each write, and a hard 30-minute connection lifetime after which the client reconnects. Falls back to polling on `EventSource` error. Identical JSON either way, so `routes_jobs.go` has one marshaller.

---

## 4. HTTP API

### 4.1 Routes

| Method | Path | Body / query | Notes |
|---|---|---|---|
| GET | `/api/session` | — | `{authenticated, mode, user, admin, readOnly, version, isQTS, jailed, csrf}` |
| POST | `/api/login` | `{username,password,code}` | throttled |
| POST | `/api/setup` | `{username,password}` | only inside the claim window (§5.5) |
| POST | `/api/logout` | — | |
| GET | `/api/fs/list` | `path` \| `pathB64`, `hidden`, `volumes`, `sort`, `desc`, `offset`, `limit` | §2.1 |
| GET | `/api/fs/stat` | `path` | single entry |
| GET | `/api/fs/properties` | `path` | + filesystem free/total, mount, ACL flag |
| GET | `/api/fs/roots` | — | quick-jump list: `/`, `/share`, each share, each volume, `/etc`, `/etc/config`, install dir |
| POST | `/api/fs/mkdir` | `{path,name,mode}` | |
| POST | `/api/fs/rename` | `{path,name,overwrite}` | same directory only |
| POST | `/api/fs/copy` | `{src:[…],dst,conflict,followSymlinks}` | → `202 {job}` |
| POST | `/api/fs/move` | `{src:[…],dst,conflict}` | → `202 {job}` |
| POST | `/api/fs/delete` | `{paths:[…],recursive,trash,confirm}` | `202 {job}` or `409 confirm_required` |
| POST | `/api/fs/chmod` | `{paths:[…],mode,recursive,dirMode,follow}` | sync when 1 non-recursive item, else job |
| POST | `/api/fs/chown` | `{paths:[…],uid,gid,recursive}` | same |
| POST | `/api/fs/size` | `{paths:[…]}` | → `202 {job}` |
| POST | `/api/fs/search` | `SearchOptions` | → `202 {job}`; results in `job.result` |
| GET | `/api/fs/text` | `path` | |
| POST | `/api/fs/text` | `{path,content,etag,atomic,create}` | |
| POST | `/api/fs/upload` | query `path`,`name`,`mtime`,`conflict`; raw or multipart body | §2.10 |
| GET | `/api/fs/download` | `path` | `ServeContent`, Range |
| GET | `/api/fs/archive` | `path`, `items`, `format` | streamed |
| GET | `/api/fs/trash` | — | trash listing |
| POST | `/api/fs/trash/restore` | `{id}` | |
| POST | `/api/fs/trash/empty` | `{olderThanDays,confirm}` | → job |
| GET | `/api/ids` | `kind=users\|groups` | for the chown picker |
| GET | `/api/jobs` / `/api/jobs/get?id=` | — | |
| POST | `/api/jobs/cancel` | `{id}` | |
| GET | `/api/jobs/stream` | — | SSE, M2 |
| GET/POST | `/api/config` | | port, readOnly, trash retention, limits, auth mode |
| POST | `/api/readonly` | `{enabled,password}` | unlock requires re-auth (§6.4) |
| GET | `/api/audit` | `limit`,`since` | tail of `audit.jsonl` |
| GET | `/api/diag` | — | uid, isQTS, install path, ACL backend, /share class, port, version |

`/` serves the embedded static tree exactly as `C:\Dev\GitBackup\internal\web\server.go:374` does.

**Why `/api/fs/list?path=…` and not `/api/fs/list/{path...}`.** Go's `http.ServeMux` cleans `..` and collapses `//` in the URL path before routing, and `%2F` handling in path segments is a permanent source of surprise. Paths live in **query parameters** (percent-encoded by `encodeURIComponent`, which covers space, `#`, `?`, `+`, `&` and all unicode) or in JSON bodies. `#` in a filename is the classic break here and this design handles it with no special cases.

### 4.2 JSON shapes

Success: the object itself (`Listing`, `Entry`, `Job`, …). Async: `202` with `{"job": {…}}`.

Error, uniformly:
```json
{"error":{"code":"protected","message":"/etc/config is protected: QTS firmware configuration","path":"/etc/config","op":"delete","detail":"..."}}
```
`code` ∈ `bad_request, unauthorized, not_found, exists, not_empty, permission, protected, readonly, ramdisk, cross_device, no_space, too_large, unsupported, conflict, confirm_required, cancelled, queue_full, internal`.

`internal/fsx/errors.go` exposes `func Code(err error) string`, mapping `fs.ErrNotExist`→`not_found`, `fs.ErrExist`→`exists`, `fs.ErrPermission`→`permission`, `syscall.ENOTEMPTY`→`not_empty`, `syscall.EXDEV`→`cross_device`, `syscall.ENOSPC`→`no_space`, `syscall.EROFS`→`readonly`, `context.Canceled`→`cancelled`, and the `guard` sentinels. `internal/web/jsonhttp.go` maps code→status: 400/401/403/404/409/413/415/429/500.

### 4.3 Limits and timeouts

- `http.Server{ReadHeaderTimeout: 10*time.Second, IdleTimeout: 2*time.Minute}` — copy the reasoning comment from `C:\Dev\GitBackup\internal\web\server.go:427-436`. **No `WriteTimeout`** (multi-gigabyte downloads) and **no `ReadTimeout`** (multi-gigabyte uploads).
- JSON bodies: `http.MaxBytesReader(w, r.Body, 1<<20)` in middleware for every `/api/` path **except** `/api/fs/upload` and `/api/fs/text` (the latter gets `maxTextBytes + 64 KiB`).
- Uploads bounded by free space, not by a fixed byte cap.
- Per-request `context.WithTimeout(r.Context(), 15*time.Second)` on metadata handlers. **Honest caveat**: a blocked syscall on a hung NFS/SMB mount cannot be interrupted by a context. Mitigation in `List`: run the `ReadDir` in a goroutine and return `504 {"code":"internal","message":"the filesystem did not respond"}` when the timeout fires, deliberately leaking that goroutine rather than hanging the tab. Documented in `docs/safety.md`.
- `MaxHeaderBytes: 64 << 10`.

### 4.4 Headers (middleware, adapted from `server.go:665-682`)

```
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
    img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store         (on /api/ and on the HTML shell)
```
The strict `script-src 'self'` is why the JS is split out of `index.html` (§1.3).

### 4.5 CSRF — a required divergence from GitBackup

`C:\Dev\GitBackup\internal\web\server.go:1271` requires `Content-Type: application/json` on every write. That is elegant, but **it cannot work here**: `/api/fs/upload` sends `application/octet-stream` or `multipart/form-data`, both of which a cross-site `<form>` *can* produce. So `internal/web/security.go` uses three locks:

1. Session cookie `SameSite=Strict` (copied from `session.go:105`).
2. `Origin`/`Referer` host must equal `r.Host` when present (copied logic).
3. **A required header on every non-GET/HEAD request**: `X-QFM-CSRF: <token>`, where the token is issued in `/api/session` and bound to the session. A cross-site `<form>` cannot set headers at all; a cross-site `fetch` that sets a custom header triggers a preflight this server never answers. `Sec-Fetch-Site: cross-site` is also rejected outright when present.

JSON endpoints additionally keep the `application/json` requirement, so nothing is lost relative to GitBackup.

---

## 5. Authentication

### 5.1 The three options

**(a) Own bcrypt login** (as `C:\Dev\GitBackup\internal\web\server.go:827-879` + `session.go` + `throttle.go`).
*Pro:* proven code, already written, testable in CI and on the Windows dev box; works when QTS's own web server is down, on a nonstandard port, or behind QuFirewall; independent of firmware changes. Supports TOTP if wanted (GitBackup already has `internal/totp`).
*Con:* a second password to manage; a first-run bootstrap window to secure; no relationship to who is actually a NAS admin.

**(b) QTS session validation** via `authLogin.cgi`.
*Pro:* one identity, real admin gating, no second password, the "opens straight from App Center" experience.
*Con:* every part of it is undocumented and firmware-version dependent; untestable off a real NAS; a firmware update that renames a cookie locks the admin out of their root file manager — the tool they would use to fix it.

**(c) Both**, selected by `auth.mode`.

### 5.2 Recommendation

**v1 = (a).** Ship (b) in M4 as an additional mode with `config.auth.mode ∈ {"local","qts","both"}`, defaulting to `"local"` until (b) has been verified on the user's actual NAS, then defaulting to `"both"`. `"both"` is the right steady state precisely because it keeps a working door when the firmware side breaks.

### 5.3 Exact QTS flow to implement in M4 — `internal/qts`

```go
type Client struct{ Port int; TLS bool; HTTP *http.Client }
func Detect() (*Client, error)                    // ports from /etc/config/uLinux.conf, fallback 8080/443
func (c *Client) ValidateSID(ctx context.Context, sid string) (Session, error)
func (c *Client) Login(ctx context.Context, user, password string) (Session, error)
type Session struct{ SID, Username string; Admin bool; ExpiresAt time.Time }
```

**Port discovery.** `internal/qts/ulinux.go` parses `/etc/config/uLinux.conf` as a plain INI (`func GetCfg(section, key string) (string, bool)`), looking for the system web port and the SSL port. Fallback 8080/443. Do **not** shell out to `/sbin/getcfg` from the request path — a fork per request is unacceptable — but *do* compare the parsed value against `getcfg` output once at startup and log a warning on disagreement, since `getcfg` is the authoritative reader.

**Validation.** `GET http://127.0.0.1:<port>/cgi-bin/authLogin.cgi?sid=<url-encoded sid>`, 5 s timeout, redirects disabled, response capped at 64 KiB. Parse with `encoding/xml` **leniently** — walk tokens and pick up `authPassed`, `authSid`, `username`, `isAdmin` wherever they appear, so an unexpected wrapper element does not break it. Require `authPassed == 1` and, when `config.auth.requireAdmin` (default true), `isAdmin == 1`.

**Cache.** `sid → Session` for 60 s in a small `sync.Map` with sweeping. `authLogin.cgi` is a CGI — a process fork per call — and a single page load can issue ten API requests. Without the cache this is a self-inflicted fork bomb. Validation failures are fed to the existing `loginThrottle`.

**Credential-proxy login** (the fallback that needs no cookie at all, and the shape I would actually ship first): our own login form posts `{username,password}`; the server calls `c.Login()` → `authLogin.cgi?user=<u>&pwd=<ezEncode(password)>` on loopback, requires `authPassed=1 && isAdmin=1`, and issues **our own** session cookie. The QTS sid is never stored. This gives "sign in with your NAS admin account" with no dependency on cookie propagation. `ezEncode` is believed to be plain base64 of the password for this endpoint — **verify**.

### 5.4 True SSO — how the sid would reach us, and what is uncertain

The useful fact: **HTTP cookies are not scoped by port.** A cookie QTS sets for host `nas.local` with `Path=/` is sent by the browser to `http://nas.local:8770/` as well. So when App Center's tile opens `http://<nas>:8770/`, the QTS session cookie should arrive at our handler. Two things break it:

- If QTS sets the cookie `Secure` (which it does under "Force secure connection"/HTTPS-only), the browser will **not** send it to our plain-HTTP port. Fix: serve TLS on our port too — copy `C:\Dev\GitBackup\internal\web\selfsigned.go` and the dual-listener/HTTPS-redirect wiring at `server.go:420-460`.
- If the user reaches QTS by IP and our app by hostname (or vice versa), it is a different host and no cookie is sent. Fix: fall through to the local login form; never hard-fail.

Server side: read the cookie, fall back to `?sid=` in the query (App Center *may* append one) and to an `X-QNAP-SID` header, then `ValidateSID`. On success, issue our own session cookie so exactly one credential path exists after the first request.

**Must be verified on a real NAS — do not build on any of these without checking:**
1. The exact cookie name(s) QTS sets (`NAS_SID`, `NAS_USER`, `qtoken`, others) and their `Secure`/`HttpOnly`/`SameSite`/`Path`/`Domain` attributes. `document.cookie` in the QTS desktop plus the browser devtools cookie jar answers this in a minute.
2. Whether App Center's tile link is a literal `http://<host>:8770/` or goes through a QTS redirector that changes the origin.
3. The real element names in the `authLogin.cgi?sid=` response, and whether `sid` alone suffices or a `user=` is also required.
4. Whether `isAdmin` is returned on sid *validation* or only on *login*. If only on login, admin gating over SSO needs a second call or is not possible.
5. The `uLinux.conf` keys for the web port and the SSL port on this firmware.
6. Whether `ezEncode` is plain base64 for the login call.
7. Whether accounts with QTS 2-step verification yield a usable sid from a password-only login (probably not — the credential-proxy path must degrade to the local password for those users).
8. Whether QuFirewall or an "allowed IP" policy blocks loopback CGI calls.
9. Whether `authLogin.cgi` rate-limits or logs a failed-login event per call (it may pollute QuLog).

`docs/nas-checklist.md` carries these nine as a numbered test script with the exact commands.

### 5.5 First-run bootstrap — the claim window

A root file manager must never have an open pre-setup window; GitBackup's "serve setup endpoints before a password exists" pattern (`server.go:690-720`) is **not** safe to copy here. Instead:

- With no password configured, **every** `/api/fs/*` route returns `403 unauthorized`. Only `/api/session` and `/api/setup` answer.
- `/api/setup` accepts a username+password **only within 15 minutes of process start** (`claimDeadline`). After that it returns `403` with *"restart the app from App Center to open a new setup window."*
- This ties bootstrap to App Center access, which already requires QTS admin — SSO's security property without SSO's uncertainty.
- The claim is written to `audit.jsonl` **and** mirrored to QuLog via `qnap.Log(qnap.Warning, …)` with the client IP, so a stolen claim is visible in QuLog Center.
- Once QTS auth is verified (M4), `/api/setup` can additionally accept QTS admin credentials, which removes the window entirely.

---

## 6. Safety guardrails for a root daemon — `internal/guard`

### 6.1 API

```go
type Op uint16
const (OpRead Op = 1<<iota; OpTraverse; OpCreate; OpWrite; OpDelete; OpRename; OpChmod; OpChown)

type Rule struct {
    Prefix string
    Deny   Op
    Warn   Op       // allowed, but requires a confirmation token
    Reason string
    Exact  bool     // matches only the path itself, not its children
}

type Guard struct{ rules []Rule; installDir string; readOnly atomic.Bool; shareIsRAM bool }
func New(installDir string, shareIsRAM bool) *Guard
func (g *Guard) Check(op Op, path string) error       // ErrProtected / ErrConfirmRequired / ErrReadOnly / nil
func (g *Guard) Classify(path string) string          // "normal"|"warn"|"protected" — drives the UI badge
func (g *Guard) SetReadOnly(bool)
```

**The prefix-matching bug to avoid, and a test for it:** matching must be on path boundaries — `p == prefix || strings.HasPrefix(p, prefix+"/")`. Raw `HasPrefix` makes `/etc/configuration` match the `/etc/config` rule. `guard_test.go` asserts this explicitly.

### 6.2 Default rule table

| Prefix | Deny | Warn | Reason |
|---|---|---|---|
| `/proc` | all except `OpRead\|OpTraverse` at depth ≤1 | — | kernel interface; recursive ops must never enter it |
| `/sys` | all writes and `OpTraverse` for recursion | — | same |
| `/dev` | `OpDelete\|OpRename\|OpWrite` | `OpChmod\|OpChown` | deleting a device node breaks the running system |
| `/run`, `/var/lock` | `OpDelete` on the root | — | RAM disk runtime state |
| `/etc/config` | `OpDelete` (Exact, the dir itself) | `OpWrite\|OpChmod\|OpChown\|OpRename` | **QTS firmware config — editing is a legitimate reason to use this app, so it warns rather than denies** |
| `/mnt/HDA_ROOT/.config` | `OpDelete` (Exact) | writes | firmware config on the DOM |
| `/` and every first-level dir (`/bin`,`/etc`,`/lib`,`/sbin`,`/usr`,`/var`,`/home`,`/root`,`/opt`,`/mnt`,`/share`,…) | `OpDelete\|OpRename` (Exact) | — | |
| `/share` (Exact) | `OpCreate` **when `shareIsRAM`** | — | the RAM-disk trap; `errShareRoot` text from `C:\Dev\GitBackup\internal\web\server.go:2155` |
| `/share/*_DATA` volume roots | `OpDelete\|OpRename` (Exact) | — | |
| `<installDir>` (from `getcfg … Install_Path`) | all writes | — | the daemon deleting itself mid-request |
| `<installDir>/config`, `<installDir>/logs` | `OpRead` too | — | contains the password hash and the audit log |
| any mount point | `OpDelete\|OpRename` (Exact) | — | detected dynamically, not by prefix (§6.5) |

`Check` runs on the **canonicalised** path from `fsx.ResolveParent`, so a symlink cannot be used to slip past a prefix rule.

### 6.3 Confirmation tokens — `internal/guard/confirm.go`

Required when: the op touches a `warn`-class path; a delete affects more than `confirmThreshold` (default 100) files or more than 1 GiB; the target is a mount point; setuid/setgid is being set outside `normal`; the RAM-disk override is used; `EmptyTrash` is called.

```go
func (g *Guard) Issue(op, summary string, paths []string) (token string, exp time.Time)
func (g *Guard) Redeem(token, op string, paths []string) error   // single-use, 60s TTL
```
Token = base64url of `nonce || HMAC-SHA256(serverKey, op|sorted(paths)|expiryUnix|nonce)`. Stateless except for a small `seen` set that makes it single-use. `serverKey` is 32 random bytes generated at startup, so tokens do not survive a restart.

Wire protocol: the first POST returns
```json
{"error":{"code":"confirm_required","message":"…"},
 "confirm":{"token":"…","expires":"…","summary":{"files":8003,"bytes":41231234,"warnings":["/etc/config is QTS firmware configuration"]}}}
```
and the client re-posts the identical body with `"confirm":"<token>"`. The summary comes from a real scan, so the dialog states facts rather than a guess.

### 6.4 Read-only mode

`config.readOnly` (persisted) plus a `-readonly` flag (overrides, cannot be turned off from the UI when set). When on, every op other than `OpRead|OpTraverse` returns `403 readonly` **in the guard**, not in the handlers, so no route can forget it.

A **temporary unlock** action — `POST /api/readonly {"enabled":false,"password":"…"}` — requires re-entering the password and re-locks automatically after 15 minutes (a `time.AfterFunc` reset on each write). Both transitions go to the audit log and to QuLog. Default for a fresh install: `readOnly: true`, so the first thing an operator does is a deliberate act.

### 6.5 Mount points and never crossing into /proc

`internal/fsx/mount.go`:
```go
func Mounts() ([]Mount, error)          // parses /proc/self/mountinfo, cached 5s
func IsMountPoint(osPath string) bool   // mountinfo hit OR st_dev != parent's st_dev
```
Both tests, because `mountinfo` is authoritative but unavailable on the Windows dev box, while the `st_dev` comparison works everywhere and catches bind mounts the parse might miss.

Every recursive walk (`copy`, `delete`, `size`, `search`, `archive`, recursive `chmod`/`chown`) is **one-filesystem by default**: it records the top-level `st_dev` and skips any entry whose `st_dev` differs, adding `p.Warn("skipped mount point %s")`. That single rule is what stops a "copy /" from descending into `/proc`, `/sys`, `/dev`, every volume and every USB disk — and it is stronger than a path blacklist because it needs no list.

### 6.6 Audit log — `internal/audit`

```go
type Event struct {
    T      time.Time `json:"t"`
    Actor  string    `json:"actor"`
    IP     string    `json:"ip"`
    Op     string    `json:"op"`
    Path   string    `json:"path"`
    PathB64 string   `json:"pathB64,omitempty"`
    Dst    string    `json:"dst,omitempty"`
    Job    string    `json:"job,omitempty"`
    Phase  string    `json:"phase"`   // "intent" | "result"
    Result string    `json:"result"`  // "ok" | "error" | "denied" | "cancelled"
    Code   string    `json:"code,omitempty"`
    Files  int64     `json:"files,omitempty"`
    Bytes  int64     `json:"bytes,omitempty"`
    Detail string    `json:"detail,omitempty"`
}
type Logger struct{ w *logfile.Writer; qulog bool }
func Open(path string, qulog bool) (*Logger, error)
func (l *Logger) Write(ev Event)     // never blocks the request: buffered chan, 1024 deep, drops + counts on overflow
```
- JSON Lines to `<install>/logs/audit.jsonl`, rotated by the **copied** `internal/logfile.Writer` at 8 MiB keeping one generation. Mode 0600 in a 0700 directory (`package_routines`).
- Destructive ops (`delete`, `move`, `trash empty`, `chown`, recursive `chmod`) are logged **twice**: `phase:"intent"` before the work starts and `phase:"result"` after, so a crash or a power cut mid-delete still leaves evidence of what was attempted.
- **QuLog mirror** via the copied `internal/qnap.Log`, and only for milestones — every call is an `exec` of `/sbin/log_tool` and must not run per file: sign-in success/failure, claim, read-only toggle, any `denied`, any delete of >100 files or >1 GiB, any write under `/etc/config`, any chown. Severity maps to `qnap.Info/Warning/Error`.
- `GET /api/audit` tails the file for the UI's "Recent activity" panel.

---

## 7. QPKG packaging

### 7.1 `qpkg/qpkg.cfg`

```sh
QPKG_NAME="QNAPFileManager"
QPKG_DISPLAY_NAME="File Manager (root)"
# QPKG_VER is overwritten by CI from the git tag.
QPKG_VER="0.1.0"
QPKG_AUTHOR="Sveinung"
QPKG_LICENSE="MIT"
QPKG_SUMMARY="Browse and manage the whole NAS filesystem from a browser — every path, not just shared folders. Permissions, ownership, copy/move, upload/download, search."

QPKG_RC_NUM="198"
QPKG_SERVICE_PROGRAM="QNAPFileManager.sh"

# Declared firmware compatibility — without this App Center shows a generic
# "may be only partially compatible" warning.
QTS_MINI_VERSION="4.5.0"

QPKG_WEBUI="/"
QPKG_WEB_PORT="8770"

QPKG_DIR_ICONS="icons"
```

**Port 8770**: 8765 is GitBackup's and is already bound on this NAS. 8080/443 are QTS, 8081 the Web Server app, 8080±1 is crowded. Confirm on the NAS with `netstat -tlnp | sort -t: -k2 -n` before the first release. If the operator changes `web.port` in the config, App Center's tile would point at the old one — so on startup the daemon compares `web.port` against `getcfg <name> Web_Port -f /etc/config/qpkg.conf` and, when they differ and it is running as root on QTS, calls `/sbin/setcfg <name> Web_Port <n> -f /etc/config/qpkg.conf` and logs it. Small, and it removes a guaranteed support question.

**`QPKG_RC_NUM=198`** — one below GitBackup's 199, keeping both in the third-party band.

### 7.2 `qpkg/shared/QNAPFileManager.sh`

Copy `C:\Dev\GitBackup\qpkg\shared\GitBackup.sh` and:
- keep verbatim: the `Install_Path` empty-guard (lines 9-12 — it is the reason a corrupt `qpkg.conf` does not write to the ramdisk root), `is_running()` including the `/proc/<pid>/cmdline` check, `cd "$QPKG_ROOT"`, the `-log` rationale, and the **`sleep 2; is_running || tail startup.log; exit 1`** block at lines 98-104 (the reason App Center shows a truthful status).
- delete: `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_SSL_CAINFO`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, and the two `ln -sf` repair blocks (lines 61-70).
- launch line becomes:
```sh
"$QPKG_ROOT/bin/qnapfilemanager" serve \
    -config "$QPKG_ROOT/config/config.json" \
    -log "$QPKG_ROOT/logs/qfm.log" \
    > "$QPKG_ROOT/logs/startup.log" 2>&1 &
```
Must be LF — add `qpkg/shared/*.sh` coverage via the existing `*.sh text eol=lf` rule in `.gitattributes`.

### 7.3 `qpkg/package_routines`

```sh
pkg_post_install(){
    mkdir -p "$SYS_QPKG_DIR/config" "$SYS_QPKG_DIR/logs"
    # The config holds the UI password hash and the audit log holds every
    # path this app touched — admin-only, both of them.
    chmod 700 "$SYS_QPKG_DIR/config" "$SYS_QPKG_DIR/logs"
    [ -f "$SYS_QPKG_DIR/config/config.json" ] && chmod 600 "$SYS_QPKG_DIR/config/config.json"
}
pkg_post_remove(){ : ; }   # per-volume .@qfm_trash is deliberately left in place
```
Note the deliberate difference from GitBackup: **no config is seeded on install.** An absent config is what opens the first-run claim window (§5.5); seeding one would have to invent a password.

### 7.4 Local dev loop on Windows

**`.claude/launch.json`**
```json
{"version":"0.0.1","configurations":[{
  "name":"qnapfilemanager",
  "runtimeExecutable":"go",
  "runtimeArgs":["run","./cmd/qnapfilemanager","serve","-config","dev-config.json",
                 "-jail","testdata/fakeroot"],
  "port":8899
}]}
```
Port 8899 for the same reason GitBackup uses it (`C:\Dev\GitBackup\CLAUDE.md`, Commands section): the real service holds the production port on this box. **It must be `go run`** — `go:embed` means a prebuilt binary keeps serving stale UI assets (GitBackup gotcha 2, and it cost real debugging time there).

**The `-jail` flag** is the centrepiece:
```go
// internal/fsx/root.go
type Root struct{ base string }        // "" == identity
func NewRoot(base string) (Root, error)
func (r Root) OS(apiPath string) string   // "/etc/passwd" -> "C:\...\fakeroot\etc\passwd"
func (r Root) API(osPath string) (string, error)
func (r Root) Jailed() bool
```
Every syscall in `internal/fsx` goes through `r.OS(...)`; nothing else in the codebase touches an OS path. Consequences: the whole app runs on Windows against `testdata/fakeroot`; every test gets a sandbox for free with `NewRoot(t.TempDir())`; and in production `-jail /share/CACHEDEV1_DATA` is a genuine defence-in-depth option for a cautious operator.

`scripts/make-fakeroot.ps1` builds a realistic tree: `/etc/passwd`, `/etc/group`, `/etc/config/*`, `/share/Public`, `/share/CACHEDEV1_DATA/Public`, `/share/Multimedia -> CACHEDEV1_DATA/Multimedia` (symlink, needs Developer Mode or an elevated shell on Windows — the script detects and warns), a dangling link, a name with a `#` and a space, and a unicode name.

**Platform splitting**: prefer `_linux.go` / `_windows.go` / `_other.go` file suffixes over build tags, matching `C:\Dev\GitBackup\internal\diskfree\diskfree_unix.go`. Windows stubs return `fsx.ErrUnsupported` for `Chown`, `HasACL` and `Mounts`; `statDetail` synthesises uid/gid 0 and derives a mode from `fs.FileMode`. **The three-GOOS vet sweep is mandatory** — GitBackup gotcha 3 proves `go vet ./...` on Windows silently skips the Linux files, including a type error:
```
GOOS=linux go vet ./... && GOOS=windows go vet ./... && GOOS=linux GOARCH=arm64 go vet ./...
```

**Testing the real QPKG on the NAS**: App Center → *Install Manually* → pick the `.qpkg` → accept the unsigned-package warning. Then
```sh
INST=$(/sbin/getcfg QNAPFileManager Install_Path -f /etc/config/qpkg.conf)
tail -f "$INST/logs/startup.log"     # a start that died: wrong arch, bad flag, bad config
tail -f "$INST/logs/qfm.log"         # rotated at 8 MiB, one generation kept
tail -f "$INST/logs/audit.jsonl"
"$INST/QNAPFileManager.sh" restart
```
plus QuLog Center for the milestone events. Structure `docs/qnap-install.md` on `C:\Dev\GitBackup\docs\qnap-install.md` — same arch table, same RAM-disk warning, same "install manually / unsigned warning" wording.

### 7.5 CI — `.github/workflows/build.yml`

Adapt `C:\Dev\GitBackup\.github\workflows\build.yml`. **Delete** `static-git`, `docker`, `windows`, the git-lfs download and the git smoke assertions — no bundled binaries here, which makes this workflow roughly a third the size.

- `env: GO_VERSION: '1.26.5'` pinned to the exact patch, for the reason given at lines 14-19 (govulncheck gates stdlib advisories against the building toolchain).
- **`test`** (ubuntu): `go vet ./...`, `go mod tidy -diff`, `go test -race ./...`, `GOOS=windows go vet ./...`, `GOOS=linux GOARCH=arm64 go vet ./...`, `test -z "$(gofmt -l .)"`, pinned `staticcheck@v0.7.0`, pinned `govulncheck@v1.6.0` — copy the reasoning comments; they are the record of why each one exists.
- **`test-windows`** (windows-latest): `go vet ./...`, `go test ./...`. Essential here, not optional: development happens on Windows and the `_windows.go` files are invisible to a Linux build.
- **`test-linux-root`** (new, ubuntu): `sudo -E env "PATH=$PATH" go test -tags rootonly -run 'TestRoot' ./internal/fsx/...`. GitHub runners are not root by default, so `chown`, mount-point detection, `/proc` traversal refusal and setuid handling are otherwise never exercised anywhere. This is the job that makes the guardrails real.
- **`package`** (needs test, test-windows, test-linux-root): build `amd64`+`arm64` with `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=$VERSION"`; version formula copied verbatim (tag → `${GITHUB_REF_NAME#v}`, else `0.0.${GITHUB_RUN_NUMBER}`); assemble `qpkg/x86_64` and `qpkg/arm_64`; `sed -i` the `QPKG_VER`; `chmod -R a+rx`.
- **Smoke test** with `docker/setup-qemu-action` binfmt so the arm_64 tree runs too — and go further than GitBackup's version-string check with a *functional* smoke:
  ```sh
  for arch in x86_64 arm_64; do
    [ "$(qpkg/$arch/bin/qnapfilemanager version)" = "$VERSION" ]
    mkdir -p /tmp/fakeroot/etc && cp /etc/passwd /etc/group /tmp/fakeroot/etc/
    qpkg/$arch/bin/qnapfilemanager serve -config /tmp/ci.json -jail /tmp/fakeroot \
      -addr 127.0.0.1:18770 -readonly & pid=$!
    for i in $(seq 20); do curl -sf localhost:18770/api/session >/dev/null && break; sleep 0.5; done
    curl -sf localhost:18770/api/session | grep -q '"readOnly":true'
    kill $pid
  done
  ```
  This catches a wrong-arch or dynamically-linked binary *and* a broken route table, before anyone installs it.
- **QDK install pinned by commit**, copied verbatim from lines 384-396 including the comment explaining why a tag is not a pin (`QDK_SHA: 955d98c9913989561142f9a9ac994ec0091559d6`), then `cd qpkg && PATH="$PATH:/usr/share/QDK/bin" qbuild`.
- Release on tag: `sha256sum *.qpkg > SHA256SUMS`, `gh release create … --generate-notes`. `permissions: contents: read` at the top; only `package` gets `contents: write`.
- Artifact `retention-days: 7` — GitBackup's account-wide storage quota has blocked releases twice (gotcha 5); do not inherit the 90-day default.

---

## 8. Testing strategy

### 8.1 Unit tests, by package

**`internal/fsx`** — the bulk of the suite. A fixture builder keeps them readable:
```go
// internal/fsx/testtree.go
func newTree(t *testing.T, spec map[string]string) Root
// "dir/"            -> directory
// "dir/f.txt: hi"   -> file with content
// "link -> target"  -> symlink
// "mode:0640 f.txt" -> mode prefix
```
Cases that must exist:
- Listing: hidden toggle; sort by each key; offset/limit + `Truncated`; a directory of 20 000 entries (generated) for the cap; a name with `#`, a name with a space, a unicode name, and a **name with invalid UTF-8 bytes** asserting `NameB64` round-trips through the API.
- Symlinks: relative, absolute, dangling, a 2-cycle loop (`a→b→a`) asserting `List` terminates and `LinkResolved == ""`, a link whose target is outside the jail, and **a symlinked parent of a write target** asserting `ResolveParent` catches it.
- Copy: file, empty dir, nested tree, mode+mtime preservation, `Conflict` ∈ skip/overwrite/rename, symlink recreated not followed, FIFO skipped with a warning, cancel mid-file leaving a partial dst, `OneFileSystem` skipping a foreign device (faked by injecting the `dev` in a test-only hook).
- Move: same-device rename path; forced-`EXDEV` path via a hook asserting the source survives a failed copy.
- Delete: post-order; `ENOTEMPTY` without `Recursive`; refusal on a mount point; cancel leaving a partial tree.
- Trash: `TrashRoot` detection, `meta.json` content, `Restore` refusing when the original path reappeared, `EmptyTrash` age filter.
- Text: binary detection, size cap + `Truncated`, ETag mismatch → conflict, atomic write preserving mode and owner, non-atomic path.
- Archive: build a zip, read it back with `archive/zip`, assert names and modes; assert the `ERROR.txt` member appears on a mid-stream failure.
- Upload: raw and multipart; `.part` file removed on an aborted body (`io.Reader` returning an error mid-stream).

**`internal/guard`** — pure table test, no filesystem, with a stubbed resolver. Must include the `/etc/configuration` vs `/etc/config` boundary case, `..` normalisation, read-only mode short-circuiting every op, and every default rule asserted once.

**`internal/jobs`** — deterministic with fake work functions. Cancel, concurrency caps per class (two byte-movers run, the third queues), `ErrQueueFull`, retention reaping, progress monotonicity, and `Subscribe` fan-out. Use `testing/synctest` (stdlib, Go 1.25+) so the timing-dependent tests are instant and not flaky.

**`internal/idmap`** — fixture `passwd`/`group` files including a `+` compat line, a malformed row, a duplicate uid, and a reload triggered by an mtime bump.

**`internal/web`** — `httptest.NewServer` over a jailed temp dir. CSRF header rejection; `Origin` mismatch rejection; `403 readonly`; the `409 confirm_required` → re-post flow including token replay rejection and expiry; `Range` download; `Content-Disposition` unicode encoding; a path with `#` surviving the query round-trip; `pathB64` accepted everywhere `path` is; the pre-setup lockdown (every `/api/fs/*` is 403 with no password) and the claim window closing after its deadline.

**`internal/qts`** — `httptest` server returning captured `authLogin.cgi` XML (real captures once available, hand-written fixtures until then), including a malformed body, an unexpected wrapper element, a slow response hitting the timeout, and the 60-second cache being honoured.

### 8.2 Cross-platform reality

- `os.Symlink` needs Developer Mode or elevation on Windows. A helper probes it once and `t.Skip`s the symlink tests with a clear message rather than failing:
  ```go
  func requireSymlinks(t *testing.T) // creates one in t.TempDir(), skips on failure
  ```
- `chown`, mode bits below 0666, setuid/sticky, mount points and ACLs are `runtime.GOOS == "windows"` skips **and** `os.Geteuid() != 0` skips — which is why `test-linux-root` exists (§7.5). Without it those paths are tested nowhere.
- `t.TempDir()` on Windows is under a path with a drive letter and spaces (`C:\Users\ADMINI~1\...`), which is itself useful coverage for the `Root.OS`/`Root.API` mapping.
- Known local hazard, carried into `CLAUDE.md`: **Windows Smart App Control** on this dev box blocks freshly compiled unsigned `*.test.exe` at random (GitBackup gotcha 1). When a package "fails" without an assertion, check `Microsoft-Windows-CodeIntegrity/Operational` before hunting a bug, try `go test -c -o /tmp/check.exe ./internal/fsx && (cd internal/fsx && /tmp/check.exe -test.count=1)`, and if that is refused too, say plainly that CI is the only way to run it.

### 8.3 Manual NAS checklist — `docs/nas-checklist.md`

1. Install the correct arch via App Center → Install Manually; confirm the tile appears and the app auto-starts.
2. Confirm `getcfg QNAPFileManager Install_Path` and that `logs/startup.log` is empty of errors.
3. Open `http://<nas>:8770/`; complete the claim window; confirm a second browser is refused after 15 min.
4. Browse `/`, `/etc`, `/etc/config`, `/root`, `/mnt/HDA_ROOT`, `/share`, each `HDA_DATA…HDK_DATA`, and `/share/CACHEDEV1_DATA/.qpkg` — the paths File Station cannot reach. Confirm owner/group names resolve from `/etc/passwd`.
5. Toggle "show volume mounts" at `/share`; confirm share symlinks and raw volume roots are distinguished.
6. Attempt `mkdir` directly in `/share`; confirm the RAM-disk refusal.
7. Attempt to delete `/etc`, a mount point, and the install dir; confirm each is refused with its stated reason.
8. Copy a ~5 GB folder within a volume, then across volumes (`EXDEV` path); check progress, rate, ETA, and cancel mid-way; verify the partial state matches what the UI said.
9. Delete 10 000 small files with trash on, then off; verify `.@qfm_trash` layout, `Restore`, and `EmptyTrash`.
10. Upload a >4 GB file; download it back; checksum both ends. Download a folder as zip; verify with `unzip -t`.
11. chmod/chown a file and a whole tree; verify with `ls -l` over SSH; confirm a symlink's own ownership changed (`ls -l` on the link) and that chmod on a symlink was refused.
12. Find a share with Advanced Folder Permissions on; confirm the `HasACL` badge appears and the warning text is shown.
13. Edit `/etc/config/<something harmless>` in the text editor; confirm the warn-class confirmation, the ETag conflict on a second stale tab, and the `nlink`/ACL non-atomic fallback.
14. Search `/` for a filename; confirm it does not enter `/proc` or other volumes and reports truncation honestly.
15. Toggle read-only; confirm every write is refused and the timed unlock re-locks.
16. Check `logs/audit.jsonl` for intent+result pairs and QuLog Center for the milestone events.
17. Run the nine §5.4 QTS-auth probes and record the answers in this file.
18. Reboot the NAS; confirm the service restarts and the port survives.
19. Upgrade over the top with a newer `.qpkg`; confirm config and trash survive.

---

## 9. Milestones

Relative sizes as a share of total effort; each ends at something installable and demonstrable.

| | Milestone | Contents | Size |
|---|---|---|---|
| **M0** | **Skeleton + browse** | `go.mod`; `cmd/qnapfilemanager/main.go`; `internal/config`; `internal/fsx` `root.go`/`path.go`/`entry.go`/`list.go`/`stat.go`/`share.go`/`errors.go`; `internal/idmap`; `internal/guard` (rules + `Check`, no confirm tokens); copied `qnap`/`diskfree`/`logfile`/`jsonfile`/`durable`; `internal/web` server + copied `session`/`throttle`/`clientip` + local login + claim window; static shell with breadcrumbs, listing table, sort, hidden toggle; CI `test` + `test-windows` jobs; `scripts/make-fakeroot.ps1`; the `-jail` dev loop working end to end on Windows. | **15 %** |
| **M1** | **Basic ops** | `mkdir`, `rename`, `delete` (sync for small, guarded), `copy`/`move` sync for small sets; `internal/guard/confirm.go`; `internal/audit` + QuLog mirror; read-only mode; the full error model; `qpkg/` complete; CI `package` job + QDK + smoke; **first real install on the NAS** and the first pass of `docs/nas-checklist.md`. This is the milestone that proves the whole premise — root browse and write above `/share` from App Center. | **20 %** |
| **M2** | **Jobs + transfer** | `internal/jobs` with scan/work phases, cancel, concurrency classes, retention; `copy`/`move`/`delete`/`size`/`archive`/`search` converted to jobs; progress UI + polling; SSE endpoint; upload (raw + multipart); download with Range; folder zip/tar.gz streaming; text view/edit with ETag; `internal/fsx/search.go`; `test-linux-root` CI job. The largest milestone and the one with the most surface area. | **25 %** |
| **M3** | **Permissions + trash** | `chmod` (octal field + rwx grid + setuid/setgid/sticky, recursive as a job with dir/file split), `chown`/`chgrp` with `/api/ids` pickers, `HasACL` detection + badge + honest warning text, properties dialog with recursive size, `internal/fsx/trash.go` + Trash view + Restore + Empty + retention sweep. | **15 %** |
| **M4** | **QTS auth + polish** | `internal/qts` (`ulinux.go`, `authlogin.go`, cache, throttle); the nine §5.4 probes run on the real NAS and the results written down; credential-proxy login; SSO cookie path if verified; `auth.mode` config; TLS/self-signed listener (copied `selfsigned.go`) for https-only NASes; keyboard shortcuts, multi-select, drag-and-drop upload, dark mode; `docs/qnap-install.md`, `docs/api.md`, `docs/safety.md`; tagged v1.0.0 release. | **25 %** |

Sequencing constraints worth naming: `internal/guard` must exist before any write lands (M1), not be retrofitted; `internal/jobs` must exist before recursive `chmod`/`chown` (so M2 precedes M3); and M4's QTS work is gated on physical NAS access, so it is deliberately last and everything before it must be fully usable without it.

---

### Critical Files for Implementation

- `C:\Dev\GitBackup\internal\web\server.go` (lines 355-460 wiring/timeouts, 640-720 middleware, 1262-1290 `checkSameOrigin`, 2063-2226 `handleBrowse`/`browsable`/`defaultBrowseDir` and the `/share` rule)
- `C:\Dev\GitBackup\qpkg\shared\GitBackup.sh` and `C:\Dev\GitBackup\qpkg\qpkg.cfg` (service-script and packaging template)
- `C:\Dev\GitBackup\.github\workflows\build.yml` (the `test`, `test-windows` and `package` jobs plus the QDK-pinned-by-commit install at lines 384-402)
- `C:\Dev\GitBackup\internal\qnap\qnap.go` and `C:\Dev\GitBackup\internal\diskfree\diskfree_unix.go` (QuLog writer, `IsQTS`, `SameDevice` RAM-disk detection — copied verbatim)
- `C:\Dev\GitBackup\internal\web\session.go` and `C:\Dev\GitBackup\internal\web\throttle.go` (session and login-throttle primitives — copied verbatim)
- `C:\Dev\GitBackup\CLAUDE.md` (Toolchain policy at line 584, Gotchas at line 599 — carry 1, 2, 3, 6 and 8 into the new repo's `CLAUDE.md`)