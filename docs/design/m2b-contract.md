# M2-B contract — copy and move (2026-09-13)

This is the shared contract for M2-B, fixed by the orchestrator before the implementers fan out, the way M2-A fixed
its contract in `09a0772`. Three pieces are built in parallel against it: the worker-side engine (`internal/fsops`,
`internal/worker`, `internal/workerpool`), the web routes (`internal/web/routes_transfer.go`) and the UI. Anything
not stated here follows the M2-A precedent (delete-to-trash) in the same file.

Sources of intent: PLAN.md decision 9 (crossing) and the M2-B line; `docs/design/backend-packaging-plan.md` §2.5
(copy) and §2.6 (move); `docs/design/ui-ux-safety-plan.md` §6 (ladder, error table, §6.4 deferred);
`docs/design/identity-and-hero-plan.md` (EXDEV pre-flight wording); `docs/reviews/ownership-mkdir-review.md`
(ownership of content an admin creates).

## 1. Decisions

1. **One engine, two job kinds.** `wproto.JobCopy` and `wproto.JobMove` both carry a `wproto.CopyReq` body. A move
   tries `renameat2` per source root first (instant, same filesystem; the kernel decides, INV-2). On `EXDEV` — or when
   the destination exists as a directory and the source is a directory (a merge) — it falls back to copy, verify,
   then delete the source. **The source of a root is deleted only when that root copied with zero warnings and zero
   skips**; otherwise both copies stay and the job says so (design §2.6: never delete before the copy is verified).
   A cancelled move leaves both copies and says so (`JobResult.Partial`).
2. **The EXDEV pre-flight is a prediction made by the front-end, as the user, and it warns; it never refuses.** A
   new plain RPC `OpFSIdentity` returns the mount identity of a path, computed in the worker from an opened
   descriptor (statx mount id, falling back to st_dev — the same identity `fsops.walk` uses). For a move the route
   compares every source root against the destination directory. When they differ the confirm summary carries one
   sentence per differing pair, e.g. *"`Public` and `Media` are on different volumes, so this move copies 41.2 GB and
   then deletes the source, not an instant rename. It can be cancelled, and a cancelled move leaves both copies."*
   Cross-device is grade L1 (a plain confirm). The worker still relies on the kernel's actual `EXDEV`, never on the
   prediction.
3. **Conflict policy is chosen up front** (PLAN M2-B; §6.4 pause deferred): `skip` (default), `overwrite`, `rename`
   ("keep both" → `name (2).ext`, then `(3)`…, bounded at 100 tries, then a warning and a skip). Policy applies to
   non-directory entries. **Directories always merge** into an existing destination directory of the same name. A
   type mismatch (file over directory or directory over file, symlink over anything else) is a warning and a skip
   under every policy. `overwrite` for a regular file is write-to-temp-then-rename-over (never a truncate-in-place
   that can leave a half file), and it needs a confirm (L1, ui-ux §6 table).
4. **Ownership.** A copy made by the root worker gets `CopyOptions.As` applied to every created entry (chown only,
   `GID -1` = inherit; never chmod — ownership review findings B/D) when the route gates it exactly as mkdir does:
   `sess.who.Root` and both spellings of the destination directory classify `normal`. A move that fell back to
   copy+delete **preserves the source owner and group** when the worker's euid is 0 (that is what the rename would
   have done); `As` is ignored for a move. A non-root worker never chowns.
5. **Mode and times.** Created files use `open(O_CREAT|O_EXCL, srcMode & 0777)` and created directories
   `mkdirat(srcMode & 0777)` — the special bits (setuid, setgid, sticky) are never propagated, and the umask and the
   destination's inherited ACL/setgid apply as they would for `cp` without `-p`. No `chmod` is ever issued. The
   modification time is preserved (`futimens` / `utimensat AT_SYMLINK_NOFOLLOW`) — `PreserveTimes` defaults to true
   when the request omits it (the wire field is `preserveTimes` with `omitempty`, so the route always sends it
   explicitly). `PreserveMode` is accepted and ignored (mode is always the creation mode above).
6. **File types.** Regular files: copied through held descriptors (`openat` relative to the held source and
   destination directory fds, `O_NOFOLLOW|O_CLOEXEC`), 1 MiB buffer via `io.CopyBuffer` (Go's `*os.File` uses
   `copy_file_range` when it can), cancellation checked per buffer, then size verified by `fstat` before the
   destination is considered complete. Symlinks: recreated with `readlinkat` + `symlinkat` (+ `fchownat
   AT_SYMLINK_NOFOLLOW` when chowning), never followed. FIFOs, sockets, device nodes: skipped with a warning
   (`code: "unsupported"`). Hard links are copied as independent files with no warning in v1 (documented residual).
   Sparse files are materialised.
7. **Descriptor discipline** (M2-A §2.7 lessons): both trees are walked on held descriptors; no pathname is
   re-resolved after its directory was opened. Before anything is created, the destination directory is proved not
   to be the source or inside it: the destination's ancestry is collected by `openat(fd, "..")` up to the root (bounded
   by `maxWalkDepth`) as `(dev, ino)` pairs, and a source directory whose identity is in that set is refused with
   `fsx.ErrInvalidTarget` ("cannot copy a folder into itself") — before the walk starts, per root. A destination
   entry whose name equals a source root inside the same directory is `exists` under `skip`/`overwrite` and a
   `(2)` copy under `rename`.
8. **Crossing.** The source walk crosses mounts only under `CopyOptions.CrossMounts` and `platform.MayCross`, as
   delete does (decision 9). The destination never crosses: everything under it is created by the job. A source root
   that is itself a mount point is refused for a move (as delete refuses it) and copied for a copy.
9. **Free space.** After the bounded pre-scan (the same 30 s / 500 000-entry cap and `-1` totals as delete and size),
   when the total is known the engine checks `fstatfs` on the held destination fd and refuses with `fsx.ErrNoSpace`
   before writing anything if `bavail*bsize < bytesTotal`. `EDQUOT` from a write is `no_space` too (already mapped)
   and the job's detail says the quota, not the disk, is full when errno was `EDQUOT`.
10. **Progress.** Files/bytes counted against the pre-scan totals; `Current` is the entry being written;
    phases `scanning` → `working` → `finishing` (the delete-of-source phase of a move is `finishing`).
11. **Guard (route side, both spellings, worst-of).** Copy: `OpRead`+`OpTraverse` on every source root, `OpCreate`
    on the destination directory and on `dest/<base>` for every root. Move: additionally `OpRename` and `OpDelete`
    on every source root. `overwrite`: additionally `OpDelete` on `dest/<base>` for every root. The route refuses a
    destination that is a source root or lies inside one (lexically, both spellings) with `invalid_target` before the
    guard, and refuses a move whose destination directory is a source root's own parent (a no-op) with `exists`
    unless the policy is `rename`.
12. **Ladder.** Copy: confirm when `guard.NeedsConfirm` (>100 files or >1 GiB from the pre-scan as the user, the
    same measurement the delete route makes), or on `overwrite`, or on a guard warning. Move: the same plus a
    cross-device prediction. A write under a protected path is L2 as everywhere. Token parts:
    `job=copy|move`, `conflict=<policy>`, `cross=<bool>`, `dest=<resolved destination dir>`, then the sorted
    resolved source roots.
13. **Audit and titles.** Intent/result pairing exactly as delete (`jobIntentDetail`, `auditJobFinish` hook,
    milestones at 100 files / 1 GiB). Titles: `Copying: <base>` / `Copying <N> items to <destBase>`,
    `Moving: <base>` / `Moving <N> items to <destBase>`.

## 2. Wire (`internal/wproto`)

```go
// CopyOptions gains:
As *CreateAs `json:"as,omitempty"` // copy only: owner for every created entry (chown only, never chmod)
// Conflict is one of ConflictSkip/ConflictOverwrite/ConflictRename; empty = skip.
// PreserveTimes: the route always sends it; the engine treats an omitted value as true.

// Plain RPC (not a job), like OpTrashList:
OpFSIdentity Op = "fsid"
type FSIdentityReq struct { Path []byte `json:"p"` }          // the entry itself (not followed)
type FSIdentityResp struct {
    Mount    uint64 `json:"m,omitempty"` // statx mount id
    HasMount bool   `json:"hm,omitempty"`
    Dev      uint64 `json:"d"`           // st_dev
    Dir      bool   `json:"dir"`
}
```

`JobResult` gains nothing; per-root outcomes of a move ride on `Warns` (`code: "kept"` — "source kept because N
items could not be copied") and `Detail`.

## 3. Backend (`internal/backend`)

```go
// Jobs gains:
// FSIdentity reports which filesystem holds path, computed in the principal's
// worker from an opened descriptor. Used by the move pre-flight (contract §1.2).
FSIdentity(ctx context.Context, who Principal, path string) (wproto.FSIdentityResp, error)
```

## 4. HTTP API (`internal/web`)

```
POST /api/jobs/copy   body {"paths":[pathRef...], "dest": pathRef, "conflict":"skip|overwrite|rename", "crossMounts":bool, "confirm":"<token>"}
POST /api/jobs/move   same body
```

`pathRef` is `{path, pathB64}` as elsewhere. Responses: `202 {"job": <jobs.Job>}` on submit; `409 confirm_required`
with `confirm.summary {files, bytes, warnings[]}` and `confirm.token`; `403` read-only / protected; `400` bad
body; `409 invalid_target` (destination inside a source) and `409 exists` (moving into the same directory); `422`
bad conflict policy. Job kinds on the wire to the UI: `copy`, `move` (`jobs.KindCopy`/`KindMove` already exist and
class `ClassByteMover`).

## 5. UI

- Toolbar: **Copy to…** and **Move to…** (enabled with a selection); context-menu entries; keys `Ctrl+C`
  (mark for copy), `Ctrl+X` (mark for move), `Ctrl+V` (paste = open the same dialog with the current folder
  preselected as the destination). The clipboard is `state.clipboard = {mode:'copy'|'move', entries:[...]}`.
- One dialog `#dlgTransfer`: title "Copy N item(s) to…" / "Move N item(s) to…"; a destination folder tree (the
  existing `tree.js` node renderer parameterised with a container and an `onPick` instead of the hash navigation;
  starts at the current folder's volume; a path input synchronised with the pick); conflict policy radio (Skip
  existing / Overwrite / Keep both); on hero the "Include mounted sub-folders" checkbox (same gating as delete);
  a summary line "N item(s) → /dest". Submit → `runMutation` (re-post with the token on `confirm_required`), the
  server's `why` sentences shown in `confirmDialog` (danger only for overwrite). Then `trackJob`.
- `jobs.js`: add `copy` and `move` to `REFRESH_KINDS`; `actionMessage` gains `invalid_target` ("The destination
  is inside the folder being copied.") and `exists` for the no-op move; `cross_device` text already exists.

## 6. Tests

- fsops (Linux; root-gated only where chown is asserted): copy of a tree with files, subdirectories, an empty
  directory, a symlink (recreated, not followed, link text preserved) and a FIFO (warned, skipped); mtime
  preserved; special bits stripped; conflict `skip`/`overwrite`/`rename` for a file, directory merge, type
  mismatch warns and skips; overwrite is temp+rename (the destination is never observed half-written — inject a
  failure mid-copy and assert the original destination is intact); folder-into-itself refused before any write;
  cancellation leaves a partial tree and `Cancelled`; free-space refusal via a seam for `fstatfs`; move same-device
  is a rename (inode identity preserved); move via a forced-`EXDEV` seam copies then deletes the source, and a copy
  that warned keeps the source; `As` applied to every created entry (root job); move by root preserves the source
  owner (root job). ZFS job: a real move between `ZFS1_DATA/Public` and `ZFS2_DATA/Backup` and `OpFSIdentity`
  differing across datasets, equal within one.
- worker/workerpool: `OpFSIdentity` round trip; `JobCopy`/`JobMove` dispatch; cancel mid-copy drains to the
  partial result.
- web: both routes with `fakeJobs` (record the `CopyReq`, `As` gating on `Root` + both spellings, no `As` for
  move), guard both spellings, token parts and ordered redemption, the EXDEV prediction sentence via a fake
  `FSIdentity`, `invalid_target`/`exists` refusals, audit intent/result pairing, milestone.
- node: pure helpers only (`transferTitle`, `transferSummary`, keep-both name preview if any).
