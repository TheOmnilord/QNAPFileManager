# M2-A review — round 1 (backend: job spine, recursive delete, trash)

Reviewer: gpt-6-astra, low reasoning effort. Scope: commit `e6398ed` (the M2-A
backend; no web routes yet). Four passes: one standard, one full adversarial,
and two narrowly scoped adversarial passes (the full one first appeared to have
produced no findings on a 26-file/6.7k-line diff, so it was split; it then
completed too, and the scoped passes corroborated and sharpened it). Findings
are consolidated below with Fable's judgement. The four M1 residuals
(§2.0/§2.4/§2.5/§2.6) were off-limits.

## The theme

The trash design's threat model was under-enforced. `.@qfm_trash` is a `1777`
sticky directory SHARED by every uid on a volume, admins operate as root (so
root's own trash is `<trash>/0/`), and a hostile local user can create
arbitrary entries there and race any pathname-based operation. Ownership must
therefore be verified on every consuming path, and every check must be made on a
held descriptor, never a swappable pathname.

## Accepted — HIGH

1. **Forged trash entries → attacker-directed root writes** (`trash.go` list/
   restore/empty only checked "is a directory"). Any user pre-creates
   `<trash>/0/<id>/` with a payload and a `meta.json` naming an absent root-only
   destination; the root worker lists it and, on restore, performs the rename.
   Fix: `<uid>/`, each entry dir and each sidecar must be owned by the calling
   uid, verified by fstat on held fds; otherwise skipped as untrusted.
2. **Attacker-owned sticky trash root accepted** (`trashroot.go`, `trash.go`).
   The owner of a sticky dir is exempt from its restrictions and can rename
   other users' `<uid>/` away between validation and use. Fix: the trash root
   must be owned by uid 0 with the sticky bit, checked on both sides; all trash
   operations run relative to held descriptors.
3. **`Ensure` chmods by pathname after mkdir** → a swapped-in symlink gets an
   arbitrary target chmodded to `1777` as root. Fix: open the created dir
   `O_DIRECTORY|O_NOFOLLOW`, fstat, fchmod through the fd, re-verify.
4. **Mount crossing decided on a pre-open stat** (`walk.go`). A mount placed
   over a child between lstat and open is entered even with `CrossMounts=false`;
   a same-device bind mount created after the mount table was captured is
   invisible to both the table and a device comparison; and a device mismatch
   could be authorised by stale caps. Fix: decide on the OPENED fd by mount id
   (`statx STATX_MNT_ID`, fdinfo fallback, then `st_dev`), refresh the table,
   and fail closed when the mount cannot be identified; same on retry passes.
5. **Cancel acknowledged before the job registers** (`worker/job.go`). The
   handler spawns asynchronously and registers later, so an immediate
   `OpCancel{JobID}` is a no-op and the destructive job runs uncancellable while
   the pool drains, times out and releases its hold. Fix: register both the
   request id and the JobID synchronously in the read loop before spawning.

## Accepted — MEDIUM

6. **Restore follows a parent that became a symlink** (no race needed). Fix:
   the original parent must be reached with no symlink component.
7. **Cancellation discards the structured partial result and warnings** (the
   Err frame has no body). Fix: contract extended with `JobResult.Cancelled`;
   the worker sends the terminal as OK with the partial result; `Pool.Job`
   returns it with `context.Canceled`; the Manager keeps it.
8. **Planted FIFO sidecar blocks a handler forever** (blocking open). Fix: open
   `O_NONBLOCK|O_NOFOLLOW`, require a regular, uid-owned, size-capped file.
9. **Duplicate job ids corrupt cancel ownership.** Fix: reject a live
   duplicate; unregister only one's own entry, before the terminal is written.
10. **An item named `meta.json` cannot be trashed** (collides with the sidecar;
    an orphan sidecar could be mistaken for a payload) — reproduced by a test
    the standard reviewer wrote. Fix: payload under a fixed internal name.
11. **`.zfs` and `@Recycle` descended into by a recursive delete** — reproduced
    by tests. The front-end guard sees only a job's roots, so the worker must
    apply the never-write component rule to every entry it walks. Fix: skip
    and warn `protected` in mutating walks (and `.zfs` in Size).
12. **Pre-write deadline expiry retires a healthy worker** (`workerpool`): an
    expired context before any bytes are written was treated as a
    desynchronised transport, failing every concurrent RPC with `worker_gone`.
    Shared by the plain call path. Fix: distinguish "nothing written".
13. **Cancel-grace expiry abandons a live job**: the client is released and the
    worker deemed idle while it may resume mutating. Fix: retire (kill) that
    worker on grace expiry and return `Cancelled` with a terminate note.
14. **Emptying trash deletes a sidecar before its payload**, so a payload that
    then fails to remove vanishes from the listing and can never be restored.
    Fix: empty entries individually, payload first. (Follow-up to the trash fix
    pass, which was already running on that file.)

## Confirmed sound

Leaf symlinks are unlinked as links and child opens use `O_NOFOLLOW`; a missing
trash or `EXDEV` never falls back to a permanent delete; restore is `NOREPLACE`;
the jail still constrains `origPath`; the `deliver` terminal eviction cannot
consume a frame a caller already took; the jobs map is per worker process so
cross-user cancellation is impossible; the Manager recovers panics, releases
semaphores and copies slices; non-UTF-8 paths keep their bytes through the
sidecar.

## Disposition

All fourteen accepted. Fixed in two parallel Opus passes on disjoint files —
fsops + trashroot (1–4, 6, 8, 10, 11) and worker + workerpool + jobs (5, 7, 9,
12, 13) — with 14 as a follow-up on `trash.go`. Round 2 re-reviews the result.
