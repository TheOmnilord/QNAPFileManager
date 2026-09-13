# M2-C upload / archive / search — review round 14 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 13's five findings were fixed: the upload read deadline is cleared before `Finalize`; archive roots are
streamed from an `ArchivePlan` whose root and parent identities are re-proved before each root (a swap skips the
root with a `changed` note); `OpenWrite` is bound to the directory identity taken at authorization
(`OpenWriteReq.DirIdentity`, `changed` on mismatch, `Finalize` publishes through the held dirfd); GET/HEAD with a
body is refused 400 + `Connection: close` before routing; a reaped search answers 404.

Round 14 is the penultimate round of the fifteen the owner allows; M2-B converged in nineteen passes with
verification-only rounds at the end, and the same rule applies here: the loop stops when a full round finds nothing
new, or at the ceiling.

Linux CI on the round-13 tree (run 34760653044 at e9ba1b8): all five jobs green.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: in a multipart upload, EOF from the file part is not EOF of `r.Body`; a withheld closing tail is drained by net/http at the first response write, after the stall deadline was cleared, and a large success JSON makes that drain block inside the handler with the upload slot held (reproduced over a real connection). | routes | **Accepted.** The remaining body is consumed under the stall deadline with a hard bound before the deadline is cleared; a bound hit or a stall sets `Connection: close` so net/http never drains. |
| 2 | P2: the archive's directory identity is checked on `lstat` and the directory then opened separately; a real directory swapped in between passes the check and is archived whole under the original selection. | engine | **Accepted.** Identity is proved on the held descriptor after the open (as `copyTree` does), for roots and for every directory the walk descends. |

Adversarial review: 3 findings ("no other qualifying defects"), one root cause.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P1: the worker resolves the web's canonical archive roots again, following symlinks, when `ArchiveCheck` records the plan's identities; an ancestor swapped for a symlink between the guard's resolution and the check records the protected target as the approved identity. Tickets too. | engine | **Accepted.** Every worker resolution of a web-supplied path walks it `O_NOFOLLOW` per component from the jail root; a canonical path has no symlinks, so any symlink means the tree changed — refused `changed`, never followed. |
| 4 | P1: the `FSIdentity` RPC taken at upload authorization re-resolves the canonical directory following symlinks, so an ancestor swap returns the identity of a protected directory, which `OpenWrite` then accepts. | engine | **Accepted.** Same `O_NOFOLLOW` rule for `FSIdentity` and `OpenWrite`'s walk. |
| 5 | P1: dev+ino identity can be satisfied by inode recycling across the client-controlled multipart wait. | engine | **Accepted.** Identity gains statx birth time (`Btime`/`HasBtime`), compared when both sides have it; dev+ino alone where the filesystem gives none. The `O_NOFOLLOW` rule already removes the redirect the recycling attack needs. |

Routes side: pin tests that every M2-C worker request (archive roots, upload directory, identity, search roots,
ticket replay) carries the resolved spelling.
