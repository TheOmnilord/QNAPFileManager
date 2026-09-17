# M3 permissions and properties — Astra round 4 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit d0ac837 (the round-3 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-3 table. Judged by Claude Fable 5.1.

Normal review: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the mount-agreement rule (round 3 #8) is one-directional — when the **worker** has the newer table (a `discard` dataset mounted beneath a `passthrough` parent, worker refreshed first), its real `discard` observation is discarded as "elsewhere" while the daemon's stale `passthrough` is kept: L1 and a promise that other entries survive, then the precondition is satisfied. | routes | **Accepted.** Disagreement invalidates the retained `aclmode` as well: the grade is the worst of both observations (an unknown or `discard` on either side is L2). Reverse-direction test. |
| 2 | P2: the inode-recycling test (`heldIn`) keeps the child's descriptor open through the remove/recreate loop, so the inode can never be recycled and the test always skips before reaching `unopened`. | engine (test) | **Accepted.** Open only the parent; check birth-time support independently; assert the enumeration preserved it. |
| 3 | P2: the pending-cancel set is runner-local, so with two runners sharing one pending POST (Properties + Permissions), the last holder to stop gets no ownership when the 202 lands and the cancel fails — its Stop/Recount never retry. | ui | **Accepted.** Pending-cancel ownership lives with the shared entry (or a shared registry), not with the runner that submitted it; deferred-202 test. |

Adversarial review: 5 findings, one of them #2 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 4 | P1: `resp.Identity.Mount` is the newly opened inode's while `resp.ACL.Aclmode` is the worker's **cached** row's — replace `pool/a` (`passthrough`) with `pool/b` (`discard`) at one mount point, refresh the daemon, worker still on `a`: the agreement check passes and `a`'s `passthrough` replaces the daemon's `discard`. | routes | **Accepted, folded into #1.** The worker's `aclmode`/dataset can never make the grade less severe than the daemon's — worst of both, agreement or not; agreement only decides whether the worker's *state* is believed. |
| 5 | P1: a demonstrated mount mismatch does not raise the floor when the daemon's row is a probed POSIX one — an NFSv4 `discard` dataset under a cached POSIX parent grades `posix/unknown` (L1), and the stale worker's double POSIX probe satisfies the precondition. | routes | **Accepted.** A mismatch is the unknown floor (L2) regardless of the daemon's backend. |
| 6 | P2: the incarnation changes only when a refresh sees different row values; a field-identical remount between two refreshes, or `zfs set aclmode` on a live dataset, keeps it, and a stale answer is cached indefinitely. | routes (platform) | **Accepted, narrowed.** Mutable probe facts get a 60 s freshness bound, re-probed by the single-flight pass and published under the incarnation rule; residual §17.3 narrows from "until the table refreshes" to "within a minute". |
| 7 | P2: without `STATX_BTIME` the Unopened fallback silently degrades to dev+ino — `lstatIn` closed its only descriptor — so inode reuse still passes. | engine | **Accepted.** Where the enumeration carries no birth time, the O_PATH reference `lstatIn` already holds is retained and the fallback acts on it — no reopen, no gap. |

Unique findings this round: 7. Rejected: none.
