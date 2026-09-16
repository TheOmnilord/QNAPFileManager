# M3 permissions and properties — Astra round 2 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 23eaf89 (the round-1 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-1 table. Judged by Claude Fable 5.1.

Normal review: 12 findings. Adversarial review: see the addendum below.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the sync route turns a worker state of `""` (no backend detected, or a worker answer the route discarded in favour of its own pessimistic grade) into `unknown` and sends **that** as the exact `Expect.State`; the worker re-probes the unchanged object, sees `""`, and refuses `changed`. A legitimate chmod fails even after confirmation. Only the fake mutator's request was inspected. | routes + engine | **Accepted — a round-1 regression.** The route sends the worker-**observed** state, kept apart from the ladder's grade; with nothing observed it sends identity only. The workerpool test drives Props → Chmod through the real worker. |
| 2 | P1: the post-order identity check runs only when the reopened object is a directory — a nested directory renamed away and replaced by a regular **file** receives the chmod/chown. Round-1 #7 half-closed. | engine | **Accepted.** The proof is gated on the traversed item, and any replacement — a different type included — is `changed`. |
| 3 | P1: the amended trivial rule still admits `EVERYONE@ ALLOW DELETE` and an append-only `APPEND_DATA` without `WRITE_DATA` — neither is rwx-expressible. | engine | **Accepted.** Representable-mask rule: an ALLOW for a special principal is trivial only if its mask ⊆ read bits ∪ write bits ∪ execute (∪ the two admin bits for `OWNER@`), with `WRITE_DATA` and `APPEND_DATA` both or neither; `DELETE`/`DELETE_CHILD` are non-trivial. If hardware shows QNAP's trivial ACLs carry `DELETE_CHILD`, that is amended with the real bytes in hand. §6.1 amended. |
| 4 | P2: a bind mount keeps the parent's `st_dev`, so the device comparison misses a same-filesystem file bind; and `crossMounts:true` skips the check without `MayCross`. Round-1 #19 half-closed. | engine | **Accepted.** Non-directory entries use the walker's statx mount-id and domain checks, exactly as directories do. |
| 5 | P2: the unlistable-directory fallback covers only the selected root; a nested `0000` directory is still skipped (no post-order hook when the open fails). Round-1 #8 half-closed. | engine | **Accepted.** The held-reference fallback applies to nested traversal failures. |
| 6 | P2: off Linux the identity is inode zero and `SameInode` rejects zero, so every Windows sync chmod now fails `changed` — against §14's best-effort dev loop. | engine + routes | **Accepted.** An unsupported identity (no inode on either side) proves the state only; Linux is unchanged. |
| 7 | P2: `Refresh` now probes new mounts **synchronously**, inside `maybeRefresh` on the request path, with `zfs get` timeouts of 3 s each and a batch of 16 — up to 48 s under a 15 s handler budget, uncancellable. | routes (platform) | **Accepted.** Probing is asynchronous after the refresh; an unprobed mount stays unknown, which the ladder already grades pessimistically. |
| 8 | P2: each root gets a fresh 500 000-entry allowance, so a multi-root selection scans a multiple of the bound and reports a measured count. | routes | **Accepted.** The remaining allowance is passed root to root; the sum is what is capped. |
| 9 | P2: `abandon` marks the entry cancelled before the cancel is sent; when the poll failed for a lost connection the cancel fails the same way and the id is gone — round-1 #14's original scenario. | ui | **Accepted.** Cancellation requested ≠ acknowledged; the id is kept for retry until the server answers. |
| 10 | P2: after `0788`, toggling a grid checkbox rewrites the field with a valid mode but only `onOctal` clears `octalInvalid` — Apply stays disabled with a stale error. Reproduced through the registered handlers. | ui | **Accepted.** Validity is recomputed whenever `paintGrid` writes the field. |
| 11 | P2: the NFSv4 ZFS test skips on upstream OpenZFS (no `system.nfs4_acl`), so a detection regression would skip rather than fail. | tests | **Accepted in part.** CI cannot stage QNAP's attribute; that is the hardware check the contract already lists. The skip becomes a failure under `QFM_NFS4_TEST=1` (a runner that has the attribute), and the ZFS job's log says why it skipped. |
| 12 | P2: the chown-ordering test never drives `applyNow`; removing the `await awaitJob` leaves it passing. | ui | **Accepted.** The apply flow is driven with a deferred chown; no chmod POST before completion, including failed/cancelled. |

Adversarial review (landed after the normal pass): 5 findings, 3 of them #1, #6 and #10 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 13 | P1: two datasets mounted at the **same** mount point before a refresh are both in `pending`; the lower row's probe wins the first-write assignment, so the xattr answer is the upper dataset's and the `aclmode` the lower's — lower `passthrough` + upper `discard` grades L1 where L2 is due, cached across refreshes. | routes (platform) | **Accepted.** Only the visible row is probed, and an asynchronous result is published only if the mount identity at that point still matches. |
| 14 | P2: `Detect()` calls `Refresh()` then `Probe()`, and `Refresh` now probes too — every daemon and worker probes the first 16 storage mounts twice at start-up; four datasets at the 3 s `zfs get` timeout go from ~12 s to ~24 s and exceed the worker pool's 20 s hello timeout. | routes (platform) | **Accepted.** One synchronous probing pass at start-up; the asynchronous path is for later refreshes only. |

Rejected: none outright; #11 narrowed to what CI can execute. Unique findings this round: 14.
