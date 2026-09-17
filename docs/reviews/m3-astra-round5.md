# M3 permissions and properties — Astra round 5 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit ef57fb6 (the round-4 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-4 table. Judged by Claude Fable 5.1.

Normal review: 4 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: on a demonstrated mount mismatch the route sets `unknown`, but with both cached tables saying `passthrough` `worstAclmode` keeps `passthrough` and `chmodACLNotice` still grades the L1 passthrough notice — the mismatch case is not L2 after all. | routes | **Accepted.** A demonstrated mismatch forces the destructive rung: `aclmode` becomes `""` (read as `discard`), the L2 typed phrase with the unknown suffix, whatever both caches say. |
| 2 | P2: expiry only queues a re-probe; lookups keep returning the expired backend and `aclmode` until publication, and a blocked or queued probe extends that past the promised minute. | routes (platform) | **Accepted.** Expired mutable facts are masked pessimistically at lookup (`aclmode` unknown) until the re-probe publishes. |
| 3 | P2: expired rows join the first-16 selection from the start of `p.mounts`, so with enough slow rows the early ones expire again before the trailing ones are reached — trailing (and newly mounted trailing) rows starve. | routes (platform) | **Accepted.** Never-probed first, then oldest facts first, with a cursor across passes. |
| 4 | P2: the recycled-inode test now **fails** when the allocator does not hand the inode back within 64 tries — an allocation-policy failure on ZFS or delayed-allocation filesystems, not a defect. | engine (test) | **Accepted.** Missing birth-time capture stays a hard failure; inability to stage recycling is a skip that says so. |

Adversarial review: 5 findings, three of them #1, #2 and #3 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 5 | P1: `worstAclmode` folds two *known* non-destroying modes that disagree to the daemon's — daemon `passthrough`, worker refreshed after `zfs set aclmode=groupmask` — so the dialog promises "other entries are kept" while the kernel reduces named entries. | routes | **Accepted.** `discard`/unknown on either side is L2; two known modes that **differ** are unknown (L2) — neither cache is proved and the two warnings are not interchangeable; only agreement keeps a value. |
| 6 | P2: the module-wide pending-cancel register has no session owner and survives sign-out; after Alice's cancel fails, Bob's runner retries Alice's job with Bob's credentials (reproduced; admins may cancel others' jobs). | ui | **Accepted.** Claims record the session generation; only current-generation claims are retried; a session switch drops the rest. |

Unique findings this round: 6. Rejected: none.
