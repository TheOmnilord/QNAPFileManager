# M3 permissions and properties — Astra round 6 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit f3da0f1 (the round-5 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-5 table. Judged by Claude Fable 5.1.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: `sessionGeneration` increments on every session install, same-user refreshes included (the read-only toggle, the minute poll), so refreshing Alice's session while her measurement runs makes `jobId` null and Stop/close drop ownership without a cancel — the cancel-on-close contract regresses. Reproduced. | ui | **Accepted.** Claims are scoped by an ownership epoch that changes only on sign-out or a change of user (`sessionTransition === 'switch'`), not on a refresh. |
| 2 | P2: the expiry mask covers `aclmode` only; `sameMountRow` ignores mount options, so an ext4 mount remounted `noacl` → `acl` keeps its incarnation and its `none` backend past expiry while a slow pass delays publication — the POSIX mask warning is omitted. | routes (platform) | **Accepted.** The expired backend is masked as unknown too (the ladder's unknown-storage floor), and the row identity includes the mount options so a remount that changes them advances the incarnation. |

Adversarial review: 3 findings, two of them #1 and #2 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P1: a confirmation token outlives the facts — `passthrough` at t=0, `zfs set aclmode=discard`, an L1 token at t=59 redeemed at t=61: the re-grade is L2 but `permTokenParts` binds neither the grade nor the ACL consequence, so the old token redeems and the chmod destroys the ACL without the destructive confirmation. | routes | **Accepted.** The token parts carry the ACL verdict (grade, discards, the `aclmode` the sentence was built on); a redemption whose re-grade differs is a new challenge with the current sentence. §7 amended. |

Unique findings this round: 3. Rejected: none.
