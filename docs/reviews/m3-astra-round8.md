# M3 permissions and properties — Astra round 8 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 5df561c (the round-7 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-7 table. Judged by Claude Fable 5.1.

Normal review: 3 findings. Adversarial review: 4 findings, two of them the same. Unique: 5, plus one judgement
that the contract must correct. Round 7 #1 confirmed closed with substantive assertions; "not converged" on the
challenge loop and on two §17 claims.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2 (both): at the challenge bound `runMutation` throws the generic "This change needs confirmation." — the real sentences live in `confirm.summary.warnings`, which `actionMessage` never reads; the third warning is hidden. | ui | **Accepted.** The bound error is built from the latest challenge's warnings plus "no change was submitted". |
| 2 | P2 (adv): a subsequent challenge is owned by whoever holds the page when it arrives — Alice approves, the page switches to Bob, the second 409 opens Bob's dialog and reposts Alice's operation with Bob's credentials. Reproduced. | ui | **Accepted.** The initiating owner epoch is captured and checked before presenting and before redeeming every subsequent challenge. |
| 3 | P2: the round-7 polling tests pass against the pre-patch `jobs.js` — the fetch mock never holds a GET across the session change, and the switch test accepts poll exhaustion as abandonment. | ui (test) | **Accepted.** A deferred GET across the refresh; the switch asserts no subsequent GET. |
| 4 | P2 (adv): the token binds **submission**, not execution — with the slots occupied, an accepted recursive chmod can wait while `zfs set aclmode=discard` lands; the dispatch callback rechecks only the guard. | routes | **Accepted.** The dispatch callback rebuilds the ACL verdict and refuses to dispatch when its digest differs from the redeemed one: the job fails with "the ACL facts changed while this was waiting; confirm it again". §7 amended. |
| 5 | P2 (both): §17.16 claims an orphaned size walk is reaped by "the server's job lifetime"; there is none — `Submit` uses a background context, `Reap` skips live jobs, `runJob` has no call timeout, the size route's scan is uncapped. | Fable (contract) | **Accepted.** §17.16 restated as the real residual: an orphaned walk runs to completion, cancellation, worker failure or shutdown, holding a metadata slot. A reader-idle reaper is a v1.1 item. |
| 6 | (both) restated §17.14: a candidate-order change re-challenges conservatively. | — | Already recorded. |

Rejected: none.
