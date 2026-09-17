# M4 polish and release — Astra round 4 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit d23cb3e (the round-3 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-3 table. Judged by Claude Fable 5.1.

Normal review: 3 findings, all on the refusal-summary accounting from round 3 #2.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: a flush claims the count and waits for audit admission; a second login from the same source sees `suppressed == 0` and deletes the entry, or another source's refusal prunes it; if the first write then fails admission the rollback finds nothing and the burst is lost. | door | **Accepted.** An explicit in-flight claim on the entry; neither deletion path removes a claimed entry until the write outcome is known. |
| 2 | P2: `WriteSync` can return `ErrSyncTimeout` after its worker was **admitted** and goes on to write; restoring the counters on every error then reports the same refusals twice. | door | **Accepted.** Rollback only on a definite non-admission; a timed-out-but-admitted write is not restored. |
| 3 | P3: with the auditor idle, reverting `WithoutCancel` does not reliably fail the cancellation test — Go may pick the semaphore send over the cancelled context. | door | **Accepted.** The test saturates the writer slots before the cancelled request and releases them under synchronisation. |

Adversarial review: 3 findings, two of them #1 and #2 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 4 | P2: the round-3 salt-tail spare-bit check refuses a hash bcrypt still verifies — the decoder discards salt padding bits and the comparison keeps the supplied spelling — so a previously working credential could stop the daemon after an upgrade. | door | **Accepted.** The salt-tail check is dropped; the checksum-tail check (which does make a hash impossible) stays. Contract §18.15 corrected. |

Unique findings this round: 4. Rejected: none.
