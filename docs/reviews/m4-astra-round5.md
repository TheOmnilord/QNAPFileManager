# M4 polish and release — Astra round 5 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit eef69cc (the round-4 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-4 table. Judged by Claude Fable 5.1.

Adversarial review: 2 findings, both in tests; "no additional production isolation defect was confirmed".

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the claimed-burst test observes the competing refusal's tracking entry and then replaces `s.auditor` while that goroutine may still be about to read it — a scheduling-dependent data race the Linux race job can catch. | door (test) | **Accepted.** The goroutine signals completion and is joined before the auditor is replaced. |
| 2 | P3: `SyncWaiting` increments before the admission `select`, so observing a waiter does not prove admission is blocked; with `WithoutCancel` reverted a schedule exists where admission wins and the regression test passes. | door (test) | **Accepted.** The handshake distinguishes a blocked admission from the pre-select interval (or the test asserts the summary's context is detached directly). |

Normal review: 3 findings, two of them #1 and #2 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P2: `emitSync` appends the whole line and then `Sync()` fails — `WriteSyncInFlight` answers "definitely unwritten" although the line is readable, so the rollback sites restore the burst and report it twice. Round 4 #2 not fully closed. | door (audit) | **Accepted.** A failure after the append is ambiguous and is classified in-flight; only a failure before anything was written is definite. |

Unique findings this round: 3. Rejected: none.
