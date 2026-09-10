# M1 review — round 5 (adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`, adversarial
prompt). Scope: commit `3bd0fea` (the round-4 fixes) against parent `d7e2c09`.

Overall: the round-4 fixes resisted the specified attacks — concurrent-toggle
ordering, requested-path error construction, unconditional overwrite destination
policy, and direct protected reads all held. The one broken dimension is
**request-context cancellation**, which the round-4 change made observable in
`WriteSync`: it can now damage records of work that already happened.

## Findings

**[P1] Do not roll back a toggle on an ambiguous audit cancellation** —
`internal/web/routes_admin.go`. Cancel the admin request after the result writer
is admitted but before its fsync completes: `WriteSync` returns `context.Canceled`
while its goroutine still durably writes `Result:ok, readOnly=newVal`, and the
handler then rolls the guard and file back to `prevVal`. The durable audit trail
ends up contradicting both live values, on a healthy disk with no concurrent
toggle. Cancellation after admission is an *uncertain* outcome, not proof the
write never landed.

**[P1] Preserve post-mutation milestones after request cancellation** —
`internal/web/routes_mutate.go` (`writeAudit` durable path, used by `finish` and
the batch milestone). If the request is cancelled after a successful large delete,
its result milestone is submitted with an already-cancelled context; `WriteSync`
can select `ctx.Done()` during admission and discard the event, even with a
healthy sink. A completed destructive operation loses its required durable record
solely because the client disconnected.

**[P2] Mark cancellation-shortened batches as partial** —
`internal/web/routes_mutate.go` batch-outcome switch. Cancel after the first
successful deletion in a multi-item batch: the loop break leaves
`succeeded=1, failed=0`, so the outcome is `"ok"` and the milestone reads
`1 of 1 (ok)` (denominator was changed to `attempted`), despite every remaining
target being untouched. (Same as standard finding.)

## Judgement (Fable)

**All three accepted.** They are one regression class introduced by the round-4
context-awareness change: cancellation may gate *waiting* and *pre-work* records,
but must never discard or contradict records of *completed* work. Fixed in the
round-5 commit:

- Records of completed work — a milestone with result `ok`/`error`/`partial`, and
  the settings toggle's final-state result — are persisted with
  `context.WithoutCancel`, so a client disconnect cannot discard them or turn a
  durable success into a false `Canceled` that triggers rollback. `WriteSync`'s
  own `writeSyncTimeout` still bounds each wait.
- Intent (pre-work) records and denials (no work happened) stay request-scoped,
  so a cancelled batch still stops promptly and a wedged sink cannot stall a live
  request (the round-4 adv-4 property is preserved).
- The batch outcome counts unattempted targets: any unattempted item forces
  `partial`, and the milestone denominator is the requested count.

New tests: `TestBatchMilestoneSurvivesCancel` (a milestone for a completed delete
survives a mid-batch cancel, marked partial) and an outcome assertion added to
`TestBatchDeleteStopsOnContextCancel`.
