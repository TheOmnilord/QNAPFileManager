# M1 review — round 7 (standard)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: commit
`5a7c6e8` (the round-6 `auditContext` fix).

## Result

**No material new defects.** The reviewer enumerated the `writeAudit` call sites
and confirmed `auditContext` covers the full result matrix: intent passes `''`
and denials pass `"denied"` (both stay request-scoped); `finish` passes
`ok`/`error` and the batch milestone passes `ok`/`partial`/`error` (all
cancellation-immune). `context.WithoutCancel` drops the deadline but nothing
bypasses `WriteSync`'s own 2s `writeSyncTimeout`, so no unbounded wait is
introduced. `TestAuditContextCancellation` passes and pins the mapping.

## Observation

`PLAN.md` §2.6 correctly described the late-persistence scenario, but its
"writes remain blocked" phrasing assumed the toggle was *enabling* writes and
that the rollback save succeeds.

## Judgement (Fable)

**No code change required by the finding.** The §2.6 observation is valid and was
acted on: the residual text was corrected (the direction-dependence and the
double-failure case), and — going beyond the doc — the rollback code was hardened
so the live guard is set to whatever value is actually persisted, guaranteeing the
guard and config can never disagree even if the rollback save fails (see the
round-7 adversarial review, which raised the same double-failure point). Added an
unrecognised-result case to `TestAuditContextCancellation`.
