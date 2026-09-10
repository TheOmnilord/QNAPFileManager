# M1 review — round 6 (adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`, adversarial
prompt). Scope: commit `9583b3a` (the round-5 cancellation fixes) against parent
`3bd0fea`.

## Finding

**[P2] Restrict cancellation immunity to result-phase milestones** —
`internal/web/routes_mutate.go`. Same defect the standard pass found: for a
confirmed single-file delete larger than 1 GiB, `deleteSingle` calls
`auditIntent(..., big=true)`, supplying `phase="intent"`, `result=""`. The
predicate `milestone && result != "denied"` makes that pre-work intent
uncancellable, so a wedged sink or writer admission consumes the full 2s audit
timeout despite no destructive work having happened — reintroducing the request-
deadline regression (round-4 adv 4). Require the result to be `ok`/`error`/
`partial` before applying `WithoutCancel`.

## Excluded observation (not a formal finding)

The reviewer noted, but excluded as pre-existing: a genuine result-write timeout
under a wedged sink during a settings toggle can cause a rollback followed by a
late durable `ok` line with no compensating record. Recorded as an accepted,
fail-safe residual in **PLAN.md §2.6** (the guard and config are the previous
value, so writes stay blocked; only the log over-reports; the clean close is the
architectural change §2.0 defers).

Otherwise: batch outcomes share the same HTTP/audit value, `WithoutCancel`
preserves values, timer and writer accounting intact, concurrent toggles still
serialized. (Web cancellation tests failed in the sandbox — environmental; CI is
green.)

## Judgement (Fable)

**Accepted** (finding). Fixed in the round-6 commit via `auditContext`, keyed on
the result value, with a direct unit test. The excluded observation is documented
as an accepted residual (§2.6), not fixed in M1.
