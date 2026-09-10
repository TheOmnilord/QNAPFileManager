# M1 review — round 6 (standard)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: commit
`9583b3a` (the round-5 cancellation fixes) against parent `3bd0fea`.

## Finding

**[P2] Keep milestone intent records request-cancellable** —
`internal/web/routes_mutate.go` (`writeAudit` durable-context predicate). For a
large single-item delete, `deleteSingle` calls `auditIntent(..., big=true)`,
which reaches the round-5 condition `milestone && result != "denied"` with
`phase == "intent"` and an empty result. The empty result is not `"denied"`, so
the pre-work intent lost cancellation and deadline handling too: a cancelled
request could wait the full audit timeout on a wedged sink before any destructive
work happened — the round-4 adv-4 regression the comment promised to preserve
against. Fix: restrict `WithoutCancel` to result-phase records with `ok`,
`error`, or `partial`, not intent records.

(The reviewer's two web-test failures were environmental again; CI for the
reviewed commit passed every job.)

## Judgement (Fable)

**Accepted** — a real bug in my own round-5 code. Same issue the adversarial pass
found. Fixed in the round-6 commit by extracting `auditContext(reqCtx, result)`,
which keys strictly on the result value (`ok`/`error`/`partial` → cancellation-
immune; intent and denials → request-scoped), and unit-testing it directly
(`TestAuditContextCancellation`).
