# M1 review — round 7 (adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`, adversarial
prompt). Scope: commit `5a7c6e8` (the round-6 `auditContext` fix).

## Result

**No defect introduced by `5a7c6e8` was found.** Completed-mutation results use
`ok`/`error`/`partial`; intents remain cancellable; `WithoutCancel` preserves
values; `WriteSync` keeps its independent 2s timeout and bounded worker slots;
root authorization and destructive dispatch are unchanged.

## Pre-existing caveats raised (not introduced by this commit)

1. **Zero-work batch emits an uncancellable `error` milestone** — a big batch
   where every item fails records its milestone with result `error`, which is
   cancellation-immune. **Judged acceptable by design:** a large all-failed batch
   is a security-relevant *attempt* (someone tried to mass-delete) worth recording
   durably, and the write is bounded by the single 2s `writeSyncTimeout` — not a
   per-item stall, so no DoS.
2. **Settings rollback persistence can itself fail** (`routes_admin.go`), so §2.6
   was not the only possible toggle inconsistency: if the rollback's `config.Save`
   fails, the previous code left the guard at `prevVal` while the file held
   `newVal` — a guard/config disagreement.

## Judgement (Fable)

Caveat 2 **accepted and fixed** (this is a real, if double-failure-gated,
inconsistency): the rollback now sets the live guard to whatever value is actually
persisted, so the guard and config can never disagree — under a double failure the
guard stays at `newVal` to match the file rather than contradicting it. `PLAN.md`
§2.6 updated to state the guaranteed invariant (guard == config always) and scope
the residual to the audit narrative plus, in the rare double failure, a divergence
from the "refused" response shown to the admin. Caveat 1 documented as
by-design. Test-coverage note addressed with an unrecognised-result case.
