# M1 review — round 8 (adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`, adversarial
prompt). Scope: commit `3578b52` (the round-7 rollback hardening).

## Finding

**[P1] Distinguish rollback publication from save success** —
`internal/web/routes_admin.go` rollback branch. Same defect the standard pass
found, rated higher: if the initial save succeeds but the audit result write
fails, the rollback can publish `prevVal` via the rename and *still* return an
error from `durable.SyncDir` or `os.Chmod` afterwards. For `prevVal=true,
newVal=false`, the round-7 branch then leaves writes enabled and
`s.cfg.ReadOnly=false` while the published config contains `true`, despite telling
the admin the change was refused — "not merely an audit-narrative discrepancy".
Fix: track whether publication occurred separately from durability/mode errors,
and reconcile the effective value; add fault-injection coverage for post-rename
failures.

The reviewer confirmed the good properties: one deferred `cfgMu` unlock covers the
whole transition (no early-return-unlock or double-unlock bug), nil guards block
mutations, and concurrent toggles stay serialized. The guard-check/dispatch race
and the empty-`ConfigPath` success path are pre-existing.

## Judgement (Fable)

**Accepted** (both round-8 findings are the same issue). Fixed by reconciling the
guard against the actual on-disk value after a save error (re-read; fail-closed if
the re-read fails), so the guard and config can never disagree in any failure
combination. The reviewer's "add fault-injection coverage" was addressed by
extracting `reconcileReadOnly(...)` — with an injected loader — and unit-testing
the post-publish case (`save error, file already swapped`) plus the fail-closed
fallback directly, since forcing a post-rename failure inside `config.Save` is not
otherwise reachable from a test. PLAN.md §2.6 rewritten to state the guaranteed
invariant precisely.
