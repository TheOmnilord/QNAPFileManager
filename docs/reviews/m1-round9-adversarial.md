# M1 review — round 9 (adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`, adversarial
prompt). Scope: commit `b8d510f` (the round-8 `reconcileReadOnly` fix).

## Result

**No actionable regression found.** The reviewer's attacks did not break the fix:

- Atomic publication (temp file + rename) prevents `Load` parsing a partial write.
- `config.Load` is uncached and does not re-enter `cfgMu` — no deadlock.
- The rollback updates both the live guard and the in-memory config consistently.
- Fail-closed to read-only blocks writes without locking admins out of Settings —
  the safe direction.
- Concurrent toggles remain serialized under `cfgMu`.

## Observations (accepted, not regressions)

- **Transitional guard window** (pre-existing): a mutation racing an in-flight
  toggle can observe the guard mid-transition. Accepted — the admin's intent is
  recorded by the durable intent line before anything is applied, and a write that
  slips through during a "enable writes" toggle is one the admin authorized.
- **Synchronous re-read cost** (new, minor): the reconciliation adds one
  synchronous `config.Load` on the already-failed rollback path, which on unhealthy
  storage can lengthen the toggle's completion window under `cfgMu`. An
  availability cost on an error path, not a correctness one.
- The injected-loader test checks branching, not real filesystem failures (forcing
  a post-rename `config.Save` failure is not reachable from a test); accepted.

## Judgement (Fable)

**No code change required.** The synchronous-re-read availability nuance was folded
into PLAN.md §2.6. Both round-9 passes were clean of correctness findings.
