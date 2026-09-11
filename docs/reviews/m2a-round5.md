# M2-A review — round 5 (range 27b8d60..eee5738: the round-4 fixes)

Reviewer: gpt-6-astra, low reasoning effort. One verification pass with the
adversarial angle folded in, since the `Ensure` attack surface had been worked
over in rounds 2–4. PLAN §2.0-2.7 residuals were off-limits.

## Verified

- **R4-1** freshness-only refusals are a distinct stale case: owner, mode and
  emptiness are proven *before* the timestamp is consulted, so a stale verdict
  can never apply to a foreign directory; the retry re-derives a fresh time
  reference and a new random name each attempt.
- **R4-2** the leftover-temp diagnostic is emitted through `trashroot.Logf`
  before the retry loop continues, `Logf` is initialised (no-op default, wired
  to the daemon logger in `main`) and reaches only the server log.
- The ETA test gate holds the work function until the assertion has run.

## Accepted

- **R5-1 (P2)** the publication budget was enforced only in the stale branch.
  A mixed sequence — stale, stale, then a lost race whose winner vanished
  before the next lookup — reached the publish with the budget already spent
  and started a fourth temporary directory; and a stale result on the single
  extra pass after a lost race stretched that pass into another publication.
  Still bounded, but beyond the intended three, adding work and potential
  litter during mount-root churn. Fix (orchestrator): one budget check before
  *every* publication, whichever branch led there; the winner-validation
  lookup stays allowed on every pass. A Linux-only test drives the mixed
  sequences through the existing seams.

## Readiness

The reviewer's verdict was conditional: fix the mixed-retry bound before the
supervised hardware test. With R5-1 fixed, round 6 is a brief verification of
that one change; M2-A is then ready for the supervised test of recursive
delete, folder size and trash (delete-to-trash, restore, empty) on QTS and
QuTS hero.
