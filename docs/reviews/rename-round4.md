# Rename to Taproot — Astra round 4 (2026-10-21, gpt-6-astra, effort high)

Reviewed: the staged diff of commit b9b38e1 (`wip/rename`, the round-3 fixes) against main 7ba8d5e — the whole
rename once more. Judged by Claude (Opus 5.5, conducting in place of Fable 5.1). The adversarial pass was given the
current shape of the pre-1.0 cleanup snippet (pinned uid removals, the root removed by its absolute path only when
the pinned step succeeded, fixed-format reports) and asked to verify confinement, empty-only removal, symlink
protection, skip gating and busybox behaviour, then to re-examine every category.

Normal review: 0 findings — "No actionable regressions were found in the rename across code, UI, packaging, and
scripts."

Adversarial review: 0 findings — "No actionable defects found: under the stated conditions, cleanup preserves
confinement, empty-only removal, symlink protection and skip gating; decoder, reporting, shell constructs and
operator instructions are sound by inspection. Rename pairs, packaging/service/CI, break-glass discovery, behavior
changes and nonexempt old-name references are clean."

What no reviewer could run: the cleanup snippet under busybox on a NAS (dash and POSIX sh fixtures only), and the
Go suite inside the reviewers' sandbox (the conductor's local sweep and CI cover it).

Unique findings this round: 0. **Converged after four rounds** (2, 1, 2, then 0 findings) — every finding was in
the pre-1.0 upgrade steps; the code, UI, packaging and CI rename drew none.
