# Rename to Taproot — Astra round 3 (2026-10-21, gpt-6-astra, effort high)

Reviewed: the staged diff of commit fea950c (`wip/rename`, the round-2 fix) against main 7ba8d5e. Judged by Claude
(Opus 5.5, conducting in place of Fable 5.1). The adversarial pass was asked to walk every step of the pinned
cleanup snippet in `docs/qnap-install.md` for a rename or symlink swap under Linux semantics, to confirm the
empty-only and no-symlink guarantees and busybox behaviour, and to re-examine the whole rename.

Normal review: 0 findings — "No actionable regressions were found in the rename across code, UI, packaging, and
scripts."

Adversarial review: 2 findings; "No additional defects were found in decoding, rmdir's empty-only/no-symlink-removal
guarantees, rename pairs, packaging/service/CI, break-glass discovery, hidden behavior, other documentation, or
nonexempt old names."

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the trash root is mode 1777, so another user can move the pinned folder into a different directory on the same filesystem; `cd -P ..` then enters its new parent and the final `rmdir` removes that parent's unrelated empty `.@qfm_trash`. Child removals stay confined; the final one does not. | D (qnap-install.md) | **Accepted.** The root is removed by its absolute path instead (`rmdir -- "$t"`): a mount point cannot be renamed and its parents are system folders, so only the last name can change, and `rmdir` removes only an empty directory of exactly that name in that mount root, never through a final symlink. The step also says to run it while nobody else writes to the shares, which covers the unusual mount nested inside a user-writable folder. |
| 2 | P3: `echo` in dash interprets a literal `\c` in a path, truncating the report; busybox does not, so the output differs by shell. | D (qnap-install.md) | **Accepted.** Every message is a fixed-format `printf` with the path as a `%s` argument. |

Unique findings this round: 2. Rejected: none.
