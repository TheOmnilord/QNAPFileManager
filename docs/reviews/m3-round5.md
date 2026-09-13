# M3 permissions + properties — review round 5 (2026-09-13, verification)

Round 4's accepted findings were fixed (routes: with crossing the ladder folds every dataset below each root and
names the discarding ones, bounded; UI: server sentences are the single displayed source, the special-bit line
leads and the mode line is dropped beside it, apply scope is `all` unless recursive, one rule decides Apply; engine:
`NFS4State` tolerates a NUL-counted who and an unpadded final who; CI: the node tests run in the Linux test job).

This round verifies those fixes and looks for regressions only, in the M2-B manner (verification passes, then stop).
Reviewer: Opus (gpt-6-astra paused). Linux CI on the round-4-fixed tree (run 34775191254 at 0c0b830, PR #3): all
five jobs green, with the node tests now part of the Linux test job.

Verification pass: every round-4 fix verified, no regressions, four P3 nits ("no other qualifying defects").

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P3: the crossing fold also runs for non-recursive jobs, where crossing is inert — over-warns and forces a milestone for datasets the job will not touch. | routes | **Accepted.** Fold only when `cross && recursive`. |
| 2 | P3: the "garbage after the last ACE" test row is inert, and `NFS4State` ignores trailing bytes after an honest count. | engine | **Accepted.** Trailing bytes → `unknown`; the row rewritten to exercise it. |
| 3 | P3: `perm.js` `diffSummary` is dead since the concatenation was removed. | UI | **Accepted.** Removed; tests assert what `showDiff` toasts. |
| 4 | P3: unnamed discarding datasets de-dup to one, so the sentence says "this dataset" for many. | routes | **Accepted.** De-dup keyed on the mount path when the name is empty. |
| 5 | P3 (doc): contract §7's token parts omit the round-3 `kind=` part. | orchestrator | **Accepted.** §7 amended. |

Round-5 nits landed (routes: fold only when crossing and recursive, unnamed datasets keyed on their mount point;
engine: trailing bytes after the last ACE are `unknown`; UI: `diffSummary` removed). The M3 loop ends here: five
rounds, 31 findings, 30 accepted and fixed, one recorded as M1 behaviour. Final Linux CI run recorded in PLAN.md.
