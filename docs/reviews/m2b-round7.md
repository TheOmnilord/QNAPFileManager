# M2-B copy/move — review round 7 (2026-09-13, gpt-6-astra, effort high)

Round 6's four findings were fixed (bracketed byte comparison with the settle proof; name re-proved before the
post-compare unlink; cancellation propagates; `Dirs` counted as items). Linux CI on the round-6 tree (draft PR #1,
run 34736397650): all five jobs green — the first full execution of every Linux-only test.

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: `contentMatches` settles after `sameBytes`; on a coarse-timestamp filesystem the survivor's post-unlink ctime is current-tick, so a same-tick rewrite of already-compared bytes passes both state checks. | engine | **Accepted.** Settle-then-confirm BEFORE the compare, the order `copyFile` uses; one shared function. |

Adversarial review, round 7: 2 findings (#1 = the normal pass's #1). Nothing found in worker dispatch, routes,
`guard.Contains`, the UI, or the M2-A/M1 changes.

| 2 | P1: a root move reproduces ownership from the pre-open lstat (`ref.fi`); an owner change before the open hands the destination to the former owner and the source is deleted — a disclosure. | engine | **Accepted.** Reproduced metadata comes from the descriptor's fstat after the settle, never an earlier pathname lookup. |
