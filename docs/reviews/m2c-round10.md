# M2-C upload / archive / search — review round 10 (2026-09-13, gpt-6-astra, effort high)

Round 9's three findings were fixed. Linux CI on the round-9 tree (run 34755803895): all five jobs green.

Adversarial review: 1 finding ("no other qualifying defects"). Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: `/api/jobs` still deep-copies every retained search result inside `Manager.List` and decodes the hits only to drop them — 72 MB and ~200 ms per poll after nine large searches; GET has no admission limit. | routes | **Accepted.** Search hits live only in the web layer's retention ledger; the manager holds a hit-free result; the single-job view merges them. |
| 2 | P2: search hits that are symlinks carry no link metadata and render as "broken". | engine + UI | **Accepted.** The engine fills the link target via `readlinkat` on the held parent (never following); the UI renders an unresolved link without a broken/valid claim. |
| 3 | P2: cancelling an upload during a 429 back-off aborts the finished XHR and lets the wait run its full 30 s. | UI | **Accepted.** Cancel wakes the wait. |

Round 10 is the standard budget's end; the owner's rule allows up to fifteen, and the P1 is real, so the loop
continues under the same rule as M2-B.

Round-10 fixes landed for all three (routes — hits held only in the retention ledger, the manager's result hit-free,
the single-job GET splicing bytes, reaped jobs pruned at finish and from the ticker via the exported
`PruneSearchResults`; engine — `linkTarget` on symlink hits via `readlinkat`, never resolved; UI — an unresolved
link rendered without a verdict, cancel wakes the back-off wait).
