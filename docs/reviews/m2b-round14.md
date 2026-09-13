# M2-B copy/move — review round 14 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 13's seven findings were fixed (baseline stats validated against the record, the copy side via
`publishedMatches`; created objects must carry the expected creation group; a directory chown failure abandons the
subtree; held source ancestors re-proved per child and the directory record per removal; destination directories
and the container fsynced before any original is removed; marking generation in the UI). Linux CI on the round-13
tree (run 34741335199): all five jobs green.

Normal review: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the per-child ancestor check covers only the immediate parent; a grandparent tightened during a long transfer lets later descendants be copied into the still-wider destination. | engine | **Accepted.** The whole held ancestor chain is validated before each child. |
| 2 | P1: a chmod/chown during the LAST child's comparison has no following iteration; the final check before `rmdir` is identity-only. | engine | **Accepted.** The record re-validated immediately before `rmdir`. |
| 3 | P2: a plain copy retains the per-entry deletion ledger it never reads. | engine | **Accepted.** Entries recorded only for a move. |

Adversarial review, round 14: 5 findings (#2 and #3 overlap the normal pass's #1 and #2).

| 4 | P1: a group member opens the empty destination file before the chown and keeps the descriptor; chown does not revoke it, so chown-before-write does not close the disclosure. | engine | **Accepted.** Files are created unnamed (`O_TMPFILE`), owned, written, verified, then linked into place; the named-temp path is the documented fallback. |
| 5 | P1: `modeNoWiderThan` only rejects extra bits; a swapped directory WITHOUT the inherited setgid under a setgid parent passes and later files take the worker's primary group. | engine | **Accepted.** The inherited setgid bit is required, not merely allowed. |
| 6 | P1: an existing empty directory carrying a named-user ACL passes every stat-based provenance check; chown does not strip the ACL. | engine | **Accepted — by construction:** directories and symlinks are created under an unguessable temporary name, proved, owned, then renamed into place; what cannot be named cannot be swapped. The stat checks stay as defence in depth. |
