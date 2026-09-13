# M2-B copy/move — review round 15 (2026-09-13, gpt-6-astra, effort high; last round of the extended budget)

Round 14's six findings were fixed (whole ancestor chain per child; record re-validated before `rmdir`; no ledger
on a copy; files created unnamed with `O_TMPFILE` and linked into place; inherited setgid required; directories and
symlinks staged under a temporary name and renamed into place). Linux CI on the round-14 tree (run 34742572954):
the unnamed and staged paths executed and passed; two fixtures keyed on final names failed (sent to the engine).

Normal review: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a random name in a listable directory can still be watched and swapped between mkdir and open; a prepared worker-owned directory with a named-user ACL passes the stat checks. | engine | **Accepted.** A private per-job staging directory (0700, ours, proved once including "no ACL xattr" via the backend's ACL xattr name) holds every staged object; inside it only we can create or rename, so provenance holds by construction. |
| 2 | P1: the delete pass validates only the immediate directory; a grandparent tightened during a long comparison lets the rest of the subtree be deleted. | engine | **Accepted.** The ancestor chain is carried and validated before each removal, as on the copy side. |
| 3 | P2: the ownership-failure seam keys on the final name, which staging replaced. | engine | **Accepted** (already sent from the CI failure). |

Adversarial review, round 15: 2 findings — identical to the normal pass's #1 (discoverable staging names) and #2
(ancestor chain during deletion); nothing else qualified.

Budget note: round 15 is the last of the owner's extended budget. Its two P1s are real and are fixed; one further
verification-only pass (round 16) reviews those fixes, after which the loop stops and anything left is either a short
fix or a documented residual, with the overrun stated here for the owner's judgement.
