# M2-B copy/move — review round 8 (2026-09-13, gpt-6-astra, effort high)

Round 7's two findings were fixed (settle before the hard-link compare, shared with `copyFile`; owner/times and a
symlink's target from the descriptor). Linux CI on the round-7 tree (run 34736876663): all five jobs green.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: only hard-linked entries re-check their destination before the source is deleted; an ordinary file's published copy removed mid-job loses the source silently (reproduced). | engine | **Accepted.** Every recorded destination is re-verified by identity (and size) through the held destination directory before its source is unlinked. |
| 2 | P1: directory owner/mode are reproduced from the pre-open lstat; a directory chowned before the open is recreated with its former owner over the new owner's contents — disclosure, the round-7 file case again. | engine | **Accepted.** Directory metadata from the enumerated descriptor's fstat. |

Adversarial review, round 8: 3 findings (#1 and #3 overlap the normal pass; #1's variant — a listed child replaced by a different directory before the open — sharpens the remedy: identity and metadata both from the opened descriptor).

| 3 | P1: an equal-length source rewrite during the read publishes a mixed file (`AABB`) over an intact destination under overwrite, success, no warning — a copy bug, not only a move one. | engine | **Accepted.** Post-read fstat of the source must equal the pre-read state before anything is published; residual for a plain copy: a same-tick rewrite of a file small enough to read inside one tick. |
