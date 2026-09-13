# M2-B copy/move — review round 6 (2026-09-13, gpt-6-astra, effort high)

Round 5's eight findings were fixed (hard-linked entries proved by bytes, rebase machinery removed; the settle
scratch in the source directory; no retry on change; kind re-check before publish; `rmdir` re-proves its name; the
paste captures its clipboard). A draft PR (#1, branch `wip/m2b-ci`) gave the Linux-only tests their first
execution: every race, ctime, cleanup, publish, rmdir and bind-mount test passed on the non-root race job, the root
job and the ZFS job; two ledger-bound tests failed on Linux (the identity set fills before the copy ledger; a move's
rename-first path never touches the bound) — sent to the engine.

Adversarial review, round 6: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a block modified after `sameBytes` passed it still yields a match (2 MiB probe, no inode/length change) and the last link is deleted. | engine | **Accepted.** fstat both fds before and after the compare, with the settle proof between, size/ctime/mtime unchanged on both. |
| 2 | P1: the source name is proved before a possibly minutes-long compare, not before the unlink; a replacement under the name is deleted. | engine | **Accepted.** `nameStillIs` immediately before the unlink. |
| 3 | P2: cancellation during the compare becomes a kept warning; a single-file root completes as success with `Cancelled=false` (reproduced). | engine | **Accepted.** ctx errors propagate as the cancellation they are. |

Normal review, round 6: 2 findings — #1 overlaps the adversarial #1/#2; one new:

| 4 | P2: the pre-flight adds `Files` and `Bytes` but discards `Dirs`; a directory-only transfer of 102 folders reports zero items and bypasses the scale confirmation and the audit milestone. | routes | **Accepted.** `Dirs` goes through the same saturating accumulator. |
