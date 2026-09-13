# M2-B copy/move — review round 5 (2026-09-13, gpt-6-astra, effort high)

Round 4's five findings were fixed (settle before read; `unlinkIfOurs` on every cleanup; the rebase settled by the
same proof; byte-aware UI gate; clipboard ownership).

Normal review: 4 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the rebase's settle retry adopts an external writer's new ctime as its baseline; a same-length rewrite with restored mtime then passes and the remaining link is deleted. | engine | **Accepted.** After the copy, any ctime change other than our own unlink is external: the rebase must settle unchanged or the links are kept. |
| 2 | P1: the settle proof reads the destination's clock; a source with coarser timestamp resolution (whole seconds) passes immediately while a rewrite within the same second keeps its ctime. | engine | **Accepted.** The scratch is created in the held source parent — the source filesystem's own timestamp space; a move already needs write access there. |
| 3 | P2: an overwrite publish checks the temp's identity but not the final name's kind; a destination replaced by a symlink during the copy is renamed over, bypassing the kind-mismatch rule. | engine | **Accepted.** lstat the final name before `renameat`; wrong kind → no publish, temp removed, `conflict`. |
| 4 | P2: `TestARebasedHardLinkCtimeIsSettledToo` stalls the clock on `PhaseFinishing`, which is emitted after the first rebase; on a real filesystem both links vanish and CI would fail. | engine | **Accepted.** Stall before the first rebase; every never-executed Linux-only test re-read for the same pattern. |

Adversarial review, round 5: 4 findings.

| 5 | P1: a rebased hard-link ctime can be matched by a same-tick rewrite of the surviving link after the post-unlink fstat — timestamps cannot prove already-copied content across a rebase. | engine | **Accepted.** For multi-link entries the delete-time proof is a byte comparison of the surviving link against its destination copy (both through held descriptors); the rebase machinery is removed. |
| 6 | P1: the pre-read settle re-baselines on the first change (`base = after`) and publishes; the round-4 test requires `changed`. | engine | **Accepted.** First change → `changed`, no retry. |
| 7 | P2: the directory `rmdir` by name after the children are gone removes an empty replacement created under the old name during the deletion (reproduced). | engine | **Accepted.** Identity of the name re-checked immediately before `rmdir`. |
| 8 | P2: `consumed` is read at submit; a marking that completes while the paste dialog is open is cleared by the older paste's success. | UI | **Accepted.** The paste captures its clipboard object at open time. |
