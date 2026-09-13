# M2-B copy/move — review round 11 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 10's four findings were fixed (every regular file byte-verified before its source is deleted; clock
scratches only in the source root's parent and the destination container; the fresh destination symlink proved by
kind, creator and target, the copy's target compared at delete time; the scratch unlinked only if ours) and the two
ctime fixtures re-keyed by directory. Linux CI on the round-10 tree (run 34738556587): one fixture still fails
(`TestTheComparisonSettlesBeforeItReads` stages its rewrite in the copy phase, making the entry "recent") — sent to
the engine to test the order directly; everything else green.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: `unwind` restores directory timestamps by name; a directory replaced under its name during the copy is stamped instead of the held one. | engine | **Accepted.** `futimens` on an enumerable descriptor opened from the held O_PATH handle; identity verified before any by-name fallback. |
| 2 | P2: a verify test stages its corruption on the first finishing event, after the first source is already unlinked; fails on a correct engine depending on enumeration order. | engine | **Accepted.** Stage at an explicit pre-deletion seam; sweep for the same pattern. |

Adversarial review, round 11: 5 findings.

| 3 | P1: a freshly created directory is never proved on the non-root path, and on the root path a provenance failure only suppresses the chown — the copy descends into a stranger's 0777 replacement and discloses 0644 secrets. | engine | **Accepted.** Provenance (kind, creator, empty) on every created directory, every path; failure abandons the subtree. |
| 4 | P1: the temp is closed before the name-vs-inode check; an unlinked temp's inode number is reused by a stranger's file at the name and published over the intact destination. | engine | **Accepted.** Identity check, publish and cleanup happen while the descriptor is still open. |
| 5 | P1: hard-linked sources skip ctime, so a chmod/chown after the copy is invisible and the restriction is dropped when the source is deleted. | engine | **Accepted.** Mode, uid and gid recorded and compared for every entry. |
| 6 | P1: the fast-path rename moves whatever is at the name; a replacement made during ancestry collection was moved and reported as a clean one-file move (reproduced). | engine | **Accepted.** Identity re-proved immediately before `renameat2`. |
| 7 | P1: a local process with a dirty writable `MAP_SHARED` mapping can modify pages after the compare with no timestamp change. | — | **Judged a residual.** No mandatory locking on Linux; beyond what a file manager or `mv` can defend; requires a local process actively mapping the file being moved. Listed in the header's residuals. |
