# M2-B copy/move — review round 10 (2026-09-13, gpt-6-astra, effort high)

Round 9's two findings were fixed (the published copy's size/mtime/ctime recorded and re-checked; the settle
precedes every stat the decision rests on; late cancellation reported as such; residuals listed in the file header).
Linux CI on the round-9 tree (run 34737990343): two Linux-only ctime tests failed — their scripted clock seams were
sequenced for the old reading order — sent to the engine; every other Linux test passed.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a writer with write access to the destination alters already-written bytes DURING the copy, before the baseline exists; size and source-state checks pass, the tampered copy becomes the baseline, and the source is deleted (reproduced). | engine | **Accepted — and it settles the design:** a move byte-verifies every regular file against its copy before deleting the source (§2.6 "copy, verify, then delete"); the metadata record is the fast pre-filter. Cost: a cross-filesystem move reads twice. |
| 2 | P2: the destination-clock scratch is created inside a created subdirectory after `unwind` restored its mtime, so the preserved timestamp is lost. | engine | **Accepted.** Scratches only in directories whose mtime the job does not preserve: the chosen destination container and the source root's parent. |

Round 10 is the end of the standard budget; the owner's rule (2026-09-10) allows up to fifteen rounds, and these
are real defects, so the loop continues.

Adversarial review, round 10: 3 findings (#1 overlaps the normal pass's #1).

| 3 | P2: on the non-chown path a fresh destination symlink is pinned by identity with neither its kind nor its target checked; a replacement between `symlinkat` and the pin becomes the trusted copy and the original is deleted. | engine | **Accepted.** Kind, creator ownership and target (read from the pinned descriptor) always verified; the delete-time check compares identity and target. |
| 4 | P2: the clock scratch is unlinked by name unconditionally; a stranger's file put under the name is deleted. | engine | **Accepted.** `unlinkIfOurs` with the scratch fd held. |
