# M2-B copy/move — review round 13 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 12's five findings were fixed (directory mode/uid/gid recorded and verified; created objects' permission
bits a subset of the requested mode; ownership installed on the empty object before any byte; fsync before publish
with a late close error never unlinking; one fstat driving the root's creation and record). Linux CI on the
round-12 tree (run 34740101102): one new fixture failed — its seam fired after both fstats it meant to separate;
the engine's propagation was traced sound and the test now stages on an engine-announced `root-recorded` step.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the comparison's baseline fstat is accepted on identity alone; a chmod/chown landing after `matchesRecord` becomes the baseline and the source is deleted with the destination keeping the old mode/owner. | engine | **Accepted.** Every baseline stat validated against the full record. |
| 2 | P2: an older asynchronous marking (Ctrl+X still fetching pages) overwrites a newer Ctrl+C marking when its fetch completes. | UI | **Accepted.** Marking generation; only the latest request publishes. |

Adversarial review, round 13: 5 findings.

| 3 | P1: an adopted created directory's group is not validated; `GID -1` keeps a substituted `public` group and copied 0644 children become group-readable. | engine | **Accepted.** Expected creation gid computed from the held destination parent (setgid → parent's gid, else the worker's egid) and required on every created object. |
| 4 | P1: a directory chown failure warns and still copies children into the wrongly-grouped directory. | engine | **Accepted.** Ownership failure abandons the subtree, as for files. |
| 5 | P1: a source directory tightened during a long child transfer has its later siblings copied into the still-wider destination. | engine | **Accepted.** Held source ancestors re-checked against their record before each child. |
| 6 | P1: the same tightening during a long byte comparison is missed by the once-per-directory record check; children and the directory are removed. | engine | **Accepted.** The directory's record re-validated before each removal. |
| 7 | P1: the destination namespace is never directory-fsynced before originals are deleted; a power cut can lose both names of a moved symlink. | engine | **Accepted.** Every destination directory of a root fsynced (post-order) before `finishMove` deletes; failure keeps the source. |
