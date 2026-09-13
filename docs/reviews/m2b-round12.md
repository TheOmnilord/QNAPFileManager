# M2-B copy/move — review round 12 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 11's six findings were fixed (directory timestamps through the held descriptor; order-independent fixtures;
provenance on every created directory with the subtree abandoned on failure; the temp descriptor open through name
check, publish and cleanup; mode/uid/gid recorded for files; the fast-path rename re-proves its source) and the
`MAP_SHARED` residual documented. Linux CI on the round-11 tree (run 34739323381): all five jobs green.

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: directories are verified by identity only; a source directory tightened or chowned after its copy is deleted and the destination keeps the old mode/owner — the round-11 file hole, for directories. | engine | **Accepted.** Mode, uid, gid recorded for every directory and required unchanged before its contents are deleted. |

Adversarial review, round 12: 4 findings.

| 2 | P1: a substituted empty root-owned 0755 directory passes kind/creator/empty provenance; private 0644 contents land in a searchable directory. | engine | **Accepted.** The created object's permission bits must be a subset of the requested creation mode (inherited setgid allowed); subtree abandoned otherwise. |
| 3 | P1: a root move stages the file `root:<inherited group>` with the source mode for the whole copy before the chown; group members can read it. | engine | **Accepted.** Ownership installed on the empty file/directory immediately after creation and provenance, before any byte. |
| 4 | P1: a delayed close error (NFS EIO/EDQUOT) after publish unlinks the published file — neither version survives. | engine | **Accepted.** `fsync` before publish; a close error after publish is a warning, never an unlink. |
| 5 | P1: the destination root is created from one source state and the record taken from a later one; a tightened root with a new private child is disclosed and its deletion approved. | engine | **Accepted.** One fstat drives both creation and record. |
