# M2-B copy/move — review round 16 (2026-09-13, gpt-6-astra, effort high; verification pass beyond the budget)

Round 15's findings were fixed (private per-directory staging proved once — crossing, kind/creator/empty, mode
exactly 0700, gid, inherited setgid, and no ACL ALLOW granting a non-owner a write-capable permission; a
shared-writable destination builds at the final name under the stat proofs with one `shared_destination` warning,
sticky destinations without; the delete pass validates the whole ancestor chain; a crossing refusal removes the
staged directory it proved ours). Linux/Windows CI on the round-15 tree (run 34744179475): ZFS green; the crossing
fixture keyed on the wrong object again, and the mid-read `create` case failed on CI Windows only (NTFS lazy write
time) — both fixtures sent to the engine.

Adversarial review, round 16: 4 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the NFSv4 parser exempts a numeric principal equal to the worker's uid without checking ACE4_IDENTIFIER_GROUP; a group ACE naming "0" grants gid-0 members write while root calls the staging private. | engine | **Accepted.** A numeric who is the owner only when the group flag is absent. |
| 2 | P1: a staging mkdir that succeeded but whose open fails (renamed away, replaced by a symlink) is classed as "could not be made" and falls back to final-name building — attacker-forced degradation. | engine | **Accepted.** Interference after our successful mkdir refuses; only a failed mkdir itself falls back. |
| 3 | P1: a `NO_PROPAGATE_INHERIT` ACE on the destination is consumed by the staging directory and absent from the published folder (rename does not recompute ACLs); an inherit-only DENY disappears. | engine | **Accepted.** A destination carrying one-generation ACEs is not staged; final-name building with the stat proofs. |
| 4 | P2: `rmdirIfOurs` after a failed provenance removes the stranger's empty directory (the opened inode is theirs). | engine | **Accepted.** Cleanup only when the staging directory was proved ours. |

Normal review, round 16: 4 findings — identical to the adversarial pass's #1–#4 (group flag, staging-after-mkdir
interference, one-generation ACL inheritance, cleanup of an unproved staging directory). Nothing else.
