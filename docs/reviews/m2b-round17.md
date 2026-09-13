# M2-B copy/move — review round 17 (2026-09-13, gpt-6-astra, effort high; verification pass)

Round 16's four findings were fixed (group flag honoured; interference after a successful staging mkdir refuses;
no staging under one-generation ACEs; unproved staging directories abandoned) and the two fixtures repaired.

Adversarial review, round 17: 1 finding (the four round-16 fixes confirmed present).

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the staging directory's INHERITABLE ACL (POSIX default ACL; NFSv4 FILE/DIRECTORY_INHERIT ACEs) is not compared to the destination's; a swapped-in directory with a planted inheritable read entry passes and everything staged inherits it, surviving the rename. | engine | **Accepted.** Subset check against the parent: POSIX default ACL byte-equal; every inheritable NFSv4 ACE on the staging directory present on the parent with the same principal, type, mask and inherit flags. |

Normal review, round 17: 1 finding.

| 2 | P2: `/api/jobs/copy` and `/api/jobs/move` were missing from `isMutationRoute`, so a sessionless request to them was refused without the denial audit line every other mutation route leaves. | routes | **Accepted, fixed by the orchestrator** (`TestUnauthenticatedTransferIsAudited`). |
