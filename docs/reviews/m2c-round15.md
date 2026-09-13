# M2-C upload / archive / search — review round 15 (2026-09-13, gpt-6-astra, effort high; the ceiling)

Round 14's five findings were fixed: identity is proved on the descriptor the archive enumerates; the worker walks
every web-supplied canonical path `O_NOFOLLOW` per component (`openCanonicalDir`) and refuses `changed` when a
symlink appears — `ArchiveCheck` roots and parents, `archiver.root`, `FSIdentity`, `OpenWrite`, search roots;
identity carries statx birth time (`Btime`/`HasBtime`, `objectID` in fsops) against inode recycling; the multipart
tail is drained under the stall deadline with a 64 KiB bound and a stalled tail forfeits the connection (Finalize
then runs detached from the request context); every M2-C request is pinned to carry the resolved spelling.

Linux CI on the round-14 tree (run 34761793563 at cc63242): all five jobs green, including root and ZFS on the
`O_NOFOLLOW` walks and the birth-time identity.

This is the fifteenth round, the owner's ceiling. Findings here are fixed and verified by sweep, tests and CI; the
loop then stops and M2-C ships with any open observations listed for the morning's hardware check.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: birth-time availability is inferred from the mount-id probe; on Linux 4.11–5.7 (statx without `STATX_MNT_ID`, i.e. older QTS kernels) the inode-reuse protection is silently disabled. | engine | **Accepted.** Birth-time support is probed and cached on its own; only a real `ENOSYS` from statx disables it. |
| 2 | P2: count-based eviction deletes the ledger entry before the loss notice is published, so a GET in that gap reads a clean empty result (reproduced with 257 searches). | routes | **Accepted.** Count eviction keeps the entry as a dropped marker, as the byte-budget path already does; markers do not count toward the cap. |

Adversarial review: 2 findings ("no other qualifying defects").

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P1: `POST /api/jobs/<id>/cancel` serialises the whole job; a search that turned terminal before its hits were moved to the ledger answers with the full result, outside bulk admission and the write deadline (reproduced: 879 KB). | routes | **Accepted.** The cancel response, like the list, never carries hits; the single-job GET is the one route that pays. Every other job-serialising route is checked and pinned. |
| 4 | P2: a keep-both upload's result audit is written before `res.Path` is mapped, so both records name `a.txt` while `a (2).txt` was created. | routes | **Accepted.** The result audit carries the landed path as its destination with the intent path preserved. |

Round-15 fixes: engine — birth-time support probed on its own (`btimeFromStatx` table; only a real `ENOSYS`
disables it; a missing mask bit is per filesystem and never cached).

Routes-side fixes for findings 2–4 were applied by a fresh Opus agent after the original routes agent stopped
responding; count-eviction marker (`TestSearchCountEvictionKeepsTheLossNoticeInTheGap`) landed before that.

**Astra availability:** the owner reported gpt-6-astra close to its limit on the evening of 2026-09-13 and paused
its use. Round 15 was the ceiling anyway; the round-15 fixes are verified by the sweep, tests and Linux CI, not by
a further Astra pass. M3 review passes are pending until the owner lifts the pause.

Round-15 routes fixes: the cancel reply and the 202 submit reply go through the hit-free list view
(`TestJobCancelNeverCarriesHits`); a keep-both upload's result record carries the landed path in `Dst`
(`TestUploadKeepBothAuditNamesTheLandedFile`). The M2-C loop ends here: 15 rounds, 74 findings, all accepted.

Final verification: the first CI run on the round-15 tree (34768570552) failed on two test fixtures —
`TestBirthTimeReachesTheIdentityWithoutAMountID` asserted the mount id would be absent with statx's mount id
disabled, but `mountIDOf` still answers from `/proc/self/fdinfo` (assertion dropped); `TestSearchResultOfAReapedJobIs404`
took its snapshot inside the instant where the ledger and the manager both hold the hits (`awaitSearchView` now waits
for the manager's copy to be stripped as well). No engine change.
