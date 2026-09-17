# M3 permissions and properties — Astra round 9 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 1f03959 (the round-8 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-8 table. Judged by Claude Fable 5.1.

Normal review: **0 findings.** "M3 is review-converged for this diff: round-8 #1–4 are addressed, #5 accurately
records the unbounded orphan walk, and #6 remains an accepted residual." In-memory reversions of the round-8
fixes make their regression tests fail; the queued-job tests have substantive dispatch and audit assertions.
Astra's own statement of what remains: round 10 needs CI root/ZFS **verification**, not another code fix; §17
should keep the cached-fact and refresh-to-dispatch races (§17.1, §17.3, §17.16), the running-walk case (§17.16),
the pathname replacement and fallback races (§17.2, §17.13) and the orphan walk (§17.17) — all already recorded.
Confirmed on the way: the dispatch re-grade adds no synchronous per-dispatch ACL probe, chown stays
ACL-independent, and read-only enforcement remains server-side.

Adversarial review: 1 finding, contract wording.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: §7/§17.16's "the token binds the start of the walk" exceeds what the dispatch re-grade proves — it compares **cached** facts (an `aclmode` changed inside the 60 s TTL passes), it runs at callback admission while the job's own pre-scan lies between it and the first mutation, and the sync chmod's `Expect` proves identity and state, not `aclmode`. | Fable (contract) | **Accepted.** §7 and §17.16 restated to say exactly what the re-grade covers and the three windows it does not; no code change — the windows are §17.3's minute, already accepted. |

Astra's statement of round 10: settle and test consequence validation before the first mutation, or record it.
Judgement: recorded — closing the pre-scan window would mean the worker re-grading `aclmode` itself, which is the
daemon's table and INV-1's boundary; the window is the same minute §17.3 accepts, and round 10 is verification.

Unique findings this round: 1. Rejected: none.
