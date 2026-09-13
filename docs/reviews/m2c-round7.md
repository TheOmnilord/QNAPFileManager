# M2-C upload / archive / search — review round 7 (2026-09-13, gpt-6-astra, effort high)

Round 6's five findings were fixed. Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the confirmation queue advances on promise resolution, before the dialog's async `close` fires; the late close cancels the next confirmation and leaves an unresponsive modal. | UI | **Accepted.** The queue advances from the completed close handling. |
| 2 | P2: a cancelled upload's async rejection reaches `finishJob` after teardown and re-inserts the removed local job — visible to the next user in the same tab. | UI | **Accepted.** Teardown invalidates every later continuation; `finishJob` on a removed id is a no-op. |

Adversarial review, round 7: 4 findings (#2 = the normal pass's #1).

| 3 | P1: the search query is unbounded and survives in `Job.Title` and the audit detail outside the retained-hit budget (36 MB of titles from 40 searches). | routes | **Accepted.** Query capped at 1 KiB; title and audit detail display-truncated. |
| 4 | P2: the real same-user refresh path (`showSession` → `signInNotice()` → transient `session:null`) aborts uploads before any predicate runs. | UI | **Accepted.** A same-user refresh installs the new session directly; no transient null. |
| 5 | P2: collision-generated member names exceed 255 bytes and fail extraction with ENAMETOOLONG. | engine | **Accepted.** The suffix fits inside the component limit; uniqueness re-checked after shortening; the same bound on upload keep-both. |

Round-7 fixes landed for all five (UI three — dialogs advance the queue only from their own close event, batch
ownership for local upload jobs, no transient null on a same-user refresh; routes one — query capped at 1 KiB with
clipped title and audit, plus a sweep that found and closed the same shape in `jobSize` by capping every path
component at NAME_MAX in `bodyPath` and invented names in mkdir/rename; engine one — one bounded name allocator
behind archive members, upload keep-both and copy keep-both).
