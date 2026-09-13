# M2-C upload / archive / search — review round 11 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 10's three findings were fixed. Linux CI on the round-10 tree (run 34756739058): all five jobs green.

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the hits handoff (`ReplaceResult` before the ledger insert) races a single-job GET; a finished search can read as empty with no note (reproduced). | routes | **Accepted.** Ledger insert first, then `ReplaceResult`; the read merges under the ledger lock with one re-read. |

Adversarial review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 2 | P1: repeated single-job GETs of one large search result, each left unread, hold one full JSON buffer per blocked response (32 blocked writers ≈ 108 MiB for a 3.37 MiB result); no admission limit, and no write deadline can interrupt a blocked write. | routes | **Accepted.** Bulk-result responses take a per-session admission slot (429 when none free) and set a write deadline through `http.ResponseController` for the duration of the write. |
| 3 | P2: a search evicted by newer searches between its ledger insert and its `ReplaceResult` has its eviction notice overwritten by the original summary; the hits are gone but the job reads as a clean search with zero hits. | routes | **Accepted.** The handoff preserves eviction state: `ReplaceResult` is skipped (or the notice re-applied) when the ledger has already dropped the job. |
