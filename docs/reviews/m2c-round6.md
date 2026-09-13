# M2-C upload / archive / search — review round 6 (2026-09-13, gpt-6-astra, effort high)

Round 5's four findings were fixed. Normal review: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a background upload's `confirm_required` reuses an already-open `#dlgConfirm` (e.g. Empty Trash); the original handler stays attached and one click approves both. | UI | **Accepted.** Confirmations serialised through one queue; the upload queue pauses while a confirm is pending. |
| 2 | P2: a settings change bumps the session generation mid-upload; the completion is dropped and the local entry stays "running". | UI | **Accepted.** "Session ended" distinguished from "session refreshed". |
| 3 | P2: a generated archive name for a 255-byte base exceeds the 255-byte cap → 413. | UI | **Accepted.** The base is bounded on a UTF-8 boundary. |

Adversarial review, round 6: 3 findings (#3 = the normal pass's #3).

| 4 | P1: retained search results are unbounded across completed jobs — 64 large searches retain >1 GiB in the root daemon for the 60-minute retention window. | routes | **Accepted.** An aggregate retained-hit budget; the oldest results are dropped with an honest note. |
| 5 | P2: 1000 hits with very long paths serialise beyond the 64 MiB frame; the worker's reply path treats it as fatal and disconnects. | engine | **Accepted.** Encoded-byte budget while accumulating; an oversized reply degrades to a job error, not a disconnect. |

Round-6 fixes landed for all five (UI three — the confirmation queue verified live against the Empty Trash
scenario; engine one — `fsx.ErrTooLarge`/`too_large` mapped across the pool boundary; routes one —
`jobs.Manager.ReplaceResult` plus a process-wide retained-search budget of 32 MiB / 256 jobs, oldest first, with an
honest note). Design notes to carry into the docs: the retained-search budget and `ReplaceResult` (recorded here);
the archive selection reap is wired into the daemon's minute ticker.
