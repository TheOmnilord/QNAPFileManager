# M2-C upload / archive / search — review round 2 (2026-09-13, gpt-6-astra, effort high)

Round 1's fourteen findings were fixed. Linux CI on the round-1 tree (run 34749471717): all five jobs green.

Normal review: 5 findings, all accepted.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: `revealEntry` compares lossy display names; two lookalike entries (invalid UTF-8 vs literal `�`) select the wrong file (reproduced). | UI | **Accepted.** Byte comparison via `pathBytes`. |
| 2 | P2: a protected (warn-class) upload confirms with one click; the contract requires L2. | UI + routes | **Accepted.** The route pins its notice sentences; the UI grades any other summary line as a guard reason → typed phrase, as transfer does. |
| 3 | P2: a slow search A finishing after a newer search B replaces B's results. | UI | **Accepted.** Only the latest submitted search owns the results view. |
| 4 | P2: `fsops.Archive` closes the write end before the worker records the outcome, so a prompt status request sees "not done" and the route audits `unknown`. | engine | **Accepted.** Record first, then close the write end. |
| 5 | P2: the route closes the reader (releasing the worker) before asking for the outcome; a retiring or evicted worker answers `worker_gone` → `unknown`. | routes (orchestrator) | **Accepted, fixed:** Outcome before Close on the clean path. |

Adversarial review, round 2: 6 findings (#5 = the normal pass's #4).

| 6 | P1: the member cap does not bound ZIP metadata — 199 000 members with ~3.8 KiB names retain ~1.6 GiB across two producers. | engine | **Accepted.** Cumulative metadata byte budget. |
| 7 | P1: an explicit root inside a hung hard NFS mount blocks `resolve`/`statAt` before the mount-table refusal runs; repeated requests exhaust the worker's slots. | engine | **Accepted** for the worker's root validation (table refusal by requested spelling before any lookup). The route's own resolve of such a path is the pre-existing hang shared with browsing a dead NFS mount — **residual**, recorded. |
| 8 | P2: a `queue_full` refusal on Finalize releases the pin without consuming the handle; the route's Discard then finds worker_gone. | pool | **Accepted.** The pin is consumed only when the worker's reply shows the handle was consumed. |
| 9 | P2: refusals made in `serve` before authentication (401, method) are not wrapped; an unauthenticated upload waits for its whole body and gets no `Connection: close`. | routes | **Accepted.** The refusal writer installed before authentication for the upload path. |
| 10 | P2: `pendingReveal` survives a navigation elsewhere and selects a same-named entry in the wrong folder. | UI | **Accepted.** Bound to its destination and navigation generation. |

Round-2 fixes landed for all ten (engine/pool four, routes two — the pre-authentication `Connection: close` proved
with a raw-TCP client, since `http.Client` strips hop-by-hop headers — UI four, orchestrator one). The routes
implementer's scratch files (`*.debug`, `*.bak`, `*.patch`) and an unformatted test were removed/formatted by the
orchestrator before round 3.
