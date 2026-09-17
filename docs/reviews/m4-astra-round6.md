# M4 polish and release — Astra round 6 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 0975cda (the round-5 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-5 table. Judged by Claude Fable 5.1.

Normal review: **0 findings.** All three round-5 issues confirmed closed (joined goroutines, direct detached-context
assertion, real-file append-vs-fsync distinction); "no new Close/flush regression, false durability
acknowledgment, non-door context propagation, or unsound contract amendment was found; I consider the break-glass
door and non-admin UX converged at code-review level."

Residuals Astra asked to have recorded (now in contract §18.16):

1. An ambiguous audit outcome (a line appended, its fsync failed) is classified in flight, so a refusal summary can
   be **lost** rather than duplicated — the chosen side of the trade.
2. A replaced certificate needs the restart the CLI now names; trust remains first-use with a fingerprint.
3. The hardware, browser, NVDA, keyboard and narrow-layout passes are manual and remain on the release checklist.

Adversarial review: **0 findings in the diff**; four whole-door residuals named as the condition for calling the
door converged:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: cookies are host-scoped, not port-scoped — `__Host-` included — so after a break-glass login, visiting any browser-trusted HTTPS service on the NAS hostname at another port (QTS on 443, another QPKG) sends that service the root-session cookie, which it can replay against 8771 (and `/api/session` hands the CSRF token to any cookie holder). | door | **Accepted.** A break-glass session is pinned to the peer address that logged in; a request from another address is unauthenticated and audited. On a LAN door the peer is honest, and a service on the NAS replaying arrives from the NAS's own address. §18.17. |
| 2 | P2: a slow QuLog call holds a durable-writer slot; four sessionless summaries from four sources can hold all four and time out an operator's real mutation despite a healthy disk. | door | **Accepted.** Sessionless denial lines and their summaries are written through the asynchronous path and are not forced milestones — a forged mutation is not a use of the door (§6.2), and the per-source line still records it. |
| 3 | P2: an admitted summary that times out and then fails its append loses its counters for good; "in flight" must not be described as guaranteed eventual recording. | door (docs) | **Accepted as recorded.** §18.16 already chooses loss over duplication; the `WriteSyncInFlight` comment is corrected to say so. |
| 4 | P3: a source's suppressed count is discarded after two minutes when another source's refusal prunes the window, so the aggregate accounting is not complete. | door | **Accepted.** A pruned window with a pending count emits its summary through the asynchronous path before it is dropped. |

Unique findings this round: 4 (all pre-existing residuals, none introduced by the patch).
