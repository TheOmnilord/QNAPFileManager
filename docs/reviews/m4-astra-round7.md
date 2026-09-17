# M4 polish and release — Astra round 7 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 3c06c37 (the round-6 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-6 table. Judged by Claude Fable 5.1.

Normal review: 5 findings; verdict "not converged" on the audit accounting, with the peer pin and the durable-slot
isolation confirmed sound.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the asynchronous path is a new stall lever — `isMilestone` classifies every denial as a milestone whatever `ForceMilestone` says, and `Logger.drain` waits for the QuLog mirror synchronously; 256 sources × one denial a minute × a 10 s `log_tool` fills the 1024-event buffer and delays, then drops, real results. | door | **Accepted.** Sessionless refusal lines are not mirrored to QuLog at all (an explicit no-mirror marking `isMilestone` honours), and the mirror runs on its own bounded worker so a slow `log_tool` never stalls file draining. |
| 2 | P2: for an unsafe mutation, `resolve` counts the peer mismatch and `breakGlassAuth` then counts the same request again as sessionless — five replayed POSTs pend nine. | door | **Accepted.** The mismatch reports "already accounted" to the caller. |
| 3 | P2: `/api/breakglass/logout` with A's cookie from B answers 403 without recording `session_peer_mismatch`; the route bypasses `resolve`. | door | **Accepted.** The peer check runs before CSRF on that route and reports through the bounded path. |
| 4 | P2: a pruned summary is built from the *triggering* request, so A's summary carries B's structured `IP` and path — only the detail names A. | door | **Accepted.** The summary carries the pruned source's identity and no unrelated path. |
| 5 | P3: `ForceMilestone` is `json:"-"`, so asserting it on events read back from the file always sees false. | door (test) | **Accepted.** Asserted on the constructed event. |

Residuals Astra asked to have recorded (§18.17–18.19): a replay from the **same observed address** (NAT, a tunnel,
a proxy on the segment) is not caught by the pin; queued (asynchronous) lines can land after later durable ones,
so file order is not event order; a pruned summary whose queue write is refused is lost.

Adversarial review: 3 findings, two of them #1 and #4 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 6 | P1: the pin does not cover a NAS-**local** relay — an unprivileged process forwarding `nas:9443` → `127.0.0.1:8771`, or an SSH tunnel, makes the login arrive from loopback; the session is pinned to loopback, and a sibling service on the NAS replays the host-scoped cookie from loopback. Astra asks that the round-6 claim be qualified or an origin-isolated credential required. | door + Fable (contract) | **Accepted, narrowed.** The door refuses to issue a session to a loopback peer (the LAN door exists for a browser on another machine), so the relay and tunnel cases are refused rather than pinned to loopback; the shared-address case (NAT, a proxy on the segment) stays the recorded residual, and §18.17 says so instead of claiming the replay issue closed. |

Further residuals recorded (§18.12, §18.17): address steering and single-host IPv6-alias / LRU evasion of the
per-source lockout are bounded by the serialised bcrypt, not by the ladder.

Unique findings this round: 6. Rejected: none.
