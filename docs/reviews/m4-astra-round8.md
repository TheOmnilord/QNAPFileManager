# M4 polish and release — Astra round 8 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 93e5f26 (the round-7 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-7 table. Judged by Claude Fable 5.1.

Normal review: 4 findings; rounds 7 #1–5 confirmed closed with meaningful assertions; "not converged" on #6.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the loopback refusal is bypassed by a relay to the NAS's **own LAN address** — `socat TCP-LISTEN:9443 TCP:192.168.1.10:8771` on the NAS makes the login peer 192.168.1.10, the session is pinned to it, and a sibling service replays from the same address. | door | **Accepted.** The rule is "the peer is this machine": any address assigned to the NAS's own interfaces (read at arm and refreshed with the credential watcher's tick), loopback included, is refused at login and treated as a mismatch afterwards. §18.17 corrected again. |
| 2 | P2: the loopback refusal returns before the body is consumed, so `bgRefusal` adds `Connection: close` where a LAN wrong-password keeps the connection — observably different despite the uniform body and floor. | door | **Accepted.** The bounded body is consumed under the existing deadline before the refusal; the test compares headers and connection reuse. |
| 3 | P3: the loopback-logout test sends no CSRF token, so the 403 it expects arrives without the guard; and its audit assertion is satisfied by the preceding `/api/session` line. | door (test) | **Accepted.** Valid CSRF captured before re-pinning; the logout's own audit line isolated. |
| 4 | P3: §18.19 justifies summary loss by a durable opening line the asynchronous path does not guarantee — with the queue full the opening line is refused too, and the whole source-specific trail can be absent. | Fable (contract) | **Accepted.** §18.19 restated; mirror overflow and shutdown-timeout losses recorded beside it. |

Adversarial review: 3 findings, one of them #1 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 5 | P2: under `serve -dev` the listener is forced onto loopback, so the unconditional local-peer refusal fails every real development login; `bgOverTheLAN` hides it in tests. | door | **Accepted.** Under `-dev` loopback peers are accepted (the listener is loopback-only there by force); production unchanged. |
| 6 | P2: every dropped mirror event writes a stderr line synchronously; the QPKG sends stderr to an unrotated `startup.log`, so bounded overflow becomes unbounded disk growth on the drain path. | door (audit) | **Accepted.** One notice per minute carrying the count, emitted by the mirror worker. |
| 7 | Judgement (from the residual list): peer-mismatch lines are Quiet, so a replay attempt against a live root session never reaches QuLog. | door | **Accepted.** Mismatch lines are mirrored — they are already throttled to one per source per window — while every other sessionless line stays Quiet. |

Residuals recorded (§18.17, §18.19): a sibling service on the host can overwrite or clear the `__Host-` cookie
and so sign the operator out; a mirror queue shared with login refusals under attack can drop a genuine
credential-change or lockout milestone.

Unique findings this round: 7. Rejected: none.
