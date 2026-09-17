# M4 polish and release — Astra round 9 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 9992d19 (the round-8 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-8 table. Judged by Claude Fable 5.1.

Normal review: 3 findings; rounds 8 #2, #3, #5, #7 confirmed closed with meaningful assertions, #4's contract
correction confirmed sound; no production dev-flag bypass and no `Close` ticker leak found.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: address discovery fails **open** — a failed initial lookup leaves the set nil and every non-loopback peer is accepted; failed refreshes keep a stale set indefinitely, so a NAS address assigned after the last success is accepted. Reproduced through the seam. | door | **Accepted.** The set carries the time of its last *successful* discovery; with no success ever, or none within five TTLs, the door treats every peer as unverifiable and refuses (fail closed, logged once per reason, retried every tick). |
| 2 | P2: a NAS address that appears inside the cached minute is accepted for login and resolution until the refresh — a pre-running relay reconnects the moment a DHCP or VPN address appears; the contract claims all NAS-local peers are refused. | Fable (contract) | **Accepted.** §18.17 records the one-minute window as the price of not calling `InterfaceAddrs` per request. |
| 3 | P3: the mirror rate-limit test releases the worker only after advancing the clock a full minute, so deleting the interval guard still passes. | door (test) | **Accepted.** A worker iteration with more drops inside the minute, asserting no second notice; then the count after the minute. |

Astra's statement of round 10: close the fail-open discovery, strengthen the throttle test, document the TTL
window; retain shared-address replay, VPN/SNAT restrictions, cookie eviction and audit/mirror losses as §18
residuals.

Adversarial review: 4 findings, one of them #1 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 4 | P1: the one-minute TTL is itself a relay window — an address the NAS acquires after a refresh is remote for up to a minute, and a pre-running relay carries the operator's login; "automation needs seconds, not a minute". | door | **Accepted.** Locality is established at issue: a login from a peer not in the cached set triggers a fresh discovery (rate-limited to one per second) before a session is issued; resolve keeps the cached set. §18.17's "that minute" is withdrawn. |
| 5 | P2: `bgCanonicalIP` strips the IPv6 zone, so an operator at `fe80::55%eth0` is matched against the NAS's own `fe80::55` on eth1 and refused indefinitely. | door | **Accepted.** Link-local addresses keep their zone on both sides; global addresses compare zoneless. |
| 6 | P2: the mirrored replay mismatch (round 8 #7) only surfaces when the mismatch *opens* the source's window; a generic refusal first, then the replay inside the minute, is swallowed into the generic counter and summarised as a Quiet `unauthorized`. | door | **Accepted.** Mismatches have their own bounded accounting — separate window, line and summary in the mirrored shape. |

Residuals retained on Astra's list (all already in §18): shared-address and address-steering replay, sibling
cookie overwrite, IPv6-alias/LRU lockout evasion bounded by bcrypt, bounded-queue and shutdown audit losses.

Unique findings this round: 6. Rejected: none.
