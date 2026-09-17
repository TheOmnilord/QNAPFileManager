# M4 polish and release — Astra round 10 of 10, the final round (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 4dcedb9 (the round-9 fixes and the Windows flake fixes) and, as asked, the whole door as it
stands, against `docs/design/m4-contract.md`. Judged by Claude Fable 5.1.

Adversarial review (whole-door sign-off): 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the one-per-second rate limit on the fresh discovery at login is itself a window — an unknown peer arriving inside that second skips the read and is authorised from the cached **negative** (reproduce: advance `bgLocalFresh/2` in the round-9 test); a relay reconnects in far less than a second. §18.17 claims this closed. | door | **Accepted.** An unknown peer is never authorised from a cached negative: the login waits for the next allowed read (bounded by the remainder of the second, under the request deadline) or is refused as unverifiable; the locality decision moves after the queued verification. §18.17 restated. |

Normal review (sign-off): 5 findings, one of them #1 above.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 2 | P2: Go can report a numeric socket zone (`fe80::55%3`) while discovery stored the name (`%eth0`); the keys miss and the zoneless fallback misses, so a NAS-local peer is classed remote. | door | **Accepted.** Both sides normalise to the interface index; an unresolvable zone fails closed. |
| 3 | P2: §18.17 files the NAS-SNAT VPN operator under the shared-address replay residual; that operator is *refused* ("this machine") — an unavailable access path, not a replay risk. | Fable (contract) | **Accepted.** §18.17 distinguishes the two. |
| 4 | P3: the warm-cache rule (a failed fresh read refuses even with a good recent cache) has no test — removing the guard leaves the suite green. | door (test) | **Accepted.** |
| 5 | P3: §18.17 promised retries "each tick"; there is no background task — recovery is request-driven. | Fable (contract) | **Accepted.** §18.17 says so. |

**Final residual list Astra wants a reader of §18 to have** (all present or added this round): shared external
address and address-steering replay (§18.17); sibling cookie overwrite (§18.17); NAS-SNAT/VPN unavailability
(§18.17); the discovery cache and its request-driven recovery, immediate refusal on discovery failure and the
five-interval staleness (§18.17); unbounded enumeration under the set's mutex stalling logins without an error
line (§18.17 — the price of a fresh read at login); address/LRU lockout evasion bounded by bcrypt (§18.12);
trust-on-first-use and the standalone password (§18.2–3); root-owned output (§18.5); audit and mirror queue and
shutdown losses (§18.16, §18.19); certificate replacement needing a restart (§18.15); mismatch overflow keeping
its shape but losing per-source tracking when the table fills (§18.19); the M1–M3 residuals (§18.11).

**Hardware gates before v1.0.0**, both units (folded into the release checklist): clean tagged installation and
version; port 8771 free and QuFirewall; no-password and late-bind; direct TLS login with Apache stopped;
three-browser SAN/fingerprint check; root-owned creation through the door; lockout from an independent source;
credential rotation and disable evicting a live session; multi-interface IPv4/IPv6 relay and DHCP/VPN
transitions including numeric zones; discovery failure and recovery, and login latency under load; QuLog replay,
overflow and shutdown lines; the keyboard, NVDA and viewport pass — with the full CI and three-GOOS sweep green
on the tagged commit.

Unique findings this round: 5. Rejected: none.
