# M2-C upload / archive / search — review round 5 (2026-09-13, gpt-6-astra, effort high)

Round 4's three findings were fixed (filter cleared before a reveal; hits off the polled list; the archive selection
ticket). Linux CI on the round-4 tree (run 34751818092): all five jobs green.

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: revealing a `.hidden` hit with the listing's hidden toggle off cannot select it. | UI | **Accepted.** The toggle is enabled and the listing reloaded before the reveal. |
| 2 | P2: an edited search root recovers the original folder's byte reference through display-string equality (lookalike names). | UI | **Accepted.** An edited field is authoritative; the reference is used only while untouched. |

Adversarial review, round 5: 3 findings (#3 = the normal pass's #1).

| 3 | P1: consuming a selection ticket trusts the spellings guarded at select time; a parent swapped to a symlink into the install tree between select and consume archives protected contents. | routes | **Accepted.** The GET with `sel=` runs the identical resolve + guard + containment pipeline as the direct form, factored into one function; the store keeps requested spellings only. |
| 4 | P2: expired selections are reclaimed only by traffic in the same session; 16 abandoned tickets with 1 MiB names retain ~16 MiB per session for hours. | routes | **Accepted.** Name and per-ticket byte caps, a store-wide reap on every operation and from the janitor, a global retained-byte budget. |

Round-5 fixes landed (UI two; routes two by a fresh bounded agent — `authorizeArchive` shared by all three entry
points; the periodic reap wired into main's ticker by the orchestrator; the contract amended, §7).
