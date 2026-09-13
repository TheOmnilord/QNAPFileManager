# M4 polish and release — review round 3 (2026-09-14, verification)

Round 2's fourteen findings were fixed (backend: `bgRefusal` — `Connection: close` and a 5 s read deadline on every
non-2xx of the break-glass listener, the login Origin check charged to the bucket; `ErrNoPassword` does not advance
the ladder; `set-password` generates the certificate and a running daemon binds the listener when a credential
appears; the anonymous `/api/session` on 8771 is two fields; `config.Lock`/`config.Update` with a bounded lock file
on both writers and the scratch file written at the final mode; `-dev` reaches every writer; the door timeout is
sized from a measured bcrypt and a queue timeout answers `429 rate_limited`; the credential-store guard covers the
directory; logout writes no cookie without the token; a full refusal table reports. UI: Shift kept in chords under a
modifier; the New-folder offer goes through the reason table with a `guard` cause. Docs: first run without a
restart, the lockout statement, the lock-file note, the `-dev` flag).

This round verifies those fixes and sweeps for regressions. Reviewer: Opus (gpt-6-astra paused). Linux CI on the
round-2-fixed tree (run 34781637154 at c14d9a3, PR #4): all five jobs green.


Verification pass: 13 of 14 round-2 fixes verified; the P1 survives on one route; five P3s; "no further qualifying
defects". Verdict: one defect from ready — do not build from this tree.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: `bgRefusal` keys on the response status, and `POST /api/breakglass/logout` without a cookie answers 204 without reading the body or checking CSRF — the unbounded drain again, unauthenticated and un-rate-limited (reproduced). | backend | **Accepted.** The wrapper keys on "body not consumed" for any status; logout consumes its bounded body; a 2xx-shaped case joins the real-socket test. |
| 2 | P3: `config.Lock`'s stale break (stat → remove → continue) can hand the lock to two writers. | backend | **Accepted.** Rename-based break; one winner. |
| 3 | P3: the late-bind path measures bcrypt at the startup snapshot's cost, undoing the door-timeout sizing on the path that needs it; `Ensure`/`MeasureCost` rerun every minute on a bind retry. | backend | **Accepted.** Cost from the hash; measured once per hash. |
| 4 | P3: charge-before-Origin ordering and its shared-source consequence were recorded only in the round-2 log. | orchestrator | **Accepted.** Contract §18 amended. |
| 5 | P3: stale comments describe the old unauthenticated session payload. | backend | **Accepted.** |
| 6 | P3: a listener bound during the shutdown drain can miss the drain. | backend | **Accepted.** |
| 7 | P3: CHANGELOG omits the config lock; the `disable` one-liner reads as immediate. | docs | **Accepted.** |
