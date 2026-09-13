# M4 polish and release — review round 4 (2026-09-14, verification)

Round 3's seven findings were fixed (backend: the refusal wrapper keys on whether a declared request body was
consumed — `Connection: close` and a 5 s read deadline on any status while a body is unread, nothing when it was
consumed; logout reads its bounded body before answering and checks Origin before the no-cookie shortcut; the
stale-lock break is a rename only one caller can win; the door's bcrypt cost comes from the hash and a failing bind
does not re-arm every minute; a listener bound after shutdown began is closed, not served; comments match the
two-field anonymous payload. Docs: the config lock in the CHANGELOG; `disable` does not close the port until a
restart).

This round verifies those fixes, with the drain lever attacked once more across every route on 8771. Reviewer:
Opus (gpt-6-astra paused). Linux CI on the round-3-fixed tree (run 34782852000 at 7b259a9, PR #4): all five
jobs green, including the Linux-only `TestRefusalsDoNotParkConnections` with its 2xx-shaped case.

Verification pass: every round-3 fix verified; the P1 is closed at the right layer (traced through the Go 1.26.5
runtime: `closeAfterReply` skips the header-time drain, the 5 s deadline bounds the `finishRequest` drain; no
route on 8771 answers a declared body without consuming it or closing). Four P3s, no P1/P2; verdict: ready to
commit and build.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P3: `bgRefusal.Flush` bypasses the arming (unreachable today — both flush sites write first). | backend | **Accepted.** Symmetric with `Write`. |
| 2 | P3: `json.Decoder` never reaches EOF, so every successful mutation on 8771 answers with `Connection: close` (fail-safe, keep-alive lost). | backend | **Accepted.** The remainder is drained after decoding. |
| 3 | P3: the lock's stale-break branch continues without the deadline check — can spin where rename keeps failing. | backend | **Accepted.** |
| 4 | P3: logout is charged to no bucket. | backend | **Accepted.** Charged like login. |
| 5 | P3: contract §18 kept the superseded "every non-2xx" sentence beside its correction. | orchestrator | **Accepted.** Reworded. |

Round-4 nits landed (`Flush` commits the header through the check; `decodeBody` drains after decoding; the
stale-break branch honours the deadline; logout charged to the bucket). The M4 loop ends here: four Opus rounds,
45 findings, all accepted and fixed. Final Linux CI run recorded in PLAN.md.

Final-verification CI (34783669681 at 4d73bdd): root, ZFS and Windows green; the race job failed the lock
contention test — "round 11: 2 writers held the lock at once". The rename-based stale break is still racy because
the staleness verdict is not bound to the inode being renamed: a second breaker can move the first breaker's fresh
lock away. Settled by design rather than by another patch: on Linux the lock is `flock(2)` on the lock file (the
kernel releases it when a holder dies — no stale state, no break); the O_EXCL-plus-break implementation remains for
the Windows dev loop only. The round count stands; this is the fifth and final verification push (3cbf87a).

Sixth verification push (34784225695 at 3cbf87a): the lock is green under contention on Linux; the race job now
fails `TestConcurrentGenerationLeavesOneUsablePair` — two concurrent certificate generators publish `cert.pem` and
`key.pem` by separate renames, so a mixed pair can land ("private key does not match public key"). Settled: every
certificate writer takes the credential-store lock, and `Ensure` treats a torn pair as absent and regenerates, so a
crash between the two renames self-heals at the next start.
