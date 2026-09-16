# M4 polish and release — Astra round 2 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit bd2f356 (the round-1 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-1 table. Judged by Claude Fable 5.1.

Normal review: 6 findings. Adversarial review: 4 findings, 3 of them the same defects. Unique findings: 7.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2 (both): the strict-modes check (round 1 #9) looks only at the **lexical parent** of the explicit paths: root-owned symlinks in a root-owned 0700 directory pointing into a user-writable share pass, and `Ensure` follows them; a key that is itself world-readable or another uid's passes too. | door | **Accepted.** The check binds to what is loaded: `fstat` on the opened key (uid 0, no group/other bits), the resolved path's ancestor chain, `O_NOFOLLOW` on the final component. §18.13 amended. |
| 2 | P2 (adv): a strict-modes refusal in `armBreakGlass` returns success, so `watchForCredential` records the hash as armed and never retries; fixing the directory recovers nothing without a restart. | door | **Accepted.** A refused arm is an error the watcher retries every tick; the reason is logged once per distinct reason. |
| 3 | P2 (both): the late-bind path calls `Ensure`, which renews inside the 30-day window — right after `set-password` used `EnsureUsable` and printed the old fingerprint to compare. | door | **Accepted, as policy.** The daemon never renews silently: start-up and late-bind serve a valid pair and log an audited warning inside the window (*run `cert -regenerate`*); only an expired or torn pair is regenerated. §3 superseded by §18.15. |
| 4 | P2 (both): `bcrypt.Cost` validates the header only; `"$2a$10$" + 53×"!"` passes and arms a door nobody can pass. | door | **Accepted.** Structural check: 60 bytes, `$2a$`/`$2b$`/`$2y$`, cost in range, 53 base64 characters. |
| 5 | P2: with a rejected hash on disk, `break-glass disable` and `set-password` fail on the same validation before they can replace it — the recovery commands are locked out by the check meant to protect them. | door | **Accepted.** The credential-replacement commands load leniently and validate the *result*; the daemon stays strict. |
| 6 | P2: the full-table branch of `noteRefusalEvent` and `flushRefusals` bypass the sessionless callback, so a spray of 257 sources produces login-shaped events (`Actor=break-glass, Admin, Root`) for sessionless mutation denials. | door | **Accepted.** The aggregate paths keep the unauthenticated shape; the test covers overflow and flushing. |
| 7 | P2: the two unfinished-drain tests use a body that returns `os.ErrDeadlineExceeded` on its own and `httptest.ResponseRecorder`, which has no read deadline — they pass against the pre-fix code. | door | **Accepted.** A socket-level test sends a valid JSON prefix, withholds the declared remainder and asserts a bounded close. |

Rejected: none. Round-2 fixes go to the door agent; contract §18.13/§18.15 amended by Fable.
