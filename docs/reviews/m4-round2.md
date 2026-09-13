# M4 polish and release — review round 2 (2026-09-14)

Round 1's nineteen findings were fixed (backend: the break-glass listener serves at `/` with a per-listener base;
`listener:"local"` on that listener's `/api/session`; the login route takes JSON `{password}` under a strict Origin
check and no CSRF token, reads its bounded body under a 10 s deadline before admission, with a 15 s door-route
context; the read-only toggle is a read-modify-write of `readOnly` only, under a lock; refusals audited once per
source per window; the certificate is a leaf; only a wrong password advances the lockout ladder; no forwarded
headers on 8771; one shared stdin reader; plain `cert` is read-only; atomic publish; an in-process root seam for
the CLI tests. UI: the sign-in form; the dialog's own reason in `applyWhy`; ⋯ items mirror `aria-describedby`; the
Session dialog names the emergency door; Trash names its volume. Docs: two doors only, viewer not editor,
desktop drop shipped. Orchestrator: workflow header repaired, `go.mod`/`go.sum` pinned LF, contract §2 amended).

Deviation accepted: no server-wide `ReadTimeout` on the break-glass listener (uploads go through that door; the
slow-body hole is closed by the pre-admission bounded read under its own deadline, the door-route context and the
per-IP bucket, proved over real sockets by `TestSlowLoginBodiesDoNotHoldAdmissionSlots`).

Reviewer: Opus adversarial pass (gpt-6-astra paused). Linux CI on the round-1-fixed tree (run 34779859675 at
e054e36, PR #4): all five jobs green — the first fully green M4 run, node tests and the CLI seam included.

Opus adversarial pass: 14 findings, one P1 ("no other qualifying defects"; explicitly re-attacked and clean: the
Origin-only login protection on every host shape, the per-listener base with no absolute URL anywhere, the
read-modify-write under `cfgMu`, the pre-admission read ordering, the throttle's prune and carry arithmetic, the
ladder transitions, the CLI seam, the workflow's tag guard and permissions, the sign-in form's handling, docs vs
code, shared-state discipline). Verdict: convergent — one more focused round on the P1 and the two P2s.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: an unauthenticated LAN host can park 8771 connections forever — a POST declaring ≤ 256 KiB and sending nothing makes net/http drain with no deadline because the break-glass branch returns above the `uploadRefusal` wrapper and the listener has no `ReadTimeout`; the process fd table is shared with the main listener and the worker pipes. | backend | **Accepted.** Every non-2xx on that listener carries `Connection: close` under a short read deadline; the login Origin check is charged to the bucket. |
| 2 | P2: the documented first run dead-ends — `set-password` neither binds the listener nor creates the certificate, so `status` has no fingerprint and 8771 is refused until a restart the doc never mentions. | backend + docs | **Accepted.** `set-password` generates the certificate; the daemon binds when a credential appears; docs aligned. |
| 3 | P2: `ErrNoPassword` advances the lockout ladder, so after `disable` on a running daemon any peer can lock the door before the operator's new password lands. | backend | **Accepted.** Not a credential verdict; does not advance. |
| 4 | P3: `Ctrl+Shift+C/X/V` fire the clipboard bindings (`chordOf` drops Shift for printable keys). | UI | **Accepted.** |
| 5 | P3: unauthenticated `/api/session` on 8771 discloses version, family and read-only state. | backend | **Accepted.** Only `authenticated` and `listener` before a session. |
| 6 | P3: docs claim "locked out" is indistinguishable; by design it is announced (§5.1/§18.7). | docs | **Accepted.** Stated plainly; contract §5 amended. |
| 7 | P3: cross-process read-modify-write on `config.json` is unlocked and undocumented; the temp file is published 0644 before the 0600 chmod. | backend + docs | **Accepted.** Lock file with a bounded wait on both sides; temp written at the final mode; residual recorded. |
| 8 | P3: the settings route and the CLI validate strictly while the daemon may run relaxed under `-dev`. | backend | **Accepted.** The daemon's dev flag reaches the route; the CLI gains `-dev`. |
| 9 | P3: the 15 s door context is shorter than a queued bcrypt at the cost ceiling — a correct password answered "not accepted". | backend | **Accepted.** Queue timeout answers `429 rate_limited`; the door context is sized from the configured cost. |
| 10 | P3: the credential-store guard checks the file, not the directory the key is written into. | backend | **Accepted.** |
| 11 | P3: `TestVerifyHonoursTheContext` synchronises with a sleep. | backend | **Accepted.** |
| 12 | P3: `logout` clears the cookie before the CSRF check. | backend | **Accepted.** |
| 13 | P3: the refusal throttle drops new sources silently when its table is full. | backend | **Accepted.** A rate-bounded "table full" line. |
| 14 | P3: the empty-folder "New folder" offer ignores the guard classification. | UI | **Accepted.** |
