# M3 permissions and properties — Astra round 7 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 5f38962 (the round-6 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-6 table. Judged by Claude Fable 5.1.

Normal review: 2 findings; verdict "not converged" on the token binding's crossing case and the client's handling
of a re-challenge; rounds 6 #1 and #2 confirmed closed with substantive coverage.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the token's `acl=` part carries the **deduplicated set** of modes, so for a crossing job with root `passthrough`, child A `discard`, child B `passthrough`, the descriptor `discard+passthrough` is unchanged when B flips to `discard` before redemption — the old token destroys B's ACL without the changed warning naming B. | routes | **Accepted.** The part is a digest of the per-dataset consequences (dataset → mode/discards, sorted), so any dataset changing its rung invalidates the token. |
| 2 | P2: when the verdict changes while the dialog is open (expiry, a background probe), the server correctly answers a second `confirm_required`, but `actions.js:runMutation` presents only the first challenge — the second throws into the error handler as "This change needs confirmation" instead of the current warning. Reproduced 409/L1 → 409/L2 → 200. | ui | **Accepted.** The client presents subsequent challenges in turn, each requiring acknowledgement, bounded to a few rounds before giving up with the last sentence. |

Residuals Astra asked to have recorded (§17.14–15): a benign refresh (an unknown that became known between
challenge and redemption) re-challenges the user — the conservative side; and claim ownership follows the session
the page **observed**: an unobserved same-user re-login keeps the previous claims, an observed sign-out drops them.

Adversarial review: 2 findings, one of them #1 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P2: `awaitJob` still uses `sessionGuard`, so a same-user refresh arriving during a size-job GET returns null; `abandon()` passes the owner check and cancels a measurement whose dialog is still open, and the dialog stays at "Measuring…". Reproduced. | ui | **Accepted.** Polling and completion use owner-scoped validity, consistently with the claims; search and transfers keep the strict guard. |

Further residuals Astra asked to have recorded (§17.16): a job already running is not re-graded when the ACL
facts change under it — the token bound its start; a size job whose 202 was lost, or whose tab was closed, is
reaped by the server's own job lifetime; and the pathname chown fallback where `/proc` is absent keeps its
check/use window (§2.3 as amended in round 2).

Unique findings this round: 3. Rejected: none.
