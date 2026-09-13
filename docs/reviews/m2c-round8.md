# M2-C upload / archive / search — review round 8 (2026-09-13, gpt-6-astra, effort high)

Round 7's five findings were fixed. Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a queued confirmation survives a session switch; the next user can approve the previous user's operation, reposted with the new CSRF token (reproduced). | UI | **Accepted.** Queued confirmations bound to their session; a switch flushes the queue. |
| 2 | P2: `Finalize` publishes after a cancellation that arrives during fsync/metadata work; under overwrite the existing file is replaced after the UI reported cancellation (reproduced). | engine | **Accepted.** Cancellation re-checked immediately before publication; the inode is discarded. |

Adversarial review, round 8: 2 findings (#1 = the normal pass's #1, reproduced as a cross-session resend).

| 3 | P2: the upload `name` escapes the component cap; a 300-byte name streams the whole body before Finalize's lstat fails. | routes | **Accepted.** `validNewName` on the upload name before the body is touched. |

Round-8 fixes landed for all three (UI — session-ticketed confirmation queue, verified live with the cross-user
scenario; engine — cancellation re-checked before publication; routes — `validNewName` on the upload name before
the body, with a plain-language message since the UI shows `message` only).
