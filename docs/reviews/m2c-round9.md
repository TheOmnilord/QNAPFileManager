# M2-C upload / archive / search — review round 9 (2026-09-13, gpt-6-astra, effort high)

Round 8's three findings were fixed. Adversarial review: 1 finding ("no additional findings met the
concrete-consequence threshold").

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a stalled multipart upload holds the 1 MiB buffer before any worker limit applies; 96 stalled requests retained 96.7 MiB with zero `OpenWrite` calls. | routes | **Accepted.** Bounded front-end upload slots (per session and global) acquired before any allocation, lazy buffers, and a progressive body-read deadline. |

Normal review, round 9: 2 findings.

| 2 | P1: a dialog answer returned after a session switch (OK closed the dialog, the async `close` fires under the next user) submits the previous user's action with the new user's credentials (reproduced); prompt/delete dialogs are outside the confirmation queue's ticket. | UI | **Accepted.** `oneDialog` validates the originating session before returning an accepted answer — every dialog at once. |
| 3 | P2: sign-out leaves `pendingReveal` and the search form intact; the next user's load selects the previous user's target and sees their query. | UI | **Accepted.** Sign-out/switch clears pending navigation and search state. |

Round-9 fixes landed for all three (routes — 4/32 upload slots acquired before any allocation, lazy buffer, idle
read deadline, and the `Unwrap` without which `SetReadDeadline` silently never reached the connection; UI — every
dialog answer validated against its opening session at the single lifecycle, sign-out clears reveal and search
state, and uploads back off on 429 with a cancel that cuts the wait short).
