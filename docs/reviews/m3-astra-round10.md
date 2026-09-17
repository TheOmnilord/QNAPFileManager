# M3 permissions and properties — Astra round 10 of 10, the final round (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit d04b9fd (the round-9 contract corrections) and, as asked, the whole of M3 as it stands, against
`docs/design/m3-contract.md`. Judged by Claude Fable 5.1.

Normal review (sign-off): **no additional code defect** from the whole-milestone sweep; one wording correction.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: §17.16 and the round-9 record equate the unchecked pre-mutation interval with the cache TTL ("the same minute"); the TTL bounds freshness at lookup, the pre-scan adds its own length — cumulative windows, e.g. `passthrough` at t=0, `discard` at t=1, admitted at t=59, a 30 s pre-scan mutates at t=89. | Fable (contract) | **Accepted.** §17.16 restated with that example; the round-9 record corrected. No code change — recording the accepted risk. |

**Final residual list Astra wants a reader of §17 to have** (all present): P2 — the resolve/dispatch and
pathname-probe races (§17.1–2); cached facts plus the unchecked pre-mutation and running-walk intervals (§17.3,
§17.16); the heuristic NFSv4 classification (§17.4); irreversible partial changes and kernel-cleared bits
(§17.5–6); hardlink exclusions and recursive-root semantics (§17.11, §17.13); unbounded orphan measurements
holding metadata slots (§17.17). P3 — dataset naming (§17.7), the local-only identity roster (§17.8),
dataset-relative free space (§17.9), link-target spelling (§17.12), conservative re-challenges (§17.14),
observed-session ownership (§17.15).

**Hardware gates before v1.0.0**, on both units with disposable fixtures (folded into the release checklist):
P1 — real owner/non-owner/admin workers; member/non-member chgrp; dropped setgid and chown-cleared special bits;
symlink semantics; share-alias resolution; protected-path and read-only enforcement; the POSIX mask warning;
hero's actual trivial/non-trivial ACL bytes and their non-root readability; every `aclmode` value and the
unknown-mode fallback; a queued job whose facts change; crossing datasets. P2 — post-order repair of unreadable
directories; hardlink skips; partial cancellation counts; warning and audit output; chown-before-chmod ordering
in the UI; a lost 202, a disconnect and a closed tab during a size walk; session refresh and switch; domain
numeric ids; quota-relative free space. Hero NFSv4 coverage is a hardware requirement, not an upstream-OpenZFS
skip.

Adversarial review (whole-milestone sign-off): 2 findings, both code, both engine.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 2 | P2: the post-order directory identity is recorded from an ordinary `Stat()` with no birth time even on a birth-time-capable filesystem, and the walker closes the traversed directory before `Post` — an empty directory removed and recreated until its inode is reused passes `sameAsTraversed`. Defeats §17.13's substitution refusal where the filesystem could have prevented it. | engine | **Accepted.** The birth time is captured from the enumerated descriptor while it is open; the no-birth-time case stays the recorded residual. |
| 3 | P2: the leaf crossing check never applies the directory walker's fail-closed rule — on Linux with neither `STATX_MNT_ID` nor `/proc/self/fdinfo`, equal devices and no mount ids read as "same mount", and a same-filesystem file bind-mounted from outside is changed under `crossMounts:false`. | engine | **Accepted.** An unidentifiable leaf mount is skipped with the walker's unidentified-mount warning, as directories are. |

Astra's hardware list for M3 before v1.0.0, in addition to the above: mount-id fallbacks on the real kernels,
actual ACL bytes and their non-root readability, `aclmode`/dataset reporting, share-symlink operations.

Unique findings this round: 3. Rejected: none.
