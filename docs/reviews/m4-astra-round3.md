# M4 polish and release — Astra round 3 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 4607db5 (the round-2 fixes, staged in the detached worktree) against `docs/design/m4-contract.md`
and the round-2 table. Judged by Claude Fable 5.1.

Adversarial review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: with the daemon running past certificate expiry, `set-password` regenerates the pair on disk (`EnsureUsable`'s expired branch) while the listener keeps serving the old in-memory pair and the watcher has already stopped — the CLI prints a fingerprint the browser will not see and says no restart is needed. | door | **Accepted.** When `set-password` (or `cert`) generates a replacement, the CLI says a restart is required for the daemon to serve it, and the fingerprint is labelled as the *next* one. |
| 2 | P2: sessionless refusal summaries and overflow reports now go through `auditUnauthenticated`, which writes under the triggering request's cancellable context (the login-shaped path used `context.WithoutCancel`); a returning peer that disconnects while the writer slots are busy loses the summary, and the counters were already reset. | door | **Accepted.** Summaries are written detached from the request's cancellation, and the counters are reset only after the write is admitted. |

Normal review: 4 findings, one of them #1 above. New:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 3 | P2: the reverse symlink — final-component links in a root-owned 0700 directory under a writable share, pointing at a safe pair under `/root`: `treeStrict` follows the links and approves `/root`, but `writePrivate` publishes at the original paths, replacing the links, so regeneration lands where a later `Load` refuses. | door | **Accepted.** The directory that is checked is the one written to: a symlinked final component is refused for an explicit location, and publication uses the checked literal parents. |
| 4 | P2: `checkBcryptShape` accepts an impossible encoding — the last base64 character carries 23 bytes' worth of checksum, so its low two bits must be zero (`…A` passes, nothing can match it); the salt's 22nd character likewise. | door | **Accepted.** The unused bits of the salt and checksum tails are checked. |
| 5 | P2: `TestKeyOwnedByAnotherUidIsRefused` skips off root and the root job does not run `./internal/breakglass/...`, so the ownership half of round 2 #1 never executes in CI. | door (workflow) | **Accepted.** The package joins the root job. |

Unique findings this round: 5. Rejected: none.
