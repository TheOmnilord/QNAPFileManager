# M3 permissions and properties — Astra round 3 of 10 (2026-09-17, gpt-6-astra, effort high)

Reviewed: commit 2d9e422 (the round-2 fixes, staged in the detached worktree) against `docs/design/m3-contract.md`
and the round-2 table. Judged by Claude Fable 5.1.

Normal review: 6 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the representable-mask rule admits arbitrary **subsets** — `EVERYONE@ ALLOW WRITE_NAMED_ATTRS` alone passes (its bit is allowed and the data-write pair is absent), which no mode triple expresses; a `discard` chmod then destroys it without L2. | engine | **Accepted.** The rule becomes mode-**equivalence**: after removing the base bits ZFS always writes for that principal (`READ_ATTRIBUTES`, `READ_NAMED_ATTRS`, `READ_ACL`, `SYNCHRONIZE` for everybody; `WRITE_ATTRIBUTES`, `WRITE_NAMED_ATTRS`, `WRITE_ACL`, `WRITE_OWNER` for `OWNER@` only), what remains must be exactly one of the eight rwx combinations (`READ_DATA`, `WRITE_DATA|APPEND_DATA`, `EXECUTE`). Anything else — a base bit on the wrong principal included — is non-trivial. §6.1 restated. |
| 2 | P2: `cancelJob` counts any HTTP answer as an acknowledgement; a proxy 502 (an error without `network:true`) returns true and the runner marks a running job cancelled for good. Reproduced. | ui | **Accepted.** Only a 2xx, or a definitive job-not-found, acknowledges; anything else stays retryable. |
| 3 | P2: `stop()` clears `held` before `release`, and `abandon` drops the cache entry, so when the retry cancel also fails nothing retains the id. Reproduced with `cancel: async () => false`. Round-2 #9 still open for a connection that stays down. | ui | **Accepted.** Pending-cancel ownership survives Stop, close and Recount until acknowledged. |
| 4 | P2: the root-only bind-mount test selects a depth-1 root (`/share`), which `modeJob.run` refuses as protected before any crossing happens — on the runner it was written for, it fails. | engine (test) | **Accepted.** Depth-2 root. |
| 5 | P2: the platform tests call `Probe()` and `kickProbe()` directly; restoring the double probe in `Detect` or synchronous probing in `Refresh` leaves them passing. | routes (platform, test) | **Accepted.** The tests drive the real start-up and refresh paths through injected table/probe dependencies. |
| 6 | P2: `QFM_NFS4_TEST=1` alone still skips — `zfsFixture` skips first unless `QFM_ZFS_TEST=1`. | engine (test) | **Accepted.** The NFSv4 opt-in fails explicitly when its prerequisites are missing. |

Adversarial review: 4 findings, none overlapping.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 7 | P1: on Linux an empty observed state can now mean "the asynchronous probe was still pending", not "this platform cannot observe"; the identity-only proof then ignores an ACL the worker can see by the time chmod runs. | engine | **Accepted.** With an empty expectation the worker still re-probes, and a state that is now observable and not harmless (`none`, `nfs4-trivial`) is `changed` — the caller grades again. |
| 8 | P1: a worker holding an older mount table (the enclosing POSIX mount) probes a newly mounted dataset's inode for the POSIX attribute, `ENOTSUP` becomes `none`, and the rank rule accepts it over the daemon's empty backend — the unknown-storage L2 floor is gone and the worker's identical re-probe satisfies the expectation. | routes | **Accepted.** Worker facts lift the floor only when the worker's mount identification matches the daemon's row for the path; otherwise they are unverified and the floor stands. |
| 9 | P2: the Unopened fallback compares dev+ino only (no birth time; the enumeration descriptor is already closed), so an unreadable empty directory removed and recreated with a reused inode receives the change. | engine | **Accepted.** Birth time captured at enumeration (or the reference retained) and compared. |
| 10 | P2: probe publication compares row values, which an ABA remount reproduces (mount ids are reused; a remount keeps every compared field while `aclmode` changes) — a stale answer is published onto the new mount and cached. | routes (platform) | **Accepted.** Per-mount incarnation counter, captured at probe start and required at publication. |

Unique findings this round: 10. Rejected: none.
