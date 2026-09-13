# M3 permissions + properties — review round 2 (2026-09-13)

Round 1's six findings were fixed (routes: properties resolves and dispatches the resolved spelling with the read
guard on both spellings; `follow:true` dispatches the guarded, token-bound target and the wire `Follow` is inert;
the listing sets `ACLProbe`. UI: the `/api/ids` cache is keyed on the session generation and dropped on session
change; `UNCHANGED` removed. Engine: `chownHeld`'s fallback is a ladder — `chown("/proc/self/fd/N")` on the held
descriptor, then `fchown` on a reopened-and-proved descriptor, then the named call only without `/proc`, recorded
as the residual).

Reviewer: Opus adversarial pass (gpt-6-astra paused). Linux CI on the round-1-fixed tree (run 34771752227 at
b647f2d, PR #3): all five jobs green, root and ZFS included.

Opus adversarial pass: 7 findings, no P1 ("no other qualifying defects"; explicitly checked clean: the six round-1
fixes, the recursive engine's post-order/cancel/loop/rename behaviour, `.zfs`/`@Recycle` below the root, the
ladder over mixed selections, tokens, properties on special files and the jail root, `/api/ids` narrowing, audit
pairing on every early return, `WorkerCodes` mapping, test race discipline).

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: a recursive job whose selected root is a mount point is refused unconditionally — on QuTS hero that is every share; the pre-scan still counts the tree, so the user sees "changed 0 of 48102" and an L2 for nothing. The refusal is delete's, not a chmod's. | engine | **Accepted.** No root mount-point refusal for chmod/chown; child mounts stay governed by `CrossMounts`. |
| 2 | P2: a recursive job rooted on a QTS share symlink is dispatched as the link (`followLeaf:false`); chmod skips it, chown lchowns the link and reports "re-owned 1 of 1" for a tree it never touched. | routes + engine | **Accepted.** Recursive roots resolve to their targets (guarded as their own paths, token bound to the targets); in the engine a symlink root of a recursive job is skipped `unsupported` for both verbs. |
| 3 | P2: a recursive chmod applies to whatever inode an entry names; a planted hardlink to the app's path-protected config or audit log on the same data volume gets an admin's recursive 0777. Not in §17. | engine | **Accepted.** When the worker is root, a recursive job skips non-directory entries with `nlink > 1` with a warning (name it directly to change it); non-root workers are left to the kernel. The rsync `--link-dest` tradeoff goes into §17. |
| 4 | P3: `properties?follow=1` returns the target's full entry without guarding the target's spelling. | routes | **Accepted.** The target is resolved and guarded like the `follow:true` chmod; refused as a direct read would be. |
| 5 | P3: `permScanTimeout` (30 s) is unreachable under the 15 s handler context, and the pre-scan runs twice (issue and redemption). | routes | **Accepted.** Scan bounded by the request context; the measured count travels in the confirmation's summary and is reused on redemption. §13 amended. |
| 6 | P3: `DiffOf` emits a `mode` diff beside the `setuid` diff for a chown that asked for no mode, producing a wrong second sentence. | engine | **Accepted.** No `mode` field when `want.Mask == 0`. |
| 7 | P3: `reopenProved` maps every openat failure to `unsupported`, EACCES/EPERM included (INV-2). | engine | **Accepted.** Kernel refusals pass through unchanged. |
