# M3 permissions + properties — review round 3 (2026-09-13)

Round 2's seven findings were fixed (engine: no root mount-point refusal for chmod/chown; a symlink root of a
recursive job is refused `unsupported` for both verbs; a root worker's recursive job skips hard-linked
non-directories it reached by recursion; `DiffOf` emits no `mode` field for a chown; `reopenProved` passes the
kernel's verdict through. Routes: recursive roots resolve to their targets, guarded as their own paths and bound
into the token; `properties?follow=1` guards the target; the pre-scan is bounded by the request budget and its
measured count is kept against the token in a bounded `issued` ledger read by the new `guard.Peek`, so the tree is
scanned once per confirmed job).

Reviewer: Opus adversarial pass (gpt-6-astra paused). Linux CI on the round-2-fixed tree (run 34773216183 at
39d904b, PR #3): all five jobs green.

Opus adversarial pass: 7 findings, no P1 ("no other qualifying defects"; explicitly checked clean: `guard.Peek` is
not an oracle and the `issued` ledger is keyed, verified, spent, swept, capped and locked; token-bound targets;
every consumer on one `targets` slice; mount boundaries agree between pre-scan and walk; the hardlink rule's
exclusions; `DiffOf` callers; `NFS4State` arithmetic; ACL probe bounds; `WorkerCodes`; the ES-module cycle).

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: chown ids are bounded below only; the engine truncates to uint32, so uid 4294967296 chowns to root and 4294967295 is the kernel's "leave alone", while the audit and the token record the requested number. Reachable from the numeric id field. | routes + UI | **Accepted.** Bounded to 0..0xFFFFFFFE at the routes and in `parseId`. |
| 2 | P2: the recursive job's per-entry diff sentences are discarded — `jobWarnMessage` has no `unchanged` case, so "setgid dropped" publishes as "The request could not be completed." under "Show skipped items"; the copy engine's `unsupported`/`changed` wordings are reached by the mode jobs. | routes + UI | **Accepted.** Kind-aware warn messages; `unchanged` carries the worker's own path-free sentence; the UI renders it as a detail, not a skip. |
| 3 | P2: `#pImpact` measures a symlink root as one file while the recursive job changes the target tree (every QTS share). | UI | **Accepted.** The impact request measures the linked folder's target for a recursive job. |
| 4 | P3: a name renamed away while its descriptor is held surfaces as `not_found`, not `changed`, in the three re-open paths. | engine | **Accepted.** ENOENT/ENOTDIR on a re-open of a held object is `changed`. |
| 5 | P3: `properties?follow=1` guards the resolved target but the worker re-resolves the leaf-literal; a link re-pointed in between is described from a path the guard never saw. | routes + engine | **Accepted.** `PropsReq.Target` carries the guarded target; the worker walks it `O_NOFOLLOW` with no resolve; `Follow` inert. |
| 6 | P3: `#pRecursiveNote` says a recursive change never follows symbolic links; since round 2 the selected root is followed. | UI | **Accepted.** Reworded. |
| 7 | P3: a sync chmod token and a single-path non-recursive job token can coincide, letting a client swap the job route's pessimistic grade for the sync route's. | routes | **Accepted.** Job tokens carry their own op discriminator. |
