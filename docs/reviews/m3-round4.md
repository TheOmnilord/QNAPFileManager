# M3 permissions + properties — review round 4 (2026-09-13)

Round 3's seven findings were fixed (routes: chown ids bounded to `0..0xFFFFFFFE`; kind-aware job warn messages,
the `unchanged` sentence served from the worker fenced and clipped; `PropsReq.Target` carries the guarded target;
tokens carry `kind=sync|job`. Engine: a held name renamed away is `changed` on all three re-open paths; `Props`
describes `Target` through the canonical walk with no resolve. UI: `parseId` bounded with an error instead of a
silent no-op; the impact measure follows a symlink root to its target for a recursive job; details vs skips in
the job expander; the recursive note reworded).

Reviewer: Opus adversarial convergence pass over the whole change (gpt-6-astra paused). Linux CI: wip/m3-ci at
9b53a62, PR #3.

Linux CI, first run (34774235317 at 9b53a62): Windows and ZFS green; root and race jobs failed on one Linux-only
test whose expectation was left behind by round 3 — `TestReopenProvedClassifiesTheOpen` still wanted `not_found`
for a name that went away while its object was held, which round 3 made `changed`. Expectation updated; no engine
change. Rerun 34774429721 at d7d4dbf: all five jobs green.

Opus convergence pass: 7 findings, no P1 ("no other qualifying defects"; explicitly checked clean: the round-3
fixes, the guard/token machinery, descriptor discipline, mount handling in the walk, M2 reuse, `/api/ids`, the
ACL probe, test discipline). Verdict: converged — "four rounds have taken it from six findings to two"; the two
P2s are above the kernel and should land before a build; gpt-6-astra has reviewed neither this change nor the
contract.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the job route's ACL rung grades from the selected roots only, but with `crossMounts` (set on hero unconditionally) the walk enters nested datasets — a `discard` child under a `passthrough` parent loses its ACLs after an L1 that promised otherwise. | routes | **Accepted.** With crossing, the ladder folds every mount below each root and takes the worst, naming the discarding datasets; §17 gains the residual (a dataset created after issue is not seen). |
| 2 | P2: the client's headline diff sentence for the 2755-by-a-non-member case blames "the filesystem's ACL settings" (false) and the string de-dup shows the mode fact twice in two voices. | UI | **Accepted.** Server sentences are the single source of truth; the client suppresses its mode line when a special-bit diff is present and drops the causal clause. |
| 3 | P3: `properties` without `follow` still returns `Entry.LinkResolved` from the worker's own resolution — the same spelling the listing publishes for everyone since M1. | — | **Rejected as a new defect; recorded as a residual.** The `follow` refusal protects the target's attributes; its spelling is already public through the listing (`ResolveLinks`), so this is M1 behaviour, not an M3 bypass. |
| 4 | P3: `NFS4State`'s who lookup is exact-match; an encoder that counts the NUL, or does not pad the last who, would badge the whole hero NAS non-trivial and promote every chmod to L2. | engine | **Accepted.** Trailing NULs trimmed; an unpadded final who accepted. First thing to check on hero. |
| 5 | P3: the `.mjs` tests are not run by CI. | orchestrator | **Accepted.** `node --test internal/web/*.mjs` added to the Linux test job. |
| 6 | P3: apply-scope radios keep their value after Recursive is unticked, so a files-only/folders-only choice silently posts a zero mask. | UI | **Accepted.** `applyMode()` is `all` unless recursive. |
| 7 | P3: Apply re-enables itself in `finally` past the refusal that disabled it. | UI | **Accepted.** One function decides the button state. |
