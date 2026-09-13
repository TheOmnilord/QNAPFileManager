# M3 permissions + properties — review round 1 (2026-09-13)

Implementation fanned out to three Opus agents against `docs/design/m3-contract.md`: engine (`internal/perm`,
`internal/fsops/mode*.go`, `props.go`, `aclstate*.go`, worker/pool ops and jobs, wire types), routes
(`internal/web/routes_perm.go`: the six endpoints, the `aclmode` ladder, audit pairs, `/api/ids` narrowing) and UI
(`perm.js` mirror, `perms.js` F9 dialog, `props.js` Alt+Enter dialog, ACL badge). All three converged on the
contract's wire types without duplication.

**gpt-6-astra is paused** (owner, evening of 2026-09-13), so this round's reviewer is an Opus adversarial pass,
read-only, calibrated on the M2-C findings. The Astra normal + adversarial passes for M3 are pending until the owner
lifts the pause; M3 is not hardware-ready until they have run.

Deviations from the contract accepted at this round (all recorded by the agents with reasons): chown sends absent
uid/gid for "unchanged" rather than `-1`; octal renders 4-digit (`perm.Octal`) everywhere; the confirmation grade
travels as `confirm.grade`; `FSInfo`/`ACLInfo` use lowerCamel JSON tags; the job routes' ACL rung treats the
state as `unknown` (probing every root before a 409 is not defensible); `follow:true` binds the token to the
resolved target rather than adding a part; all four routes are mutation routes; `/api/ids` items are `{name, id}`;
`ChmodReq.Follow` is inert in the worker; `NFS4State` of an empty ACE list is `nfs4` (pessimistic); zero-mask
entries count as skipped; directories are changed post-order; depth-1 refusal is a whole-job error; the
`conflict` code (EBUSY from `beginJob`) was missing from `RemoteError.Unwrap` — found by the code-coverage table
test on its first run, exactly the gap the contract predicted.

Linux CI: throwaway draft PR #3 on `wip/m3-ci`.

Linux CI, first run (34770818151 at 7baee2b): ZFS and Windows green; root and race jobs failed on one Linux-only
test fixture, `TestChmodTreePreScanBoundGoesIndeterminate`, which gave the tree a Files spec only and then expected
the directory to count as changed (a zero-mask entry counts as skipped, by the engine's own rule). Fixture given a
Dirs spec; no engine change. Rerun 34771015508 at d103a6c: all five jobs green — root, ZFS and race included.

Opus adversarial pass: 6 findings, no P1 ("no other qualifying defects"; explicitly checked clean: depth-1 refusal
on both spellings incl. `..`/`//`/pathB64, recursive special-bit set on both specs, token parts/single use/binding,
the ladder over the golden hero table incl. `""`→discard, `/api/ids` narrowing, probe and warn caps, audit pairing
on all four routes, `WorkerCodes` coverage, test race discipline, `confirm.grade` on both sides).

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: `GET /api/fs/properties` dispatches the unresolved path to a worker that walks it `O_NOFOLLOW`; every item under a symlinked share would answer 409 `changed` on hardware — the exact tell §17 names. | routes | **Accepted.** The route resolves (`followLeaf:false`), guards both spellings, dispatches the resolved one; pin test. |
| 2 | P2: `follow:true` chmod resolves and token-binds the target but dispatches the unfollowed spelling, and the worker ignores `Follow` — the checkbox can only ever produce 415. | routes | **Accepted.** The target is dispatched; token root and dispatched path are one spelling. |
| 3 | P2: nothing sets `ListOptions.ACLProbe`, so `Entry.ACL` is always empty and the badge and the dialog's ACL sentence never render. | routes | **Accepted.** The listing route asks for the probe; the engine's per-mount gate and per-page bounds do the rest. |
| 4 | P2: `perms.js`'s `/api/ids` cache is module-scoped and survives a session switch — a non-admin can be shown an admin's roster. | UI | **Accepted.** Cache keyed on the session generation. |
| 5 | P3: `chownHeld`'s named fallback proves identity on one descriptor and then acts by name. | engine | **Accepted.** `chown("/proc/self/fd/N")` on the held descriptor first; the named call only without `/proc`, recorded as a residual. |
| 6 | P3: `perm.UNCHANGED = -1` is exported with a comment contradicting the wire (absent = unchanged; negatives refused). | UI | **Accepted.** Removed. |
