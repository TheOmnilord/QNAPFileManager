# M1 review — round 11 (verification of the round-10 fixes)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`), standard +
adversarial. Scope: commit `983c8ef` (initial-save reconcile + install-tree
ancestor containment) against parent `c3af0e2`.

## Result — both passes clean

**Standard:** no material new issues. `strictAncestor` has the correct argument
order and boundary semantics (no false match on a look-alike sibling), the empty
`installDir` disables it, the containment check is scoped to `OpDelete`/`OpRename`
only (reads/creates/writes on an ancestor still allowed, descendants still
governed by their own rules), and both save-error paths reconcile the guard and
`s.cfg` under `cfgMu`. Tests pass.

**Adversarial:** no commit-introduced defect found.

- Direct relocation of the install/audit subtree is blocked at the source; a
  symlinked/alias ancestor is caught because mutations check both the requested
  and the resolved spelling and take the worst.
- No false-positive: `fsx.IsWithin` boundary matching separates `.qpkg` from
  `.qpkgstore`; `installDir == "/"` yields no strict ancestor.
- The step-2 reconcile is serialized under `cfgMu`; fail-closed leaves Settings
  reachable (the toggle route is admin-gated, not read-only-gated), so no lockout.

## Observations (accepted, pre-existing, out of scope)

- **Canonical-install-ancestor / bind-mount alias**: the containment check keys on
  the configured `installDir` spelling. Reaching an ancestor by a resolved spelling
  that differs from the configured one is the same resolved-spelling class as §2.0
  / `CanonicalizeRoots`; in practice mutations already check the resolved
  (canonical) ancestor against `installDir`, so an alias-requested ancestor is
  caught via the resolved spelling. Pre-existing shape, excluded from this
  commit-scoped review.
- The extended integration test exercises the unreadable-config reconcile branch;
  the rename-then-error save branch is covered by the `reconcileReadOnly` unit test
  (the `loadOK(false)` post-publish case), since forcing a post-rename `config.Save`
  failure is not reachable from a test.
- The reviewers' web-test failures were environmental (Windows SAC / permission
  semantics); CI for the reviewed commit is authoritative.

## Judgement (Fable)

**No accepted findings — a clean verification round in both passes.** The two
round-10 P1 fixes are sound. The M1 write path has no known open correctness or
security finding outside the four documented residuals (§2.0/§2.4/§2.5/§2.6).
