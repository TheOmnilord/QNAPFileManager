# M1 review — round 10 (final holistic sign-off)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: the whole
M1 write path (routes_mutate, routes_admin, browse, resolve, guard, rules, audit),
with the four documented residuals (§2.0, §2.4, §2.5, §2.6) declared off-limits so
the pass hunts only for NEW issues.

## Findings — two P1s, both outside the accepted residuals

**[P1] Reconcile read-only state when the INITIAL config save fails** —
`internal/web/routes_admin.go` step 2. The round-8 fix reconciled the *rollback*
save (step 4) but the *initial* persist still assumed "save error ⟹ file
untouched". If that save's rename lands but a later `SyncDir`/`Chmod` errors, the
file holds `newVal` while the guard keeps `prevVal` — the same guard/config
divergence, on a different branch, with no audit timeout involved (so distinct
from §2.6).

**[P1] Refuse renaming ancestors of the protected installation tree** —
`internal/guard/guard.go`. The install-dir rules match only the install dir and
its descendants, so with read-only off a root session could rename an *ancestor*
directory (e.g. `/share/CACHEDEV1_DATA/.qpkg`, not itself a mount point),
relocating the install tree — binary, config with the password hash, and the audit
logs — out of protection, after which the relocated audit file could be deleted
while its open descriptor still acknowledges writes to an unlinked inode. Deleting
a non-empty ancestor fails in the kernel, but renaming one succeeds — the real
vector.

## Judgement (Fable)

**Both accepted and fixed.**

- routes_admin.go: the initial-save failure now runs the same `reconcileReadOnly`
  path as the rollback — re-read the file, match the guard and `s.cfg` to its
  actual value, fail-closed to read-only if unreadable — so the guard and config
  cannot disagree on either save-error branch. `TestReadOnlyIntentDurableBeforeApply`
  extended to assert `s.cfg == guard` after the failure.
- guard.go: added a containment check — `Check` refuses `OpDelete`/`OpRename` on
  any *strict ancestor* of the install dir, and `Classify` badges it protected.
  New `TestAncestorContainmentProtection` covers the `.qpkg` and volume-data
  ancestors, a look-alike sibling (not caught), the install dir itself, and the
  no-install-dir case. PLAN.md §2.6 broadened to name both save paths.

The 20 `internal/web` test failures in the reviewer's sandbox were environmental
again: CI for the reviewed commit (`c3af0e2`, run 34535617608) passed every job,
`test-windows` included, as did the local `go test ./...`.

## Status

Round 10 of 10 is complete. With these two fixes the M1 write path has no known
open correctness or security finding outside the four documented, accepted
residuals. Ready for a supervised hardware test of mkdir/rename/delete on the two
NAS units.
