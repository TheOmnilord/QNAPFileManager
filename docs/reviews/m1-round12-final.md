# M1 review — round 12 (final holistic sign-off)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: the whole
M1 write path, with the four documented residuals (§2.0/§2.4/§2.5/§2.6) declared
off-limits so the pass hunts only for NEW issues.

## Findings — two, both accepted

**[P1] Protect ancestors of the CANONICAL installation root too** —
`internal/guard/guard.go`. When the install path is reached through a symlink
(`/alias -> /data`, `installDir=/alias/.qpkg/app`), `CanonicalizeRoots` duplicates
the install *rules* under the resolved prefix but left `g.installDir` lexical. So
renaming `/data/.qpkg` passed both the requested and resolved guard checks — it is
an ancestor of neither the lexical `installDir` nor the duplicated
`/data/.qpkg/app` rule prefix — relocating the install and audit tree out of
protection. (This is the edge round 11 noted as out-of-scope; the holistic pass
correctly promotes it. Distinct from §2.0 — no concurrent symlink swap needed.)

**[P2] Preserve non-UTF-8 rename DESTINATIONS in audit records** —
`internal/audit/audit.go`. `prepare` base64-preserved a non-UTF-8 `Path` but not
`Dst`, so a rename destination with non-UTF-8 bytes was flattened to U+FFFD in
both the intent and result lines, making distinct destinations indistinguishable —
including when an overwrite destroys an existing target.

## Judgement (Fable)

**Both accepted and fixed.**

- guard.go: `CanonicalizeRoots` now records the resolved install spelling in
  `installDirCanon`, and the containment check (`isInstallAncestor`, used by both
  `Check` and `Classify`) tests strict-ancestry against BOTH the lexical and the
  canonical install path. New `TestAncestorContainmentCanonicalInstall` covers the
  canonical and lexical ancestors and a resolved-root sibling.
- audit.go: added `DstB64`; `prepare` now normalises `Dst` exactly like `Path`,
  and `message` renders a `b64:` destination for QuLog. New `TestNonUTF8Dst`
  round-trips a non-UTF-8 destination.

The reviewer's local web-test failures were environmental again; the round-10 code
CI (run 34536418467) passed every job, `test-windows` included.

## Status

With these fixes the M1 write path has no known open correctness or security
finding outside the four documented, accepted residuals. Reviewer's readiness
line: ready for a supervised hardware test of mkdir/rename/delete once these were
addressed — now done. A verification round (13) covers these two fixes.
