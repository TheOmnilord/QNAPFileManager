# M1 review — round 13 (holistic verification, standard + adversarial)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: verify the
round-12 fixes (commit `c26bec6`) and re-sweep the whole write path.

## Result — one finding, in BOTH passes (the same issue)

Both the standard and the adversarial holistic pass confirmed:

- The **canonical install-ancestor containment** is sound — third-spelling
  (nested-symlink / bind-mount) attacks resolve into guarded canonical paths, an
  unchanged canonical spelling stays lexically protected, and production startup
  calls `CanonicalizeRoots`.
- **DstB64** preserves the bytes and renders correctly; confirmation-token
  direction/overwrite binding and JSON escaping withstood the attacks.
- No other new defect beyond the four accepted residuals.

The single new finding (both passes):

**[P2] Milestone classification lost for base64-moved paths** —
`internal/audit/audit.go`. A regression from the round-12 `DstB64` fix: `prepare`
now clears `Dst` (and already cleared `Path`) into the base64 companion, but
`isMilestone` and `severity` inspect only `ev.Path`/`ev.Dst`, never the companions.
So a rename/write to a non-UTF-8 path under `/etc/config` lost its
firmware-configuration milestone and stopped being mirrored to QuLog (the JSONL
bytes were still correct). Classify on the raw bytes.

## Judgement (Fable)

**Accepted and fixed.** Added `effPath(plain, b64)`, which returns the decoded
companion bytes when `prepare` cleared the plain field, and used it in both
`isMilestone` and `severity` — for `Path` as well as `Dst`, since the same latent
gap affected a non-UTF-8 source path. New `TestNonUTF8EtcConfigStillMirrors`
covers both a non-UTF-8 destination and a non-UTF-8 path under `/etc/config`,
asserting the QuLog mirror still fires.

Round-12 code CI (run 34537403301) was green across all jobs. The reviewers' web
test failures were environmental again.

## Status

The only round-13 finding was a self-introduced regression from round 12, now
fixed; both holistic passes were otherwise clean of new findings. A verification
round (14) covers this fix.
