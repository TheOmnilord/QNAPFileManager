# M1 review — round 9 (standard)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: commit
`b8d510f` (the round-8 `reconcileReadOnly` fix).

## Result

**No material issues.** The reviewer confirmed:

1. `reconcileReadOnly` establishes guard == on-disk config for every combination;
   fail-closed (read-only) is the right direction when the file is unreadable.
2. Caller wiring is correct — `s.cfg.ReadOnly` and `s.guard.SetReadOnly` both take
   the returned value, under the single `cfgMu` hold; the `ConfigPath==""` path is
   unaffected.
3. Re-reading the file under `cfgMu` is safe: same file just written, no lock
   re-entrancy.
4. The unit test passes and pins the matrix.

## Minor observations (cosmetic, do not affect correctness)

- Two `TestReconcileReadOnly` case labels were conceptually reversed.
- §2.6's lead "guaranteed … never disagree" reads as unconditional before it
  explains the fail-closed (unreadable-file) exception.

## Judgement (Fable)

**No code change required.** Both cosmetic nits addressed: the test labels were
renamed to describe what the file actually reads (`file-reads-prev` /
`file-reads-newval` / fail-closed), and §2.6's lead was scoped to "whenever the
config file is readable". This was the first round with no accepted correctness
finding in the standard pass.
