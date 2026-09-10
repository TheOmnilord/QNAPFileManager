# M1 review — round 8 (standard)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: commit
`3578b52` (the round-7 rollback hardening).

## Finding

**[P2] Distinguish rollback errors before and after publication** —
`internal/web/routes_admin.go` rollback branch. The round-7 fix assumed a
`config.Save` error means the file is untouched, so it set `effective = newVal`.
But `config.Save` → `jsonfile.Write` renames a temp file into place and only then
calls `durable.SyncDir`, and `config.Save` then calls `os.Chmod`; either can fail
*after* the rename has already published `prevVal`. In that case the code set the
in-memory config and guard to `newVal` while the file holds `prevVal` — opposite
values — which, when rolling back an attempt to disable read-only, leaves writes
enabled against a read-only file. This invalidates the §2.6 "unconditional
guarantee". Fix: determine whether publication occurred (or reconcile with the
file) instead of assuming every save error leaves `newVal` on disk.

## Judgement (Fable)

**Accepted** — a real gap in my own round-7 fix; the "error ⟹ file unchanged"
assumption is false. Same issue the adversarial pass rated P1. Fixed in the
round-8 commit: the rollback now **reconciles against the on-disk state** — it
re-reads the file (`config.Load`) when the save errors and sets the guard and
in-memory config to the file's actual value; if the re-read also fails (a triple
failure), it fails closed to read-only. Extracted `reconcileReadOnly(...)` with
an injected loader and unit-tested all branches, including the flagged
post-publish case. PLAN.md §2.6 updated.
