# M1 follow-up review — not-empty delete blockers

Owner hardware test (2026-09-11, QTS .95 and QuTS hero .99): a folder that looked
empty would not delete ("the folder is not empty"), while File Station could.
Cause: the folder still held a hidden entry the default listing hides — QNAP
metadata such as `.@__thumb` created when files were copied in. M1 delete is
single-level (`rmdir` → ENOTEMPTY); recursion is M2. Owner chose: **name the
blockers now, defer recursion.**

Change (commit `be8d3e2`): on a `not_empty` single delete, list the directory as
the user (hidden included, capped) via the backend and return the blocking
entries so an empty-looking folder explains itself; the client names them.

## Review (gpt-6-astra low, normal + adversarial)

**Round 1 (be8d3e2) — one finding, accepted:**

- **[P2] byte-safe blocker name.** `deleteBlockers` chose `NameB64` only when
  `Name` was empty, but `fsx.Entry.SetName` keeps `Name` populated (raw bytes) and
  sets `NameB64` only for a non-UTF-8 name, which the worker's JSON step then
  flattens to U+FFFD. So the byte-safe form was never chosen and distinct
  non-UTF-8 names could collide. Fixed in `37a32eb`: prefer `NameB64` whenever
  present (matching the `*B64` companion convention; the audit `message()` helper
  legitimately keeps its "plain empty" test because `prepare()` clears the plain
  field there). New `TestDeleteBlockersByteSafeName`.

**Round 2 (37a32eb) — clean.** No material findings. Confirmed: the byte-safe
selection is correct and consistent; INV-1 preserved (the listing goes through the
worker, never fsops); the listing is bounded (25 returned, 50k scan cap); a List
error is best-effort (still returns `not_empty`); the audit result is recorded
once; responses name only the requested path (no resolved-spelling disclosure);
no nil deref, race, or injection. The reviewer's web-test failures were
environmental (Windows permission semantics); local `go test` and CI are green.

## Status

Reviewed clean. Recursive delete remains deferred to M2; this change only makes
the single-level refusal self-explanatory.
