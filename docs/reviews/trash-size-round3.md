# Trash size fix — review round 3 (2026-09-13, gpt-6-astra, effort high)

Round 2's four findings were fixed (root identity from the enumerated fd via `Visitor.Opened`, the item pinned by a
held `O_PATH` reference across scan, rename and verification; byte-preserving `platform.MountByLiteralPath`;
checked summary accumulation; `Size`/`DeleteTree` emit `capped`). Normal: 1 finding; adversarial: 2 (one overlap).

| # | Finding | Judgement |
|---|---|---|
| 1 | P1: `TestTrashSizeDescribesOnlyWhatItMeasured/nothing_landed_at_all` fails deterministically on Linux — `sameObject(measured, nil)` is "unanswered" so `describes` returns true, while the Linux expectation is false. | **Accepted.** A missing payload identity is never "the same object": `describes` rejects nil on every platform; the test expects that. |
| 2 | P2: a partially emptied entry (a protected `@Recycle` subdirectory survives the empty) keeps its sidecar's original total as known; the listing and the next Empty Trash summary overstate. | **Accepted.** The sidecar is rewritten to unknown BEFORE the first removal under an entry (invalidate first, then delete); restore needs nothing, since it renames the payload out whole. |
