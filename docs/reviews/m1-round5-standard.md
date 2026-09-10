# M1 review — round 5 (standard)

Reviewer: gpt-6-astra, low reasoning effort (`codex exec review`). Scope: commit
`3bd0fea` (the round-4 fixes) against parent `d7e2c09`.

## Build / verification (reviewer sandbox)

- `go build ./...` — pass
- three-GOOS `go vet` + `gofmt` — pass
- `go test ./internal/web` — reported 16 failures in the reviewer's Windows
  sandbox (permission-code mismatches, audit-file cleanup). **Judged
  environmental:** the authoritative CI run for `3bd0fea` (34532557941) passed
  every job including `test-windows`, and the local `go test ./...` was green.
  CLAUDE.md gotchas 1/5 (SAC, "local green is not CI green") cover this.

## Finding

**[P2] Mark batches stopped after successful items as partial** —
`internal/web/routes_mutate.go` batch-outcome switch. If cancellation occurs
after a successful deletion but before the next iteration, the round-4 early
`break` leaves `succeeded>0, failed==0`, so the outcome switch reports `"ok"`
despite leaving requested items undeleted; the batch milestone inherits the wrong
code. Fix: include `attempted < len(paths)` in the partial condition. Also:
extend `TestBatchDeleteStopsOnContextCancel` to assert `outcome == "partial"`.

## Judgement (Fable)

**Accepted.** Same regression the adversarial pass found (its finding 3). Fixed
in the round-5 commit: unattempted targets now force `partial`, the milestone
denominator is the requested count, and the cancel test asserts the outcome.
The 16 sandbox test failures are environmental (CI `test-windows` is green).
