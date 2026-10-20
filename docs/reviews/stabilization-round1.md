# Stabilization patch — Astra round 1 (2026-10-21, gpt-6-astra, effort high)

Reviewed: the staged diff of commit 1653467 (`wip/stabilization`) against main 94fbb51 — the whole patch, against
`docs/design/stabilization-contract.md`. Judged by Claude (Opus 5.5, conducting in place of Fable 5.1). Normal review
with the default instructions; adversarial review as a robustness and isolation pass over selection, ordering and
paging, the 50,000 peek, slot accounting, confirmations and audit, UI/CSS/accessibility and documentation.

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: `dateCell` calls `toLocaleString(undefined, {dateStyle, timeStyle})`, which builds a formatter per call; `render()` formats every row of a folder of up to 2,000 entries on each scroll and filter keystroke, so a 2,000-date pass costs 240–420 ms against ~5 ms before, before any DOM work. | U1 (list.js) | **Accepted.** Cached `Intl.DateTimeFormat` instances for the short text and the full title, created once; visible behaviour unchanged; a test that the formatter is reused. |

Adversarial review: 1 finding; nothing actionable in selection, ordering/paging/peek, slot accounting,
confirmations/audit, UI/CSS/accessibility or documentation.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 2 | P2: the size job's time bound is checked only every 128 `Pre` calls in `scanTrees`; a non-admin measuring a large directory it can read but not enter gets warnings from failed child `lstat`s without `Pre` ever running, so the walk can pass ten minutes, keep its metadata slot and finish without `Capped` (contract §2.1). | J (fsops/size.go) | **Accepted.** A deadline context on the walk, as `Search` derives one; expiry becomes `Capped`, a parent cancel stays a cancellation (cancel wins a tie); a Linux non-root test over a readable-but-not-searchable directory. |

Unique findings this round: 2. Rejected: none.

**Fixes (2026-10-21).** #1: `dateCell` keeps two lazily created `Intl.DateTimeFormat` instances (short text, and a
title built from the same fields `toLocaleString()` fills in by default); checked identical to the old output in 12
locales over 55 dates; 2,000 rows now cost ~7 ms; a spy test asserts two constructions across 2,004 calls and fails
on the old code. #2: `Size` runs its walk under a deadline context of its own whenever it has a time bound (the
`searchTimeout` pattern, through a `sizeWalkDeadline` seam); the walk checks it at every name, so refused children
no longer outrun the bound; the walk's own deadline becomes `Capped`, a caller cancel stays a cancellation even when
both land together; new Linux non-root tests over a 0644 directory of 64 entries, plus portable seam tests.

**Reported by the implementer, deferred (pre-existing, outside the contract).** The delete, permissions, trash and
copy pre-scans (`delete_tree.go`, `mode_job.go`, `trash.go`, `copy.go`) check their 30 s `scanMaxDuration` only every
128 counted entries, so a tree whose children all fail `lstat` can overrun it. Each overrun is bounded by the
number of children, delays the start of a job the user is watching and can cancel, and predates this patch; the
same per-walk deadline context fixes it. Recorded for 1.1 rather than widening a patch whose engine code went
through many review rounds.

**CI on 1653467** (run 39508258197): test-windows and test-zfs green. `test` failed at govulncheck: Go 1.26.9 fixed
ten standard-library advisories (net/http, net/textproto, crypto/tls) reachable from this daemon, and main's own run
on 94fbb51 fails the same way — fixed by pinning `GO_VERSION` to 1.26.9. `test-linux-root` failed two copy-race tests
(`TestCopyRefusesItsOwnOutputMovedIntoTheSource`, `TestCopyRefusesTheDestinationThatArrivesInsideTheSource`: no
`invalid_target` warning); main's root job passed on 94fbb51 the day before and the patch changes nothing the copy
engine runs.

**Diagnosis.** A re-run failed identically, while a control run of main the same evening passed its root job — on
runner image ubuntu-24.04 20261012.334; both failing attempts ran on 20261018.339. Both tests build
`src/a/{one.txt, zsub/filler.txt}` and rename the job's own output into `zsub` from a hook on the progress of
`/dst/a/one.txt`, then expect the walk to meet it there. The walker reads children in raw getdents order
(`Readdirnames`), so the tests silently assume `one.txt` is visited before `zsub`; the newer image returns the other
order, the walk has already read `zsub` when the rename lands, and production correctly reports nothing. A latent
test bug that main would hit on the new image too; the tests are being made independent of getdents order (and the
package searched for others with the same assumption), test-only unless a default-preserving seam is unavoidable.

**Test fix.** Both tests now trigger on the progress of the ROOT output folder `/dst/a`, reported once by `makeDir`
after it is created and recorded and before `walkFrom` reads a single name, so the rename lands before either
sibling order is walked; a `staged` flag asserts the hook fired. The first test's existence check named a path that
could never exist (`planted/a/zsub/planted`) and now names the first folder a recursion would create
(`planted/zsub/planted`). Test-only; no seam was needed. The sweep found no other test relying on getdents order. It
found three weak tests that do not discriminate the bug they name, all pre-existing and recorded for 1.1:
`TestDirectoryOwnerComesFromTheEnumeratedDescriptor` (its hook fires in the pre-scan, so the chown lands before the
walk's lstat), `TestACancellationThatArrivesLateIsStillACancellation` (it cancels during the pre-scan, so the late
check is never reached) and `TestSearchCountsHiddenEntriesAgainstTheCaps` (six visible entries already exceed the cap
of five).
