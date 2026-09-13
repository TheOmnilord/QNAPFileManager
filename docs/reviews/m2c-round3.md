# M2-C upload / archive / search — review round 3 (2026-09-13, gpt-6-astra, effort high)

Round 2's ten findings were fixed. Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the latest-search id is assigned from the 202 response, so a slower older submission arriving after a newer one takes ownership of the results pane (reproduced). | UI | **Accepted.** A submission sequence captured before the await decides ownership. |

Adversarial review, round 3: 4 findings (#4 = the normal pass's #1).

| 2 | P1: the route's own `resolveForGuard` on a root inside a dead hard NFS mount hangs before the engine's table refusal can run; retries exhaust worker slots. | routes | **Accepted** (reversing the round-2 residual for these two routes, whose roots are user-chosen): a table-only refusal by the requested spelling BEFORE resolve, via the new `platform.ForLiteral`. |
| 3 | P2: `refuseRootPath` uses the normalising `Platform.For`; a mount named with a backslash is missed (reproduced). | engine | **Accepted.** `platform.ForLiteral` (byte-for-byte, boundary-aware longest prefix), added by the orchestrator. |
| 4 | P2: keep-both over an existing directory/symlink fails Finalize with `conflict` instead of creating `name (2)`. | engine | **Accepted.** The kind refusal applies to overwrite only. |

Round-3 fixes landed for all four (UI submission-sequence ownership; routes' pre-resolve network refusal; engine's
literal lookup and keep-both policy). Linux CI on the round-2 tree failed only the `gofmt` gate on the routes
implementer's unformatted test, already formatted before this round.
