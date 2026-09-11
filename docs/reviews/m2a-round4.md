# M2-A review — round 4 (range 064748f..27b8d60: the round-3 fixes)

Reviewer: gpt-6-astra, low reasoning effort. Two passes: standard verification
of the nine round-3 items (seven findings plus the two race fixes) with a
regression hunt, and a narrowly scoped adversarial pass on the riskiest changes
— the two race fixes and the `Ensure` provenance/cleanup. Findings consolidated
with Fable's judgement; PLAN §2.0-2.7 residuals were off-limits.

## Round-3 verification (standard, part A)

Eight of nine closed; BA2 partially (see R4-2). Part B found no regression in
the areas probed: the freshness window on a slow filesystem, the readdir
emptiness check under a race-created entry, `detach` being called twice
(the restart budget is charged only when the identical current client is
removed), lock ordering around `isClosed`, a job legitimately started before
`Close`, outcome classification of a clean success, and guard-refusal
precedence versus token issuance.

## Adversarial (race fixes and Ensure)

Confirmed sound: a job whose slot frees because the running job finished on
its own — not because `Close` cancelled it — correctly ends `done`; the
`closed` re-check cannot cancel a function that already started; the
semaphore is released through its registered defer on every path; `detach` is
idempotent and pointer-keyed; `acquire` re-checks `dead` after selecting a
client; the old worker's termination ladder targets its own client, never the
respawned replacement; unprivileged users cannot populate a root-owned 0700
directory; cleanup re-opens `O_NOFOLLOW|O_DIRECTORY` and compares inode
identity. An earlier private temp of our own within five seconds can pass
provenance — exactly what §2.7 accepts.

## Accepted

- **R4-1 (P2, adversarial)** the five-second freshness window compares wall
  times (`ModTime` has no monotonic component), so a NAS stall of more than
  five seconds before the inode is created, or a clock step in that window,
  makes a *legitimate* fresh directory fail provenance; `Ensure` then returned
  `ErrUnsafeTrash` and left the temp behind though nothing was substituted.
  Fix: a freshness-only failure — owner, mode and emptiness all passed, so it
  is unmistakably a directory only root could have made — is classified as
  stale; the temp is removed (provably ours by identity) and the publish is
  retried with a new random name and a fresh reference, bounded, before
  failing. Any other provenance failure still refuses, never repairs, never
  retries.
- **R4-2 (P2, standard)** when another `Ensure` publishes first and this
  call's cleanup cannot prove its temp is its own, the leftover diagnostic was
  wrapped into `errPublishedFirst`, which the retry loop consumes on its way to
  returning the winner — so "a temporary directory may have been left behind"
  was never logged. Fix: a package logging hook, wired to the daemon log,
  emits that diagnostic before the loop continues.

## CI (not a review finding)

The round-3 commit failed the non-root `-race` job on
`TestETAIsUnknownUntilThereIsSomethingToEstimateFrom`: ETA 0, expected ~4. The
product is right — a finished job's ETA is 0 — the test was racy: its third
progress update was immediately followed by the work function returning, so
under the race detector's scheduling the job finished before the test read the
ETA. Fixed by a fourth lockstep gate holding the function until the assertion
has run. Stable over forty local runs.

## Disposition

Both accepted; one Opus pass on trashroot (plus a one-line log-hook wiring),
the test gate by the orchestrator. Round 5 is a final verification.
