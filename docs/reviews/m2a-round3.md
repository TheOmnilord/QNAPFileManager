# M2-A review — round 3 (range 3534d07..064748f: the round-2 fixes)

Reviewer: gpt-6-astra, low reasoning effort. Three passes: standard
verification of the sixteen round-2 items, an adversarial re-attack on the
backend hardening, and an adversarial pass on the web changes. Findings
consolidated with Fable's judgement; the M1 residuals were off-limits.

## Round-2 verification (standard, part A)

Fifteen of sixteen closed; W7 partially closed (see S2). No Manager,
mount-crossing or stacked-mount regression was found in part B.

## CI (not a review finding)

The round-2 commit failed the non-root Linux `-race` job:
`TestCloseCancelsEverythingAndWaits` saw a queued job end `done` on `Close`.
A real race: `Close` publishes `closed` under the lock, then cancels entries
one by one *after* unlocking; cancelling the running job frees the only slot,
the queued job's goroutine takes it before `Close` reaches its context, and
its instant function completes. Fixed by re-checking `closed` after acquiring
a slot and before starting — the slot only ever frees because `Close` cancelled
its holder, strictly after `closed` was set, so the outcome is deterministic. A
job that took its slot before `Close` began legitimately runs and is stopped
through its context. Stable over forty local runs; the race job is the proof.

## Accepted

- **BA1 (P1, trashroot)** the publication protocol's provenance — root-owned,
  0700, `nlink == 2` — is not authentication: `nlink == 2` also holds for a
  directory holding only regular files, and any root-owned 0700 empty
  directory made by another root process passes. Strengthened: emptiness by
  reading the directory, and a fresh mtime (a rename does not refresh an
  inode's mtime and an attacker cannot set it on a root-owned directory).
  **Documented residual (PLAN §2.7):** creation at an attacker-writable mount
  root cannot be made fully atomic on Linux, and a root-only staging parent has
  the same creation race; what remains needs the attacker to supply a
  root-owned, 0700, empty, freshly-created directory on the same volume that
  they can rename — in practice only one of our own temp directories, which is
  harmless — with the worst case being a fresh root-created empty directory
  becoming the trash root. Accepted for M2 after three rounds on this path.
- **BA2 (P2, trashroot)** failure cleanup removed the temp *pathname*
  unconditionally, so an unrelated empty directory swapped into it could be
  deleted. Now the temp is removed only when it was opened, passed provenance
  and is re-verified as the same inode; otherwise nothing is removed and a
  possible leftover is logged.
- **S1 (P2, web)** the completion hook classified the audit outcome from the
  count of warn *frames* that arrived; the terminal result's warning total is
  authoritative (frames can be dropped), so a destructive job with skipped
  items could be audited `ok`.
- **S2 (P2, web)** a refused submission (queue full, closing) wrote a result
  line without the minted job id the intent already carried, so the two could
  not be paired.
- **WA1 (P2, web)** with `trash.enabled=false` a trash-mode token was still
  issued and the refusal only surfaced on redeem, making the user confirm
  twice; the refusal now precedes token issuance, behind the guard's own.
- **WA2 (P2, UI)** a trash job that ended `failed` after moving some entries
  still carried their ids, but the UI discarded them and offered no Undo.

## Confirmed sound

The completion hook runs on each job's own goroutine with a copied terminal
snapshot after its slot is released, so a slow audit sink never blocks other
jobs' transitions; permission-bit coverage on every consuming path; the
mount-identity fail-closed rules; `Meta.ID`/`OnFinish` lifecycle.

## Disposition

All accepted; one Opus pass on trashroot + web + UI, the Close-race fix in
jobs. Round 4 re-reviews the result.
