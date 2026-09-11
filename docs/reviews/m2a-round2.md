# M2-A review — round 2 (range e6398ed..3534d07: round-1 fixes + web/UI)

Reviewer: gpt-6-astra, low reasoning effort. Three passes over the explicit
range: a standard review (verify the 14 round-1 findings closed; review the new
web/UI layer), an adversarial re-attack on the hardened backend, and an
adversarial attack on the new routes. CI for `3534d07` was green on all five
jobs. Findings consolidated with Fable's judgement; the four M1 residuals were
off-limits.

## Round-1 verification (standard, part A)

Eleven of fourteen fully closed. Three partially closed:

- **#1 ownership** — `emptyEntry` validated only the entry directory's owner,
  not an existing sidecar, before destructive work. → B6.
- **#4 mount identity** — a kernel mount id absent from the refreshed table
  fell through to pathname authorisation, and even a matched id was turned back
  into caps via `For(mountPoint)`, which can select a stacked over-mount. → B5/B7.
- **#7 structured cancel** — the web fn returned `nil` with the error, so the
  Manager had nothing to keep, and `TrashIDs` were only taken on success. → W3.

## Backend re-attack — accepted (all P1)

Ownership alone is not authenticity:

- **B1** trash dirs must be non-writable by others (a uid-owned 0777 entry lets
  an attacker swap the payload under a still-valid sidecar).
- **B2** sidecars must be non-writable by others (a 0666 `meta.json` lets the
  destination be rewritten without changing its owner).
- **B3** `Ensure` still had a mkdir→open window; the concrete exploit renames
  QNAP's root-owned `@Recycle` into the trash name so root chmods the recycle
  bin to 1777 and adopts it. Fix: a publication protocol — create under a random
  temporary name, open it, verify on the fd that it is root-owned, 0700 and
  empty (nothing an attacker can substitute looks like that), fchmod through the
  fd, then rename into place with no-replace; a pre-planted non-sticky or
  non-root directory at the final name is refused, never repaired.
- **B4** when both `statx` mount id and fdinfo are unavailable the code fell back
  to `st_dev`, reopening the bind-mount hole; mutating walks now fail closed.
- **B5** a real kernel mount id missing from the refreshed table must refuse
  crossing, never fall back to pathname caps.
- **B6** (from part A) validate an existing sidecar before emptying its entry.
- **B7** (from part A) derive caps from the exact matched mount, not
  `For(mountPoint)`.

## Web/UI attack + standard part B — accepted

- **W1 (P1)** a delete queued behind full job slots can start after read-only
  is turned on: the guard was checked only at submit. Recheck at job start,
  audit a refusal, dispatch nothing.
- **W2** a job cancelled while queued (or at shutdown) never gets a result line
  — the fn never runs. Audit every terminal transition from a Manager
  completion hook.
- **W3** return the partial result alongside `context.Canceled`, with
  warnings and `TrashIDs`.
- **W4** per-item warnings, the current path and `Job.Err` exposed resolved
  spellings and raw worker text; map each path back by its exact resolved-root
  prefix and report codes only.
- **W5** `no_trash` echoed a resolved path.
- **W6** `trash.enabled=false` was not honoured before `Ensure` created 1777
  directories; answer `no_trash` first.
- **W7** intent lines carried no targets or correlation id; choose the job id
  before the intent and record the requested roots (byte-safe, capped).
- **W8 (UI)** a job finishing before the first poll skipped completion handling.
- **W9 (UI)** the Undo toast appeared at submit, before any ids existed.

Confirmed sound: token binding (job kind, mode, crossing flag, ordered paths),
replay protection, ownership on get/cancel, request-size limits, job-id
validation, INV-1.

## Disposition

All accepted. Backend fixes B1–B5 in one Opus pass; B6–B7 as a follow-up on the
same files once it lands; web/jobs W1–W9 in a parallel pass on disjoint files.
Round 3 re-reviews the result.
