# Stabilization contract — the patch before v1.0.0

Date: 2026-10-20. Scope approved by the owner from
[roadmap-deliberation.md](roadmap-deliberation.md) "Stabilization patch", items 1–6 (item 7, the name, is decided
separately; item 8, screenshots, follows this patch). This contract is what the implementers build against and what
the reviewers check. It repairs behaviour the app already offers; it adds no feature.

Review: the CLAUDE.md rule stands (gpt-6-astra, normal + adversarial, ten-round ceiling). The tiers below say how
deep each part goes inside that ceiling: **deep** = selection, sorting, job lifetime, pre-flights; **light** =
presentation and documents.

**Status (2026-10-21):** implemented by five Opus agents; gpt-6-astra converged in two rounds (2 findings, then 0 —
`docs/reviews/stabilization-round1.md`, `stabilization-round2.md`); CI green on every job, packaging included, at
the reviewed commit. Hardware verification is the release checklist's §3 pass, still to run.

## 0. Ownership

Five implementers run in parallel. Each owns the files listed and touches nothing else; a needed change in someone
else's file is reported, not made.

| Part | Owner | Files |
|---|---|---|
| §1 Listing on the server (deep) | S | `internal/fsops/fsops.go`, `internal/web/browse.go`, their tests (`internal/fsops/*list*_test.go`, `*sort*_test.go`, new files as needed, `internal/web/browse*_test.go`) |
| §2 Bounded measurements and pre-flights (deep) | J | `internal/wproto/messages.go` (SizeReq only), `internal/worker/job.go`, `internal/fsops/size.go`, `internal/web/routes_jobs.go`, `internal/web/routes_transfer.go`, `internal/jobs/jobs.go` (only if §2.3 needs it), their tests (new files preferred) |
| §3 Selection, rows, menu, measurements in dialogs (deep) | U1 | `internal/web/static/js/{list,state,why,dom,actions,transfer,perms,props,search,api}.js`, their node tests, new `internal/web/maxroots_contract_test.go` |
| §4 Toolbar, tree, F2 (light) | U2 | `internal/web/static/js/{tree,keys,narrow,app}.js`, `internal/web/static/index.html`, `internal/web/static/app.css`, their node tests, Go static cross-check tests only if an id moves |
| §5 Truth pass (light) | D | `README.md`, `PLAN.md`, `CHANGELOG.md`, new `SECURITY.md`, `qpkg/qpkg.cfg`, `docs/keyboard.md`, `docs/release-checklist.md`, `docs/qnap-install.md` |

## 1. Listing on the server (S)

1.1 **Name order is case-insensitive with a byte tie-break.** `sortEntries` compares names rune by rune on a folded
key: a valid rune folds to `unicode.ToLower(r)`; an invalid UTF-8 byte (`utf8.RuneError` with width 1) keys as
`0x110000 + byte`, after every valid code point; a name that runs out first is less. Folded-equal names are ordered by
plain byte comparison (`a.Name < b.Name`). The order stays total, so pages never overlap for a fixed directory. Every
sort key falls through to this comparison, as it falls through to the byte name today. Natural (numeric-run) order is
out of scope.

1.2 **Folders first.** `GET /api/fs/list` takes `dirsFirst` (boolean, **default true**); `false` restores the plain
order. It sets `fsx.ListOptions.DirsFirst`, whose existing semantics stand (applied before `desc`). "Folder" is
`Type == "dir"`, as today; a symlink to a folder is not a folder for ordering.

1.3 **An honest cap.** When the read reaches `MaxListLimit` (50,000), `List` reads one more entry to learn whether
the folder really holds more. Exactly 50,000 is not capped: no note, `Truncated` false. More than 50,000 keeps
`Truncated` true and the note becomes, verbatim: `"Only the first 50,000 entries read are listed, so others are
missing, and sorting applies only to the entries listed."` (format the number with `fsx.MaxListLimit`; keep the
existing note's position in `Notes`). The peeked entry is never added to the listing.

1.4 Tests: the comparator (ASCII case pairs, accented letters, invalid bytes, U+FFFD versus a raw 0xFF byte, a
prefix pair, a byte tie-break pair), a three-page listing over a fixed directory whose pages neither overlap nor skip
with `dirsFirst` on and off and `desc` on, the exact-cap and over-cap cases (shrink the cap through the existing test
seam or add one), and the `dirsFirst` query parsing (absent, `true`, `false`, garbage → 400 as other booleans).

## 2. Bounded measurements and pre-flights (J)

2.1 **A size job has bounds.** `wproto.SizeReq` gains `MaxDuration` (seconds, `json:"md,omitempty"`), carried by
`worker/job.go` into `fsops.SizeOptions` and applied as the scan deadline (the tighter of it and any existing limit).
`POST /api/jobs/size` sends `MaxEntries = 10_000_000` and `MaxDuration = 600` (named constants in routes_jobs.go
with a comment: they match search's order of magnitude and bound an orphaned measurement). A scan that hits either
bound ends where it stands and answers `Capped`, exactly as an entry cap does today; a cancelled scan stays a
cancellation.

2.2 **The result says so.** `jobResultView` gains `Capped bool json:"capped,omitempty"`, filled by `viewOf`. The
pre-scans that already pass their own bounds (permissions) keep their behaviour.

2.3 **Capacity is held until the walk stops.** A size job's metadata slot is released only when its runner returns,
never at the moment a cancel is requested. If that is already so, prove it with a test; if not, make it so.

2.4 **Pre-flights fit the deadline at the selection limit.** With up to `maxJobRoots` (1,000) roots:
- **Copy and move** budget their sizing like the permissions route does: the measurement runs under the request
  deadline minus a 2 s reserve (reuse `permScanReserve` or an equal named constant) and a 500,000-entry total across
  roots; when the budget ends, the remaining roots are not sized and the summary carries the existing
  `noticeSizeMinimum`. The dead 30 s `context.WithTimeout` in `jobTransfer` is removed (it can never outlive the
  15 s route deadline). Per-root `FSIdentity` for moves stays per root, under the request context.
- **Delete** keeps its per-root resolve and stat, bounded by the request context; a root whose stat cannot be made
  within the budget is simply not added to the byte total (it already is so on error), and the response still
  completes.
- Batch per-root worker calls only if the test below shows the per-root round trips themselves threaten the
  deadline; if you batch, the guard checks and the token parts must not change.
- **Test:** for copy, move, delete and permissions, a selection of exactly `maxJobRoots` small files through the real
  HTTP handler and the same backend the existing route tests use completes with its confirmation challenge (or its
  202 where none is needed), and the confirmed re-post with the token also completes. Log the wall time with
  `t.Logf`; fail above 7.5 s. A second case with 1,000 directories holding a few files each must still answer
  within the deadline, with the size marked as a minimum when the budget ran out.

## 3. Selection, rows, menu and measurements in dialogs (U1)

3.1 **Invariant.** A selection never contains a row the user cannot see — a row hidden by the name filter, or a
volume-root row hidden at `/share` — and an action never sends more than `MAX_ROOTS` paths. Actions resolve selected
rows to the entries that were displayed (concrete `path`/`pathB64` references), never to a re-derived listing.

3.2 **One response for ordinary folders.** The list's first request asks for `limit: 2000` (`DEFAULT_PAGE`), so a
folder of up to 2,000 entries arrives in one consistent response; larger folders page lazily in pages of whatever
limit the server returned, as today.

3.3 **Ctrl+A** selects every visible row — all rows, or with a filter set, the rows matching it — when (a) the whole
listing came in one response (`state.pages.size === 1` and page 0 holds `state.total` entries, not loading) and
(b) the count to select is at most `MAX_ROOTS`. Otherwise it changes nothing and says why through `announce()` and
the status bar, in one sentence that names the number: e.g. "This folder has 1,532 items; select-all works on up to
1,000 at a time. Filter the names or select a range." / "This folder is too large to select all at once (only its
first 2,000 entries are loaded)." The select-all ("exclude") mode is **removed**: `state.exclude`, its branches in
`selected()`/`countSelected()`, and every place that sets or stashes it.

3.4 **Ranges and filters.** A Shift range adds only visible rows between anchor and target. Changing the filter
removes newly hidden rows from the selection (no announcement needed when nothing was selected).
`selectionEntries()` drops duplicate references (same path bytes, via `pathBytes`), keeps refusing a selection it
cannot load in full, and never returns a hidden row.

3.5 **Too many.** `why.js` exports `MAX_ROOTS = 1000`. For `needs: 'some'` actions (delete, copy, move, permissions,
download, and the trash panel's restore), a count above `MAX_ROOTS` is a `selection` cause with the sentence
`"Select at most 1,000 items at a time (N are selected)."` (N formatted). `internal/web/maxroots_contract_test.go`
reads why.js and asserts the literal equals `maxJobRoots`.

3.6 **Rows read like a file manager.** Size: folders "—"; files `formatBytes` (jobs.js) with the exact byte count
(`toLocaleString()` + " bytes") as the cell's `title`. Modified: `toLocaleString(undefined,{dateStyle:'short',
timeStyle:'short'})`, with the full `toLocaleString()` as `title`. No other column changes.

3.7 **The context menu opens where it was asked for.** A right-click opens it at the pointer; Shift+F10 / Menu at
the focused row (its left edge, just below it). It is positioned through a CSSOM rule inserted at runtime (the
`heightRule` pattern in dom.js — no inline styles, no `style` attribute), clamped inside the viewport and flipped
up or left when it would overflow. Keyboard behaviour, focus and enablement are unchanged.

3.8 **A capped measurement is a floor.** `sizeReport` (props.js) and the permissions impact line (perms.js) read
`result.capped`: the text starts "At least" and ends "— the measurement stopped at its limit (10 million entries or
10 minutes)." A capped Permissions estimate never presents itself as the exact impact.

3.9 Tests (node): Ctrl+A in a folder of 3, of exactly 1,000, of 1,001 and of 1,500 with a filter matching 30; Ctrl+A
at `/share` skipping volume rows; a Shift range across filtered-out rows; a filter change pruning the selection; the
selection's entries unchanged when the listing is later reloaded with different contents (concrete references);
duplicate references dropped; the too-many sentence; formatted size and date cells with their titles; menu
placement clamping (pure function over viewport, anchor and menu size); `sizeReport` with `capped`.

## 4. Toolbar, tree and F2 (U2)

4.1 **The toolbar does not wrap** at 1280, 1024 and 900 px: every action is a visible control or an item in ⋯. The
≤ 768 px rungs and their tests stay as they are. Suggested, not required: move the name filter and the Hidden toggle
into the path bar, tighten gaps, and collapse lower-priority secondary actions into ⋯ at a new wide rung when they
cannot fit. Labels keep their meaning; no icon-only button without an accessible name.

4.2 **Tree expansion fetches one page**: `limit: 500, dirsFirst: true`. When the page is full and every entry in it
is a folder and `total` exceeds it, the node ends with a non-interactive line, verbatim: `"More entries are not shown
— open this folder."` (a `treeitem`-free `div`, so keyboard navigation skips it). The destination picker keeps
direct path entry; ancestor reveal stops at the first link it cannot find, as it already does for hidden folders.

4.3 **F2 renames.** An app-scope binding that presses `#btnRename` when it is enabled and otherwise announces that
button's why-sentence; it is a listing chord (refused with the paused message while search results cover the
listing). KEYMAP, the `#dlgShortcuts` table and `keys_test.mjs` agree.

4.4 Tests: narrow/toolbar membership at the acceptance widths (extend the existing table), the tree's single page
and its continuation line, the F2 binding and the keymap cross-check.

## 5. Truth pass (D)

- **PLAN.md**: replace the stale status line ("planning complete, no code yet") with the current state; mark open
  questions 2 and 3 answered (root mode needs no re-arming — shipped since decision 6; both a hero and a QTS unit
  exist); point to the deliberation and this contract.
- **README.md**: status (M0–M4 implemented; the stabilization patch in progress; not yet released); the large-folder
  claim corrected (folders up to 50,000 entries, paging re-reads the folder, with 1.1 named for the fix); "never needs
  SSH" qualified for the break-glass setup; a compatibility matrix (QuTS hero h5.2.9 on ZFS, x86_64, verified on
  hardware; QTS 5.2.x on ext4 verified on hardware, its CPU architecture to be recorded at the hardware pass; any
  architecture not run on a physical unit is "built and smoke-run under emulation only"; firmware 6 untested); the
  keyboard table gains F2.
- **qpkg/qpkg.cfg**: `QTS_MINI_VERSION="5.2.0"`, with the comment saying it is the lowest firmware verified.
- **SECURITY.md**: how to report a vulnerability privately (GitHub private vulnerability reporting on this
  repository), what is in scope (the daemon, the worker boundary, the break-glass door, the QPKG), the documented
  residuals in PLAN.md that are known, and no promise of a response time the owner has not made.
- **CHANGELOG.md** `[Unreleased]`: Fixed / Changed entries for §1–§4 in user terms.
- **docs/keyboard.md**: F2.
- **docs/release-checklist.md** §3: a select-all of 1,000 items through Delete, Copy, Move, Permissions and Download;
  listing latency at 10,000 and 50,000 entries; a cross-dataset move's throughput; a capped Properties measurement
  reads "At least …".

## 6. Rules for every part

- INV-1 and INV-2 hold; no new dependency; Go stdlib only; LF endings; `gofmt`; no inline styles or `style`
  attributes in the UI; match the surrounding comment density and voice.
- Run what you can locally: the package's Go tests (`go test ./internal/<pkg>/ -run <yours>`), `node --test
  internal/web/*.mjs` for UI parts, and `GOOS=linux go vet ./internal/<pkg>/`. Windows Smart App Control may refuse a
  fresh test binary; say so rather than implying green. Linux-only behaviour is verified in CI by the conductor.
- Do not commit, push, or edit files outside your row in §0. Delete any scratch file you create.
- Report: files changed, what each change does, tests added and their results, anything not done and why, and any
  change you need in someone else's file.
