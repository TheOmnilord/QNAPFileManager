# Roadmap deliberation: what would make QNAPFileManager a great app

Date: 2026-10-20. The owner asked: "Please deliberate with Gemini (gemini-4-argon-high) and Codex (Astra high) how to
make this a great app."

**Participants.** gpt-6-astra through the Codex CLI at high reasoning effort, and gemini-4-argon-high through the
Antigravity CLI, both read-only against this repository at `c6a86a2`. Claude (Opus 5.5) conducted and judged,
standing in for Fable 5.1 under the working rules in [CLAUDE.md](../../CLAUDE.md).

**Method.** Three rounds:
1. Independent answers to one neutral brief.
2. Each model cross-examined the other's answer, with a sheet of facts the conductor had verified.
3. Both attacked the conductor's draft synthesis.

The conductor wrote down its own position before reading either model, so as not to be anchored by them. Every code
claim that moved a decision was checked in the code or reproduced in the running development build. The full text of
every brief and answer is in [roadmap-deliberation-transcripts.md](roadmap-deliberation-transcripts.md).

**Status: recommendations to the owner.** Nothing here is decided until the owner says so. PLAN.md and CLAUDE.md are
unchanged.

## Verdict

The engine is far ahead of the product. Behind the app stand:
- 54,000 lines of production Go;
- 65,000 lines of tests;
- 120 review logs.

In front of it:
- Nobody but its owner has installed it: no release, no stars, no issues.
- Its select-all shortcut highlights everything, then every action refuses.
- Its README promises responsiveness on "hundreds of thousands of entries"; the listing code does not deliver that.

All three participants converged on one thesis. A great app here is the tool a NAS administrator trusts when an
ordinary file task turns into an administration problem: finding package files, understanding a permission failure,
repairing ownership, moving data between datasets, recovering a deletion. Trust comes from three things:
- a released build that behaves correctly on the first click;
- an app that says honestly what it did;
- an app that has run on real hardware.

Therefore the recommended order is:
1. A short **stabilization patch**.
2. The **full hardware gate** on that exact build.
3. **v1.0.0**.
4. Releases that each add one capability administrators currently open SSH for:
   - 1.1: seeing large and ACL-heavy folders clearly;
   - 1.2: editing configuration safely;
   - 1.3: bringing data in.

Alongside that, review should be **tiered by consequence**. The uniform 10–19-round loop has stopped paying for itself.

## Who it is for

Administrators and technical NAS owners are the audience. Ordinary QTS users get correct, kernel-enforced behaviour
(INV-2) but do not drive the roadmap.

The bar it will be judged against has three parts:
- **File Station's familiarity**, for the everyday parts;
- **WinSCP or Midnight Commander over SSH**, for control;
- unusually clear reporting of consequences, where it can beat both.

Astra disagreed with the UX plan's ambition to replace File Station for everyday work. Whole-filesystem administration
is already a strong product on its own.

## Findings that change the release

Each finding below was verified by the conductor before it influenced a decision.

| # | Finding | Found by | Evidence | Disposition |
|---|---|---|---|---|
| 1 | `Ctrl+A` sets `state.exclude`. `selectionEntries()` then returns `null`, and Delete, Copy, Move, Permissions and archive download all refuse with "Select items individually to … in this version". | Gemini | Reproduced live in a five-item folder; list.js, actions.js, transfer.js, perms.js | 1.0 blocker |
| 2 | Every 500-row page re-reads, stats and sorts the whole directory; nothing is cached between pages. Past `MaxListLimit` (50,000) the read stops in `getdents` order *before* sorting, so the view is a sorted arbitrary subset. | Astra | internal/fsops/fsops.go:549–688, internal/fsx/entry.go:187 | 1.0 honest wording; 1.1 redesign |
| 3 | Expanding a tree node fetches every page of the folder. Combined with #2 that is quadratic. | Gemini | internal/web/static/js/tree.js:26–31 | 1.0 |
| 4 | An orphaned size walk has no lifetime bound and holds one of the four metadata slots shared with chmod/chown. | Gemini (a recorded residual) | m3-contract.md §17.17 | 1.0 bounds |
| 5 | Copy, move and delete pre-flights size and identify each root with its own worker RPC, one after another, under the 15 s deadline every ordinary route gets. The transfer route's own 30 s timeout can never be reached. A working select-all will send up to `maxJobRoots` (1,000) roots through this for the first time. | Gemini | server.go (15 s), routes_transfer.go:222–260, routes_perm.go (comment), routes_jobs.go:64 | 1.0: measured |
| 6 | Folders are not listed first (browse.go never sets `DirsFirst`). Names sort in byte order. Sizes are raw byte counts that truncate in an 80 px column. The context menu is pinned bottom-right, not at the pointer. The text toolbar wraps to two rows at 1280 px. `F2` is unbound. | Conductor (live), Gemini (F2, `DirsFirst`) | Dev build; list.js:356; app.css; browse.go:130 | 1.0 polish |
| 7 | `QTS_MINI_VERSION="4.5.0"` although only 5.2.x was tested. No `SECURITY.md`. PLAN.md still opens "planning complete, no code yet". The README still says M4 is in progress. | Astra | qpkg/qpkg.cfg:15; PLAN.md:3; README.md | 1.0 truth pass |
| 8 | The package identity `QPKG_NAME="QNAPFileManager"` embeds QNAP's mark, and App Center keys upgrades on it, so it is effectively permanent after the first public release. `QPKG_DISPLAY_NAME="File Manager"` cannot be searched for or told apart from File Station. | Conductor | qpkg/qpkg.cfg:1–2 | Owner, before 1.0 |
| 9 | Moves copy with `io.CopyBuffer` (no `copy_file_range`, by design, for cancellation and progress) and byte-verify both ends: about three reads and one write per byte. | Gemini, Astra | copy.go:146–151 | Benchmark; keep verification |
| 10 | Dropped folders are refused. | Gemini | upload.js `FOLDER_REFUSAL` | 1.3 |

## Disputes and how they were judged

**Accepted from round 3**, against the conductor's own draft:

- **Tier review by consequence, not by where the code lives** (Astra). Select-all decides which files a destructive
  operation targets. It is deep-tier work even though it is JavaScript.
- **Select-all must act on one consistent listing** (Astra). Pages fetched separately can overlap or omit entries while
  the directory changes. Selection is stored by row index. The fix:
  - fetch every eligible entry in one response;
  - capture concrete path references;
  - carry those references through confirmation and submission.

  In a filtered view, `Ctrl+A` means all matching entries in the stated scope. It is gated on the count of matches,
  not on the folder's total (Gemini).
- **The large-selection pre-flight must be exercised before select-all is enabled** (Gemini). Either the per-root RPCs
  are batched, or the supported limit is the one the hardware measured. The limit is stated before an action is
  enabled.
- **The wording of truncation must not overstate.**
  - A capped listing is "only the first 50,000 entries read were examined; others may be missing; sorting applies to
    this subset". Do not say "more than 50,000" unless an extra entry was seen.
  - The tree says "more entries are not shown — open this folder", because pages mix files and folders.
  - The destination picker keeps direct path entry and ancestor reveal (Astra).
- **Bounded size walks only, no reader-idle reaper, for 1.0** (Astra over Gemini's 15-second reaper). Time and entry
  bounds stop the unlimited work. A reaper is a new lifecycle protocol, with background tabs and reconnects to get
  right.
- **Listing generations move up to 1.1** (both). Paging that re-reads the folder is a core bottleneck, and pinned
  locations or folder upload must not queue ahead of it.
- **The editor contract was rewritten** (both). The conductor's "in-place write after a pre-image copy into an
  app-managed backup area" is withdrawn. The contract must settle all of the following before code:
  - **Crash and full-disk safety.** A failed save must never leave a truncated `/etc/config` file. Same-directory
    temporary file + `fsync` + `renameat` when `nlink == 1`; in-place only where a hardlink requires it.
  - **Metadata.** Preserve mode, owner, xattrs and ACLs, or report what differs.
  - **Backups.** Readable by no more people than the original; reachable from a rescue shell when QTS or the app is
    down (same filesystem, a documented place); never dropped into a directory that loads every file in it; with
    retention and space bounds.
  - **Concurrent writers.** Another tab, an SMB client, or the service that owns the file.
  - **Supported files.** Which files the editor will open at all.
- **The "interrupted operations from the audit log" idea is withdrawn** (both). Ordinary job results are written
  asynchronously and can be dropped, intent lines carry no job id, and the log rotates at 8 MiB and is root-only. An
  unmatched intent can mean a lost record rather than an interrupted job. If an "outcome unknown" view is ever wanted,
  it first needs job ids on intent lines and synchronous result lines.
- **The full checklist gates the first release** (Astra over Gemini and the conductor). The relay, cookie-replay and
  queued-`aclmode` items validate guarantees the documentation already claims. From 1.0.x on, tests are selected by
  changed component, using recorded evidence.

**Rejected:**

- **Dropping the move's byte verification for fstat checks** (Gemini, twice). Metadata equality does not prove byte
  equality, and deleting the source is the one irreversible step a move takes. Instead:
  - benchmark a cross-dataset move in the hardware gate;
  - a chunked `copy_file_range` path that keeps cancellation, progress *and* verification can follow if the numbers
    justify it.
- **Turning staging refusals into warnings** (Gemini). If an ordinary hero share is refused as `unverified`, capture
  its real ACL bytes as a fixture and fix the specific assumption that was wrong.
- **A break-glass `--allow-local` bypass** (Gemini). The self-address refusal is what stops a relay on the NAS from
  satisfying the session's address pin. A VPN client arriving from its own tunnel address is not refused. The rule
  stays; document the supported ways in.
- **A hard cap of two review rounds** (Gemini) and **no default cap** (Astra). See the review rule below.
- **Natural sort in 1.0.** Deferred until numeric runs, case and non-UTF-8 names are specified. Folders-first and
  case-insensitive order (with a byte tie-break) go in.
- **Durable job journals** (Astra, round 1). Withdrawn by Astra after Gemini's objection: high cost for a rare event.

## The plan

### Stabilization patch → 1.0 release candidate

Behaviour already offered is repaired. Nothing new is promised. Each item names its review tier.

1. **Select-all, end to end** (deep):
   - one consistent listing;
   - concrete references through to submission;
   - filtered scope defined and counted;
   - actions disabled with a why-sentence above the supported limit;
   - copy, move, delete and permissions pre-flights handle that limit within the request deadline;
   - tests with concurrent create, rename and delete.
2. **Bounded size walks** (deep): time and entry bounds, an explicit "at least …, incomplete" result, and capacity
   released only after cancellation completes.
3. **Tree expansion** (light): one page per expansion and an honest continuation line. The destination picker keeps
   path entry and ancestor reveal.
4. **Listing honesty** (light): the capped-listing wording above, and the README's scale claim corrected.
5. **Polish** (sort: deep; the rest: light):
   - folders first;
   - case-insensitive name order with a byte tie-break;
   - human-readable sizes, with exact bytes on hover and in Properties;
   - compact dates;
   - the context menu at the pointer;
   - a toolbar that fits one row at 1280 px, with the 768 px overflow menu intact;
   - `F2` renames.
6. **Truth pass** (light):
   - PLAN.md status block;
   - README status, scale claim, and "never needs SSH" qualified for break-glass setup;
   - `QTS_MINI_VERSION` set to the tested baseline;
   - `SECURITY.md`, with GitHub private vulnerability reporting turned on;
   - a compatibility matrix: QTS 5.2.x ext4 x86_64 and QuTS hero h5.2.x ZFS x86_64 verified; ARM64 built and smoke-run
     under emulation only; firmware 6 untested.
7. **The naming decision applied**, if the owner renames anything (see Owner decisions). It must land before the
   hardware pass, because install paths and the proxy path change with it.
8. **Four task screenshots**, taken after the polish:
   - browsing `.qpkg`;
   - the permissions dialog;
   - a cross-dataset move;
   - a Trash restore.

**Out of 1.0:** text editing, ACL display or editing, listing generations, folder upload, extraction, Trash retention,
copy-engine changes, durable job history, authentication changes, dual pane, SSE.

### Hardware gate

Run the whole of [release-checklist.md](../release-checklist.md) §3 on both units against the RC build. Add three
measurements:
- a cross-dataset move's throughput;
- listing latency at 10,000 and 50,000 entries;
- a select-all of the supported limit through each action.

Do **not** upgrade either unit to firmware 6: they are the only 5.2 baseline.

Recruit three to five outside testers (forum.qnap.com, r/qnap) during stabilization. Publishing does not wait for
them.

### 1.0.0 and 1.0.x

**1.0.0:**
- an annotated tag;
- a GitHub Release with the QPKG and `SHA256SUMS`, plus a GitHub build-provenance attestation;
- screenshots in the README.

GitHub Releases is the canonical source. Installation is by manual App Center install of the published artifact.

**1.0.x:**
- **A self-hosted App Center repository feed.** A repository XML on GitHub Pages, added by the user under App Center >
  Settings > App Repository, so updates show up in App Center. This is App Center's own mechanism, not a second
  privileged self-updater.
- **QNAP-recognised signing.** Investigate it (QDK's code-signing path, QNAP Club) without making any release depend on
  it.
- **The hardware self-test harness** (see the self-test section below).
- **Component-based test selection** for later releases.

### 1.1 — see everything clearly

- **Listing generations.** A worker-held, sorted snapshot per directory identity with a short lifetime. Paging no
  longer re-reads the folder, pages never overlap, and the 50,000 cap is either lifted or stated where it applies.
- **Read-only ACL entries.** Step A of [acl-plan.md](acl-plan.md), validated against real QTS and QuTS hero fixtures.
- **The editor contract**, written and reviewed (see the editor bullet in Disputes).

### 1.2 — edit and recover

- **The text editor**, built to that contract.
- **Trash.** Usage per volume; restore choices for a missing parent or an occupied name; retention that the
  administrator explicitly opts into, with a preview. `trash.days` is never silently activated by an upgrade.
- **Pinned locations.**

### 1.3 — bring data in

- **Folder upload.**
- **Archive extraction**, under its own contract: traversal, links, decompression bombs, conflicts, ownership.

### Later

- POSIX ACL editing (acl-plan step B).
- Snapshot browse and restore.
- The `copy_file_range` fast path, if the benchmark justifies it.
- An "outcome unknown" operations view, after its prerequisites.
- Natural sort, once specified.
- Dual pane, only on demonstrated demand.

### Cut or frozen

- **Cut:** the credential-proxy door on the main listener; server-side thumbnails.
- **Frozen** (no work planned): TOTP on break-glass, SSE.
- **Kept:** the review logs. Add a short index, `docs/reviews/README.md`, so they stop being the first thing a reader
  meets.

## The self-test

Both models adopted the conductor's on-device self-test idea, with changes, and the changes are what make it safe.

It is an **opt-in test harness**, built as a separate binary in the CI artifacts. It is not a subcommand of the root
daemon, and it is not part of a release blocker. Its rules:
- It creates its own fresh `0700` fixture directory and refuses an existing path.
- It removes only what it created.
- It drives operations through **real workers** as owner, non-owner and administrator. A root-only syscall probe
  cannot validate the per-user design.
- Read-only probes, scratch mutations, cross-volume tests and expensive benchmarks are separate stages.
- It reports exactly which claim each probe tests.

Browser, proxy and authentication checks stay manual. The goal is to make every hardware pass after 1.0 cheap and
repeatable.

## Review rule (owner decision)

If adopted, this replaces the ten-round rule recorded in CLAUDE.md.

1. **Tier by consequence, not by location.** Deep tier: anything that decides identity or authentication; which paths
   an operation touches (selection, path resolution, traversal); destructive or publishing operations; ACL writes;
   durability and audit. Light tier: presentation, formatting, documentation.
2. **Light tier:** one focused review plus a rendered-browser check.
3. **Every finding needs a concrete failure scenario inside the threat model.** Deliberate same-uid self-sabotage and
   local root are out of scope. Ordinary same-uid concurrency is in: another tab, an SMB client, a service writing
   the same file.
4. **Deep tier: three rounds by default.** A fourth needs a written reason in the review log. A loop ends when:
   - blocking findings are fixed and verified;
   - CI, including the non-root Linux race job, is green;
   - residuals are accepted by the owner.
5. **Findings that persist after three rounds trigger a design reassessment, not more rounds.**

## Distribution and trust

- **Two kinds of signature must not be confused.** QDK documents a GPG signature and QNAP's code-signing as separate
  mechanisms. A signed git tag does not remove App Center's warning.
- **The unsigned-app warning is real.** An unsigned QPKG installs only after "Allow installation of applications without
  a valid digital signature" is ticked, and Security Counselor then flags it. Say so in the install guide. Do not make
  the first release wait on QNAP.
- **The README opens with what users do.** First the four task screenshots, then a short "why you can trust this with
  root" list:
  - read-only by default;
  - per-user kernel identity;
  - the protected-path guard;
  - no network calls or telemetry;
  - the audit trail and QuLog.

  The engineering record stays available but stops being the front door.
- **Compatibility claims are proved claims.** ARM64 is "built and emulated", not "supported", until it runs on a
  physical ARM64 NAS. Firmware 6 is "untested" until a unit that is not a baseline runs it.

## The biggest risk

The two models named it differently and meant the same thing:
- Astra: complexity growing faster than evidence that people can finish ordinary tasks.
- Gemini: a fortress whose defensive checks refuse legitimate work on real QNAP filesystems.

Both point at one gap: the code is checked thoroughly, but real users on real hardware have never tried it. The
review loop found races in ever-more-exotic interleavings while the most-used shortcut in a file manager did not
work. It is retired by:
- the stabilization patch;
- the full hardware gate;
- an outside pilot judged on observable outcomes: people finish the core tasks without coaching, can say what changed,
  and can recover from an interruption.

## Owner decisions

1. **Approve the stabilization scope**, and that v1.0.0 waits for it.
2. **The name.** Both models: choose a distinctive display name now.
   - Gemini: also drop "QNAP" from `QPKG_NAME` now, while only the owner's two units have it installed (its examples:
     RootDeck, QDeck).
   - Astra: keep the package ID unless the owner accepts the migration (install path, proxy path, config location, a
     reinstall on both units). It made no legal finding.
   - Conductor: this is the only cheap moment for either change, so decide both in one sitting. If the package ID
     changes, it changes in the stabilization patch, so the hardware pass verifies it.
3. **The review rule above**, which amends CLAUDE.md and the working-rules memory.
4. **Still open from 2026-09-18:** the LAN break-glass listener's default. The standing recommendation is to keep the
   door and ship `web.breakGlass.enabled=false`.
5. **Firmware 6 coverage:** a third unit, an outside tester, or "untested" in the 1.0 notes.

## What each participant got wrong

Kept so that the record is honest about how much any single voice could be trusted.

**Gemini, retracted in round 2 after the facts sheet:**
- a break-glass "256-bit key file plus the OS admin password" (there is one bcrypt-hashed local password);
- an Apache `ProxyPass` file written by the service script (App Center's `QPKG_USE_PROXY` does the proxying);
- "placeholder" icons (they are the designed icon from 5bb64a9);
- domain users unresolved (`internal/idmap/exec_linux.go` resolves them);
- a README that omits M4.

**Gemini, not retracted but contradicted by the code:**
- an `openat2(RESOLVE_NO_SYMLINKS)` traversal (`openat2` appears only in a comment; the walks hold descriptors per
  component);
- a header `#chkAll` checkbox (no such element exists);
- "signed checksums and separate architecture packages" (one combined QPKG and a plain checksum file);
- a 66 % I/O saving from dropping verification.

**Astra:** its code claims held. It first suggested disclosing the listing cap might be enough for 1.0, and retracted
that once the tree amplification and the select-all failure were confirmed.

**The conductor, corrected in round 3:**
- classifying review tier by code location;
- "unsorted subset" and "N more folders" wording;
- the app-managed editor backup area;
- interrupted operations from the audit log;
- triaging the first release's checklist to about 20 items;
- a reader-idle reaper in 1.0.

**Missed by the conductor and caught by a model:** the select-all failure (Gemini), the listing re-read (Astra) and
the pre-flight deadline (Gemini).

## Sources

- QNAP, [Adding an app repository](https://docs.qnap.com/operating-system/quts-hero/5.1.x/en-us/adding-an-app-repository-BB9370CB.html)
  and [Install third-party apps repository in the App Center](https://www.qnap.com/en/how-to/faq/con_show.php?cid=2435).
- QNAP, [What to do if an app does not have a digital QNAP signature](https://www.qnap.com/en-gr/how-to/faq/article/what-to-do-if-an-app-does-not-have-a-digital-qnap-signature).
- QNAP Community, [QuTS hero h6.0.0.3397 Public Beta 3](https://community.qnap.com/t/quts-hero-h6-0-0-3397-build-20260206-public-beta-3-released/5314)
  and [the invalid-signature update report](https://community.qnap.com/t/critical-flow-issue-automatic-installation-bypasses-invalid-digital-signature-warning-during-beta-update/5706).
- [QDK Developer Guide](https://github.com/qnap-dev/QDK/blob/master/docs/QDK-Developer-Guide.md) (GPG and code
  signing, cited by Astra); [MyQNAP repository install](https://www.myqnap.org/install-the-repo/) (cited by Astra).
