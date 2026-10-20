# Roadmap deliberation — transcripts

The three briefs and six answers behind [roadmap-deliberation.md](roadmap-deliberation.md), 2026-10-20. Answers are
verbatim except that headings are nested one section deeper, the CLIs' footers are dropped, and Astra's absolute
links (`C:/Dev/QNAPFileManager/...`) are rewritten relative to this directory. The round-2 facts sheet corrected
several round-1 claims; read the answers with it in mind. Participants: gpt-6-astra (Codex CLI 0.153.3, reasoning
effort high, read-only sandbox, one resumed thread) and gemini-4-argon-high (Antigravity CLI via the Gemini plugin,
read-only, one resumed conversation).

## Round 1 — the shared brief

### Deliberation brief, round 1 of 3: how do we make QNAPFileManager a great app?

The owner's request, verbatim: "Please deliberate with Gemini (gemini-4-argon-high) and Codex (Astra high) how to make
this a great app."

You are one of two independent models answering this same brief (the other is from a different vendor). In round 2
you will see the other model's answer and be asked to challenge it; in round 3 you will challenge a synthesis. So in
this round give YOUR OWN view, be specific, and do not hedge into a generic list.

This is a read-only consultation. Do not modify, create or delete any file in the repository.

#### What the app is

QNAPFileManager (repository root = your working directory; public on GitHub as TheOmnilord/QNAPFileManager, MIT) is a
root-capable, per-user web file manager for QNAP QTS and QuTS hero NAS units, shipped as a QPKG installed from App
Center. A Go daemon started as root serves an embedded vanilla-JS UI that opens as a window inside the QTS web
desktop through QTS's reverse proxy, with no login of its own: identity comes from the QTS session. Every filesystem
operation runs in a worker process that has already dropped to the signed-in user's uid and groups, so the Linux
kernel decides permissions; administrators operate as root, as File Station does. Unlike File Station it reaches the
whole filesystem: `/`, `/etc`, `/root`, `.qpkg` trees, raw volume mounts.

#### Where it stands (2026-10-20)

- Milestones M0–M4 are on `main` (last commit c6a86a2, 2026-09-24): browse, mkdir/rename/delete, trash with
  restore/empty, recursive delete and folder size as jobs, copy/move with a cross-filesystem pre-flight and verified
  move, upload (picker and drag from desktop), zip/tar.gz archive download, bounded search, chmod/chown (single and
  recursive) with a post-call diff, ACL badges, a properties dialog, a text viewer, a read-only switch (on at first
  install), a protected-path guard and a confirmation ladder ending in a typed phrase, a JSON-lines audit log mirrored
  to QuLog, a break-glass TLS door on port 8771 for when QTS/Apache is broken, keyboard and screen-reader passes, a
  ≥768 px layout contract.
- Not yet tagged. v1.0.0 waits on a hardware pass on two units (a QuTS hero TVS-h1688X on ZFS and a QTS unit on ext4,
  firmware 5.2.x); M0–M2 were verified on that hardware, the final M3/M4 review rounds have not been.
- Size: about 54,000 lines of production Go, 65,000 lines of Go tests, 7,100 lines of UI JavaScript, 120 review logs
  under docs/reviews/. Each milestone went through up to 10–19 rounds of a high-effort automated adversarial review
  loop; most findings were concurrency, TOCTOU and identity-proof issues in the filesystem engine.
- Deferred to 1.1 (CHANGELOG.md "Deferred to 1.1"): automatic trash sweep, extract, ACL editing, thumbnails/previews,
  in-app drag-and-drop, text editing, a username/password door on the main listener, TOTP on break-glass, SSE for job
  progress (polling now), dual pane.
- Owner-set constraints you should treat as fixed unless you argue explicitly that one should change: Go standard
  library only (plus golang.org/x/crypto for bcrypt), CGO_ENABLED=0, single static binary, `go:embed` UI with no npm
  and no framework; INV-1 (the web layer never touches user data, only the per-user worker does) and INV-2 (the kernel
  decides permissions, the app only predicts); same-origin through the QTS reverse proxy.

#### Read before answering (cite paths when you rely on them)

README.md, PLAN.md, CHANGELOG.md, docs/identity.md, docs/release-checklist.md, docs/design/ui-ux-safety-plan.md,
docs/design/acl-plan.md, docs/research/existing-tools.md, docs/research/qts-integration-facts.md, and the UI in
internal/web/static/ (index.html, app.css, js/*.js). Skim internal/fsops/ and internal/web/ for the engine and API as
far as you need. If you use outside knowledge about QNAP (App Center, QNAP Club, QTS 5.x / QuTS hero behaviour, file
managers people compare against), say which facts you are confident in and which are assumptions.

#### What to send back (aim for 1,500–2,500 words, plain Markdown)

1. **Thesis.** In one paragraph: who the users really are, the jobs they hire this app for, and what "great" means
   for it. Name the bar it should be compared against.
2. **Top 10 moves, ranked by leverage.** For each: what to do, the user-visible value, the evidence in the repository
   (paths), rough cost (S/M/L), and the main risk. Include product, UX, performance, reliability, trust and release
   items as they deserve — not one of each by quota.
3. **Stop / cut / simplify.** What currently makes the app or the project worse and should be removed, frozen or
   simplified — features, process, complexity, documents. Be concrete.
4. **Release path.** What must happen before v1.0.0, and what 1.1, 1.2 and 2.0 should contain, in order.
5. **Distribution and trust.** How people find, install, update and come to trust a root-capable file manager on
   their NAS (App Center / QNAP Club / GitHub releases, signing, update channel, screenshots, documentation).
6. **The single biggest risk** to this becoming a great app, and how to retire it.
7. **What you are unsure of** and what you would want to verify on real hardware first.

Ground every claim you can in the repository. Where you disagree with a decision recorded in PLAN.md or the design
documents, say so and give the reason.

## Round 1 — gpt-6-astra

QNAPFileManager should become the tool a NAS owner trusts when an ordinary file task turns into an administration problem: finding package files, understanding a permission failure, repairing ownership, moving data between datasets, or recovering a mistaken deletion. Its primary users are owners and administrators; ordinary users deserve reliable support, but should not determine the feature roadmap. “Great” means completing these tasks with less uncertainty, effort, and accidental damage than the available alternatives. The bar is **File Station’s familiarity, the explicit control people seek from WinSCP or Midnight Commander, and unusually clear reporting of consequences**. I disagree with the ambition to replace File Station for everyday work in [the UX plan](../../docs/design/ui-ux-safety-plan.md). The whole-filesystem administration workflow is already a strong product.

My ten moves, ranked by leverage, follow. Costs include implementation and validation: **S** means days, **M** roughly one or two weeks, **L** several weeks.

1. **Make the next milestone a successful hardware release.**

   Freeze features and run the release package through both NAS units, recording firmware, package checksum, account type, result, and unresolved limitations. Add several observed sessions with owners who did not build the app: inspect a package directory, repair permissions on disposable data, move between shares, and restore a deletion.

   The value is discovering whether the existing capability actually works without coaching. [The release checklist](../../docs/release-checklist.md) explicitly identifies ordinary hero destinations being refused as the most likely transfer surprise. [The integration research](../../docs/research/qts-integration-facts.md) records proxy, HTTPS, and worker-execution failures that green CI missed.

   **Cost: M. Main risk:** hardware findings expand into another feature cycle. Fix release blockers; record other work separately.

2. **Fix the large-directory contract before advertising scale.**

   This is a concrete mismatch. [README.md](../../README.md) promises responsive directories containing hundreds of thousands of entries. However, [fsops.List](../../internal/fsops/fsops.go:549) collects entries, sorts them, and only then slices the requested page; [MaxListLimit](../../internal/fsx/entry.go:187) is 50,000. Each page invokes that listing work again. Browser windowing does not solve this server cost.

   For 1.0, disclose the limit prominently and verify that truncated listings and select-all cannot suggest broader coverage than they deliver. Subsequently introduce bounded, worker-owned listing generations, consistent pagination, and selection semantics tied to the displayed generation. Fresh authorization must still happen when executing mutations.

   Measure cold/warm listing latency, memory, and browsing during transfers on both units.

   **Cost: L; immediate disclosure S. Main risk:** caching stale identities or permissions while improving speed.

3. **Design the interface around three complete administration journeys.**

   Prioritize **find and inspect**, **change and verify**, and **move and recover**. Add per-user bookmarks and recent destinations; make resolved paths and mount boundaries easy to inspect; keep advanced permission controls available through progressive disclosure.

   [index.html](../../internal/web/static/index.html) currently gives many actions similar toolbar prominence. [narrow.js](../../internal/web/static/js/narrow.js) preserves access through overflow, which is good, but preserving every button is different from making the next action obvious. Retain the useful explanatory states in `why.js` and `empty.js`.

   Keep administrator-as-root semantics, but display “Administrator · operations run as root” where users act, rather than requiring discovery through Session.

   **Cost: M. Main risk:** hiding useful power controls. Test task completion at the actual QTS window size before rearranging them.

4. **Make operation outcomes useful after something goes wrong.**

   Extend Operations into a reliable answer to: “What changed, what remains, and what can I safely do next?” Cross-dataset moves should distinguish copying, verification, and source removal; cancellation should identify retained source and destination data.

   [copy.go](../../internal/fsops/copy.go) already contains valuable guarantees and substantial verification costs. [jobs.go](../../internal/jobs/jobs.go) explicitly keeps history only in memory and caps warning details at 100. [jobs.js](../../internal/web/static/js/jobs.js) already handles partial outcomes, so build on that.

   Persist bounded summaries with operation IDs and an “interrupted; outcome requires inspection” state after restart. Never infer success from a missing terminal record. Offer retry only where the recorded scope is complete and reauthorized.

   **Cost: L. Main risk:** accidentally building unsafe automatic replay or promising rollback.

5. **Ship ACL inspection before ACL editing.**

   Read-only ACL entries belong near the top of 1.1. A permission-repair tool that says an ACL exists but cannot show it leaves the user at the moment they most need help.

   [acl-plan.md](../../docs/design/acl-plan.md) records this exact owner complaint and already specifies bounded entries, POSIX masks, inheritance, unknown states, and a separate Windows ACL notice. Adopt that sequence. Explain that the group column can represent the POSIX ACL mask; show filesystem permissions separately from SMB-specific metadata.

   I agree with avoiding an authoritative effective-permissions calculator. I disagree with calling display hardware-independent merely because it is “parse only”: real hero encodings, access restrictions, and identity names still need validation.

   **Cost: M. Main risk:** presenting a partial ACL interpretation as the whole access decision.

6. **Test the rendered browser experience as a first-class system.**

   Preserve the existing Go and JavaScript tests, but add repeatable browser journeys covering selection, scrolling, confirmation, cancellation, session refresh, and focus return. Capture the default QTS window in both themes and perform the keyboard/NVDA checks.

   I specifically reject [the UX plan’s §7.2](../../docs/design/ui-ux-safety-plan.md) assertion that element-ID and endpoint checks replace most browser-test value. They cannot verify modal behavior, layout, event ordering, or selection visibility. Comments in [state.js](../../internal/web/static/js/state.js) document real failures involving session refresh, uploads, and hidden selections.

   This does not require npm or a framework in the application: use an external browser harness or a repeatable manual suite.

   **Cost: M. Main risk:** brittle tests that assert markup instead of observable behavior.

7. **Make provenance and support part of the product.**

   Publish a tested compatibility matrix, recognizable screenshots, exact release artifacts, clear update instructions, and a private vulnerability-reporting route. Add an operator-reviewed diagnostic export containing version, platform facts, relevant failure codes, and suitably minimized logs.

   [.github/workflows/build.yml](../../.github/workflows/build.yml) already pins build inputs and publishes checksums. [docs/qnap-install.md](../../docs/qnap-install.md) currently makes troubleshooting largely a shell exercise. Improve that first-response experience while preserving the useful detailed documentation.

   Explicitly distinguish **built for ARM64**, **smoke-tested under emulation**, and **verified on a physical ARM64 NAS**.

   **Cost: M, with external signing lead time unknown. Main risk:** signatures and review counts being mistaken for proof of safety.

8. **Add a deliberately small text editor after release stability.**

   Editing a small configuration file is directly connected to the reason this app exists. It deserves priority over thumbnails, media previews, and dual pane.

   Start with bounded text files, explicit encoding/line-ending handling, a before/after diff, concurrent-change refusal, and a recoverable previous version. Saving must preserve or explicitly report ownership, mode, and ACL consequences. A generic temporary-file rename can replace an inode and alter metadata; “atomic save” alone is not an adequate specification.

   [The UX plan](../../docs/design/ui-ux-safety-plan.md) originally included editing; [CHANGELOG.md](../../CHANGELOG.md) defers it, and [viewer.js](../../internal/web/static/js/viewer.js) supplies the current inspection surface.

   **Cost: L. Main risk:** apparently successful saves changing file semantics or racing another writer.

9. **Finish the Trash experience before automating deletion.**

   Show usage by volume, state clearly that retention is manual, and explain restore failures involving missing parents or occupied names. Provide deliberate recovery choices rather than leaving the user to reconstruct paths.

   [PLAN.md](../../PLAN.md) says `trash.days` is accepted but unenforced, and restore neither recreates missing parents nor resolves collisions. [trash.js](../../internal/web/static/js/trash.js) provides the existing panel.

   Add opt-in retention later, with a preview of eligible items and an understandable activity record. Do not silently activate a dormant configuration value during upgrade. Also distinguish logical trash size from actual reclaimed storage, especially on snapshot-backed volumes.

   **Cost: M. Main risk:** a convenience feature permanently deleting data users expected to retain.

10. **Reduce the cost of understanding and changing the system.**

    Keep the worker boundary, kernel authority, static binary, and vanilla UI. Those constraints are productive. Concentrate simplification on current-state documentation and the filesystem mechanisms that recur across operations.

    [copy.go](../../internal/fsops/copy.go) alone is approximately 221 KB. Changes to identity proofs deserve focused ownership and narrow interfaces. Extract common mechanisms only where their semantics are demonstrably identical; a broad rewrite would discard hard-earned knowledge.

    Replace fixed review-round quotas with risk-based exit criteria: reproducible findings, appropriate regression tests, reviewed residuals, and hardware evidence. [PLAN.md](../../PLAN.md) records M2-C ending at its review ceiling rather than a clean round.

    **Cost: M, ongoing. Main risk:** abstraction weakening operation-specific guarantees.

I would stop or simplify the following immediately:

- **Stop presenting every deferred feature as 1.1.** The changelog’s heading conflicts with the ACL plan’s display/2.0/3.0 sequence. Maintain one ordered roadmap.
- **Retire stale instructions from the active documentation.** `PLAN.md` opens with “no code yet,” retains superseded root-arming questions, and says M3/M4 Astra reviews have not happened. README still calls M4 ongoing. Preserve history, but label it historical and link to current decisions.
- **Freeze the credential-proxy login proposal.** The two existing doors already impose substantial complexity. Another authentication flow needs evidence of a failure the existing model cannot adequately address.
- **Keep thumbnails, dual pane, in-app dragging, and SSE off the next release’s critical path.** Existing copy/paste and polling already support the central jobs.
- **Replace categorical market claims with dated comparisons.** [existing-tools.md](../../docs/research/existing-tools.md) is useful research; “nothing maintained exists” is a claim requiring continued verification.
- **Correct “never needs SSH.”** Normal file management can meet that promise; initial emergency-door provisioning explicitly requires a root shell in [identity.md](../../docs/identity.md).

The release sequence should be explicit:

- **Before 1.0.0:** complete the exact-commit CI and two-unit hardware checklist; test installation, upgrade, restart during work, and removal using disposable fixtures; fix identity, data-integrity, and ordinary-workflow blockers; publish screenshots and current documentation; disclose listing limits and accepted residuals. Challenge `QTS_MINI_VERSION="4.5.0"` in [qpkg.cfg](../../qpkg/qpkg.cfg): support should initially track verified 5.2.x configurations unless older firmware is actually tested. Install the published artifact as the checklist requires.
- **1.1, in order:** repair demonstrated listing/selection problems; add ACL inspection; improve navigation and operation summaries; deliver diagnostics. Keep this a focused release.
- **1.2:** small-file editing, then Trash recovery and opt-in retention. Archive extraction follows only with a separate bounded design for traversal, links, conflicts, expansion limits, and ownership.
- **2.0:** POSIX ACL editing after Samba/QTS round-trip testing, then any justified richer transfer workflow. NFSv4 editing remains contingent on verified QNAP write semantics. A version number should not force an unproven backend into production.

For distribution, start with **GitHub Releases as the canonical source and App Center manual installation as the installation method**. State clearly whether the app is merely installable through App Center or actually listed in QNAP’s official catalog. The current pipeline supports the former; official listing should be pursued separately.

Keep immutable versions and checksums. Add authenticated release provenance or signed release manifests, and investigate QNAP-recognized package signing. These are distinct: [QDK documents separate GPG and QNAP code-signing mechanisms](https://github.com/qnap-dev/QDK/blob/master/docs/QDK-Developer-Guide.md). Do not imply that signing a Git tag removes App Center’s warning. [QNAP’s guidance](https://www.qnap.com/en/how-to/faq/article/what-to-do-if-an-app-does-not-have-a-digital-qnap-signature) describes the unsigned-app allowance as intended for development/testing; broad distribution should make trusted installation a concrete priority.

For community discovery, use QNAP forums and investigate an actively maintained third-party repository. [MyQNAP currently documents an App Center repository installation route](https://www.myqnap.org/install-the-repo/). I have not established current QNAP Club submission or signing arrangements, so I would not make launch depend on them.

Initially, update through App Center’s manual package replacement with clear instructions to finish active work. Later offer stable-channel notifications and a separately opted-in preview channel; avoid building a second privileged self-updater. Revise the checklist’s “exactly two artifacts” requirement if authenticated provenance needs additional release assets.

Show four real screenshots: browsing `.qpkg`, explaining permissions, a cross-dataset move, and recovering a deletion. Lead documentation with those tasks, followed by installation, permissions/identity, recovery, and troubleshooting. The thorough engineering record should remain available without becoming the first-run experience.

The single biggest risk is **complexity growing faster than evidence that users can complete ordinary tasks**. The repository already demonstrates why: review-driven staging protections can reject ordinary hero destinations, and substantial frontend state machinery exists to prevent session refresh from disrupting operations. Retire that risk through a release freeze and a small external pilot whose success criteria are observable: users finish the core tasks without coaching, can explain what changed, and can recover from an interruption. Further review should investigate failures against that standard.

My remaining uncertainties require hardware or observation:

- Whether ordinary inherited hero ACLs permit the intended copy/staging behavior.
- Actual listing latency and memory at 10,000, 50,000, and 200,000 entries, including concurrent directory changes.
- Cross-dataset move throughput and cancellation latency with many small files.
- ACL bytes, birth-time availability, domain groups, and QTS/SMB permission interactions.
- Upgrade interruption, low-space behavior, worker cleanup, and emergency access with Apache stopped.
- Whether new users understand read-only mode, administrator/root identity, loaded-name filtering, and partial outcomes.

The strongest QNAP-specific evidence here is the repository’s recorded 5.2.x hardware findings. Broader firmware compatibility, physical ARM64 behavior, distributor acceptance, and signing eligibility remain unverified. This was a source-based, read-only consultation; I did not run the app or modify the repository.
## Round 1 — gemini-4-argon-high


QNAPFileManager already has a stronger security and filesystem correctness architecture than any third-party NAS utility in its category: per-user privilege-dropped workers (`INV-1`), kernel-enforced permissions (`INV-2`), `openat2(..., RESOLVE_NO_SYMLINKS)` traversal (`internal/fsops/fsops.go:29-42`), and zero external runtime dependencies. However, the project has spent 120 adversarial review rounds (`docs/reviews/`) hardening edge-case theoretical races while leaving core admin workflows broken or incomplete—most notably a non-functional `Ctrl+A` / Select-All across the entire UI (`internal/web/static/js/list.js:42-43,626`), no way to edit configuration files in place (`internal/web/static/js/viewer.js:150-161`), opaque ACL warnings on a NAS OS where ACLs are pervasive (`docs/design/acl-plan.md:10-21`), and four milestones of code (`M2-B` through `M4`) that have not yet run on physical QNAP hardware (`PLAN.md:191,223,247,271`). Making this a great app requires pivoting immediately from synthetic adversarial review loops to real-NAS ergonomics, daily-driver admin workflows, and high-trust community distribution.

---

##### 1. Thesis

The real users of QNAPFileManager are homelabber power users, SMB sysadmins, and technical NAS owners who outgrow QNAP File Station the moment they need to inspect `.qpkg` installations, fix broken Docker/Container Station bind-mount ownership (`UID`/`GID` mismatches), edit `/etc/config` or custom startup scripts without opening an SSH client, clean up orphaned ZFS/ext4 directories, or recover when QTS's web tier is wedged. Non-admin household users are secondary beneficiaries of `INV-2`, not the people who install a root-capable QPKG. For these users, "great" means **WinSCP + Midnight Commander power with Synology File Station's responsiveness and desktop feel, backed by guardrails that prevent bricking the NAS**. The bar it will be judged against is not FileBrowser or OwnCloud (`docs/research/existing-tools.md:10-46`); it is **WinSCP over SFTP** for root surgery and **Synology DSM File Station** for everyday share management.

---

##### 2. Top 10 Moves, Ranked by Leverage

###### 1. Fix `Ctrl+A` and header "Select All" (`#chkAll`) before v1.0.0
- **What to do:** Stop setting `exclude: true` when the entire directory is already loaded in memory (`state.entries.length === state.total && !state.filter`), or materialize the selection indices `0..state.total-1` up to the 1,000-item batch limit (`internal/web/routes_mutate.go:34`).
- **User-visible value:** Restores bulk actions. Right now, pressing `Ctrl+A` (`internal/web/static/js/list.js:626`) or clicking `#chkAll` (`internal/web/static/js/list.js:647`) sets `state.exclude = true`. Because `selectionEntries()` (`internal/web/static/js/list.js:42-43`) returns `null` whenever `state.exclude` is true, **every bulk action in the app fails** after `Ctrl+A`—Delete (`internal/web/static/js/actions.js:604`), Copy/Move (`internal/web/static/js/transfer.js:390,412`), Permissions (`internal/web/static/js/perms.js:561`), and Archive Download (`internal/web/static/js/list.js:513`) all reject `null` with *"Select items individually to … them in this version"*, even in a 3-file folder.
- **Evidence:** `internal/web/static/js/list.js:42-43,513,626,647`, `internal/web/static/js/actions.js:604`, `internal/web/static/js/transfer.js:390,412`, `internal/web/static/js/perms.js:561`.
- **Cost:** **S** | **Main risk:** Folders >1,000 items still need a clear message until server-side `{all: true, exclude: [...]}` (`docs/design/ui-ux-safety-plan.md:208`) is wired in v1.1.

###### 2. Execute the physical NAS hardware pass and tune `stagingIn` / `EXDEV` moves on QuTS hero
- **What to do:** Run `docs/nas-checklist.md:1-73` on both target NAS units (QuTS hero TVS-h1688X on ZFS and QTS 5.2 on ext4) and relax `stagingIn` (`internal/fsops/copy.go:63-95`, `internal/fsops/acl_linux.go:198-250`) where ZFS default/inherited NFSv4 ACLs (`system.nfs4_acl` / `system.richacl`) cause legitimate share-to-share moves to abort as `unverified`.
- **User-visible value:** Ensures cross-share moves actually work on QuTS hero, where every shared folder is its own ZFS dataset (`PLAN.md:69`).
- **Evidence:** `PLAN.md:191-195` and `docs/release-checklist.md:64-66` explicitly warn that 18 rounds of review hardened `stagingIn` without hardware validation and may reject real QuTS hero shares.
- **Cost:** **M** | **Main risk:** Discovering ZFS xattr behavior on QNAP's kernel that requires reworking `captureIdentity` (`internal/fsops/acl_linux.go:198-246`).

###### 3. Ship safe in-place text editing with `expectMtime` and `.bak` backup
- **What to do:** Promote the text editor originally designed in `docs/design/ui-ux-safety-plan.md:52,72,474` (and dropped in `docs/design/m3-contract.md:435-436`) to the top of v1.1: atomic save preserving mode/ownership/xattrs, `expectMtime`/`expectSize` conflict check, LF/CRLF indicator, and optional `.bak` sibling creation when editing `Warn`-tier paths.
- **User-visible value:** `README.md:18` and `internal/guard/rules.go:35-42` state that editing `/etc/config` (`uLinux.conf`, `smb.conf`, `qpkg.conf`) and `.qpkg` startup scripts is a primary reason to install this app. Today, the viewer is strictly read-only (`internal/web/static/js/viewer.js:150-161`), forcing admins to download a config file to Windows/macOS, edit it locally (risking CRLF corruption), and re-upload it (risking permission/ACL loss).
- **Evidence:** `internal/guard/rules.go:35-42`, `internal/web/static/js/viewer.js:1-166`, `docs/design/ui-ux-safety-plan.md:52,72,474`.
- **Cost:** **M** | **Main risk:** Preserving inode/ACLs vs. atomic rename semantics on `/etc/config` (require in-place write + `.bak` copy when ACLs/hardlinks exist, or copy security xattrs to the `O_TMPFILE` before `linkat`).

###### 4. Ship read-only ACL inspection (`docs/design/acl-plan.md` Step A)
- **What to do:** Implement `docs/design/acl-plan.md:53-105` (Step A): decode `system.posix_acl_access` and `system.posix_acl_default` in `internal/fsops/acl_linux.go` and render the named-user/group entries and mask in `#dlgProps` and `#dlgPerms`, plus surface the NFSv4 ACL type cleanly on QuTS hero.
- **User-visible value:** On QTS (with Advanced Folder Permissions or Windows ACL support) and QuTS hero, almost every shared folder has ACLs. Currently, the app shows an `ACL` badge (`internal/web/static/js/badges.js:24-27`) and a frustrating dead-end warning: *"This item has an extended ACL that this app does not display"* (`docs/design/m3-contract.md:151-155`). Showing *who* has access turns the app into a real permissions debugger without the risk of ACL mutation.
- **Evidence:** `docs/design/acl-plan.md:1-105`, `internal/fsops/acl_linux.go:40-150`, `internal/web/static/js/perms.js:126-135`.
- **Cost:** **S** | **Main risk:** QuTS hero ZFS datasets use QNAP's proprietary/NFSv4 ACL xattrs (`docs/design/acl-plan.md:157-170`); until their wire format is inspected on the TVS-h1688X, label NFSv4 ACLs distinctly from POSIX ACLs.

###### 5. Eliminate double-read and userspace copying in cross-filesystem moves (`internal/fsops/copy.go`)
- **What to do:** Use `io.Copy` with Linux `copy_file_range(2)` / `sendfile(2)` (via Go's `os.File.ReadFrom` instead of hiding the concrete `*os.File` behind `io.CopyBuffer(dstFile, io.LimitReader(srcFile, ...), buf)` in `internal/fsops/copy.go:121-155`) and replace the full post-copy byte-for-byte re-read of both source and destination (`contentMatches` in `internal/fsops/copy.go:40-48,149`) with pre/post `fstat` (`size`, `mtime`, `ctime`, `ino`) verification plus `fsync`.
- **User-visible value:** Cuts cross-share move I/O by **66%** (from 3× file size—read source, write dest, re-read source + re-read dest—down to 1× kernel-space copy). Moving a 200 GB media folder between two ZFS shares on QuTS hero currently generates 600 GB of userspace read/write traffic.
- **Evidence:** `internal/fsops/copy.go:40-48,121-155`.
- **Cost:** **S** | **Main risk:** Preserving the per-chunk cancellation check (`internal/fsops/copy.go:130-137`) by looping `ReadFrom` over 16 MiB `io.LimitedReader` windows if `os.File.ReadFrom` unwraps `io.LimitedReader` (as Go's `internal/poll.CopyFileRange` does).

###### 6. Fix the orphaned size-walk slot leak and unbounded tree pagination
- **What to do:**
  1. Add a `MaxEntries` cap (e.g., 250,000) and a 15-second reader-idle reaper to `/api/jobs/size` (`docs/design/m3-contract.md:513-518`, residual `§17.17`).
  2. Cap the sidebar tree loop in `internal/web/static/js/tree.js:26-31`, which currently runs `for (let offset=0;;)` fetching every page of a directory until `entries.length >= res.total`.
- **User-visible value:** Prevents a soft-lock of all metadata jobs (`chmod`, `chown`, `size`, `trash`), which share a `ClassMetadata` limit of 4 (`docs/design/m3-contract.md:369`). Today, if a user opens `#dlgProps` (`internal/web/static/js/props.js:19-35`) on `/` or `/share` 4 times and closes the browser tab, 4 orphaned size walks can hold all 4 slots indefinitely. Capping `tree.js:26-31` prevents hanging the browser when expanding a parent directory with 50,000 subfolders.
- **Evidence:** `docs/design/m3-contract.md:369,513-518`, `internal/web/static/js/props.js:19-35`, `internal/web/static/js/perms.js:194-203`, `internal/web/static/js/tree.js:26-31`.
- **Cost:** **S** | **Main risk:** None; when the tree or size walk hits the cap, display `≥ N items (truncated)`.

###### 7. Add recursive folder upload (drag-and-drop and directory picker) and fix 0-byte extensionless file drops
- **What to do:** Traverse `DataTransferItem.webkitGetAsEntry()` trees in `internal/web/static/js/upload.js:155-187` to create subdirectories and queue files, and remove the broken heuristic at `internal/web/static/js/upload.js:179` (`if (Number(file.size)===0 && !file.type) return {files:[], hadFolder:true}`) which misclassifies every 0-byte extensionless file (`.gitkeep`, `Dockerfile`, lockfiles) as a folder when `webkitGetAsEntry` is unavailable.
- **User-visible value:** Dropping a folder from the desktop is table stakes for a web file manager; rejecting it (`internal/web/static/js/upload.js:185`) forces users to zip on desktop, upload, and wait until v1.1 has archive extraction.
- **Evidence:** `internal/web/static/js/upload.js:155-190`.
- **Cost:** **M** | **Main risk:** Ordering `mkdir` calls ahead of file uploads and respecting the 250-item upload queue cap (`internal/web/static/js/upload.js:13`).

###### 8. Add server-side archive extraction (`.zip`, `.tar.gz`, `.tgz`, `.tar`) as a background job
- **What to do:** Add `/api/jobs/extract` running in the per-user worker (`INV-1`), extracting into a dedicated subfolder or current directory with strict zip-slip/path-traversal rejection, symlink rejection (`RESOLVE_NO_SYMLINKS`), decompression bomb byte/entry limits, and `ClassTransfer` quota tracking.
- **User-visible value:** Completes the archive round-trip (`CHANGELOG.md:223`). Admins routinely upload `.tar.gz` or `.zip` releases, scripts, or container configs to their NAS and need to unpack them without SSH.
- **Evidence:** `CHANGELOG.md:223`, `internal/web/routes_transfer.go:1-120`.
- **Cost:** **M** | **Main risk:** Zip-slip, embedded symlinks pointing outside the extraction root, and tar sparse-file expansion exhausting disk space.

###### 9. Fix Break-Glass VPN / SSH-tunnel lockouts (`internal/web/breakglass.go`)
- **What to do:** Replace the blanket rejection of connections whose source IP matches a local NAS interface (`docs/design/m4-contract.md:606-608`, `docs/qnap-install.md:169-175`) with an explicit allowlist option or loop-avoidance check that only blocks requests originating from the Apache reverse-proxy loop, or allow `127.0.0.1` / VPN interfaces when `--allow-local` is set in `/etc/config/qnap-filemanager/breakglass.conf`.
- **User-visible value:** Remote sysadmins almost always reach their NAS during an outage via **QVPN, WireGuard, Tailscale subnet routing, or an SSH port-forward (`ssh -L 8771:127.0.0.1:8771`)**—all of which can present the NAS's own tunnel/loopback IP as the TCP peer and get rejected by the current check (`docs/design/m4-contract.md:606-608`).
- **Evidence:** `docs/design/m4-contract.md:606-608`, `docs/qnap-install.md:169-175`.
- **Cost:** **S** | **Main risk:** If a user runs an open forward proxy on the NAS itself, an attacker could reach `:8771`, which is still gated by the 256-bit `breakglass.key` + `admin` password + rate limiter.

###### 10. Complete keyboard & dual-pane power-user workflows (`F2`, `Shift+Delete`, and Tab-switched Dual Pane)
- **What to do:**
  1. Bind `F2` (Rename focused item) and `Shift+Delete` (Permanent delete dialog) in `internal/web/static/js/keys.js:53-83` and `internal/web/static/index.html:173-202`—both were promised in `docs/design/ui-ux-safety-plan.md:216,273` and omitted in M4 (`internal/web/static/js/keys.js:28-29`).
  2. In v1.2, add an optional `Tab`-switched dual-pane view (`F5` copy across panes, `F6` move across panes) reusing the existing `transfer.js` pre-flight engine.
- **User-visible value:** Eliminates the multi-step modal tree picker (`#dlgTransfer`, `internal/web/static/js/transfer.js:180-260`) for admins reorganizing shares or copying files between `/share/Container` and `/share/Multimedia`.
- **Evidence:** `docs/design/ui-ux-safety-plan.md:216,273`, `internal/web/static/js/keys.js:28-29,53-83`, `internal/web/static/index.html:173-202`.
- **Cost:** **S** (`F2`/`Shift+Del`), **L** (Dual Pane) | **Main risk:** Dual-pane layout density at the 768 px minimum width (`internal/web/static/app.css:185`)—auto-collapse to single pane below 1,100 px.

---

##### 3. Stop / Cut / Simplify

1. **Stop the unbounded 10–19 round automated adversarial review loops (`docs/reviews/`).**
   - Across M0–M4, 120 review logs (`docs/reviews/m3-astra-round10.md`, `docs/reviews/m4-astra-round10.md`, etc.) pushed `internal/fsops/copy.go` to 221 KB (5,196 lines) and `internal/web/breakglass.go` to 114 KB. Late rounds chased synthetic threat models—such as two adversarial users sharing a single browser tab (`internal/web/static/js/actions.js:78-84`) or a root attacker on the NAS racing `stagingIn` (`docs/design/m4-contract.md:581-633`, where the contract itself finally had to declare local root out of scope!). Cap future milestone reviews at **3 rounds max**, gated by a explicit threat-model boundary (`INV-1`, `INV-2`, network/CSRF/XSS, symlink traversal, and loss-less crash recovery).
2. **Cut "Username/password door on main listener" and "TOTP on break-glass" from the 1.1 roadmap (`CHANGELOG.md:223`).**
   - A separate password login on port 8770 duplicates QTS authentication, creates a second credential store or PAM attack surface on normal LAN traffic, and weakens the "zero-login QTS session integration" value proposition (`README.md:5`). TOTP on break-glass is an anti-feature: break-glass (`internal/web/breakglass.go`) already requires a 256-bit random token from `/etc/config/qnap-filemanager/breakglass.key` **plus** the `admin` OS password (`docs/qnap-install.md:176-184`). Adding TOTP to an emergency recovery door creates clock-skew lockouts when NTP/QTS is broken.
3. **Cut server-side media thumbnails/transcoding from the roadmap (`CHANGELOG.md:223`).**
   - Generating image/video thumbnails inside the Go worker violates the spirit of `CGO_ENABLED=0` single-binary simplicity, bloats memory on NAS units, and competes poorly with QTS Multimedia Console / QuMagie. At most, allow the browser's native `<img>` tag to preview a single selected image on demand in the viewer modal (`internal/web/static/js/viewer.js`).
4. **Reconcile and prune stale documentation (`PLAN.md`, `README.md`, `docs/reviews/`).**
   - `PLAN.md:3,240,262,268` still says the repository is at M3 with M4 "not started", and `README.md:12-14,29-32` omits M4 features (break-glass, audit log, QuLog, keyboard map) while linking to non-existent release URLs. Archive the 120 `docs/reviews/` files into a single summary or separate branch so contributors can navigate `docs/`.

---

##### 4. Release Path

- **Before `v1.0.0` (ship blocker list):**
  1. Fix `Ctrl+A` / `#chkAll` selection materialization (`internal/web/static/js/list.js:42-43,626,647`).
  2. Cap orphaned size walks (`docs/design/m3-contract.md:513-518`) and unbounded sidebar tree pagination (`internal/web/static/js/tree.js:26-31`).
  3. Update `README.md:10-48` and `PLAN.md:1-15,240-275` to match `CHANGELOG.md:15-225`, and replace placeholder screenshots/icons (`qpkg/icons/`).
  4. Run the full hardware verification pass (`docs/nas-checklist.md` and `docs/release-checklist.md:56-75`) on both the QuTS hero ZFS NAS and QTS ext4 NAS; adjust `stagingIn` (`internal/fsops/copy.go:63-95`) if ZFS ACLs trip false-positive `unverified` errors.
  5. Tag `v1.0.0` so `.github/workflows/build.yml:222-320` publishes the signed checksums and `x86_64` / `arm64` `.qpkg` artifacts.
- **`v1.1` (The Sysadmin Daily-Driver Release):**
  - Safe in-place text editor with `expectMtime` and `.bak` toggle (`docs/design/ui-ux-safety-plan.md:474`).
  - Read-only POSIX & NFSv4 ACL inspection in `#dlgProps` and `#dlgPerms` (`docs/design/acl-plan.md` Step A).
  - Cross-FS move kernel fast-path (`copy_file_range` + `fstat` verification instead of double-read in `internal/fsops/copy.go:40-48,149`).
  - Archive extraction job (`.zip`, `.tar.gz`, `.tar`) and recursive folder drag-and-drop upload (`internal/web/static/js/upload.js:155-190`).
  - Break-glass local/VPN interface flag (`internal/web/breakglass.go`) and `F2` / `Shift+Delete` shortcuts (`internal/web/static/js/keys.js`).
  - Scheduled/automatic trash retention sweep (`CHANGELOG.md:223`).
- **`v1.2` (Power Workflow & Live Telemetry Release):**
  - Optional `Tab`-switched dual-pane commander mode (`F5` copy / `F6` move) and in-app drag-and-drop (`CHANGELOG.md:223`).
  - Server-Sent Events (SSE) for real-time job progress (`CHANGELOG.md:223`).
  - Server-side `{all: true, exclude: [...]}` batch actions for 100k+ entry directories (`docs/design/ui-ux-safety-plan.md:208`).
  - Bookmarks / pinned paths in the left tree (e.g., `/share`, `/etc/config`, `/share/CACHEDEV1_DATA/.qpkg`).
- **`v2.0` (Deep NAS Mastery Release):**
  - Full POSIX ACL editing (`docs/design/acl-plan.md` Step B) and ZFS/QuTS hero snapshot `.zfs/snapshot` browse & one-click file restore UI.
  - Checksum verification / computation tool (`SHA-256` / `BLAKE3` background job) and side-by-side config file diff viewer (comparing a config file against its `.bak` or snapshot version).

---

##### 5. Distribution and Trust

*(Confidence note: The following statements about QNAP App Center, QTS 4.3.6+ code-signing badges, and MyQNAP.org vs. QNAPClub.eu are confident industry facts; exact current review turnaround times at QNAP are assumptions.)*

1. **Where QNAP users actually find third-party QPKGs:**
   - Official **QNAP App Center** inclusion requires passing QNAP's internal security review, which is historically reluctant to approve third-party apps that run as `root` and expose `/` (`docs/research/qts-integration-facts.md:62-64`). Apply to App Center, but do not block on it.
   - In practice, power users install third-party QPKGs via custom XML repository feeds added in *App Center → Settings → App Repository* (historically QNAPClub.eu, now largely succeeded by **MyQNAP.org** and self-hosted GitHub Pages XML feeds) or by manual `.qpkg` upload from GitHub Releases.
2. **Self-hosted App Center XML repository on GitHub Pages:**
   - Publish a static App Center repository XML feed on GitHub Pages backed by GitHub Releases. Once a user adds that single HTTPS URL to QTS App Center, they get native **one-click install and update notifications** inside QTS App Center without manual `.qpkg` downloads.
3. **Code signing, SLSA provenance, and reproducible builds:**
   - Since QTS 4.3.6+, unsigned packages display an orange *"No digital signature"* warning in App Center (`docs/qnap-install.md:20`). Document clearly how to verify the `.sha256` digest (`.github/workflows/build.yml:261-265`), enable GitHub Artifact Attestations (`actions/attest-build-provenance`) in `.github/workflows/build.yml`, and make the `.qpkg` build reproducible (`SOURCE_DATE_EPOCH`).
4. **Visual and architectural trust on first visit:**
   - Replace the placeholder 1 KB icons in `qpkg/icons/` before `v1.0.0`.
   - Put a 30-second GIF/screenshot tour and a 5-bullet **"Why you can trust this with root"** box at the top of `README.md` highlighting: (1) starts in **Read-Only mode** (`internal/web/server.go`), (2) per-user kernel privilege drop (`INV-1`/`INV-2`, `docs/identity.md`), (3) Protected-Path Guard on `/proc`, `/sys`, `/dev` (`internal/guard/rules.go`), (4) zero external network calls or telemetry, and (5) full QuLog + JSONL audit trail.

---

##### 6. The Single Biggest Risk — and How to Retire It

**The single biggest risk is shipping an over-constrained "fortress" whose defensive checks reject or cripple legitimate sysadmin operations on real QNAP filesystems.**

Because M2-B, M2-C, M3, and M4 underwent ~70 rounds of synthetic adversarial review without running on the physical QTS and QuTS hero units (`PLAN.md:191,223,247,271`), several mechanisms are tuned to fail closed on conditions that are normal on a NAS:
- `Ctrl+A` sets `exclude: true` and every action refuses `exclude: true` (`internal/web/static/js/list.js:42-43,626`).
- `stagingIn` (`internal/fsops/copy.go:63-95`, `internal/fsops/acl_linux.go:198-250`) refuses cross-dataset moves if destination security/ACL xattrs differ from the source after `fchmod`—which happens routinely on QuTS hero ZFS datasets with ACL inheritance (`PLAN.md:191-195`).
- Break-glass (`docs/design/m4-contract.md:606-608`) rejects connections whose source IP belongs to the NAS, locking out admins connecting over NAS-hosted VPNs or SSH tunnels.

**How to retire it:** Run a mandatory **"Real Sysadmin Tasks" acceptance suite on both physical NAS units** before tagging `v1.0.0` (moving files across ZFS shares with inherited ACLs, using `Ctrl+A` + Copy/Delete, fixing permissions on a Container Station folder, editing a config workflow, and reaching break-glass over VPN/SSH tunnel), and convert any false-positive hard refusal into a clear pre-flight warning or option.

---

##### 7. What I Am Unsure Of (Verify on Hardware First)

1. **QuTS hero ZFS ACL xattr behavior during `stagingIn` (`internal/fsops/acl_linux.go:198-250`):** Which exact `system.*` xattrs does QNAP's ZFS kernel module expose to `llistxattr(2)` on the TVS-h1688X, and does creating an `O_TMPFILE` or staging dir inside a share with inherited ZFS ACLs cause `verifyIdentity` (`internal/fsops/copy.go:75-85`) to abort every cross-share move?
2. **QTS 5.2 Apache reverse-proxy idle timeout and buffering on large transfers:** `qpkg/shared/QNAPFileManager.sh:50-65` generates `/etc/apache-sys-proxy-qnap-filemanager.conf` with `ProxyPass /qnap-filemanager/ http://127.0.0.1:8770/ retry=0`. Without `timeout=3600` or `flushpackets=on`, does QTS Apache kill multi-gigabyte uploads (`internal/web/routes_transfer.go`) or slow archive downloads at the default 60-second `ProxyTimeout`?
3. **Domain / AD / LDAP UID & GID resolution in `internal/fsops/idmap_linux.go`:** The worker parses `/etc/passwd` and `/etc/group` directly (`CGO_ENABLED=0`, no NSS/winbind). On a QNAP joined to Active Directory or LDAP where domain users live only in winbind (`UID >= 1000000`), verify that `#dlgPerms` (`internal/web/static/js/perms.js:598-601`) cleanly supports raw numeric UID/GID entry without confusing warnings.

---

##### Next Steps

1. **Fix the 3 pre-release code defects** (`Ctrl+A` in `internal/web/static/js/list.js:42-43,626`, size-walk cap/reaper in `docs/design/m3-contract.md:513-518`, and tree pagination cap in `internal/web/static/js/tree.js:26-31`).
2. **Run the hardware verification checklist** (`docs/nas-checklist.md`) on the QuTS hero TVS-h1688X and QTS 5.2 ext4 units, specifically testing cross-share moves on ZFS, multi-GB proxy uploads/downloads, and break-glass over VPN/SSH tunnel.
3. **Update `README.md`, `PLAN.md`, and `qpkg/icons/`**, tag `v1.0.0`, publish the GitHub Pages App Center XML repository, and begin `v1.1` with in-place text editing and read-only ACL display.

## Round 2 — the shared facts sheet

Each model received this sheet, then the other model's round-1 answer, then the questions below.

### Deliberation, round 2 of 3: cross-examination

Below is the round-1 answer of the OTHER model, given the same brief you answered. Read it critically against the
repository; it may be wrong about the code, about QNAP, or about priorities. Do not defer to it, and do not dig in for
the sake of it either. This is still a read-only consultation: do not modify any file.

#### Facts the conductor verified after round 1 (2026-10-20)

Checked in the code and, where marked, reproduced in the running development build (`serve -dev -jail
testdata/fakeroot`). These settle the factual disputes; argue about priorities, not about these.

Confirmed:
- **Select-all is broken.** `Ctrl+A` (list.js) sets `state.exclude=true` with an empty set, `selectionEntries()`
  returns `null` in that mode, and Delete, Copy, Move, Permissions and archive download then refuse with "Select items
  individually to … in this version" — reproduced live in a five-item folder: every row highlights, the toolbar
  enables Delete/Copy/Move/Permissions, and Delete answers that sentence in the status bar.
- **Large directories.** `fsops.List` (internal/fsops/fsops.go:549) reads and stats the whole directory up to
  `MaxListLimit` = 50,000 entries, sorts, then slices one page; nothing caches between pages. A directory beyond 50,000
  entries is cut in `getdents` order before sorting, so the sorted view silently covers an arbitrary subset. The UI
  pages 500 rows at a time (list.js), so scrolling a 50,000-entry folder re-lists it about 100 times; `tree.js`
  fetches every page of a folder to build one tree node. The README promises responsiveness on "hundreds of
  thousands of entries".
- **Orphaned size walk** has no lifetime bound and holds one of four metadata slots shared with chmod/chown
  (docs/design/m3-contract.md, §17 item 17); the reader-idle reaper is recorded as a v1.1 item.
- **Folder drops are refused** (upload.js `FOLDER_REFUSAL`); the 0-byte heuristic only applies where the browser lacks
  `webkitGetAsEntry`. `F2` is unbound; `Shift+Delete` is deliberately unbound (keys.js:29).
- **Copy engine** deliberately uses `io.CopyBuffer`, not `ReadFrom`/`copy_file_range` (copy.go:146-151, for per-buffer
  cancellation and progress), and a move byte-verifies source and destination before deleting the source.
- `qpkg.cfg` declares `QTS_MINI_VERSION="4.5.0"`; only 5.2.x has been tested. No `SECURITY.md`. Job history is
  in-memory with per-job warnings capped at 100 (`jobs.WarnCap`). `PLAN.md` still opens "planning complete, no code
  yet"; the README still says M4 is in progress.
- Observed live in the UI: folders are not sorted first (`fsx.ListOptions.DirsFirst` exists, the UI does not request
  it); names sort in byte order (case-sensitive, not natural); sizes are raw byte counts (list.js:356) that truncate in
  their column; the right-click menu opens pinned to the bottom-right corner rather than at the pointer; the
  text-only toolbar wraps to two rows at 1280 px.
- GitHub: 0 stars, 0 forks, 0 issues, no release has ever been published. Nobody but the owner runs this app.

Not true (claims made in round 1 that the code contradicts):
- The break-glass door has ONE local password, set from the NAS shell and stored as a bcrypt hash; there is no key file
  and no QTS/OS admin password involved (docs/qnap-install.md, internal/breakglass/).
- The service script generates no Apache `ProxyPass` configuration; the proxy is App Center's `QPKG_USE_PROXY`.
- `qpkg/icons/*.gif` are the deliberately designed app icon (commit 5bb64a9), not placeholders.
- Domain users ARE resolved, by a bounded exec of `id(1)`/`getent(1)` (internal/idmap/exec_linux.go).
- The README does describe the break-glass door, the audit log and the keyboard map.

Partly true:
- The break-glass door refuses a login whose TCP peer is any address of the NAS itself (loopback, its LAN address,
  its own VPN interface addresses) — deliberately, because a relay on the NAS would satisfy the session's address pin
  and let a replayed cookie through (docs/qnap-install.md §break-glass). A VPN client arriving from its own tunnel
  address is not refused; an SSH tunnel or `socat` forward running on the NAS is.

Outside facts (web, 2026-10-20):
- App Center supports third-party repositories: Settings > App Repository > Add (name + repository XML URL; QNAP Club
  publishes https://www.qnapclub.eu/en/repo.xml), after allowing non-QNAP apps under Settings > General. The Update tab
  can notify about or auto-install updates.
- A QPKG without a valid QNAP signature installs only after the admin ticks "Allow installation of applications without
  a valid digital signature", and Security Counselor then flags it. A 2021 forum reply (not official) says QNAP Club can
  sign packages uploaded to it.
- QuTS hero h6.0 has been in public beta since February 2026; QNAP lists apps removed or temporarily unavailable on it.
  Nothing in this repository has been tested on firmware 6.



#### What to send back (about 1,000–1,800 words)

1. **Agree:** the points of theirs you accept, and which of your own ranks they change.
2. **Disagree:** each point of theirs you reject, with the reason and the evidence (paths, or a stated assumption).
3. **Missed:** what they found that you did not, and what you found that they did not and still stand by.
4. **Retract:** anything in your own round-1 answer you no longer stand by, given their answer or the facts above.
5. **Revised top 10**, ranked, one line each with cost (S/M/L), and the **one thing to do next week**.
6. **The release question, sharply:** should v1.0.0 ship essentially as it is after the hardware pass, or should
   named work (a bug fix, a polish pass, a missing feature, a simplification) land first? Pick one, name exactly
   what is in and out, and defend it.
7. **The review-process question, sharply:** both of you criticised the 10–19-round adversarial review loop. Propose
   the concrete replacement rule (what gets the deep loop, what gets a light pass, what ends a loop) in five lines or
   fewer.

## Round 2 — gpt-6-astra

**I agree with Gemini’s diagnosis more than its remedies.** The verified failures strengthen the case for a short stabilization milestone before release. They do not justify weakening verified moves, relaxing authentication checks, or replacing lengthy review quotas with an arbitrary three-round quota.

**What I accept, and how my ranking changes.** Select-all becomes my first priority. A five-item folder whose rows highlight and whose enabled actions subsequently refuse is a broken basic interaction, not an advanced feature omission. Gemini found this; my first answer did not.

The orphaned size walk also moves ahead of feature work. [The M3 contract](../../docs/design/m3-contract.md:513) explicitly records an uncapped measurement holding a metadata slot after its reader disappears. The tree’s automatic page exhaustion compounds the browsing problem: [tree.js](../../internal/web/static/js/tree.js) fetches every page before finishing an expansion. Both deserve pre-release containment.

I retain hardware validation as the release gate, ACL inspection as the first substantive addition afterward, and administrators as the primary audience. I also accept F2 as a worthwhile small improvement. Folder upload and extraction are useful, but the confirmed defects make them less urgent.

The conductor’s observations change my UX recommendation from a broad journey redesign to concrete repairs: readable sizes, folders-first ordering, a context menu at the pointer, usable toolbar organization, and reliable selection. Those improvements have clearer evidence than my proposed bookmarks.

**What I reject.**

1. **Removing byte verification from moves.** Metadata equality and `fsync` do not establish source/destination byte equality. The guarantee in [copy.go](../../internal/fsops/copy.go) deliberately makes that distinction before deleting the original. Gemini’s arithmetic is also wrong: copying plus rereading both sides entails three logical reads and one write per byte. Eliminating verification removes two reads; kernel-assisted copying does not inherently eliminate storage I/O. Physical traffic depends on caching and filesystem behavior.

   Benchmark first. Investigate a bounded kernel-copy fast path separately, preserving cancellation, progress, and verification. This is neither an established 66% improvement nor an S-sized safe change.

2. **Converting unexplained staging refusals into warnings.** The engine already distinguishes legitimately shared destinations from suspicious or unverifiable staging. A hardware failure should produce a captured fixture and an explanation of which assumption was wrong. It should not automatically downgrade a safety decision. “A root administrator could do it over SSH” does not make substitution by another writable-share participant harmless. The relevant distinctions are documented in `copy.go` and `internal/fsops/acl_linux.go`.

3. **Adding a break-glass local-peer bypass.** The conductor settles the VPN distinction and the nonexistent key-file claim. [breakglass.go](../../internal/web/breakglass.go) explains the actual concern: cookies are host-scoped, and a NAS-local relay can defeat address-based replay protection. An allowlist would not establish that the request is benign. Keep the present rule; document supported remote-access topologies and test them. Supporting SSH forwarding would require a new authentication/session design, not an `--allow-local` escape hatch.

4. **Treating the editor as an atomic-save recipe.** I agree with the feature, but not the proposed implementation shortcut. In-place writing preserves inode relationships while risking partial content; replacement changes inode relationships and can affect ownership, ACLs, hardlinks, and service behavior. An optional sibling `.bak` is not a complete recovery policy, and size/mtime alone is a weak concurrent-change check. Define supported files and save semantics first. I retain **L**, after stabilization, rather than Gemini’s **M** near-immediate implementation.

5. **Calling the size/tree fix risk-free.** A 15-second reader-idle timeout could cancel useful work during a background-tab delay or transient disconnection. Polling Operations could also keep abandoned work alive unless “reader” is defined carefully. Conversely, an entry cap must never become an apparently exact folder size. For 1.0, bounded measurement with explicit incomplete results is simpler than introducing a new lease protocol. Cooperative cancellation cannot guarantee recovery from every blocked kernel I/O call.

6. **Bundling power features into 1.1.** Editor, extraction, recursive upload, retention deletion, authentication changes, and copy-engine changes introduce several independent failure domains. That roadmap reproduces the problem both answers criticize. Dual pane and SSE come after evidence of demand. Shift+Delete is deliberately unbound in [keys.js](../../internal/web/static/js/keys.js); an old design sketch does not make that a defect.

7. **The categorical security and distribution claims.** “Stronger than any third-party utility” is unsupported. The cited traversal description does not establish an `openat2(RESOLVE_NO_SYMLINKS)` implementation; the repository describes held-descriptor, per-component walks. The icon, Apache configuration, domain-resolution, and break-glass credential claims are retracted by the conductor’s findings. The pipeline publishes one combined-architecture QPKG and an ordinary checksum file, not the asserted signed checksums and separate architecture packages. QNAP signing eligibility and catalog acceptance remain external questions.

8. **Deleting review history or imposing three rounds maximum.** Retain the evidence and replace its prominence with a current index. Some late rounds found real defects; stopping at three would not have made those disappear. Conversely, image previews do not inherently violate a static Go binary constraint. Defer them because they are low priority, not because the architecture forbids them. TOTP likewise needs an actual recovery tradeoff assessment; the invented existing second factor cannot justify rejecting it.

**What each of us missed.** Gemini found the select-all failure, orphaned measurements, and sidebar pagination that I should have examined more directly. Its useful contribution is showing that “feature implemented” can conceal an unusable interaction.

I found the server’s repeated full listing and 50,000-entry cap; Gemini addressed only the tree symptom. I also stand by browser-level testing, restart-surviving operation summaries, conservative retry semantics, compatibility claims grounded in hardware, and authenticated release provenance. The conductor’s live findings particularly strengthen the browser-testing argument: static checks can confirm that a control exists while missing that it is awkward or functionally misleading.

**What I retract or narrow from my own answer.** I retract treating large-directory disclosure as potentially sufficient pre-release containment: the confirmed tree amplification and selection failure require code changes. I withdraw the implication that completed features plus hardware validation are almost enough.

I also deprioritize broad UI restructuring, bookmarks, and durable operation-history implementation relative to these immediate defects. Durable summaries remain valuable, but their absence is acceptable for 1.0 if interruption behavior is tested and explained.

With no external users yet, an external pilot is an objective to begin, not a prerequisite that indefinitely blocks the first release. I would recruit testers during stabilization and publish only after the owner’s hardware gates pass.

My revised top ten are:

1. **Repair select-all and action eligibility, including filtered and oversized selections — M.**
2. **Complete exact-artifact hardware validation and repair demonstrated failures — M.**
3. **Bound size measurements and stop automatic exhaustive tree expansion — M.**
4. **Ship focused browser polish and rendered interaction checks — M.**
5. **Make listing limits explicit; then redesign consistent, bounded pagination — S now / L afterward.**
6. **Publish accurate compatibility, screenshots, security reporting, and release provenance — M.**
7. **Add read-only ACL inspection with real NAS fixtures — M.**
8. **Add durable operation summaries and clearer move phases/recovery guidance — L.**
9. **Implement a narrowly specified text editor — L.**
10. **Improve Trash restoration and introduce deliberate, opt-in retention — M.**

**The one thing to do next week:** produce a stabilization release candidate that passes one end-to-end owner task suite on both NAS units. Use disposable fixtures for select-all actions, filtered selection, an oversized directory, an abandoned measurement, a cross-dataset move, interrupted work, and Trash restore. Record package checksum and outcomes. The deliverable is a candidate with evidence, not another feature milestone.

**The release decision: named fixes must land before v1.0.0.** I would not ship essentially as-is after the hardware pass.

The pre-release scope is:

- **Selection:** make select-all work for supported batch sizes across Delete, Copy, Move, Permissions, and archive download. Resolve selected entries to a concrete path set; do not truncate to the first 1,000. For unsupported sizes, explain the limit before enabling an unusable action. Filtered selection must have explicit scope. Gemini’s `state.entries` shortcut does not match the actual `state.pages` store.
- **Resource containment:** give automatic size measurements cooperative time/entry bounds and honest incomplete outcomes. Stop the sidebar’s fetch-all loop; offer bounded expansion with an explicit continuation or navigation fallback. Keep job capacity occupied until cancellation actually finishes.
- **Listing honesty:** prominently identify capped results as an incomplete subset, avoid implying global sort completeness, and prevent “all” from claiming the entire directory. Correct the README. A full listing-generation redesign can follow in 1.1.
- **Small polish pass:** human-readable sizes with exact values available, folders-first ordering, pointer-positioned context menus, F2 rename, and toolbar/layout verification at 768 and 1280 pixels. Defer natural sorting and structural redesign.
- **Release evidence:** current status documents, tested firmware/architecture matrix, screenshots, vulnerability-reporting instructions, and the existing hardware/package checks.

Out of 1.0: text editing, ACL editing or display, folder upload, extraction, automatic retention, dual pane, SSE, authentication bypasses, copy-verification removal, durable replay, and snapshot restoration. QNAP-recognized signing should be pursued, but an external approval process need not prevent an accurately labeled initial release.

This is a bounded repair of behavior already offered. It does not require expanding the product promise.

The replacement review rule is:

1. Deep review covers identity/authentication, traversal, destructive operations, publication/cleanup, ACL writes, and durability changes.
2. Ordinary UI, documentation, and presentation changes get one focused review plus relevant browser or regression checks.
3. Every finding needs a concrete failure argument within the stated threat model; unsupported speculation does not accumulate rounds.
4. End when blocking findings are fixed and verified, required checks pass, and residuals have explicit owner acceptance.
5. If findings persist after three rounds, stop adding features and reassess the design; exceeding three is neither automatic failure nor permission to ship.
## Round 2 — gemini-4-argon-high


##### 1. Agree

I accept four substantive points from the other model, and they shift my rankings:

1. **The `fsops.List` pagination and 50,000-entry truncation bug is a top-tier architectural defect.** The other model caught what I missed in `internal/fsops/fsops.go:549-688` (though I caught its cousin in `internal/web/static/js/tree.js:26-31`). Every 500-row page fetch re-reads and `lstat`s up to `MaxListLimit` = 50,000 entries (`internal/fsx/entry.go:187`), resolves symlinks (`internal/fsops/fsops.go:625-628`), sorts all 50,000 in memory (`internal/fsops/fsops.go:660`), and slices one 500-item page (`internal/fsops/fsops.go:663-667`). Worse, if a directory has >50,000 entries, it breaks out of the `getdents` loop *before* sorting (`internal/fsops/fsops.go:644-647`), so the user sees a sorted view of an arbitrary unsorted filesystem prefix. This moves into my **#3** spot (fix the cap disclosure and `tree.js` loop before `v1.0.0`; add worker-cached listing generations in `v1.1`).
2. **Lowering the `QTS_MINI_VERSION="4.5.0"` claim in `qpkg/qpkg.cfg:13`.** Shipping a package claiming QTS 4.5.0 support when only QTS/QuTS hero 5.2.x has ever been tested invites support failures on older kernels (especially since `openat2` requires Linux ≥ 5.6, and while a fallback exists in `internal/fsops/openat2_linux.go`, 4.5.x Apache/CGI session plumbing is unverified). Raising `QTS_MINI_VERSION` to `"5.0.0"` or `"5.2.0"` belongs in the pre-`v1.0.0` cut.
3. **Trash UX honesty before automatic retention sweeps.** They are right that `trash.days` in `PLAN.md:173` is accepted in config yet unenforced, and that silently turning on automated deletion in `v1.1` for users who already have a config file could destroy data unexpectedly.
4. **Adding `SECURITY.md` and distinguishing QDK GPG signatures from QNAP's official App Center certificate.** This strengthens the distribution and trust plan directly.

---

##### 2. Disagree

1. **I reject shipping `v1.0.0` before fixing `Ctrl+A` and the live UI defects (`Move 1` / Release Path in their answer).**
   - The other model puts "repair demonstrated listing/selection problems" in `v1.1` and wants to freeze code now for `v1.0.0`.
   - **Why that is wrong:** When `Ctrl+A` and `#chkAll` highlight every row in a 5-item folder and then every toolbar action (`Delete`, `Copy`, `Move`, `Permissions`, `Download`) fails with *"Select items individually to … in this version"* (`internal/web/static/js/list.js:42-43,626,647`), any tester or early adopter will conclude the app is broken within 60 seconds. Combine that with folders mixed alphabetically into files because `internal/web/browse.go:130` forgets to pass `DirsFirst: true` (`internal/fsx/entry.go:214`), raw byte counts overflowing an 80 px column (`internal/web/static/js/list.js:356`, `internal/web/static/app.css:21`), and `#ctxMenu` hardcoded to `right:1rem; bottom:2.5rem` (`internal/web/static/app.css:32`), and a "freeze now" `v1.0.0` wastes its first impression. These are 1–2 day fixes, not a new feature cycle.
2. **I reject pushing the small text editor and archive extraction out to `v1.2` (their Release Path).**
   - They agree that editing a small config file is *"directly connected to the reason this app exists"*, yet they relegate both text editing and archive extraction behind a `v1.1` consumed by "operation summaries" and "diagnostics export", and rate a bounded text editor as **Cost: L** (several weeks).
   - **Why that is wrong:** The read path (`/api/fs/text` and `internal/web/static/js/viewer.js:1-166`), the guard tiers (`internal/guard/rules.go:35-42`), and the typed-phrase confirmation ladder already exist. Adding a `PUT /api/fs/text` worker operation that checks `expectMtime`/`expectSize`, writes an optional `.bak`, and overwrites in-place (preserving inode, mode, ownership, and ACL xattrs on existing files) is an **M** (1 week), not an **L**, and delivers more daily utility to a QNAP admin than persistent job-history telemetry.
3. **I reject their **Cost: L** push to build persistent cross-restart job journals and retry state machines (`Move 4`).**
   - `internal/jobs/jobs.go` is intentionally in-memory, and `/var/log/qnap-filemanager/audit.jsonl` already records durable mutation outcomes on disk (`docs/design/m4-contract.md:394-455`). Building a persistent state machine for interrupted jobs across daemon restarts is high-complexity infrastructure for a rare event (restarting the QPKG mid-copy) and risks violating the simplicity constraint they praise in `Move 10`.
4. **I reject leaving `internal/fsops/copy.go:40-48,146-151` untouched while praising its "substantial verification costs."**
   - Reading every cross-dataset moved file **twice** in userspace (`io.CopyBuffer` write + `fsync` + full byte-for-byte re-read of both source and destination via `contentMatches`) means moving a 500 GB folder between two QuTS hero shares (always `EXDEV`, `PLAN.md:69`) performs **1.5 TB** of userspace I/O. Verifying pre/post `fstat` (`size`, `mtime`, `ctime`, `ino`) after `fsync` provides the exact same protection against silent truncation without re-reading every byte twice.

---

##### 3. Missed

**What they found that I missed:**
1. **`fsops.List` re-reads and re-sorts up to 50,000 entries on every 500-row page request, and truncates before sorting (`internal/fsops/fsops.go:598-667`).** I caught `tree.js:26-31` looping over all pages, but missed that the backend re-runs the full 50,000-entry `getdents`+`lstat`+`sortEntries` on every page offset.
2. **`qpkg/qpkg.cfg:13` claims `QTS_MINI_VERSION="4.5.0"`** despite zero testing below 5.2.x.
3. **No `SECURITY.md`** in the repository for private vulnerability disclosure on a root-capable daemon.
4. **Dormant `trash.days` config risk (`PLAN.md:173`).**

**What I found that they missed (and still stand by):**
1. **`Ctrl+A` and `#chkAll` are completely non-functional for every action in the UI** (`internal/web/static/js/list.js:42-43,513,626,647`, `actions.js:604`, `transfer.js:390,412`, `perms.js:561`)—confirmed live by the conductor.
2. **Orphaned `/api/jobs/size` walks (`internal/web/static/js/props.js:19-35`, `perms.js:194-203`) have no `MaxEntries` cap and no idle reaper**, so 4 abandoned Properties/Permissions dialogs on large trees can permanently exhaust all 4 `ClassMetadata` slots (`docs/design/m3-contract.md:369,513-518`) and block `chmod`/`chown`/`trash`.
3. **`internal/web/static/js/tree.js:26-31` fetches every page of a directory in an unbounded `for (let offset=0;;)` loop** whenever a user expands one tree node.
4. **`internal/fsops/copy.go:40-48,146-151` reads every file twice (`contentMatches`) during cross-dataset moves.**
5. **`internal/web/static/js/upload.js:179` rejects 0-byte extensionless files as folders** in its fallback heuristic, and folder drag-and-drop is refused (`upload.js:185`).
6. **`F2` (Rename) is unbound** (`internal/web/static/js/keys.js:53-83`) despite being specified in `docs/design/ui-ux-safety-plan.md:216`.

*(Note on the conductor's live UI findings: both models missed in static code reading that `internal/web/browse.go:130` omits `DirsFirst: true`, `list.js:356` formats sizes as raw `toLocaleString()` bytes in an 80 px column, and `#ctxMenu` in `app.css:32` is pinned to `right:1rem; bottom:2.5rem` because CSSOM positioning like `heightRule` in `dom.js:111-115` was never applied to `#ctxMenu`. All three belong in the pre-`v1.0.0` polish pass.)*

---

##### 4. Retract

Based on the conductor's verified facts, I retract five specific claims from my Round 1 answer:
1. **Break-glass credentials:** Break-glass uses a single local password set via CLI and stored as a bcrypt hash (`internal/breakglass/`, `docs/qnap-install.md`); there is no separate `breakglass.key` file and no OS `admin` password check.
2. **Break-glass VPN behavior:** A VPN client connecting from its own tunnel IP is *not* refused by the NAS self-address check—only a local relay on the NAS itself (such as an SSH `-L` port forward or `socat` running on the NAS) is refused.
3. **Apache proxy config:** The service script (`qpkg/shared/QNAPFileManager.sh`) does not write an Apache `ProxyPass` config file; QTS App Center handles reverse-proxying via `QPKG_USE_PROXY` (`qpkg/qpkg.cfg`).
4. **Domain/AD identity resolution:** Domain users *are* resolved via bounded execution of `id(1)`/`getent(1)` in `internal/idmap/exec_linux.go`.
5. **Icons and README M4 coverage:** `qpkg/icons/*.gif` are intentional designs (commit `5bb64a9`), and `README.md` already documents break-glass, audit logging, and the keyboard map (only the milestone status line saying M4 is in progress is stale).

---

##### 5. Revised Top 10 (Ranked)

1. **Fix pre-`v1.0.0` functional & UI blockers (`Ctrl+A`/`#chkAll`, `DirsFirst: true`, human-readable sizes, pointer-anchored `#ctxMenu`, toolbar wrap, `tree.js` page cap, and size-walk `MaxEntries`/reaper)** — **(S)**
2. **Run the two-NAS physical hardware verification pass (QuTS hero ZFS + QTS 5.2 ext4) and tune `stagingIn` (`internal/fsops/copy.go:63-95`) for real ZFS ACLs** — **(M)**
3. **Fix large-directory listing scale: disclose the 50k cap in `v1.0.0` (S), then add worker-cached sorted directory snapshots so paging does not re-`stat` 50,000 entries per page (`internal/fsops/fsops.go:549-688`)** — **(M)**
4. **Ship read-only ACL inspection (`docs/design/acl-plan.md` Step A) in `#dlgProps` and `#dlgPerms`, validated against real QuTS hero ZFS & QTS SMB shares** — **(S)**
5. **Ship a bounded, safe in-place text editor (`PUT /api/fs/text` with `expectMtime`/`expectSize`, in-place write preserving inode/mode/ACLs, and `.bak` option)** — **(M)**
6. **Eliminate the post-copy double-read (`contentMatches` in `internal/fsops/copy.go:40-48,149`) in cross-dataset moves using `fsync` + pre/post `fstat` verification and chunked `copy_file_range`** — **(S)**
7. **Add recursive folder upload (`webkitGetAsEntry` traversal in `internal/web/static/js/upload.js:155-190`, removing the broken 0-byte heuristic) and bounded archive extraction (`/api/jobs/extract`)** — **(M)**
8. **Add navigation power-ups: pinned bookmarks/recent paths (`#tree`), `F2` rename shortcut (`internal/web/static/js/keys.js`), and natural case-insensitive sorting** — **(S)**
9. **Harden release provenance & docs: reconcile `PLAN.md`/`README.md`, set `QTS_MINI_VERSION="5.2.0"` in `qpkg/qpkg.cfg:13`, add `SECURITY.md`, publish 4 real screenshots, and host an App Center repo XML feed** — **(S)**
10. **Finish Trash UX (per-volume size, collision/missing-parent choices in `internal/web/static/js/trash.js`, and explicit opt-in before activating `trash.days`)** — **(M)**

**The one thing to do next week:** Land the 2-day pre-release bug-and-polish patch (Move #1 + Move #9 doc/version cleanup), build the release `.qpkg`, and install it on the physical QuTS hero TVS-h1688X and QTS 5.2 ext4 NAS units to execute `docs/nas-checklist.md`.

---

##### 6. The Release Question, Sharply

**`v1.0.0` must NOT ship as-is; a strictly bounded 2-day bug-and-polish patch must land BEFORE the hardware verification pass and tag.**

If you run the hardware checklist first and then fix `Ctrl+A`, `DirsFirst`, `tree.js`, and size-walk caps afterward, you invalidate the exact-commit hardware sign-off (`docs/release-checklist.md:5-7`). Conversely, shipping `v1.0.0` with known broken `Ctrl+A` and bottom-right right-click menus undermines user trust on day one.

**Strictly IN for `v1.0.0` (code changes capped at ~250 LoC):**
- Materialize `Ctrl+A` / `#chkAll` into `state.selection` for loaded directories ≤1,000 items (`internal/web/static/js/list.js:42-43,626,647`), and disable `#chkAll` with a clear `why` tooltip above 1,000 items.
- Pass `DirsFirst: true` in `internal/web/browse.go:130` and switch default name sort in `internal/fsops/fsops.go` to case-insensitive natural order.
- Format file sizes as human-readable (`1.4 MB`) with exact bytes in `title` (`internal/web/static/js/list.js:356`).
- Position `#ctxMenu` at the pointer/focused row via a CSSOM rule in `internal/web/static/js/dom.js:111-115` (respecting `style-src 'self'`) instead of fixed `right:1rem; bottom:2.5rem` (`internal/web/static/app.css:32`), and tighten toolbar padding so it stays single-row at 1280 px.
- Cap `internal/web/static/js/tree.js:26-31` at 1 page (500 dirs) and add a `MaxEntries` cap + 15s idle timeout to `/api/jobs/size`.
- Bump `QTS_MINI_VERSION="5.2.0"` in `qpkg/qpkg.cfg:13`, add `SECURITY.md`, update stale status lines in `README.md` / `PLAN.md`, and fix any hardware blocker uncovered on the two NAS units.

**Strictly OUT for `v1.0.0` (deferred to `v1.1+`):**
- New endpoints or features: text editing, ACL entry display, worker-cached directory pagination, folder upload, archive extraction, Trash retention, and `copy.go` refactor.

---

##### 7. The Review-Process Question, Sharply

1. **Deep loop (max 2 adversarial rounds):** Only code that crosses `INV-1`/`INV-2` privilege boundaries, executes path resolution/mutation in `internal/fsops/`, or handles authentication/CSRF in `internal/web/` and `internal/breakglass/`.
2. **Light pass (1 single-pass checklist + live browser check):** UI layout/JS state (`internal/web/static/`), read-only formatting, and documentation.
3. **Out of scope by rule:** Same-UID multi-tab self-sabotage, local-root attackers on the NAS, and unbacked theoretical races without a concrete exploit steps reproduction.
4. **Hard exit criterion:** A review loop ends immediately when Round 2 has zero P0/P1 findings with a reproducible test case, **or** after Round 2 completes—whichever comes first; remaining edge cases are logged as accepted residuals.

## Round 3 — the conductor's draft synthesis

### Deliberation, round 3 of 3: attack the conductor's synthesis

You have seen both round-1 answers and both cross-examinations. Below is the conductor's draft plan, which judges
the disputes between you. Attack it: find what is wrong, missing, mis-ordered or unsafe. Agreeing with everything is
not useful; neither is relitigating a point without new evidence. Read-only consultation: do not modify any file.

#### Where all three of us already agree

- The app's audience is NAS owners and administrators doing administration work (find and inspect system paths,
  change and verify permissions, move between datasets, recover). Ordinary users get correct, kernel-enforced
  behaviour but do not drive the roadmap.
- v1.0.0 must not ship as-is: a bounded stabilization patch lands first, then the hardware pass runs on that exact
  build, then the tag. Nothing new in features.
- After 1.0, read-only ACL inspection and a text editor are the most valuable additions; dual pane, SSE, thumbnails
  and the credential-proxy door are off the critical path.
- The review loop must become risk-tiered; the 10–19-round loop on everything has stopped paying for itself.

#### Judgements on the disputes

1. **Move verification stays.** Gemini proposed replacing the byte re-read with fstat + fsync. Rejected: metadata
   equality does not prove byte equality, and deleting the source is the one irreversible step a move performs.
   Throughput is a real concern, so the hardware pass benchmarks a cross-dataset move; a chunked `copy_file_range`
   fast path that keeps cancellation, progress and verification may follow in 1.2 if the numbers justify it.
2. **Staging refusals are diagnosed, not downgraded.** If an ordinary hero share is refused as `unverified`, capture its
   real ACL bytes as a fixture and fix the specific wrong assumption (Astra's position).
3. **The break-glass self-address refusal stays.** Document the supported topologies (LAN, VPN client address); no
   `--allow-local` escape hatch.
4. **Select-all** materialises a concrete selection when the listing is fully loaded and within `maxJobRoots` (1,000,
   routes_jobs.go:64); otherwise the actions are disabled with a why-sentence BEFORE the click. Never truncate. In a
   filtered view Ctrl+A selects the visible rows and says so.
5. **Size walks** get time/entry bounds with an explicit "at least …, incomplete" result, plus a reader-idle reaper
   with a window of minutes (not 15 seconds); a slot is released only when cancellation completes.
6. **Sorting:** folders first and case-insensitive natural order with a byte tie-break (keeps the order total, so pages
   never overlap) go into 1.0 — they are a comparator change and the most visible defect in any screenshot.
7. **Editor:** 1.1, not 1.2, but contract-first and sized M–L: a defined set of supported files (text, bounded size,
   UTF-8/ASCII, LF/CRLF preserved), in-place write after a pre-image copy into an app-managed per-user backup area
   (not a sibling `.bak` dropped into /etc/config), conflict detection by content hash plus size/mtime, ownership/
   mode/ACL reported after save, a diff before save, and the guard's ladder for protected paths.
8. **Durable job outcomes:** not a new journal. In 1.2, Operations reads the audit log's intent lines that have no
   result line and shows them as "interrupted — inspect" (the data already exists).
9. **Review rule** (an owner decision, since CLAUDE.md records the ten-round rule): deep tier = identity/auth, path
   resolution and traversal, destructive and publishing operations, ACL writes, durability; light tier = UI,
   formatting, docs (one focused pass plus a rendered-browser check). Every finding needs a concrete failure scenario
   inside the stated threat model (same-uid self-sabotage and local root are out of scope). Deep tier: three rounds by
   default; a fourth needs a written reason, and persistent findings mean "stop and reassess the design", not more
   rounds.

#### The plan

**Stabilization patch → 1.0 release candidate** (UI and small server changes; light-tier review except item 2):
1. Select-all per judgement 4.
2. Bounded size walks + reaper per judgement 5 (deep tier: it touches job lifetime).
3. Tree expansion fetches one page, then "N more folders — open the folder to see all".
4. Listing honesty: a capped listing says it shows an unsorted subset of more than 50,000 entries; the README's
   scale claim is corrected.
5. Polish: folders first, case-insensitive natural sort, human-readable sizes (exact bytes on hover and in
   Properties), compact dates, context menu at the pointer, a toolbar that fits one row at 1280 px, F2 renames.
6. Truth pass: PLAN.md status, README status and scale claims, "never needs SSH" qualified for break-glass setup,
   `QTS_MINI_VERSION` set to what was tested, `SECURITY.md` (GitHub private advisories), a compatibility matrix
   (QTS 5.2.x ext4 x86_64 and QuTS hero h5.2.x ZFS x86_64 verified; ARM64 built and emulated only; firmware 6 untested).
7. Four task screenshots: browsing `.qpkg`, the permissions dialog, a cross-dataset move, a Trash restore.

**Hardware gate** on both units against the RC build, plus a cross-dataset move benchmark and a 50,000-entry listing
measurement. Recruit three to five outside testers (forum.qnap.com, r/qnap) during stabilization; they install the RC
or 1.0.0 — publishing does not wait for them.

**1.0.0:** annotated tag, GitHub Release (QPKG + SHA256SUMS + GitHub artifact attestation), screenshots in the README.
**1.0.x:** a self-hosted App Center repository feed (repo XML on GitHub Pages) so updates appear in App Center;
investigate QNAP-recognised signing (QDK's code-signing path, QNAP Club) without blocking on it.

**1.1 "Edit and inspect":** read-only ACL entries (acl-plan step A, real-NAS fixtures), the editor (judgement 7),
pinned locations.
**1.2 "Scale and recover":** listing generations (a worker-held sorted snapshot per directory identity with a short
TTL, so paging stops re-reading the folder), Trash UX + explicit opt-in retention, folder upload, "interrupted"
operations from the audit log, the copy fast path if the benchmark justified it.
**Later:** extraction (needs its own zip-slip/links/bombs/ownership contract), POSIX ACL editing (acl-plan B),
snapshot browse/restore, dual pane only on demonstrated demand.
**Cut:** the credential-proxy door, TOTP on break-glass, server-side thumbnails. Keep review logs, add an index.

#### Conductor's additions neither of you raised — evaluate each

A. **An on-device self-test.** `qnapfilemanager selftest --scratch <dir on each volume>` run as root over SSH: creates
   a disposable fixture, probes what the 68-item manual checklist (docs/release-checklist.md §3) asks a human to
   observe — birth time per volume, `aclmode` readability, `nfs4-trivial` classification of a fresh file, the staging
   category of each share, trash-root creation, a small cross-dataset copy and move, listing latency at 10k/50k
   entries — and prints one report to paste back. The goal is to make every future hardware pass cheap and repeatable.
B. **Triage the 68-item checklist** into a release gate (~20 items covering identity, browse, delete/trash/restore,
   copy/move incl. the hero staging category, upload, archive, search, chmod on an ordinary share, break-glass basics,
   read-only, clean stop) and a soak list (the relay, VPN-flap, slow-QuLog, aclmode-race items) run after release,
   with findings going to 1.0.x.
C. **The name.** `QPKG_NAME="QNAPFileManager"` (the package identity App Center keys upgrades on — effectively
   permanent after the first public release) embeds QNAP's trademark, while `QPKG_DISPLAY_NAME="File Manager"` is too
   generic to search for or tell apart from File Station. Decide a distinctive name before 1.0, or accept both.
D. **Firmware 6.** QuTS hero h6.0 is in public beta; the auth and proxy plumbing is firmware-coupled. Test the RC on
   h6 if either unit can run it, and say "untested" otherwise.

#### What to send back (600–1,200 words)

1. The **strongest objection** to this plan as a whole.
2. Anything **mis-ordered, unsafe or missing**, with evidence.
3. A verdict on each of **A–D**: adopt, change (how), or reject (why).
4. **One change** you would make to the stabilization scope, or "none".

## Round 3 — gpt-6-astra

**The strongest objection is that the plan classifies changes by where the code lives, while weakening the release gate by checklist length.** Selection determines which files a destructive operation targets. Sorting affects that selection. Neither becomes low risk because it is implemented in JavaScript. Meanwhile, the proposed “soak” list includes tests of authentication and destructive authorization guarantees. Those changes would save effort in the wrong places.

The stabilization direction is sound, but these details need correction.

**Selection and sorting do not yet form a coherent contract.** A total comparator prevents ties; it does **not** prevent overlapping pages from separate directory enumerations. Read page one, insert an earlier-sorting filename, and page two can repeat an entry. Deletion can produce omissions. [list.js](../../internal/web/static/js/list.js) combines independently fetched pages and stores selection by row index. “Fully loaded” therefore does not establish “one consistent listing.”

For the bounded select-all fix, obtain the complete eligible listing in one response, capture concrete path references, and use those references throughout confirmation and submission. Do not reconstruct targets later from mutable row indices. Test selection while another client creates, renames, and deletes files. This needs focused deep review.

Also, “visible rows” is ambiguous in a virtualized grid. Define filtered Ctrl+A as **all matching entries in the explicitly stated loaded scope**, not merely the viewport’s rendered rows. The selection count and confirmation must agree.

Natural sorting is optional polish, not the mechanism that solves pagination. Specify numeric-run, case, and non-UTF-8 behavior before implementing it. The byte tie-break alone does not supply those semantics.

**The proposed tree message asserts information the endpoint does not provide.** [tree.js](../../internal/web/static/js/tree.js) receives pages containing files and directories, then filters them. The remaining entry count is not “N more folders.” Say “More entries are not shown; open this folder,” and preserve direct-path navigation in the destination picker. Its shared tree renderer currently searches loaded children to reveal an ancestor chain; limiting it to one page can stop that behavior.

Similarly, the capped listing is a **sorted arbitrary subset**, not an “unsorted subset.” Say: “Only 50,000 entries were examined. Other entries may be missing; sorting applies only to this subset.” Avoid claiming “more than 50,000” unless an additional entry was actually observed.

**The editor contract chooses its hardest tradeoff prematurely.** In-place writing protects inode relationships but can leave a truncated or partially rewritten configuration after failure. A backup does not automatically make the NAS bootable or the affected service recoverable. Hashing the pre-image also does not atomically prevent another writer changing the file between comparison and writing.

Before committing to that implementation, define interrupted-write recovery, hardlink behavior, concurrent service writers, and how backups remain accessible when QTS fails. Backups must preserve the source’s confidentiality: an administrator’s readable “per-user backup area” must not accidentally expose root-only configuration secrets. The contract must specify access, retention, space exhaustion, and restoration—not just storage location. Keep 1.1 as a target, not a deadline that overrides these decisions.

**Audit-derived outcomes need a narrower claim.** [audit.go](../../internal/audit/audit.go) rotates at 8 MiB, retains one previous generation, and permits asynchronous events to be dropped. [jobAudit](../../internal/web/routes_jobs.go:128) uses asynchronous writes for non-milestone results. An unmatched intent can therefore mean a lost completion record, not interrupted work; a running job also has an unmatched intent.

Show **“Outcome unknown—no completion record available”**, reconcile with live jobs, and describe retention coverage. Do not expose other users’ audit paths through Operations. Reusing the audit log is reasonable, but it does not provide complete durable history without additional guarantees.

The review rule also needs one qualification: excluding deliberate same-UID sabotage must not exclude ordinary same-UID concurrency—another tab, SMB client, editor, or service. Those are normal operating conditions.

**A — Change.** Adopt repeatable hardware probes, initially as an opt-in test harness rather than a new production CLI prerequisite. Separate read-only inspection, scratch mutations, cross-volume tests, and expensive 50,000-file benchmarks. Require fresh, uniquely owned fixture directories; never clean up arbitrary caller-supplied contents.

Run operations through the actual workers as owner, non-owner, and administrator. A root-only syscall probe cannot validate the per-user architecture. A fresh file also cannot represent every inherited ACL configuration, and scratch-space trash creation does not necessarily exercise the real volume-root behavior. Report precisely which claims each probe tests. Browser/proxy/authentication checks remain separate.

**B — Change substantially.** Reduce repetition, not coverage of unresolved guarantees. NAS-local relay refusal and cookie replay belong in the first public release gate because they validate the rationale for the emergency door. The queued `aclmode` change test validates whether a destructive operation executes under authorization the user never gave. Keep it before release.

The relevant checks are explicitly enumerated in [release-checklist.md](../../docs/release-checklist.md:109). Later releases may select tests by changed components and firmware, using previously recorded evidence. This first release lacks that baseline for the final implementation. “Approximately 20” is not a defensible coverage criterion.

**C — Change.** Decide a distinctive display name now; retain the package identifier unless the owner deliberately accepts migration work. Existing private installations still matter even without public releases. A package-ID change needs upgrade/coexistence and proxy/configuration testing. I make no legal finding about the trademark. That question should not be answered by treating the technical identifier as automatically unacceptable.

**D — Change.** Test h6 on separate hardware or an already available beta installation. Do not upgrade either sole 5.2 baseline merely because it can run h6: that trades required release evidence for exploratory compatibility. Otherwise publish “untested” prominently. A minimum-firmware field does not establish compatibility with every later release.

**My one stabilization-scope change:** replace **“bounded size walks plus reader-idle reaper”** with **bounded size walks only** for 1.0, with explicit incomplete results and cancellation acknowledged before releasing capacity. The bounds address the reported unlimited-work problem. A reader-idle reaper adds a separate lifecycle protocol involving background tabs, polling ownership, and reconnects; defer it until there is evidence the bounded behavior is inadequate.

Finally, move listing generations ahead of optional 1.2 additions if the hardware measurements show everyday browsing remains poor. The release may honestly support limited scale, but the roadmap should not postpone a demonstrated core bottleneck behind pinned locations or folder upload.
## Round 3 — gemini-4-argon-high


##### 1. The Strongest Objection to This Plan as a Whole

**Enabling `Ctrl+A` up to 1,000 items in `v1.0` while deferring listing generations to `v1.2` and leaving per-root synchronous pre-flight RPC loops untouched in `routes_transfer.go`, `routes_jobs.go`, and `routes_perm.go` will cause bulk actions and mid-sized directory scrolling to time out under the 15-second HTTP deadline.**

Because `Ctrl+A` was previously broken (`internal/web/static/js/list.js:42-43,626`), the backend's `maxJobRoots = 1000` path (`internal/web/routes_jobs.go:64`) has never been exercised from the UI on a real NAS. Look at what happens the moment Judgement 4 makes `Ctrl+A` materialize 500–1,000 items in a folder:
- **Copy/Move pre-flight (`internal/web/routes_transfer.go:150-175,230-255`):** For *each* of the 1,000 selected roots, the HTTP handler runs `resolveForGuard` (1 worker RPC), `transferSize` (1 worker job RPC), and for moves `FSIdentity` (1 worker RPC)—**2,000 to 3,000 sequential IPC round-trips** inside a single HTTP POST that `internal/web/server.go:413` kills at **15 seconds** (`routes_perm.go:110-113` notes that `routes_transfer.go:222`'s 30s timeout is dead code under `server.go:413`'s 15s deadline). When the user clicks "Confirm" on the 409 challenge, the second POST repeats all 2,000–3,000 RPCs again.
- **Delete pre-flight (`internal/web/routes_jobs.go:625-658`):** Loops over all 1,000 roots calling `resolveForGuard` + `s.backend.Stat` sequentially, twice (challenge + confirm).
- **Paging (`internal/fsops/fsops.go:598-667`, `internal/web/static/js/list.js:98-101`):** `loadList()` eagerly fetches up to 4 pages (2,000 items) sequentially; every page re-reads and `lstat`s the *entire* directory up to 50,000 entries and now runs a more expensive natural sort (`Judgement 6`).

Pushing worker-held listing snapshots to `v1.2` and not batching or bounding the per-root pre-flight loop means the very `v1.0` hardware gate you planned (50,000-entry listing + bulk selection) will expose severe latency and 15-second timeouts.

---

##### 2. What Is Mis-Ordered, Unsafe, or Missing

1. **Unsafe — Judgement 7's editor design ("in-place write after a pre-image copy into an app-managed per-user backup area, not a sibling `.bak`") is dangerous for `/etc/config`:**
   - **Why in-place write (`O_TRUNC`) is unsafe on `/etc/config`:** If an admin edits `/etc/config/uLinux.conf` or `/etc/config/qpkg.conf` and `write(2)` hits `ENOSPC` on `/mnt/HDA_ROOT` or power fails mid-write, `O_TRUNC` leaves a zero-byte or half-written system config file, bricking QTS boot. Conversely, a naive temp-file rename loses mode/UID/GID/ACLs. The safe contract is: **when `nlink == 1` and the parent directory is writable, write to a same-directory temp file, copy mode/UID/GID and all `system.*`/`security.*` xattrs from the original fd, `fsync`, and `renameat` over the target**; use in-place overwrite only when `nlink > 1` or directory write is denied.
   - **Why hiding backups in an "app-managed per-user backup area" fails during recovery:** If a bad edit to `/etc/config/smb.conf` or `/etc/config/uLinux.conf` breaks QTS or stops the QPKG, the admin is at a rescue shell without QNAPFileManager running. A backup hidden inside an app-managed per-user store (or worse, on a different volume or RAM disk) is hard to find or unmounted when needed most. Store backups on the **same filesystem** or offer an explicit checkbox (`Keep <name>.bak alongside file`, on by default for `Warn`-tier paths).

2. **Broken as specified — Judgement 8 ("In 1.2, Operations reads the audit log's intent lines that have no result line and shows them as 'interrupted — inspect'"):**
   - The data in `audit.jsonl` **does not support this today** for three reasons in the code:
     1. **Missing `Job` ID on `intent` lines:** `s.writeAudit` (`internal/web/routes_mutate.go:290-307`) never sets `Event.Job`! In `internal/web/routes_jobs.go:722` and `internal/web/routes_transfer.go:291`, the job ID is buried inside the free-text `Detail` string (`"job <id>: ..."`, `routes_jobs.go:805`), whereas `auditJobFinish` (`routes_jobs.go:953`) sets `Event.Job = id` on the `result` line.
     2. **Dropped async `result` lines look identical to crashes:** Every `intent` line is written via `WriteSync` (`routes_mutate.go:312`), but non-milestone `result` lines (`files < 100 && bytes < 1 GiB && result == "ok"`) use async `s.auditor.Write(ev)` (`routes_jobs.go:136-142`), which drops events when `bufferDepth` (1,024) overflows (`internal/audit/audit.go:33,174`). An unmatched `intent` can simply be a dropped async `result`.
     3. **Log rotation and non-admin access:** `audit.jsonl` rotates at 8 MiB (`internal/audit/audit.go:30`), is mode `0600` root-only (`audit.go:237`), and `/api/audit` is gated by `requireAdmin` (`internal/web/routes_admin.go:17-23`). Non-admin users cannot read it, and an `intent` across an 8 MiB rotation boundary loses its pair.
   - **Fix:** If you want this in `1.2`, stamp `Event.Job = id` on job `intent` lines in `1.0` (`routes_mutate.go:290`) and make all job `result` lines `WriteSync` (`routes_jobs.go:136`—there is at most one `result` line per job, so `WriteSync` costs almost nothing).

3. **Subtle bug in Judgement 4 (`Ctrl+A` in a filtered view vs. `maxJobRoots`):**
   - Judgement 4 says: *"materialises a concrete selection when the listing is fully loaded and within `maxJobRoots` (1,000)... In a filtered view Ctrl+A selects the visible rows."*
   - Note that `loadList()` (`internal/web/static/js/list.js:100`) eagerly loads all pages up to **`state.total <= 2000`**, not 1,000. If a folder has 1,500 items (all loaded) and the user filters to 30 visible rows, `Ctrl+A` should succeed because the **resulting selection** (30) is `<= maxJobRoots` (1,000). Gate `Ctrl+A` on **all pages loaded (`state.pages.size * pageSize >= state.total`) AND matching row count `<= 1000`**, not `state.total <= 1000`.

4. **Mis-ordered — Move listing generations from `1.2` to `1.1` (and archive extraction from `Later` to `1.2`):**
   - Leaving `fsops.List` (`internal/fsops/fsops.go:549-688`) re-reading, `lstat`-ing, symlink-resolving, and natural-sorting up to 50,000 entries on *every 500-row scroll request* until `1.2` means `1.0` and `1.1` remain `O(N²)` on directories of 5,000–50,000 items. Move worker listing generations to `1.1`.
   - Conversely, "interrupted operations from the audit log" is low-leverage telemetry compared to archive extraction; swap them between `1.2` and `Later`.

---

##### 3. Verdict on Conductor's Additions (A–D)

- **A. On-device self-test (`qnapfilemanager selftest --scratch <dir>`): ADOPT WITH ONE CHANGE.**
  - Brilliant leverage. Automating birth-time, `aclmode`, `nfs4-trivial`, `stagingIn` classification, trash-root creation, cross-dataset move, and 10k/50k listing latency turns a multi-hour manual SSH ritual into a 30-second regression gate.
  - **Change:** Do **not** compile test/fixture logic into the production daemon binary if it adds any surface area to the root-installed CLI; either require `--scratch` to be an newly created empty `0700` subdirectory (`mkdir` by the command itself, refusing pre-existing non-empty paths so a typo cannot wipe user data) and clean it up on exit, or ship it as a separate `qfm-selftest` binary in the CI artifact / QPKG.

- **B. Triage the 68-item checklist into a ~20-item release gate + post-release soak list: ADOPT.**
  - Combined with `selftest` (Addition A), this prevents the hardware pass from stalling `v1.0.0` for weeks over synthetic fault-injection items (like `aclmode` races or slow `log_tool` queues).

- **C. The name (`QPKG_NAME` / `QPKG_DISPLAY_NAME`): ADOPT — RENAME NOW BEFORE `v1.0.0`.**
  - This is a one-way door: once `v1.0.0` ships, `QPKG_NAME` in `qpkg/qpkg.cfg:2` can never change without breaking App Center upgrades, config paths (`/etc/config/...`), and proxy prefixes (`internal/web/server.go:240`).
  - **Change:** Drop the `QNAP` trademark prefix from `QPKG_NAME` (which gives QNAP legal/policy grounds to reject App Center listing or send a takedown) and make `QPKG_DISPLAY_NAME` (`qpkg/qpkg.cfg:3`) distinctive so it does not collide visually with QTS "File Station". A short distinctive name like **`RootDeck`** or **`QDeck`** (`QPKG_NAME="RootDeck"`, `QPKG_DISPLAY_NAME="RootDeck File Manager"`) fixes both problems in one commit while there are still zero external installs.

- **D. Firmware 6 (QuTS hero h6.0 beta): CHANGE.**
  - Do **not** upgrade either of the only two physical verification NAS units (TVS-h1688X or the QTS 5.2 unit) to a beta OS before `v1.0.0` ships—if h6.0 breaks something or cannot cleanly downgrade without pool/config migration, you lose your `5.2.x` baseline hardware gate. Mark Firmware 6 `"untested"` for `1.0.0`, and test h6.0 only after `1.0.0` is tagged (or via an external tester from the forum recruitment).

---

##### 4. One Change to the Stabilization Scope

**In `internal/web/routes_transfer.go:230-255` and `internal/web/routes_jobs.go:625-658`, stop running per-item worker RPCs synchronously inside the 15-second HTTP pre-flight when a multi-selection exceeds 50 items (or batch them into one worker RPC).**

Otherwise, fixing `Ctrl+A` (Stabilization Item 1) up to `maxJobRoots = 1000` immediately introduces a trap where selecting 500 files in a folder and clicking **Copy**, **Move**, or **Delete** executes 1,000–3,000 sequential IPC calls inside a 15-second HTTP request (`internal/web/server.go:413`) and fails with a timeout before the confirmation dialog can even open.
