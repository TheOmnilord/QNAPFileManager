# Release checklist

**When to release is the owner's call. This fixes how.**

Work top to bottom. Nothing here is optional, and nothing here is a substitute for §5 — a release nobody installed is a
release nobody tested.

## 1. Green, on the exact commit

- [ ] The `build` workflow concluded **success** on the commit you intend to tag. Check that **SHA**, not the branch head:

      gh run list --workflow build --branch main --limit 10 \
        --json headSha,conclusion,displayTitle,url

      # or, for one commit:
      gh run list --workflow build --commit <sha> --json conclusion,url

- [ ] Every job in that run passed, not just the required ones: `test` (race, staticcheck, govulncheck), `test-windows`,
      `test-linux-root`, `test-zfs`, and `package` (the qemu smoke test of both architecture trees, then `qbuild`).
- [ ] **`test-linux-root` and the non-root race job are the two to read**, even when green. The race job has produced
      every genuine CI failure on this project so far; Windows and a root shell both miss what it catches.
- [ ] `main` has no uncommitted changes: `git status --porcelain` is empty.
- [ ] The local sweep passes as well. Local green is not CI green, but local red is definitely not releasable:

      GOOS=linux go vet ./... && GOOS=windows go vet ./... && GOOS=linux GOARCH=arm64 go vet ./... \
        && test -z "$(gofmt -l .)" && go test ./...

- [ ] `go.mod` still has exactly one `require` — `golang.org/x/crypto` — and `go mod tidy` is a no-op.

## 2. Documents match what ships

- [ ] [CHANGELOG.md](../CHANGELOG.md) has a **dated** section for this version, and its `Security` block names the
      accepted residuals (PLAN §2.0, §2.4, §2.5, §2.6, §2.7 and the M4 list). A 1.0.0 tag must not imply they were fixed.
- [ ] [docs/identity.md](identity.md) and [docs/qnap-install.md](qnap-install.md) match the shipped behaviour: ports,
      default configuration values, the `break-glass` subcommand names and flags, the cookie names.
- [ ] [docs/keyboard.md](keyboard.md) and the README's map agree with the app's own shortcuts dialog.
- [ ] Nothing in the documents describes a v1.1 feature as present.

This item is a human reading the documents. Nothing executes them, and that is the weakest link in this checklist.

## 3. Hardware, on **both** units, against a package built from the release commit

Build the package from that commit (the `package` job's `qpkg` artifact, 7-day retention), install it on the QuTS hero
unit and on the QTS unit, and work through the list. Anything that fails here stops the release.

### Browse and identity

- [ ] The App Center tile opens a **desktop window**, and the app is signed in with no prompt of its own.
- [ ] A non-administrator sees the filesystem's shape but is refused where their account would be refused over SSH, and
      the refusal names the owner and mode rather than showing an empty folder.
- [ ] Signing out of QTS destroys the session in the app window, with a re-authentication panel and no top-level redirect.
- [ ] A domain user (if the units have one) resolves, and either has complete groups or shows the "groups incomplete"
      banner.

### Trash, delete and size (M2-A)

- [ ] Recursive delete of a folder tree, with progress and a cancel that reports itself partial.
- [ ] Folder size reports a real number, and a trashed folder shows that size in the Trash panel rather than "—".
- [ ] Trash, restore and Empty Trash on each unit, including on a hero share where the trash root lands beside
      `@Recycle` (which must remain untouched).

### Copy and move (M2-B)

- [ ] **First**: an ordinary QuTS hero share lands in the "shared destination, warn once" category, **not** the "refuse as
      unverified" one. The staging proof grew over three review rounds and each addition is a way a normal share could be
      refused; a real inherited NFSv4 ACL is the case CI cannot stage. This is the single most likely M2-B surprise.
- [ ] A move **within** one dataset is instant (it is a rename).
- [ ] A move **between** datasets is predicted in the dialog before it starts, and completes.
- [ ] Each conflict policy — skip, overwrite, keep both — behaves as chosen.
- [ ] `Ctrl+C` / `Ctrl+X` / `Ctrl+V`.
- [ ] A copy made by an **administrator** is owned by the real signed-in user, verified over SSH with `ls -l`.

### Upload, archive, search (M2-C)

- [ ] A share reached through a symlink (`/share/Public` → `/share/CACHEDEV1_DATA/Public`) uploads, archives and searches
      normally. A `changed` refusal on a plain share means the front end's symlink resolution is not happening — stop and
      fix it.
- [ ] A 1 GB upload finishes without a 408 or a 409.
- [ ] Keep-both names the uploaded file, and the audit line says so.
- [ ] An archive of a mixed selection (files, folders, a symlink) downloads and unzips.
- [ ] A cancelled search returns a small response, not the accumulated hits.
- [ ] `FSIdentity` reports a birth time on **ext4** and on **ZFS** — without one the inode-reuse guard degrades silently.

### Permissions and properties (M3)

- [ ] `zfs get -Hp -o value aclmode <dataset>` as root on hero for an ordinary share returns a value. An empty answer
      makes **every** hero chmod a typed-phrase confirmation.
- [ ] Listing an ordinary hero share shows **no** ACL badge on plain files (they are `nfs4-trivial`). If every row badges,
      the on-disk `system.nfs4_acl` encoding is why, and `internal/perm.NFS4State` is the one-line fix.
- [ ] The dataset name in a level-2 confirmation sentence matches `zfs list`.
- [ ] A chmod through `/share/Public` → `/share/CACHEDEV1_DATA/Public` succeeds (a `changed` refusal is the same bug as
      above).
- [ ] A QTS share reports `ACLBackend == "posix"` while an ordinary file on it reports `none`.
- [ ] A recursive chmod over a hero share containing a **nested dataset** demands the grade the contract says it should.
- [ ] Requesting 2755 on a file as a non-member owner shows exactly one sentence — the setgid one — and the audit line
      carries the diff of what the kernel actually did.

### The break-glass door (M4)

- [ ] `netstat -tlnp` before anything: **8771 is free**, and QuFirewall does not block it.
- [ ] With no password set, the listener **does not bind**, and `break-glass status` reports no hash.
- [ ] `break-glass set-password` generates the certificate as part of setting the password: `break-glass status` prints a
      SHA-256 fingerprint immediately afterwards, with no restart in between.
- [ ] The listener comes up **without a restart** once the password is set. If it needs one, say so — that dead end is
      what round 2 fixed.
- [ ] `break-glass set-password` run at the same moment as a read-only toggle in the app either waits briefly or fails
      with a lock timeout, and `config.json` is intact either way.
- [ ] A browser on the LAN reaches `https://<nas>:8771/` and shows the **expected** self-signed warning — not a
      name-mismatch warning, which would mean the certificate has no IP SAN.
- [ ] The fingerprint the browser shows matches the one in the app log and in `break-glass status`.
- [ ] Signing in yields an **administrator** session whose banner says content will be root-owned, and a file created
      through it really is `root:root` (check over SSH).
- [ ] Five wrong passwords lock the account, and QuLog Center shows milestone lines for the attempts, the lockout and the
      successful login.
- [ ] `break-glass set-password` run while the daemon is up takes effect on the next attempt and evicts a live
      break-glass session.
- [ ] The certificate warning flow in three browsers.

### Accessibility and layout (M4, manual by design — there is no npm, so no axe run)

- [ ] The QTS desktop window at its default size passes the 768 px rung: no horizontal scroll on the body, every toolbar
      action reachable, every dialog fitting with its action row pinned.
- [ ] The same at 1280×800, 1024×768, 900×600 and 375×667.
- [ ] A keyboard-only pass: browse → select → permissions → confirm → job, with no trap and no action reachable by mouse
      alone.
- [ ] An NVDA pass over the same path.

### General

- [ ] Read-only mode blocks writes and the banner explains it; turning it off writes a QuLog milestone.
- [ ] QuLog Center shows the app's milestones and is not flooded by ordinary file operations.
- [ ] Stop and start from App Center leaves no stray worker processes (`ps | grep qnapfilemanager`).

## 4. Tag

- [ ] The tag matches `^v[0-9]+\.[0-9]+\.[0-9]+$`. CI fails a tag that does not, before anything is built or uploaded.
- [ ] The tag points at a commit on `main` whose `build` run concluded **success** (§1).
- [ ] The tag is **annotated**, never lightweight, so the tagger and the date are recorded — and signed if a key is
      configured:

      git tag -a v1.0.0 -m "QNAPFileManager 1.0.0"
      git push origin v1.0.0

- [ ] **One tag per released version, never moved.** A bad release is superseded by `v1.0.1`; `v1.0.0` is never
      re-pointed. The QDK installer and the checksums file both take the version at its word, and a moved tag makes every
      copy of that version ambiguous.

## 5. Publish, then install what was published

CI stamps the version from the tag (`${GITHUB_REF_NAME#v}`), rewrites `QPKG_VER` in `qpkg/qpkg.cfg`, builds both
architecture trees into one package, and attaches it to a GitHub release with `--generate-notes`.

- [ ] The release carries exactly two things:
      - `QNAPFileManager_<version>.qpkg` — one package, both architecture trees inside; QDK names it from `qpkg.cfg`.
      - `SHA256SUMS` — the checksum of that package, so a download can be verified.
- [ ] Pre-release builds from `main` stay workflow artifacts with 7-day retention and are **never** attached to a
      release. The account-wide artifact quota is the reason; it has blocked releases on the sibling project twice.
- [ ] Verify the checksum of the file you downloaded from the release page against `SHA256SUMS`.
- [ ] **Install the released artifact** from a clean App Center install on one unit, and confirm that the version string
      in `api/session` matches the tag.

## 6. Afterwards

- [ ] Open an `[Unreleased]` section in [CHANGELOG.md](../CHANGELOG.md) for the next cycle.
- [ ] Record anything the hardware pass found that CI did not, in PLAN.md, so the next release knows to look for it.
