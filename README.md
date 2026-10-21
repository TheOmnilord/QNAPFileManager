# Taproot

A file manager for the QNAP QTS / QuTS hero desktop, installed from App Center as a QPKG and opened as a window in the
QTS desktop with your QTS login, exactly like File Station. Unlike File Station it can browse and manage the **whole**
filesystem — `/`, `/etc`, `/root`, `.qpkg` directories, raw volume mounts — and edit permissions and ownership. Normal
use needs no SSH or Telnet; setting up the optional break-glass door does, because its password is set from the NAS
shell as root ([The two doors](#the-two-doors)).

Every operation runs with the signed-in user's own Linux identity, in a separate process that has already dropped to that
user's uid and groups, so the **kernel** decides what is allowed. Administrators operate as root, the way File Station
does, with a guard and a confirmation ladder standing between a mis-click and an irreversible change.

Taproot was called QNAPFileManager before its first release.

**Status:** M0–M4 are implemented and reviewed on `main`. Development builds have run on a QuTS hero unit and a QTS
unit, where M0, M1 and M2-A were verified ([Compatibility](#compatibility)). A stabilization patch is in progress —
select-all, large folders, bounded measurements and interface polish, specified in
[docs/design/stabilization-contract.md](docs/design/stabilization-contract.md). Nothing has been released or tagged: the
first release will be 1.0.0, after that patch and the full hardware pass on both units
([docs/release-checklist.md](docs/release-checklist.md) §3). Start with [PLAN.md](PLAN.md).

## Who it is for

Anyone who has had to SSH into a NAS to fix a permission, read a log under `/etc`, or look inside a `.qpkg` directory —
and anyone who would rather their users did not have to. It is equally for the ordinary QTS user: open it and you see the
same filesystem, with your own account's permissions enforced by the kernel rather than by a UI that hides things.

## Why

File Station and its HTTP API only accept paths inside shared folders. No maintained, QTS-integrated alternative exists
(see [docs/research/existing-tools.md](docs/research/existing-tools.md)). The mechanism is already proven by the sibling
project GitBackup: QTS App Center runs a package's service script as root, so a Go daemon can list the filesystem locally
and serve its own UI.

## Screenshots

*To be added before the 1.0.0 release: the desktop window browsing `/`, the permissions dialog, a running job, and the
level-2 confirmation.*

## What it does

- **Browse everything** — a tree, breadcrumbs, an editable path, sorting, filtering, hidden files. A folder of up to
  50,000 entries is listed in full; a larger one lists the first 50,000 entries read and says that the rest are
  missing. Each page of a long listing re-reads the folder; listing generations, planned for 1.1, are the fix.
- **Copy, move, rename, delete** as cancellable jobs with progress and per-item warnings, including a pre-flight that
  predicts a cross-filesystem move before it starts (on QuTS hero every share is its own dataset).
- **Trash** on the same volume, in a `.@taproot_trash` directory at the volume root, so deleting is instant and
  restorable, with permanent delete one rung further up the confirmation ladder. QNAP's own `@Recycle` is never touched.
- **Upload and download** — drag files from your desktop onto the list, or download any selection as a zip or tar.gz,
  streamed as it is walked.
- **Search** a whole subtree, bounded, with its own results view.
- **Permissions and ownership**, on one item or recursively, reporting what the kernel actually did rather than what was
  asked — with capability hints, an ACL badge per filesystem, and a warning when a chmod may discard an inherited ACL.
- **View text files** (up to the configured size limit).
- **Safety**: a global read-only switch that is on at first install, a table of protected paths, a confirmation ladder
  ending in a typed phrase, and an audit log whose milestones appear in QuLog Center.

Not in 1.0: editing text files, extracting archives, editing ACLs, thumbnails, dragging items within the app to move or
copy them, and an automatic trash sweeper. See [CHANGELOG.md](CHANGELOG.md).

## The two doors

On the normal path there is **no login of our own**: the app is served from the QTS origin at `/taproot/` through App
Center's reverse proxy, so the QTS desktop's cookies arrive first-party and are validated against QTS itself on
loopback. There is a **second door** — a local password on its own TLS port, 8771 — for the case where App Center or
QTS's Apache is broken and the normal path therefore does not exist; it does not bind until a password is set from the
NAS shell with `taproot break-glass set-password`, and everything created through it is owned by `root:root`. The two
doors never mix: neither listener will look at the other's cookie, and the break-glass listener never calls the QTS
validation path at all.

Read [docs/identity.md](docs/identity.md) before relying on any of that.

## Compatibility

| Firmware | Filesystem | CPU architecture | Status |
|---|---|---|---|
| QuTS hero h5.2.9 (a TVS-h1688X) | ZFS | x86_64 | verified on hardware |
| QTS 5.2.x | ext4 | not yet recorded; to be recorded at the hardware pass | verified on hardware |
| any | any | arm_64 (aarch64) | built and smoke-run under emulation only |
| firmware 6 (QuTS hero h6.0 is in public beta) | any | any | untested |

"Verified on hardware" means development builds have been installed and used on that unit; the full release pass
([docs/release-checklist.md](docs/release-checklist.md) §3) runs on both units before 1.0.0. Any architecture that has
not run on a physical unit is listed as built and smoke-run under emulation only: CI runs both architecture trees under
qemu before packaging. The package declares 5.2.0 as its minimum firmware, the lowest line verified on hardware. 32-bit
ARM models are not targeted.

## Install

[docs/qnap-install.md](docs/qnap-install.md) — choosing the package for your CPU (`Taproot_<version>_x86_64.qpkg` or
`Taproot_<version>_arm_64.qpkg`) and installing it from App Center on QTS and QuTS hero, the proxy path `/taproot/` and
the ports, first run, setting up the break-glass door, upgrade (including from a pre-1.0 build under the old name) and
removal, where the logs and configuration live, and troubleshooting.

## Keyboard

The app's own shortcuts dialog (`?`) is authoritative; a test cross-checks it against the handlers. Mirrored here, and in
full in [docs/keyboard.md](docs/keyboard.md). Every shortcut has a mouse equivalent, because the QTS desktop swallows some
chords.

| Keys | Action | | Keys | Action |
|---|---|---|---|---|
| `↑` `↓` `Home` `End` `PgUp` `PgDn` | move | | `Ctrl+L` | edit the path |
| `Shift` + movement | extend the selection | | `/` | filter loaded names |
| `Ctrl` + movement | move, keep the selection | | `Ctrl+F` | search this subtree |
| `Space` | select or deselect | | `Ctrl+C` `Ctrl+X` `Ctrl+V` | copy / cut / paste |
| `Ctrl+A` | select every visible item (up to 1,000) | | `Del` | move to Trash |
| `Enter` | open | | `F2` | rename the selected item |
| type a name | jump to the first match | | `F9` | permissions |
| `Backspace` | parent folder | | `Alt+Enter` | properties |
| `Alt+←` / `Alt+→` | back / forward | | `F4` | view as text |
| `Shift+F10` / `Menu` | actions menu | | `Ctrl+H` | hidden items |
| `Esc` | clear or close | | `F5` | refresh |
| `?` | the keyboard map | | `Ctrl+R` | the browser's reload, never intercepted |

`Ctrl+A` also needs the folder to have loaded in one response, which folders of up to 2,000 entries do; otherwise it
says why.

## Build from source

Go 1.26, standard library only. The single dependency is `golang.org/x/crypto` (bcrypt, for the break-glass account).
No npm, no framework — the UI is `go:embed`ed HTML, CSS and ES modules.

```bash
go test ./...
go run ./cmd/taproot serve -config dev-config.json -jail testdata/fakeroot -addr 127.0.0.1:8899
```

`-jail` reroots every syscall inside the worker, so the dev loop never touches the real filesystem; `-impersonate <user>`
spawns a worker as a chosen user without QTS. Always `go run` — a stale `go build` binary keeps serving embedded UI
assets that were already edited.

Before claiming green, run the three-GOOS sweep. `go vet ./...` on Windows silently skips the Linux files:

```bash
GOOS=linux go vet ./... && GOOS=windows go vet ./... && GOOS=linux GOARCH=arm64 go vet ./... \
  && test -z "$(gofmt -l .)" && go test ./...
```

Permission-semantics tests skip on Windows and when not running as root, deliberately: the kernel decides permissions and
a test that simulates it would be testing the simulation. Root and ZFS behaviour is covered by the CI jobs.

The QPKGs — one package per architecture, `x86_64` and `arm_64`, with one `SHA256SUMS` covering both — are built by
GitHub Actions with QDK pinned by commit; there is no Docker or QDK on the development box.
`powershell -File scripts/build-local.ps1` builds locally for a quick check.

## Documents

- [PLAN.md](PLAN.md): decisions, milestones, accepted residuals, verification, open questions.
- [CHANGELOG.md](CHANGELOG.md): what each milestone shipped, and what is deferred to 1.1.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately, and what is in scope.
- [docs/identity.md](docs/identity.md): identity, the two doors, what an administrator can and cannot do, the guard and
  the confirmation ladder, the audit log, and what the kernel decides versus what the app predicts.
- [docs/qnap-install.md](docs/qnap-install.md): install, first run, break-glass setup, upgrade, removal, troubleshooting.
- [docs/keyboard.md](docs/keyboard.md): the full keyboard map.
- [docs/release-checklist.md](docs/release-checklist.md): how a release is cut, and the hardware pass that gates it.
- [docs/development.md](docs/development.md): using Codex and GPT-6 Astra as agents.
- [docs/design/identity-and-hero-plan.md](docs/design/identity-and-hero-plan.md): per-user identity, worker processes,
  QuTS hero semantics, proxy embedding (rev 2 core).
- [docs/design/backend-packaging-plan.md](docs/design/backend-packaging-plan.md): Go packages, API, guard rules, QPKG
  and CI.
- [docs/design/ui-ux-safety-plan.md](docs/design/ui-ux-safety-plan.md): feature matrix, wireframes, confirmation ladder,
  QTS-iframe rules.
- [docs/design/m2b-contract.md](docs/design/m2b-contract.md),
  [m2c-contract.md](docs/design/m2c-contract.md),
  [m3-contract.md](docs/design/m3-contract.md),
  [m4-contract.md](docs/design/m4-contract.md): the milestone contracts fixed before each implementation.
- [docs/design/roadmap-deliberation.md](docs/design/roadmap-deliberation.md) and
  [docs/design/stabilization-contract.md](docs/design/stabilization-contract.md): recommendations to the owner for
  1.0.0 and after, and the patch before 1.0.0 taken from them.
- [docs/design/rename-contract.md](docs/design/rename-contract.md): the rename to Taproot, with every old and new name.
- [docs/design/astra-per-user-review.md](docs/design/astra-per-user-review.md) and
  [docs/design/codex-independent-review.md](docs/design/codex-independent-review.md): independent critiques.
- [docs/design/gitbackup-exploration.md](docs/design/gitbackup-exploration.md): what to lift from GitBackup.
- [docs/research/qts-integration-facts.md](docs/research/qts-integration-facts.md): verified QTS auth and packaging facts.
- [docs/reviews/](docs/reviews/): every review round, kept in full.

## License

**MIT** — see [LICENSE](LICENSE); `QPKG_LICENSE` in [qpkg/qpkg.cfg](qpkg/qpkg.cfg) declares the same. The Go standard
library and `golang.org/x/crypto` are BSD-3-Clause; their notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
which is shipped inside the QPKG beside the binary as that licence requires.
