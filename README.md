# QNAPFileManager

A file manager for the QNAP QTS / QuTS hero desktop, installed from App Center as a QPKG and opened as a window in the
QTS desktop with your QTS login, exactly like File Station. Unlike File Station it can browse and manage the **whole**
filesystem — `/`, `/etc`, `/root`, `.qpkg` directories, raw volume mounts — edit permissions and ownership, and it never
needs SSH or Telnet.

Every operation runs with the signed-in user's own Linux identity, in a separate process that has already dropped to that
user's uid and groups, so the **kernel** decides what is allowed. Administrators operate as root, the way File Station
does, with a guard and a confirmation ladder standing between a mis-click and an irreversible change.

**Status:** M0–M3 implemented and reviewed; M0, M1 and M2-A verified on real hardware (a QTS unit and a QuTS hero unit,
firmware 5.2.x). M4 — the break-glass listener, the non-admin and accessibility passes, and these documents — is in
progress. Not yet tagged; the first release will be 1.0.0. Start with [PLAN.md](PLAN.md).

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

- **Browse everything** — a tree, breadcrumbs, an editable path, sorting, filtering, hidden files — with listings that
  stay responsive on directories with hundreds of thousands of entries.
- **Copy, move, rename, delete** as cancellable jobs with progress and per-item warnings, including a pre-flight that
  predicts a cross-filesystem move before it starts (on QuTS hero every share is its own dataset).
- **Trash** on the same volume, so deleting is instant and restorable, with permanent delete one rung further up the
  confirmation ladder. QNAP's own `@Recycle` is never touched.
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

On the normal path there is **no login of our own**: the app is served from the QTS origin through App Center's reverse
proxy, so the QTS desktop's cookies arrive first-party and are validated against QTS itself on loopback. There is a
**second door** — a local password on its own TLS port, 8771 — for the case where App Center or QTS's Apache is broken and
the normal path therefore does not exist; it does not bind until a password is set from the NAS shell, and everything
created through it is owned by `root:root`. The two doors never mix: neither listener will look at the other's cookie, and
the break-glass listener never calls the QTS validation path at all.

Read [docs/identity.md](docs/identity.md) before relying on any of that.

## Install

[docs/qnap-install.md](docs/qnap-install.md) — App Center install on QTS and QuTS hero, the proxy path and the ports,
first run, setting up the break-glass door, upgrade and removal, where the logs and configuration live, and
troubleshooting.

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
| `Ctrl+A` | select everything here | | `Del` | move to Trash |
| `Enter` | open | | `F9` | permissions |
| type a name | jump to the first match | | `Alt+Enter` | properties |
| `Backspace` | parent folder | | `F4` | view as text |
| `Alt+←` / `Alt+→` | back / forward | | `Ctrl+H` | hidden items |
| `Shift+F10` / `Menu` | actions menu | | `F5` | refresh |
| `Esc` | clear or close | | `Ctrl+R` | the browser's reload, never intercepted |
| `?` | the keyboard map | | | |

## Build from source

Go 1.26, standard library only. The single dependency is `golang.org/x/crypto` (bcrypt, for the break-glass account).
No npm, no framework — the UI is `go:embed`ed HTML, CSS and ES modules.

```bash
go test ./...
go run ./cmd/qnapfilemanager serve -config dev-config.json -jail testdata/fakeroot -addr 127.0.0.1:8899
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

The full QPKG — both architecture trees in one package — is built by GitHub Actions with QDK pinned by commit; there is no
Docker or QDK on the development box. `powershell -File scripts/build-local.ps1` builds locally for a quick check.

## Documents

- [PLAN.md](PLAN.md): decisions, milestones, accepted residuals, verification, open questions.
- [CHANGELOG.md](CHANGELOG.md): what each milestone shipped, and what is deferred to 1.1.
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
- [docs/design/astra-per-user-review.md](docs/design/astra-per-user-review.md) and
  [docs/design/codex-independent-review.md](docs/design/codex-independent-review.md): independent critiques.
- [docs/design/gitbackup-exploration.md](docs/design/gitbackup-exploration.md): what to lift from GitBackup.
- [docs/research/qts-integration-facts.md](docs/research/qts-integration-facts.md): verified QTS auth and packaging facts.
- [docs/reviews/](docs/reviews/): every review round, kept in full.

## License

The package declares **MIT** (`QPKG_LICENSE` in [qpkg/qpkg.cfg](qpkg/qpkg.cfg)). No `LICENSE` file is checked in yet; one
should be added before the 1.0.0 tag so the declaration and the repository agree.
