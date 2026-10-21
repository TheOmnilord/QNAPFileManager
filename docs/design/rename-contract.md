# Rename contract — QNAPFileManager becomes Taproot

Date: 2026-10-21. Owner decision the same day: the app is called **Taproot** (reasoning in the conversation that
followed `roadmap-deliberation.md` "Owner decisions" item 2: a distinctive name, no QNAP mark in the package
identity, decided before the first public release while only the owner's two units have it installed). This contract
fixes every new name so four implementers can work at once; the reviewers check the code against it.

The rename changes names, not behaviour. Every guard rule, proof, bound and test keeps its meaning under the new
spelling. Review: the CLAUDE.md rule stands (gpt-6-astra normal + adversarial, ten-round ceiling); the Go module
rewrite is mechanical, the protocol and on-disk names are the deep-tier part.

## 1. The names

| Thing | Old | New |
|---|---|---|
| `QPKG_NAME` (App Center identity, install dir `.qpkg/<name>`, `qpkg.conf` section) | `QNAPFileManager` | `Taproot` |
| `QPKG_DISPLAY_NAME` (tile, window title) | `File Manager` | `Taproot` |
| `QPKG_SUMMARY` | (current) | "Taproot is a file manager for the whole NAS — every path, not just shared folders: /, /etc, .qpkg, raw volume mounts. Permissions and ownership, copy/move, upload/download and search, each run as the signed-in user, with no SSH needed." |
| `QPKG_PROXY_PATH` / `QPKG_WEBUI` | `/qnapfilemanager` / `/qnapfilemanager/` | `/taproot` / `/taproot/` |
| `QPKG_SERVICE_PROGRAM` and its file | `qpkg/shared/QNAPFileManager.sh` | `qpkg/shared/Taproot.sh` |
| Icons | `qpkg/icons/QNAPFileManager{,_80,_gray}.gif` | `qpkg/icons/Taproot{,_80,_gray}.gif` (same pixels) |
| Binary and CLI | `qnapfilemanager` (`dist/<arch>/bin/qnapfilemanager`) | `taproot` (`dist/<arch>/bin/taproot`) |
| Command directory | `cmd/qnapfilemanager` | `cmd/taproot` |
| Go module path | `qnapfilemanager` | `taproot` |
| QuLog keyword (`internal/qnap.Keyword`) | `QNAPFileManager` | `Taproot` |
| HTTP User-Agent to QTS | `qnapfilemanager` | `taproot` |
| Break-glass certificate subject | CN `qnapfilemanager`, O `QNAPFileManager break-glass` | CN `taproot`, O `Taproot break-glass` |
| CLI config fallback | `.qpkg/QNAPFileManager/config/config.json`, section `QNAPFileManager` | `.qpkg/Taproot/config/config.json`, section `Taproot` |
| Worker staging on tmpfs | `<tmp>/.qnapfilemanager/qnapfilemanager`, temp `qfm-*` | `<tmp>/.taproot/taproot`, temp `taproot-*` |
| Trash root on each volume (and its publish temp) | `.@qfm_trash` (`.@qfm_trash.tmp-<hex>`) | `.@taproot_trash` (`.@taproot_trash.tmp-<hex>`) |
| Copy temporaries | `.qfm-copy-*` | `.taproot-copy-*` |
| Upload temporaries | `.qfm-upload-<hex>.part` | `.taproot-upload-<hex>.part` |
| App log | `logs/qfm.log` | `logs/taproot.log` |
| Session cookie | `qfm_sid` | `taproot_sid` |
| Break-glass cookie | `__Host-qfm_bg` | `__Host-taproot_bg` |
| CSRF header | `X-QFM-CSRF` | `X-Taproot-CSRF` |
| Base meta tag | `qfm-base` | `taproot-base` |
| Theme preference (localStorage) | `qfm-theme` | `taproot-theme` |
| Audit stderr prefix | `qfm audit:` | `taproot audit:` |
| Inherited-fd names | `qfm-worker`, `qfm-worker-parent`, `qfm-worker-child` | `taproot-worker`, `taproot-worker-parent`, `taproot-worker-child` |
| ZFS CI test gate | `QFM_ZFS_TEST` | `TAPROOT_ZFS_TEST` |
| UI `<title>` and header `<h1>` | `QNAPFileManager` | `Taproot` |
| Icon and favicon SVG `<title>` | `QNAPFileManager — root access` | `Taproot — root access` |
| Dev preview configuration (`.claude/launch.json`) | `qnapfilemanager` | `taproot` |

Not renamed: the ports (8770, 8771), every API route, every config key, the repository URL (a GitHub repository
rename is a separate owner decision; GitHub redirects old URLs), and history — `docs/reviews/`, the older design
documents and contracts, `docs/research/`, the deliberation transcripts and the CHANGELOG's released-milestone
sections keep the name they were written under.

## 2. Pre-1.0 installations

Taproot is a different App Center package, not an upgrade of QNAPFileManager. No migration code: the only
installations are the owner's two test units. The install guide says, for a unit that ran a pre-1.0 build: remove
QNAPFileManager in App Center first (both packages bind 8770); empty its Trash before removing it, then delete each
volume's leftover `.@qfm_trash` once it is empty; set the break-glass password again with `taproot break-glass
set-password` if the door was in use.

## 3. Ownership

| Part | Owner | Files |
|---|---|---|
| Go | G | `go.mod`; every `*.go` file (the module path in imports, and the identifiers in §1); `cmd/qnapfilemanager` → `cmd/taproot` (`git mv`); `scripts/icongen` and ALL of its outputs (`qpkg/icons/*.gif` via `git mv`, `docs/brand/icon.svg`, `internal/web/static/favicon.svg`) |
| UI | U | `internal/web/static/` except `favicon.svg`; `internal/web/*.mjs` |
| Packaging, CI, scripts | P | `qpkg/qpkg.cfg`, `qpkg/package_routines`, `qpkg/shared/QNAPFileManager.sh` → `qpkg/shared/Taproot.sh` (`git mv`), `.github/workflows/build.yml`, `scripts/*.ps1`, `.claude/launch.json`, `config.example.json`, `dev-config.json`, `.gitignore`/`.gitattributes` if they name anything |
| Documents | D | `README.md`, `CHANGELOG.md`, `PLAN.md`, `SECURITY.md`, `CLAUDE.md`, `THIRD_PARTY_NOTICES.md`, `docs/identity.md`, `docs/qnap-install.md`, `docs/keyboard.md`, `docs/release-checklist.md`, `docs/nas-checklist.md`, `docs/development.md` |

Cross-part names (the cookie, header and meta names; `TAPROOT_ZFS_TEST`; `cmd/taproot`; the binary path) are fixed by
§1 — each side spells them from this table and never from the other side's work in progress.

## 4. Acceptance

- `git grep -n -i -E "qnapfilemanager|qfm"` finds nothing outside the history kept in §1 and the explicit pre-1.0
  upgrade text of §2 (and this contract).
- Everything builds and passes: the three-GOOS vet sweep, `gofmt`, `go test ./...`, `node --test internal/web/*.mjs`,
  and the dev loop (`go run ./cmd/taproot serve -config dev-config.json -jail testdata/fakeroot -addr
  127.0.0.1:8899 -dev -impersonate sveinung -readonly=false`) serves the UI with a working mutation (CSRF header and
  cookie agree).
- Rules from the stabilization contract §6 apply: LF, no new dependency, match the surrounding voice, do not commit,
  touch only your row; report files changed and anything that needed another part.
