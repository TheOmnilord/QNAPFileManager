## Headline finding

**GitBackup does not talk to a QNAP NAS over any network API at all.** There is no File Station HTTP API, no `cgi-bin/filemanager/utilRequest.cgi`, no `func=get_list` / `func=login`, no `sid` handling, no SMB, no WebDAV, no `ezEncode`. I grepped the whole tree for every one of those tokens — the only hits are the words "browse"/"browser" in unrelated prose.

The reason it needs no SSH/Telnet is different from what you assumed: **the Go daemon runs *on* the NAS as a QPKG package (as root), and browses the NAS's local filesystem directly with `os.ReadDir`.** The browser talks to *GitBackup's own* HTTP server on port 8765, and GitBackup does the directory listing locally. `docs/wiki/Install-on-QNAP.md:29` states this design goal outright: "No SSH needed; everything, including restore, is configured in the browser".

So there is **no reusable QNAP HTTP API client here** — it does not exist in this repo. What *is* reusable is the folder-picker (server endpoint + vanilla-JS UI) and the QTS-specific path knowledge, which is genuinely valuable.

---

## 1. The actual mechanism

### Server endpoint

`C:\Dev\GitBackup\internal\web\server.go:418` — route registration:
```go
mux.HandleFunc("/api/browse", s.handleBrowse)
```

`C:\Dev\GitBackup\internal\web\server.go:2063-2151` — `handleBrowse`. Contract (documented at `C:\Dev\GitBackup\docs\wiki\HTTP-API.md:67` and `:85`):

- `GET /api/browse?path=<abs>&files=1` → `{"path":…, "parent":…, "dirs":[…], "files":[…]}`
- `POST /api/browse` with `{"path":…, "name":…}` → creates a folder, returns `{"path":…}`

The listing itself is plain stdlib (`server.go:2077`):
```go
entries, err := os.ReadDir(dir)
```

### The one genuinely QNAP-specific trick — symlink resolution at `/share`

`C:\Dev\GitBackup\internal\web\server.go:2082-2116`. This is the most transferable insight in the repo:

```go
// QTS shared folders under /share are symlinks to the volumes, so
// they must be resolved to be seen. At /share itself, show only the
// symlinked entries — the registered shares, matching File Station —
// and hide raw volume mounts like CACHEDEV1_DATA.
```
The loop splits entries into `plain` (real dirs) and `linked` (symlinks that `os.Stat` resolves to a dir — note `os.Stat`, not `os.Lstat`, is what follows the link at line 2102), then:
```go
dirs := append(append([]string{}, plain...), linked...)
if dir == "/share" && len(linked) > 0 {
    dirs = linked
}
```
So at `/share` the picker shows exactly the File Station shares and hides `CACHEDEV1_DATA` et al. Everywhere else it shows both.

### Path conventions

Paths are **absolute root-level Linux paths**, not File-Station-relative. Both spellings are valid and documented (`docs/qnap-install.md`, "Choosing a backup folder"): `/share/CACHEDEV1_DATA/Backups/git` (the real volume path) and `/share/Backups/git` (via the share symlink). The UI placeholder is `/share/Backups/GitBackup` (`internal/platform/platform_unix.go:14`, `internal/web/static/index.html:552`).

### Authentication

There is **no NAS credential anywhere** — the daemon is already root on the box. The only auth is GitBackup's own web login: bcrypt hash in `web.password_hash`, optional TOTP (`internal/config/config.go:99-178`, `Web.CheckPassword`). No base64, no ezEncode, no session `sid` for QNAP.

Notably, `/api/browse` is reachable **before** a password is ever set, in "setup mode" — `internal/web/server.go:716-736`. In that state it lists directories only (no files) and refuses `POST` (mkdir):
```go
withFiles := r.URL.Query().Get("files") != "" && !inSetupMode(r)
```
(`server.go:2090`), and `server.go:721-727` returns 403 for the create-folder button with a helpful message.

---

## 2. Tech stack

- **Language**: Go 1.25.0, module `gitbackup` (`C:\Dev\GitBackup\go.mod`)
- **HTTP**: stdlib `net/http` + `http.ServeMux`. No web framework.
- **Deps** (whole list): `robfig/cron/v3`, `gopkg.in/yaml.v3`, `golang.org/x/crypto` (bcrypt), `golang.org/x/sys`, `filippo.io/age` (offsite encryption), `filippo.io/hpke` (indirect)
- **UI**: a single hand-written **vanilla HTML/CSS/JS** file, `C:\Dev\GitBackup\internal\web\static\index.html` (3093 lines), plus `dash.html` (491 lines). No React/Vue, no npm, no bundler. Served via `//go:embed static` (`internal/web/server.go:37`).
- **Build**: `go build`; `scripts/build-local.ps1`, `scripts/build-static-git.sh`; GitHub Actions `.github/workflows/build.yml`; Docker; QDK for the `.qpkg`.
- **Tests**: Go stdlib `testing` only — ~90 `_test.go` files, no testify.
- **Dev launcher**: `.claude/launch.json` runs `go run ./cmd/gitbackup serve -config dev-config.yaml` on port 8899. Note the CLAUDE.md warning (line ~634): `go:embed` means you **must** use `go run`, not a stale `go build` binary, or HTML edits appear to do nothing.

---

## 3. Can it browse outside `/share`? — Yes, fully

The only gate is `browsable()` at `C:\Dev\GitBackup\internal\web\server.go:2173-2188`, and it enforces exactly two rules:

1. Path must be absolute (`errNotAbsolute`)
2. No UNC/network path **while unauthenticated only** (`isRemotePath`, `server.go:2200-2209`) — a signed-in admin may browse `\\host\share`

There is **no chroot, no allow-list, no `/share` prefix check**. Since `parent` is computed as `filepath.Dir(dir)` (`server.go:2119`) and the UI renders a `⬆ ..` row (`index.html:2958`), a user can walk up from `/share` to `/` and straight into `/etc`, `/root`, `/mnt`, anything the root-running daemon can read. With `&files=1` (signed in) it lists files too. That is a deliberate design decision, not an oversight — the security comments at `server.go:2160-2172` reason only about the pre-password window.

`defaultBrowseDir()` (`server.go:2213-2226`) picks: configured `BackupRoot` → `/share` if it exists → `$HOME` → `/`.

**Guard rails that exist** (all about the RAM disk, not about scope):
- `errShareRoot` (`server.go:2155`): mkdir directly in `/share` is refused — "folders directly under /share live on the NAS system RAM disk"
- `qnap.IsQTS()` (`internal/qnap/qnap.go:41`): detects QTS by `os.Stat("/etc/config/uLinux.conf")` — explicitly *not* by `/share` existing
- `diskfree.SameDevice()` (`internal/diskfree/diskfree_unix.go:10-19`): `syscall.Stat` and compare `sa.Dev == sb.Dev` — if the backup root is on the same device as `/`, it is the tmpfs
- Enforced twice: at save time `cmd/gitbackup/main.go:415-423`, and again at run time `internal/backup/backup.go:1026-1037` (a share that failed to mount silently turns a good path into a RAM-disk path)

---

## 4. Config / credentials

- Schema: `C:\Dev\GitBackup\internal\config\config.go` (773 lines), YAML via `yaml.v3`. `Config.BackupRoot` at line 291; `Web` struct at line 99 (`Listen`, `Username`, `Password`, `PasswordHash`, `TOTPSecret`, `TLS`, `TrustedProxies`).
- **No NAS host/port/credential fields exist** — nothing to connect to, since it runs locally.
- Location on QNAP: `$QPKG_ROOT/config/config.yaml`, via `GITBACKUP_CONFIG` exported in `C:\Dev\GitBackup\qpkg\shared\GitBackup.sh:27`. `$QPKG_ROOT` comes from `/sbin/getcfg GitBackup Install_Path -f /etc/config/qpkg.conf` (line 5), typically `/share/CACHEDEV1_DATA/.qpkg/GitBackup`.
- Default path elsewhere: `internal/platform/platform_unix.go:10` returns relative `"config.yaml"`; Windows uses ProgramData (`platform_windows.go:15`).
- Secrets are mode 600 in a 700 dir (`platform_unix.go` `Protect()`), and every secret field is `json:"-"` so it never reaches the browser.
- Sample: `C:\Dev\GitBackup\config.example.yaml` (11.8 KB, heavily commented).

---

## 5. Reusable modules for a new QNAP file manager

| Piece | Path | Note |
|---|---|---|
| Browse endpoint (list + mkdir) | `internal/web/server.go:2063-2151` | ~90 lines, stdlib only, drop-in |
| `/share` symlink-resolution rule | `internal/web/server.go:2082-2116` | The QTS-specific bit worth stealing |
| Path guard | `internal/web/server.go:2173-2188` (`browsable`) + `2200-2209` (`isRemotePath`) | UNC detection handles `\\`, `//`, `\/`, `/\`, `\\?\UNC\` |
| Default start dir | `internal/web/server.go:2213-2226` | |
| QTS detection + RAM-disk check | `internal/qnap/qnap.go:41-44`, `internal/diskfree/diskfree_unix.go` | Tiny, self-contained |
| QNAP event-log writer | `internal/qnap/qnap.go` (whole file, 101 lines) | `/sbin/log_tool` wrapper; zero deps |
| **Folder-picker UI component** | `internal/web/static/index.html:2939-3001` (JS) + `550-565` (markup) + `124-129` (CSS) | ~65 lines of vanilla JS; supports dir-mode and file-mode via `data-browse` / `data-mode` attributes; reusable across three fields (`backup_root`, `off_path`, `tls_cert`/`tls_key` at lines 553, 712, 853, 862) |
| Tests to port | `internal/web/browse_test.go` (48 lines), `internal/web/remotepath_test.go` | |
| QPKG packaging | `qpkg/qpkg.cfg`, `qpkg/shared/GitBackup.sh`, `qpkg/package_routines` | Complete working QPKG skeleton incl. `QPKG_WEBUI` / `QPKG_WEB_PORT=8765` |

The picker panel is a **single DOM node moved between fields** (`index.html:2980`: `picker.input.closest('.pickfield').appendChild($('browser'))`) — a neat pattern, though it means only one picker open at a time.

---

## 6. Docs on QNAP quirks

- `C:\Dev\GitBackup\docs\qnap-install.md` — the richest source. Covers the `/share` RAM-disk trap in detail, `getcfg Install_Path`, arch selection (`x86_64` vs `arm_64`, no armv7l), the QuLog **Alert**-rule-only limitation, and that QTS has a bare userland requiring bundled static `git`/`git-lfs` + CA bundle.
- `C:\Dev\GitBackup\docs\wiki\Install-on-QNAP.md` — user-facing version; line 29 has the "No SSH needed" claim.
- `C:\Dev\GitBackup\docs\wiki\HTTP-API.md:67,85` — the `/api/browse` contract.
- `C:\Dev\GitBackup\CLAUDE.md` (47 KB) — engineering notes. Relevant lines: 16 (bare userland), ~643 (`go vet` on Windows silently skips `diskfree_unix.go`, the `/share` guard — must run a three-GOOS sweep), 542-547 (QPKG smoke test; a flattened hardlink once stat'd fine and failed on QTS), 754 (index of docs).
- `internal/qnap/qnap.go:1-6` — the package doc explains why Event notification rules are unavailable to third-party packages (reserved for QNAP-registered apps), forcing the keyword-in-message approach.

---

## `C:\Dev\GitBackup` — one caveat

`git status` shows the repo has committed **backup artifacts** under `./backups/TheOmnilord/…` (`.pack`, `.bundle`, `manifest.json`). Probably test fixtures, but worth knowing if you clone it.

## `C:\Dev\QNAPFileManager`

**Completely empty.** Created 9 Sep 2026 15:30 (same minute as this session started). No files, no subdirectories, not a git repo, no hidden entries.

---

## The gap you should know about before planning

If your new project is meant to run **on a Windows/dev machine and reach a QNAP over the network**, none of GitBackup's access mechanism transfers — it assumes co-location. You would be writing the File Station HTTP client (`/cgi-bin/authLogin.cgi` for the `sid`, `/cgi-bin/filemanager/utilRequest.cgi?func=get_list`, the base64/ezEncode password quirk) from scratch. What GitBackup gives you is the *other* half: the `/share` symlink semantics, the RAM-disk trap, the path conventions, and a working folder-picker UI to hang it on.