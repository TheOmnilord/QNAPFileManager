# QNAPFileManager — master plan

Status: planning complete, no code yet. Revised 2026-09-09 (rev 2) for three requirement changes from the owner:
QuTS hero is in scope for v1; the app is a native QTS-desktop app with no separate login; every operation runs with
the identity of the user signed into QTS. This file is the single source of truth; the design documents under
`docs/design/` are inputs and are superseded by the decisions here where they disagree.

## Context

QNAP's File Station 6 only shows shared folders under `/share`. System paths (`/`, `/etc`, `/root`, `/mnt/HDA_ROOT`,
`/share/CACHEDEV1_DATA/.qpkg`) are unreachable, and the only ways in are SSH/Telnet tools. Research
(`docs/research/existing-tools.md`) found no maintained, QTS-integrated tool that browses the whole filesystem and edits
permissions without SSH. The sibling project GitBackup proves the mechanism: a Go daemon packaged as a QPKG is started
as root by App Center, lists the filesystem locally and serves its own web UI.

A note on "not web based": QTS has no native GUI toolkit. Every QNAP app, File Station included, is a web UI opened as a
window inside the QTS web desktop. "Native app" therefore means: a tile in App Center and the main menu, opened as a QTS
desktop window, same origin as QTS, no login of its own, identity taken from the QTS session. That is what this plan builds.

Deliverable: a `.qpkg` for QTS and QuTS hero 4.5+ (x86_64, arm_64) giving every QTS user a File-Station-like UI over the
whole filesystem, with the kernel enforcing that user's permissions, and giving administrators an explicit root mode for
system paths. Operations: browse, copy, move, rename, delete with trash, mkdir, upload, download, text edit, search,
chmod, chown, ACL awareness.

## Inputs

| Document | What it holds |
|---|---|
| `docs/design/identity-and-hero-plan.md` | **Rev 2 core**: identity model, per-user worker processes, RPC protocol, QuTS hero (ZFS) semantics, proxy embedding, revised milestones (Opus) |
| `docs/design/astra-per-user-review.md` | Independent critique of the same requirements (GPT-6 Astra via Codex, medium) |
| `docs/design/backend-packaging-plan.md` | Go package layout, `fsx` semantics, jobs, API, guard rules, QPKG/CI, tests (Opus, rev 1; §2.5-2.9, §5, §6.5, §7.1 superseded) |
| `docs/design/ui-ux-safety-plan.md` | Feature matrix, UI architecture, wireframes, confirmation ladder (Opus, rev 1; §5.1 framing is now the primary path) |
| `docs/design/codex-independent-review.md` | First-round critique (Codex) |
| `docs/design/gitbackup-exploration.md` | What to lift from `C:\Dev\GitBackup`, with line numbers |
| `docs/research/existing-tools.md`, `docs/research/qts-integration-facts.md` | Alternatives with sources; verified QTS auth and packaging facts (Tailscale, QDK) |
| `docs/development.md` | How to drive Codex / GPT-6 Astra as agents |

## Two invariants

- **INV-1**: no filesystem read of user data or any mutation for a non-root session ever executes in the root front-end process. The front-end only does guard metadata work (`Lstat`, `EvalSymlinks`, `statfs`, mountinfo). Enforced by an import-graph test: `internal/web` must not import `internal/fsops`.
- **INV-2**: permission decisions are made by the Linux kernel, never re-implemented. The app computes hints to grey out controls, treats `EACCES`/`EPERM` as truth, and re-`Lstat`s after chmod/chown to report what actually happened.

## Accepted safety residuals (M1)

These are known, bounded gaps that the M1 review accepted rather than closed now; each has a code comment pointing here.

- **§2.0 — residual dispatch race (guard check → worker re-resolve).** The front-end guard resolves an operation's parent symlinks (`resolveForGuard`) and now checks **both** the requested and the resolved spelling, taking the stricter verdict; it then dispatches the **resolved** canonical path to the worker, binding the operation as tightly as possible to what was guarded (mkdir/rename/delete). A parent symlink swapped between that front-end check and the worker's own re-resolve remains a residual race — the full descriptor-passing close (worker prepares and retains parent descriptors, authorizes the prepared operation, executes against those descriptors) is deferred past M1. This is accepted because it only affects the *confirmation step*: a non-root worker is kernel-blocked from protected paths regardless of the guard, and a root admin can already do anything via SSH, so the residual lets an already-root admin skip a confirmation dialog, not gain access. Matches the M0-style accepted-residual note above.
- **§2.5 — read-side guard checks the requested path only (alias bypass on reads).** The read handlers (`list`, `stat`, `text`, `download`) now enforce the guard's `OpRead`/`OpTraverse` denials — the install-dir config and the audit logs — but on the **requested (cleaned) path only**, with no `Resolve` round-trip, so the read path stays fast. A symlink whose resolved target lies in a protected read region is therefore not caught on reads. This is an accepted low-severity residual: only a root-admin session runs as a principal that could open those files at all, and a root admin can read them over SSH regardless, so it closes no access a root admin does not already have. (Mutations still check both the requested and the resolved spelling.)
- **§2.4 — rename no-overwrite TOCTOU fallback.** `!overwrite` is enforced atomically on Linux by `renameat2(RENAME_NOREPLACE)`. Where that syscall or flag is unavailable (an old kernel, a filesystem that does not implement it, or a non-Linux host) it falls back to an `lstat` pre-check whose narrow TOCTOU is accepted: between the check and the `renameat` a third party could create the destination. Far less dangerous than the containment races the O_PATH walk closes.

## Decisions (reconciled)

1. **Stack**: Go 1.26 stdlib, single static binary, `CGO_ENABLED=0`, `go:embed` UI split into `index.html` + `app.css` + ES modules, no npm. Module and binary `qnapfilemanager`. JSON config. One dependency: `golang.org/x/crypto/bcrypt` (break-glass account only).
2. **Deployment: same-origin through the QTS proxy.** `QPKG_USE_PROXY="1"`, `QPKG_PROXY_PATH="/qnapfilemanager"`, `QPKG_WEBUI="/qnapfilemanager/"`, `QPKG_DESKTOP_APP="1"`, `QPKG_WEB_PORT="8770"` bound to `127.0.0.1` only. The UI is served from the QTS origin, so QTS cookies arrive first-party, there is no mixed content and no certificate problem. The daemon serves its mux at both `/` and the prefix so it works whether or not QTS strips the prefix. No `X-Frame-Options`; CSP `frame-ancestors 'self'`. Session cookie `Path=/qnapfilemanager/`, `SameSite=Lax`, `Secure` when behind TLS.
3. **Identity from the QTS session, no login of our own.** Read `NAS_USER` + `qtoken` (or `NAS_SID`), validate against the configured loopback endpoint `http://127.0.0.1:<port>/cgi-bin/authLogin.cgi` (port from `uLinux.conf`, fallback 8080), never a request-derived host. Lenient XML parse of `authPassed`, `isAdmin`, `authSid`, `username`. 60 s cache with single-flight; unconditional revalidation before any write; QTS sign-out destroys our session in place. **Fail closed**: the `sid` path is enabled only if the validation response carries the username (otherwise `NAS_USER` could be forged to gain another identity); if `isAdmin` is absent on validation, everyone gets a normal-user session and admins re-enter their password once. Fallbacks, in order: credential-proxy form (`authLogin.cgi?user=&pwd=`, non-admins allowed), then a local bcrypt break-glass admin on a second listener `0.0.0.0:8771` with self-signed TLS, so the tool still works when Apache or App Center is broken.
4. **Username to Linux identity** (`internal/idmap`): `/etc/passwd` + `/etc/group` in pure Go (primary gid always included in the group set), reloaded on mtime/size change. Domain users are not in `/etc/passwd`: resolve once per session with `id -u/-g/-G` (or `getent`) as a bounded exec, cache for the session; admit with a visible "groups incomplete" banner if `-G` is unavailable; refuse if no uid resolves. Never fall back to root. Admin = `isAdmin == 1` **and** local membership (uid 0 or `administrators`); on disagreement take the lower privilege and log it.
5. **Impersonation: one long-lived worker process per uid.** The root front-end re-execs its own binary in `-worker` mode with `SysProcAttr.Credential{Uid,Gid,Groups}` (groups explicit, never nil), talking over an inherited anonymous socketpair with length-framed JSON where paths are `[]byte`. Every file operation, including listing, search, trash and upload temp files, runs inside the worker. Downloads and uploads: the worker opens the file as the user (kernel permission check at open) and passes the fd up with `SCM_RIGHTS`; the front-end only streams bytes. Never the reverse. Jobs are one long-lived RPC with in-band progress and per-item warning frames, coalesced to 10/s. Pool: lazy spawn with single-flight, `max` 8, idle reap 10 min (never while a job runs), LRU eviction, crash recovery with a restart budget of 5/min, retire on group change, `bye`/`SIGTERM`/`SIGKILL` shutdown. In-process `setuid`/`setresuid` is rejected. Per-job processes are an optional mode for huge jobs.
6. **Administrators operate as root** (owner decision, 2026-09-10, like File Station). An admin session's worker runs as uid 0, so it sees and (in M1, subject to the guard) changes the whole filesystem; a non-admin runs as their own uid. `sess.who.Root = sess.admin` in the web layer; the pool keys all admin sessions to one `root` worker. The guard's protected-path confirmations and the `readOnly` toggle still apply to a root session, so a dangerous operation is still deliberate; there is no separate identity-arming step. (Superseded the earlier plan of admins starting as themselves and arming root.)
7. **Safety model** unchanged in shape: `readOnly` (global, persisted, default on at first install), the guard's prefix rule table (applies to non-root sessions too as defence in depth, plus a never-descend component rule for `.zfs`), HMAC confirmation tokens carrying a real scan summary, audit JSON lines with intent and result phases mirrored to QuLog for milestones. Guard and audit live in the root front-end before the RPC.

   **Deviation (2026-09-10, M1 review):** the original "password to disable read-only" is dropped. It predates the QTS-session identity model (decision 3), under which this app holds no password of its own — an admin is authenticated by their live QTS desktop session, so there is nothing to re-challenge against. The toggle is instead gated by: admin session + CSRF + Origin, a **required client confirmation** so the change is deliberate, and a forced milestone audit line (written durably). The only password that exists is the break-glass one on the separate TLS listener (decision 3), never on this route. In M1 every delete is likewise permanent (trash is M2), so **every delete requires a redeemed confirmation token regardless of size** (finding adv 9 / this decision), not only warn-class paths or multi-GiB targets.
8. **One binary, data-driven platform table** (`internal/platform`): parse `/proc/self/mountinfo` into per-mount `FSCaps{FSType, Storage, Domain, ACLBackend, ACLXattr, ZFSAclmode, Network}`. Volume roots are storage mounts that are direct children of `/share` (works for `CACHEDEV1_DATA`, `ZFS530_DATA`, legacy `HDA_DATA`). QTS vs hero is only a label; **no operation branches on it**, every operation asks `Platform.For(path)`.
9. **Recursion crosses storage domains, not devices.** QuTS hero mounts one ZFS dataset per shared folder, so `st_dev` differs per share and the rev 1 one-filesystem rule would skip every share. Walks may cross into mounts of the same domain (`zfs:<pool>` or the same block device) that are `Storage` and not `Network`; they still never enter `/proc`, `/sys`, `/dev`, tmpfs, USB disks, other pools or network mounts. Exposed in the UI as "Include mounted sub-folders". Moves between shares on hero are `EXDEV`: predicted before the job starts and stated in the confirm dialog; `EDQUOT` gets its own message.
10. **Trash**: the nearest enclosing storage mount root gets `.@qfm_trash` (mode `1777`, sticky, created once by the front-end, audited and disclosable) with per-uid subdirectories; a delete is a same-device `rename` by the user's worker. On hero that lands per share, next to `@Recycle`, which stays read-only and is never written to. No same-device trash means permanent delete at confirmation level 2.
11. **ACLs**: per-mount detection via `Getxattr` on `system.posix_acl_access` (QTS) or `system.nfs4_acl` / RichACL (hero, exact name to verify). Hero badge text warns that chmod may discard or reduce the ACL; when `aclmode` is `discard` or unknown, chmod on an ACL-bearing item requires level-2 confirmation. Editing ACLs is v2 (POSIX) and v3 (NFSv4).
12. **chmod/chown for non-root users**: kernel rules apply (chmod owner-only, chown root-only, chgrp to own groups only, setgid silently dropped for non-members). The API returns the post-call `Entry` and diffs it against the request; recursive jobs treat `EPERM` per item as a skip and finish with "changed N of M, K owned by others". UI shows capability hints from uid/gid, never hard blocks.
13. **API paths** stay as rev 1 (query parameters or JSON bodies, `pathB64` for non-UTF-8 names, `X-QFM-CSRF` on every non-GET plus an `Origin` check). `RemoteAddr` is loopback behind the proxy, so audit records `X-Forwarded-For` only when the peer is loopback.
14. **Packaging/CI**: GitBackup's `qpkg/` layout, service script and workflow (minus static git); the service script passes the proxy prefix and web port from `getcfg`; `QPKG_TIMEOUT="30,60"` so stop can drain workers. New CI jobs: `test-linux-root` (fixture users and groups, worker impersonation, sticky-dir and setgid cases, fd passing, crash recovery) and a ZFS job (file-backed pool with two datasets under a fake `/share/ZFS1_DATA` for crossing, `EXDEV`, trash root and `aclmode`). Unprivileged `unshare -Ur` gate for pool logic. qemu smoke test of both arch trees before `qbuild`.
15. **Dev loop**: `-jail <dir>` reroots every syscall (applied inside the worker); `-impersonate <user>` spawns a worker as a chosen user without QTS; `Platform.FromMountinfo` over golden mountinfo files captured from the real QTS and hero NAS lets hero paths run on Windows.

## Repository layout (target)

```
cmd/qnapfilemanager/main.go        serve | -worker | version
internal/platform/                 mountinfo parser, FSCaps, MayCross, QTS/hero detection, ACL backend probe
internal/idmap/                    passwd/group parser, NSS exec fallback, admin decision
internal/qtsauth/                  cookie extraction, authLogin.cgi client, cache, session issue
internal/wproto/                   frame codec, request/response types, SCM_RIGHTS helpers
internal/worker/                   worker main loop (runs as the user), executes fsops
internal/workerpool/               spawn, lifecycle, crash recovery, INV-1 boundary
internal/fsx/                      read-only path/type helpers shared by both sides
internal/fsops/                    list, stat, copy, move, delete, chmod, chown, text, search, archive, upload, trash (worker only)
internal/guard/                    rules, Check/Classify, confirm tokens, read-only, .zfs component rule
internal/jobs/  internal/audit/    job manager over RPC progress; JSON-lines audit + QuLog
internal/qnap/ diskfree/ logfile/ jsonfile/ durable/   copied verbatim from GitBackup
internal/config/  internal/web/   JSON config; server, routes, security, static/
qpkg/  scripts/  docs/  testdata/  .github/workflows/build.yml
```

## Hardware bring-up (M0 verified on real hardware, 2026-09-10)

M0 (read-only browse) is working end to end on both of the owner's NAS units — a QuTS hero (192.168.1.99, ZFS) and a
QTS unit (192.168.1.95, ext4), firmware 5.2.x — installed from App Center, opened as a QTS desktop window, authenticated
from the QTS session, browsing the whole filesystem as the signed-in user via a per-user worker. Five hardware-only
fixes were needed on top of the CI-green M0, each described in docs/research/qts-integration-facts.md §5-7:

1. The QTS reverse proxy joins its target with a doubled slash (`/qnapfilemanager//app.css`); collapse it before routing.
2. The desktop opens the app at the bare proxy path, so the shell must use absolute URLs under the prefix.
3. Force HTTPS: validate the QTS session over HTTPS on loopback when the HTTP port redirects or is closed.
4. QTS ext4 shared folders deny a non-root worker even reaching the QPKG binary; stage the worker binary on a safe
   root-owned tmpfs (`/tmp` when sticky, else `/`) and exec workers from there. (QuTS hero's ZFS volume does not enforce
   this, so the hero worked without staging.)
5. Make the install tree traversable and log worker-spawn failures with their cause.

Running build at verification: 0.0.35. Still open: the administrator identity decision (below), and the M1 items.

## Milestones

| Milestone | Exit criterion | Share |
|---|---|---|
| **M0 Platform table + worker spine + browse** | `platform`, `idmap`, `wproto`/`worker`/`workerpool` (List, Stat, OpenRead, Ping), `qtsauth`; browse the whole NAS as a chosen non-root user with the kernel enforcing permissions; hero paths pass against synthetic mountinfo and a file-backed ZFS pool in CI | 22% |
| **M1 Safety spine + basic ops + first NAS install** | guard, confirm tokens, readOnly, root-mode arming, audit + QuLog; mkdir/rename/single delete/OpenWrite+Finalize over RPC; `qpkg/` with proxy config; **first real install on QTS and on hero**; NAS checklist items 1-14 answered; both auth doors work | 20% |
| **M2 Jobs + transfer** | job RPC with progress and warnings, cancel; copy/move/delete/size/search/archive; upload and download via passed fds; per-uid sticky trash; EXDEV pre-flight; crossing checkbox | 23% |
| **M3 Permissions + properties** | chmod/chown with post-call diff and partial-success jobs; capability hints; ACL badge per backend; `aclmode=discard` confirmation; properties with streaming size | 17% |
| **M4 Polish** | non-admin UX pass, break-glass TLS listener, accessibility/keyboard/narrow passes, `docs/identity.md`, `docs/qnap-install.md`, tagged v1.0.0 | 18% |

Ordering: `platform` before `fsops`; `workerpool` before any write path; `idmap.Resolve` before `qtsauth` issues sessions; QTS auth is built in M0 and verified on hardware in M1.

## Must verify on the real NAS (QTS and hero; blocks M1 sign-off)

1. ~~The Apache rule QTS writes for `QPKG_PROXY_PATH`, whether it strips the prefix~~ Verified 2026-09-10: the prefix is stripped and the remainder is joined with a doubled slash (see docs/research/qts-integration-facts.md §5). Still open: which forwarded headers it sets.
2. ~~Whether App Center accepts `QPKG_WEB_PORT` bound to `127.0.0.1`, and whether `QPKG_DESKTOP_APP=1` with the proxy opens a desktop window~~ Verified 2026-09-10: both work on QTS and QuTS hero. Still open: the exact iframe URL.
3. `QPKG_VISIBLE` semantics and whether non-admins need an App Center app permission to see the tile.
4. Cookie names and attributes (`NAS_USER`, `qtoken`, `NAS_SID`; `Secure`, `SameSite`, `Path`).
5. Whether `authLogin.cgi` validation returns `username` (gates the `sid` path) and `isAdmin` (gates admin over SSO); rate limiting or QuLog noise per call; QuFirewall on loopback.
6. `uLinux.conf` keys for web/SSL ports and the `[System] Version` prefix on hero.
7. `id -G` / `getent` availability; `admin` uid; `administrators` group name and gid; whether `/etc/passwd` is a symlink.
8. Hero: `/share/ZFS*_DATA` naming, per-share `st_dev`, ACL xattr name, `zfs` binary path, `aclmode`, `.zfs` visibility, `@Recycle` behaviour.
9. `Pdeathsig` behaviour with `Credential`; free ports (`netstat -tlnp`).
10. Whether the QTS proxy sets `X-Forwarded-For` (or another client-attribution header) on proxied requests. Without it every
    peer is loopback, and the authentication failure budget can only key on the presented username: an attacker who
    spams bad tokens for a known username can delay that user's uncached logins, and rotating usernames can slow all new
    logins (established sessions and cached credentials are unaffected). This is an accepted residual risk of M0
    (docs/reviews/m0-round6-adversarial.md finding 2) until the header is verified and per-client admission can be keyed on it.

## Verification

- Windows: `go test ./...` plus the three-GOOS vet sweep; permission-semantics tests skip by design (INV-2).
- CI: `go test -race`, staticcheck, govulncheck, `test-windows`, `test-linux-root`, ZFS job, `unshare -Ur` gate, qemu smoke of both trees, `qbuild`.
- Golden tests: guard rule matrix, read-only blanket test over every route, import-graph test for INV-1, element-id and endpoint cross-checks between `static/` and the mux, `Platform.FromMountinfo` over captured QTS and hero mountinfo.
- Manual: `docs/nas-checklist.md`, run on QTS and on hero, once in a desktop window and once on the break-glass port.

## Open questions for the owner

- Break-glass listener on `0.0.0.0:8771` with a local admin password: keep it (recommended, so the tool works when Apache or App Center is broken) or drop it for a smaller surface?
- Should administrators be allowed to *stay* in root mode across sessions, or is the 60-minute arming always required? (Plan: always required.)
- Do you have a QuTS hero unit available for the M1 install, or only the QTS NAS from the screenshots? Hero verification needs real hardware.
