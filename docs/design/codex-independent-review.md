## 1. Existing alternatives: the gap is integration and safe administration

**Recommendation is to build it, but position it as an administrator's filesystem tool.** Root browsing through a browser already exists elsewhere; the defensible value is QNAP-aware navigation, reliable file operations, ownership/permission controls, and deliberate safeguards.

| Candidate | Reaches system folders? | QTS login integration? | Permission editing? | Verdict |
|---|---|---|---|---|
| **MyQNAP FileBrowser QPKG** | Yes if daemon privileges/server root permit `/`. **UNVERIFIED**. | Own auth; native QTS SSO **UNVERIFIED**. | No dedicated POSIX mode/owner editor established: **UNVERIFIED**. | Closest lightweight alternative, insufficient evidence of being a complete replacement. |
| **Container Station + File Browser, `/:/srv`** | Conditional on host mount + container privileges. | No native QTS integration established. | Same File Browser limitation. | Plausible but has namespace/symlink caveats (absolute symlinks resolve inside container, not host). |
| **Nextcloud Local external storage** | Ordinarily cannot manage root-owned system dirs. | Own login. | Sharing/access controls, not `chmod`/`chown`. | Poor fit. |
| **Qsirch / HBS** | Not established for arbitrary `/` administration: **UNVERIFIED**. | QNAP account integration. | Not permission editors. | Not alternatives. |
| **QTS Web Server + Tiny File Manager** | Limited to `httpdusr` capability; `/root` unreachable as given. | Own sessions. | Has `chmod`; no `chown()` found in upstream source. | Real but scoped permission-editing option, not a root manager. |
| **Webmin File Manager (missed candidate)** | Yes if Webmin runs as root. | Webmin auth, not QTS SSO. | Yes — ownership and permissions. | Functional prior art weakening any "nothing exists" claim; maintained QNAP packaging is **UNVERIFIED**. |

Two corrections to the brief: **File Browser is archived upstream** (no further security fixes, known unresolved issues) — a real concern for a root-exposed deployment. And **`/:/srv` bind mounts do not perfectly reproduce the host namespace** — absolute symlinks resolve inside the container, and mount propagation affects visibility of later host mounts.

## 2. Architecture

**Agree** with Go + embedded vanilla-JS UI + QDK/GitHub Actions packaging. **Disagree** with treating GitBackup's picker or "runs as root" alone as sufficient architecture — the hard part is a policy-enforcing filesystem operation engine.

From GitBackup: `server.go:2065` uses raw `os.ReadDir`, skips dotfiles, and the mkdir branch doesn't call `browsable()` — not sufficient validation for a general root-mutation API. `qpkg.cfg` declares web path `/`, port `8765`, min QTS `4.5.0`. `GitBackup.sh` discovers install path and launches without dropping privileges (root depends on the launcher, not the script). `build.yml` cross-compiles with `CGO_ENABLED=0`, QEMU smoke-tests, and pinned QDK — reuse that packaging pattern.

Recommended changes: `net/http.ServeMux` is fine, no need for a router library; separate concerns into HTTP/auth, filesystem policy (race-resistant, path-safe), operation engine, durable jobs/trash/audit, and a QNAP adapter (mounts, identity, auth). Make MVP **administrator-only** (no impersonation of regular NAS users). Prefer QTS session validation via `authLogin.cgi`/`authSid` conditional on verification — exact SID delivery into App Center iframes is **UNVERIFIED**; fail closed rather than silently falling back to a separate login. Use durable jobs + SSE for progress (not blocking HTTP for copy/move/recursive chmod). Design trash before delete: app-owned trash dir per filesystem, same-filesystem rename preferred, journaled state, explicit refusal rather than silent permanent delete when trash is unavailable.

## 3. Top 10 risks and mitigations

1. **Web vuln → root access** — admin-auth-gated everywhere, CSRF/Origin checks, no shell exec, escape rendered filenames.
2. **RAM-disk/mount exhaustion** — inspect `/proc/self/mountinfo`; require persistent storage for uploads/jobs/trash; recheck mount identity before commit.
3. **Symlink races/loops** — descriptor-relative ops, no symlink-follow in recursive jobs by default, check resolved identity not just path string.
4. **`/proc`/`/sys`/special files** — bounded metadata read only, reject generic writes/streaming, stop recursion at mount boundaries.
5. **Self-deletion / other apps** — protect own install dir/binary/state; require explicit preview for other `.qpkg` trees.
6. **QTS config overwritten** — label `/etc` paths as possibly-managed/ephemeral; require explicit system-write opt-in; blanket "flash-backed" claim flagged **UNVERIFIED/overbroad**.
7. **Cross-device move/crash/data loss** — stage-copy-verify-then-remove-source for `EXDEV`; never claim atomic; journal trash transitions.
8. **Large directory listings** — batched/cursor-based listing, virtualized UI, recursive size/search as explicit jobs.
9. **POSIX/ACL/QuTS hero mismatch** — show numeric IDs separate from ACLs, probe tooling per-firmware, disable ACL writes until tested, respect ZFS dataset boundaries.
10. **Deployment/App Center integration failures** — publish checksums/signing status, test on real hardware not just QEMU, discover free port, only support iframe embedding after testing cookies/CSP/origin.

## 4. Minimal viable API

`/api/v1`, absolute paths, all mutations auth-required, no overwrite/no symlink-follow/no mount-crossing by default:

- `GET /list?path=&limit=&cursor=` → `{path, entries[{name,type,version}], nextCursor}`
- `GET /stat?path=&follow=` → `{path, type, mode, uid, gid, size, mtime, version, mountId, acl, allowed[]}`
- `POST /mkdir` `{parent,name,mode}` → `{path}`
- `POST /rename` `{path,name,ifVersion}`
- `POST /move` / `POST /copy` `{sources[], destinationDir, conflict}` → job (202 `{jobId}`)
- `POST /delete` `{paths[], disposition:"trash", recursive}` → job
- `POST /chmod` `{path,mode,recursive,ifVersion}` → job
- `POST /chown` `{path,uid,gid,recursive,ifVersion}` → job
- `PUT /upload?path=&conflict=` → stream, staged then committed
- `GET /download?path=` → attachment stream, reject special files
- `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/events` (SSE), `POST /jobs/{id}/cancel`
- Destructive/recursive ops: `dryRun:true` first → bounded preview + expiring `planToken`, revalidated at execution.
- Error shape: `{"error":{"code":"PROTECTED_PATH","message":"...","path":"/etc"}}`

## 5. QTS specifics

- **UID/GID**: `/etc/passwd`/`/etc/group` conventional; QNAP commonly also persists copies under `/etc/config` — exact symlink/backing relationship **UNVERIFIED**. Always retain numeric IDs; domain user resolution (winbind/NSS) availability **UNVERIFIED** for a CGO-free Go build.
- **ACLs**: Control Panel → Privilege → Shared Folders → Advanced Permissions covers Advanced Folder Permissions and Windows ACL support, which QNAP documents as interacting with each other. `getfacl`/`setfacl` presence and QuTS hero ACL representation are **UNVERIFIED** — probe at runtime, don't assume.
- **Recycle bin**: `@Recycle` within shared folders, applied by File Station/Samba/FTP service logic — not a kernel-level `unlink` interceptor, so a direct Go delete must implement its own trash, not rely on `@Recycle`.
- **App Center**: `QPKG_WEBUI` (path) and `QPKG_WEB_PORT` (port) define the entry point only, not auth. Automatic SID delivery into the launched page, and iframe vs. new-window behavior, are **UNVERIFIED** for current firmware.
- **`/etc/config/uLinux.conf`**: distinct from `/etc/config/qpkg.conf` (QPKG registry). Commonly referenced keys include `[System] Web Access Port` and `[Stunnel] Port`/`Enable`, but exact names/availability are **UNVERIFIED on target firmware** — discover read-only rather than hard-coding.

Full sourced citations (MyQNAP, Nextcloud docs, Tiny File Manager source, Webmin docs, QNAP ACL/authentication/recycle-bin/App-Center docs, Go traversal-resistant API blog, Docker bind-mount docs) were provided by Codex inline in the original analysis above.