# QTS integration facts (verified from public source code and docs, 2026-09-09)

These resolve several items the design agents marked UNVERIFIED. Anything still uncertain is marked **VERIFY ON NAS**.

## 1. How a QPKG web app validates the QTS session (from Tailscale, BSD-3 licensed)

Source: https://github.com/tailscale/tailscale/blob/main/client/web/qnap.go

- Cookies set by the QTS desktop and forwarded to a same-host app: `NAS_USER` (username), and either `qtoken` (QTS 5) or `NAS_SID` (older).
- Validation calls, on the QTS web server:
  - qtoken: `GET <scheme>://<host>/cgi-bin/authLogin.cgi?qtoken=<qtoken>&user=<NAS_USER>`
  - sid:    `GET <scheme>://<host>/cgi-bin/authLogin.cgi?sid=<NAS_SID>`
- Response is XML; the fields used are `authPassed` (int), `isAdmin` (int), `authSid` (string), `errorValue` (int).
  Tailscale requires `authPassed != 0` and `isAdmin != 0`.
- Tailscale infers scheme and host from the incoming request URL (issues 7108 and 6903) and falls back to `http://localhost`.
  PR #6858 earlier moved it to `http://localhost:8080` because QTS "Force HTTPS" uses a self-signed certificate without usable CN/SAN,
  so any HTTPS call to it needs `InsecureSkipVerify`.
- QNAP's own auth API doc says the loopback address on the QTS HTTP port (default 8080) is the documented way to call `authLogin.cgi`.

Verbatim struct:

```go
type qnapAuthResponse struct {
    AuthPassed int    `xml:"authPassed"`
    IsAdmin    int    `xml:"isAdmin"`
    AuthSID    string `xml:"authSid"`
    ErrorValue int    `xml:"errorValue"`
}
```

## 2. How Tailscale gets same-origin cookies: serve the UI through QTS's own Apache

Source: https://github.com/tailscale/tailscale/tree/main/release/dist/qnap/files/Tailscale

`qpkg.cfg.in` (key lines):

```
QPKG_NAME="Tailscale"
QPKG_RC_NUM="101"
QPKG_SERVICE_PROGRAM="Tailscale.sh"
QPKG_SERVICE_PORT="41641"
QPKG_WEBUI="/cgi-bin/qpkg/Tailscale/index.cgi"
QPKG_USE_PROXY="1"
QPKG_VISIBLE="1"
QPKG_VOLUME_SELECT="1"
QTS_MINI_VERSION="5.0.0"
QDK_DATA_DIR_ICONS="icons"
QDK_DATA_DIR_SHARED="shared"
```

`Tailscale.sh` start does `mkdir -p /home/httpd/cgi-bin/qpkg && ln -sf ${QPKG_ROOT}/ui /home/httpd/cgi-bin/qpkg/Tailscale`.
`ui/index.cgi` is:

```sh
#!/bin/sh
CONF=/etc/config/qpkg.conf
QPKG_NAME="Tailscale"
QPKG_ROOT=$(/sbin/getcfg ${QPKG_NAME} Install_Path -f ${CONF} -d"")
exec "${QPKG_ROOT}/tailscale" --socket=/tmp/tailscale/tailscaled.sock web --cgi --prefix="/cgi-bin/qpkg/Tailscale/index.cgi/"
```

So the UI lives on the QTS origin (port 8080/443) and the QTS cookies arrive automatically. The CGI runs as root under QTS's
Apache for each request. For a file manager that streams gigabytes, a CGI-per-request model is too slow; the plan instead runs a
persistent Go server and either (a) opens it on its own port (cookies still arrive because cookies are not port-scoped, unless
QTS marks them `Secure` and we are plain HTTP), or (b) uses `QPKG_USE_PROXY="1"` + `QPKG_PROXY_PATH` so QTS reverse-proxies a
path on its own origin to `127.0.0.1:<QPKG_WEB_PORT>`. **VERIFY ON NAS**: the exact Apache rule QTS writes for `QPKG_PROXY_PATH`,
and whether it strips the prefix.

Tailscale builds the QPKG in Docker (Ubuntu 24.04, QDK from a fork pinned by commit, `./InstallToUbuntu.sh install`,
then `qbuild --root /Tailscale --build-arch $ARCH --build-dir /out`). GitBackup does the same in GitHub Actions without a fork.

## 3. qpkg.cfg keys that matter (QDK template)

| Key | Meaning |
|---|---|
| `QPKG_WEBUI` | Relative path to the web interface (App Center tile link) |
| `QPKG_WEB_PORT` / `QPKG_WEB_SSL_PORT` | Port the tile link uses |
| `QPKG_USE_PROXY="1"` | Enable QTS HTTP proxy so clients connect via the QTS HTTP port (default 8080) |
| `QPKG_PROXY_PATH="/qpkg_name"` | Path prefix the proxy serves |
| `QPKG_DESKTOP_APP` | 0 = new browser tab, 1 = iframe on the QTS desktop, 2 = desktop only |
| `QPKG_VISIBLE` | Which users see the tile in the QTS main menu |
| `QPKG_SERVICE_PROGRAM` | Start/stop script, run as root by App Center |
| `QPKG_RC_NUM` | Start order |
| `QPKG_TIMEOUT="10,30"` | Start/stop timeouts |
| `QPKG_VOLUME_SELECT` | Let the user pick the install volume |
| `QTS_MINI_VERSION` | Minimum firmware; without it App Center shows a compatibility warning |

## 4. Other QTS facts used by the plan

- Install path: `/sbin/getcfg <QPKG_NAME> Install_Path -f /etc/config/qpkg.conf` (typically `/share/CACHEDEV1_DATA/.qpkg/<name>`).
- `/share` is a small tmpfs holding one symlink per shared folder plus the raw volume mounts (`CACHEDEV1_DATA`, or legacy `HDA_DATA`..`HDK_DATA` on this NAS). Creating files directly in `/share` fills RAM and vanishes on reboot (GitBackup's `errShareRoot` guard).
- QTS detection: `/etc/config/uLinux.conf` exists. Web ports live in that file (**VERIFY ON NAS**: exact keys).
- QuLog: third-party packages write events with `/sbin/log_tool`; only *Alert* notification rules (severity + keyword) can forward them.
- Recycle bin: `@Recycle` inside each shared folder is maintained by File Station/Samba logic with a private metadata store; a direct `rename` into it will not restore correctly, so the app needs its own trash.
- Unsigned QPKGs install through App Center's *Install Manually* with a warning; on newer firmware the setting "Allow installation of applications without a valid digital signature" must be on.
- Architectures: `x86_64` and `arm_64` (aarch64); 32-bit ARM models are not targeted.

## 5. Verified on real hardware (2026-09-10)

Two units: a QuTS hero NAS at 192.168.1.99 (firmware 5.2.9, x86_64, install path `/share/ZFS530_DATA/.qpkg/QNAPFileManager`)
and a QTS NAS (also 5.2.x). Both behave identically for the points below.

- `QPKG_DESKTOP_APP="1"` with `QPKG_USE_PROXY="1"` opens the app as a window inside the QTS desktop with the package's
  display name as the title. App Center writes `WebUI = /qnapfilemanager/` and `Proxy_Path = /qnapfilemanager` into
  `/etc/config/qpkg.conf` (also mirrored at `/mnt/HDA_ROOT/.config/qpkg.conf`); no Apache file under `/etc/config/apache`
  mentions the package, so the proxy is driven from `qpkg.conf` directly.
- **The proxy keeps the prefix and joins with a doubled slash**: the target is `http://127.0.0.1:8770/qnapfilemanager/`, so
  `/qnapfilemanager/app.css` reaches the daemon as `/qnapfilemanager//app.css` and the bare `/qnapfilemanager` as
  `/qnapfilemanager/`. Go's `http.ServeMux` cleans the doubled slash and answers 307 to the cleaned path, which is the URL
  the browser already asked for: an infinite loop until every doubled slash was collapsed before routing (commits ce1f266
  and its follow-up). The desktop opens the app at the bare path, so the shell must use absolute URLs under the prefix.
- The proxy forwards on both `http://<nas>:8080/qnapfilemanager` and `https://<nas>/qnapfilemanager`.
- QTS adds its own `Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'self';
  worker-src 'self' blob:` header to proxied responses; the app's stricter CSP is delivered alongside it and both apply.
- `getcfg System Version` prints `5.2.9` on hero (no `h` prefix); `Web Access Port` is 8080; `ps` shows the root daemon as
  user `admin` (uid 0). A non-root SSH user cannot read the package's 0700 `logs/` directory: use `sudo`.
- Still unverified: cookie names and attributes inside the desktop window, `authLogin.cgi` validation fields,
  forwarded headers set by the proxy.

## 6. Second hardware finding: Force HTTPS (QTS unit, 2026-09-10)

On the QTS unit at 192.168.1.95, "Force secure connection (HTTPS)" is on. `http://<nas>:8080/cgi-bin/authLogin.cgi`
answers `302` to `https://<nas>:8181/cgi-bin/authLogin.cgi`; only the HTTPS stunnel port (8181 here) returns the XML.
The daemon validated the QTS session over `http://127.0.0.1:8080`, received the 302 (redirects are not followed), could
not parse it, and returned `503 qts_unavailable` — a styled shell with a "Connection temporarily unavailable" banner.

Fix (commit follows): the loopback validation call now retries over HTTPS on 127.0.0.1 when the HTTP port redirects to
HTTPS or is closed. The SSL port is taken from the redirect Location (port only; the host is forced back to loopback) or,
for a closed HTTP port, from `[Stunnel] Port` in uLinux.conf (default 443), and the self-signed QTS certificate is
accepted (`InsecureSkipVerify`) because the connection is loopback only. `authLogin.cgi` on 8181 exposes `webAccessPort`,
`stunnelEnabled` and `stunnelPort`, matching `[Stunnel]` in `uLinux.conf`.
