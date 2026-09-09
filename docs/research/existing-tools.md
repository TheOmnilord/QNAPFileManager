# Is there an existing tool that manages the whole QNAP filesystem without SSH?

Research date: 2026-09-09. Short answer: **nothing polished and QTS-integrated exists.** Two generic tools can be
bent into it (FileBrowser QPKG, or FileBrowser in Container Station with a root bind mount), but neither
integrates with QTS login, neither understands `/share`, and neither can edit permissions or ownership.

## Why File Station cannot do it

File Station 6 (and its HTTP API, `/cgi-bin/filemanager/utilRequest.cgi?func=get_list|get_tree|copy|move|delete|createdir|rename|stat|upload|download`)
only accepts paths rooted at a shared folder (`share_root` / `vol_root`). Everything above `/share/<share>` is invisible.
The old forum trick of creating a shared folder whose path is `/` is not offered by modern QTS, where a share path
must lie inside a storage volume.

Sources:
- [QNAP File Station Web API v0.9 (PDF)](http://download.qnap.com/dev/QNAP_QTS_File_Station_API_v0.9.pdf)
- [File Station HTTP API v5 (PDF)](https://download.qnap.com/dev/QNAP_QTS_File_Station_API_v5.pdf)
- [Plain-text copy of the File Station Web API](https://github.com/mcaldwell85/seatec/blob/master/axis%20reference%20guide/QNAP%20File%20Station%20Web%20API.txt)
- [Forum: Where are the root system files and folders?](https://forum.qnap.com/viewtopic.php?t=150148)
- [Forum: How to access the root directory?](https://forum.qnap.com/viewtopic.php?t=112042)
- [Forum: Accessing hidden files on NAS](https://forum.qnap.com/viewtopic.php?t=127573)
- [QNAP Community: accessing .qpkg application subdirectories](https://community.qnap.com/t/accessing-folders-within-application-subdirectories-e-g-qpkg-application-subdirectories/2238)

## Candidates

| Candidate | Reaches `/etc`, `/root`, `.qpkg`? | QTS login? | chmod / chown? | `/share`-aware? | Verdict |
|---|---|---|---|---|---|
| **FileBrowser QPKG** ([myqnap.org](https://www.myqnap.org/product/filebrowser/), v2.63.11, updated 4 Jun 2026; [forum thread](https://forum.qnap.com/viewtopic.php?t=168776)) | Yes, if its scope is set to `/` (QPKGs run as root) | No, own user DB | No permissions editor ([issue #2859](https://github.com/filebrowser/filebrowser/issues/2859), [issue #2059](https://github.com/filebrowser/filebrowser/issues/2059)) | No | Closest existing option. Upstream project is archived (Codex review), so no further security fixes for a root-exposed tool. |
| **Container Station + `filebrowser/filebrowser` image with `/:/srv`** | Yes (containers run as root; compose accepts arbitrary host paths) | No | No | No; absolute symlinks resolve inside the container, not the host | Works for browsing; wrong namespace semantics for a NAS whose shares are symlinks. |
| **Webmin File Manager** | Yes if Webmin runs as root | No | Yes | No | Real prior art, but no maintained QNAP packaging and a very large attack surface. |
| **Tiny File Manager / PHP tools under the QTS Web Server** | No, Apache runs as `httpdusr` | No | chmod only | No | Not a root manager. |
| **RasulAV/File-Manager-for-QNAP-NAS** ([GitHub](https://github.com/RasulAV/File-Manager-for-QNAP-NAS)) | No, uses File Station API v4.1 | Yes | No | Yes | Same `/share` limitation as File Station. |
| **Nextcloud external storage (local)** | Not for root-owned system dirs | No | No | No | Poor fit. |
| **Qsirch, HBS, Qfile** | No | Yes | No | Yes | Not file managers for system paths. |
| **WinSCP, Midnight Commander QPKG, Entware** | Yes | n/a | Yes | n/a | All require SSH, which the question excludes. |

## The proven pattern to build on

The user's own GitBackup project (`C:\Dev\GitBackup`) is a Go daemon packaged as a QPKG. QTS App Center starts the
package's service script as **root**, so the daemon lists the local filesystem with `os.ReadDir` and serves its own web UI.
That is exactly how the second screenshot in the original question (a listing of `/`) was produced, and it is the
blueprint for this project. See `docs/design/gitbackup-exploration.md`.

Tailscale's QNAP package uses the same shape and additionally validates the QTS session; see `docs/research/qts-integration-facts.md`.

Sources for the QPKG side:
- [QDK on GitHub](https://github.com/qnap-dev/QDK), [QDK template qpkg.cfg](https://github.com/qnap-dev/QDK/blob/master/shared/template/qpkg.cfg)
- [QPKG Development Guidelines](https://www.qnap.com/en/how-to/tutorial/article/qpkg-development-guidelines)
- [QDK configuration reference (DeepWiki)](https://deepwiki.com/qnap-dev/QDK/3-qpkg-configuration)
- [QTS HTTP API Authentication v5.1.0 (PDF)](https://eu1.qnap.com/dev/QTS_HTTP_API-Authentication_v5.1.0.pdf)
- [Tailscale PR #6858: use localhost for QNAP authLogin.cgi](https://github.com/tailscale/tailscale/pull/6858)
- [Tailscale client/web/qnap.go](https://github.com/tailscale/tailscale/blob/main/client/web/qnap.go)
