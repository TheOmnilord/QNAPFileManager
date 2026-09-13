# NAS integration checklist

The **open questions about QTS and QuTS hero themselves** — things no test on a development box can answer, only a shell
on a real unit. PLAN.md's "Verification" section points here.

This is not the release pass. The functional acceptance run — browse, copy, permissions, the break-glass door,
accessibility — is [docs/release-checklist.md](release-checklist.md) §3. This file is where the *answers* go, and an
answered item moves into [docs/research/qts-integration-facts.md](research/qts-integration-facts.md) with its evidence.

Run on **both** units: the QuTS hero unit (ZFS) and the QTS unit (ext4), each once in a QTS desktop window and once
through the break-glass port.

## Answered (2026-09-10, both units, firmware 5.2.x)

Recorded in `docs/research/qts-integration-facts.md` §5–§7; listed here so nobody re-runs them.

- The Apache rule App Center writes for `QPKG_PROXY_PATH` **keeps** the prefix and joins the target with a doubled slash.
- `QPKG_WEB_PORT` bound to `127.0.0.1` is accepted, and `QPKG_DESKTOP_APP=1` with the proxy opens a desktop window.
- A unit with "Force secure connection (HTTPS)" answers `302` on port 8080; the HTTPS stunnel port returns the XML.
- QTS's ext4 shared folders deny a non-root uid any access into the `.qpkg` tree, whatever the mode bits say. `/tmp` on
  QTS is 0777 and **not** sticky, so `/` is the reliable staging parent.
- `getcfg System Version` prints `5.2.9` on hero with no `h` prefix; `Web Access Port` is 8080; `su` is absent from the
  QTS busybox.

## Open

### Session and identity

- [ ] **Cookie names and attributes inside the desktop window**: `NAS_USER`, `qtoken`, `NAS_SID` — and their `Secure`,
      `SameSite` and `Path` values. Read them from the browser's devtools on the framed app, not from the desktop page.
- [ ] **Does `authLogin.cgi` validation return `username`?** This gates the `sid` door: without a username in the
      response, `NAS_USER` is an unauthenticated claim and the door stays closed (fail-closed, by design).
- [ ] **Does it return `isAdmin`?** Without it every session is a normal-user session and administrators must
      re-authenticate once.
- [ ] Does a validation call produce QuLog noise, or hit a rate limit, when repeated? The app caches for 60 s and
      revalidates before every write, so a busy session makes a call every few seconds.
- [ ] Does QuFirewall filter loopback?
- [ ] **Does the proxy set `X-Forwarded-For`**, or any other client-attribution header? Without one, every peer on the
      main listener is `127.0.0.1` and the authentication failure budget can only key on the presented username — an
      accepted M0 residual until this is answered.
- [ ] The exact iframe URL the desktop opens.

### Identity mapping

- [ ] `id -G` and `getent` availability in the QTS busybox userland.
- [ ] The `admin` account's uid, and the exact name and gid of the `administrators` group.
- [ ] Is `/etc/passwd` a symlink? (It is on some firmware; the mtime/size reload must follow it.)
- [ ] A domain (LDAP/AD) user, if either unit has one: does the bounded `id` exec resolve them, and are the groups
      complete?

### Packaging

- [ ] **`QPKG_VISIBLE` semantics**: do non-administrators need an App Center app permission before the tile appears in
      their main menu?
- [ ] `netstat -tlnp` before the first release: 8770 and **8771** are free, and QuFirewall does not block 8771.
- [ ] `Pdeathsig` behaviour when combined with `Credential` — does a worker actually die with the daemon?
- [ ] `uLinux.conf` keys for the web and SSL ports, and whether hero prefixes `[System] Version`.

### QuTS hero specifics

- [ ] `/share/ZFS*_DATA` naming, and whether each share really has its own `st_dev`.
- [ ] The ACL xattr name actually present (`system.nfs4_acl` or a RichACL spelling).
- [ ] The `zfs` binary's path, and what `zfs get -Hp -o value aclmode <dataset>` returns for an ordinary share. **An
      empty answer makes every chmod on that unit a typed-phrase confirmation.**
- [ ] `.zfs` visibility, and `@Recycle`'s behaviour when a sibling trash directory exists beside it.

## How to answer one

Capture the evidence, not the conclusion: the command, its exact output, the firmware version and which unit. Append it
to `docs/research/qts-integration-facts.md` with a dated section heading, tick the box here, and — if it changes a
decision — say so in PLAN.md. A fact recorded without its command cannot be re-checked after a firmware update, and
firmware updates are the reason this file is not finished.
