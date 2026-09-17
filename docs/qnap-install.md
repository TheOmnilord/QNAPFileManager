# Installing on QTS and QuTS hero

Everything an operator needs: install, first run, the emergency door, upgrade, removal, where things live, and what to do
when it does not work. For *why* any of it behaves as it does, see [docs/identity.md](identity.md).

Tested on QTS 5.2.x (ext4) and QuTS hero 5.2.x (ZFS). Architectures: `x86_64` and `arm_64` (aarch64); 32-bit ARM models
are not targeted. Minimum firmware declared in the package is 4.5.0.

## 1. Install from App Center

The release artifact is a single `QNAPFileManager_<version>.qpkg` containing both architecture trees.

1. Sign in to the NAS web interface as an administrator.
2. **App Center → the gear icon → Install Manually**, choose the `.qpkg`, and confirm.
3. App Center runs the package's service script as root and the app starts by itself.
4. Open it from the **main menu** or from the App Center tile. It opens as a window on the QTS desktop, like File Station —
   not a new browser tab.

The package is **unsigned**. App Center will warn about that, and on newer firmware you must first turn on
**App Center → gear → Install Manually / General Settings → "Allow installation of applications without a valid digital
signature"**. If the setting is off, the install is refused with a signature error rather than a warning.

QuTS hero installs exactly the same way. The only visible difference is the install volume name (`ZFS530_DATA` rather
than `CACHEDEV1_DATA`) and that each shared folder is its own dataset, which affects moves between shares (§9).

## 2. The proxy path, and the ports

The app appears under **`/qnapfilemanager/`** on the NAS's own web address — `https://<nas>/qnapfilemanager/` — not on a
port of its own. That is deliberate: App Center's reverse proxy (`QPKG_USE_PROXY=1`, `QPKG_PROXY_PATH=/qnapfilemanager`)
serves the app from the QTS origin, so the QTS session cookies arrive first-party, there is no mixed content, and a unit
with "Force HTTPS" on works with no certificate of ours involved.

| Port | What | Reachable from |
|---|---|---|
| 8770 | the app itself | **loopback only** (`127.0.0.1`) — the proxy's target, never the LAN |
| 8771 | the break-glass door (§4) | the LAN, TLS only, and only once a password has been set |
| 8080 / 443 | QTS's own web server | this is what you actually connect to |
| 8765 | **not us** — that is GitBackup | |
| 8899 | the development loop only; never on a NAS | |

The main listener refuses to bind anywhere but loopback; there is no configuration key that widens it. The break-glass
listener is the one sanctioned non-loopback surface.

## 3. First run

1. Open the app. You are signed in already — it takes your identity from the QTS desktop session and never asks for a
   password of its own.
2. **Read-only mode is ON.** A fresh install cannot change anything until someone turns it off deliberately. That is not a
   bug report; it is the default a root-capable file manager should ship with.
3. To turn it off: **Settings → Read-only mode**, as an administrator. You will be asked to confirm, and the change is
   written to the audit log and mirrored to QuLog.
4. Browse. A non-administrator sees the whole filesystem's shape but can only open what their own account could open over
   SSH — the kernel enforces that, not the app.

An administrator's operations run as root, exactly as File Station's do, and the guard's confirmations still apply to
them. Read [docs/identity.md §5](identity.md#5-what-an-administrator-can-and-cannot-do) before using it that way.

## 4. The break-glass door, and when to use it

This is the door for when **App Center or QTS's Apache is broken** and the normal path therefore does not exist. It is a
local password on its own TLS port, independent of QTS's account system. It is not a convenience login, and every use of
it is a milestone in QuLog.

Two things to know before you set it up: everything you create through this door is owned by **`root:root`** (there is no
QTS user behind the session to own it), and the password lives outside QTS's account policy — no expiry, no complexity
rules, no central revocation. Leaving one set and forgotten is leaving a permanent root credential on the NAS.

**The listener does not bind at all until a password is set**, so the port is closed on a fresh install. Setting one is
the whole of the setup: the certificate is generated as part of it, and the running daemon starts the listener by itself.

### Setting the password

Over SSH to the NAS, **as root**:

```sh
# 1. Find the install path.
QFM=$(/sbin/getcfg QNAPFileManager Install_Path -f /etc/config/qpkg.conf)
echo "$QFM"        # e.g. /share/CACHEDEV1_DATA/.qpkg/QNAPFileManager
                   #  or  /share/ZFS530_DATA/.qpkg/QNAPFileManager on hero

# 2. Set the password (typed twice, not echoed). 12 to 72 bytes.
#    This also generates the certificate if there is not one yet.
"$QFM/bin/qnapfilemanager" break-glass set-password -config "$QFM/config/config.json"

# 3. Read back the state, and note the SHA-256 certificate fingerprint it prints.
#    You will compare this against what the browser shows.
"$QFM/bin/qnapfilemanager" break-glass status -config "$QFM/config/config.json"
```

The subcommand refuses to run unless it is uid 0 and the config file is owned by root and not group- or world-readable —
a credential store with the wrong mode is worth stopping for.

**The password rule is 12 to 72 bytes**, with no composition rules. The upper bound is bcrypt's own: it cannot read past
72 bytes, so a longer passphrase would carry entropy that is never checked. The command refuses one rather than accepting
it and ignoring the tail, and it warns as you approach the limit. (1024 bytes appears elsewhere as the largest *login*
body the door will look at — that is a bound on what an attacker may send, not a password you can set.)

**No restart is needed.** The daemon re-reads the credential rather than caching it, so a password set while the app is
running takes effect on the next attempt, and the listener on 8771 comes up on its own once a credential exists. If the
port is still refused, restart the app from App Center.

The one case where a restart *is* needed is a certificate that had to be **replaced** — an expired pair, or one torn in
half by a crash between the two file writes. The command prints that pair under `next fingerprint:` and says so: a
running app holds its own certificate in memory and will go on serving the old one until it is stopped and started again
from App Center. The password half is live either way; only the certificate waits for the restart.

**Do not run `break-glass set-password` while somebody is changing settings in the app.** The CLI and the daemon's
read-only toggle both rewrite `config.json`, and they coordinate through a lock file that waits at most two seconds
before giving up. It is a moment's wait, not a corrupted file — but the command can fail with a lock timeout, and the fix
is simply to run it again once the settings change has landed.

The other subcommands:

```sh
qnapfilemanager break-glass disable            # clear the hash and evict live sessions; see the note below
qnapfilemanager break-glass status             # enabled, address, whether a hash is set and when, cost, fingerprint
qnapfilemanager break-glass cert               # print the certificate fingerprint
qnapfilemanager break-glass cert -regenerate   # after an IP change or a suspected key compromise
```

Every subcommand takes `-config <path>`; `set-password` also takes `-cost <n>` (bcrypt cost, 10–15) and `-stdin` (read
one line instead of prompting, for scripts). All of them accept **`-dev`**, which permits a development configuration —
it is for the development loop on a workstation and has no use on a NAS.

Changing or clearing the password **destroys every live break-glass session** on its next request.

`disable` takes effect immediately in the sense that matters — no password is accepted any more and existing sessions are
evicted — but on a **running** daemon the port stays open and refuses every attempt until the app is next restarted. The
command says so when you run it. The port is closed from the start only on a daemon that boots with no credential set. If
you want it shut now, restart the app from App Center.

### Using it, and the certificate warning

1. Browse to `https://<nas>:8771/`. Note `https` — the listener is TLS-only and will not answer plain HTTP. If the
   connection is refused, no password is set (§4) — or, rarely, the daemon has not noticed one yet, and restarting the
   app from App Center settles it.
2. **Your browser will warn you.** The certificate is self-signed and was generated on the NAS itself, when the password
   was set or when the listener first bound; it was never transmitted anywhere and there is no authority to vouch for it.
   That warning is expected.
3. **Before typing the password, compare the fingerprint.** Expand the browser's certificate details, find the SHA-256
   fingerprint, and check it against the one printed by `break-glass status` or in the app log at every start. This is the
   only protection you have against somebody on your LAN answering in the NAS's place, and the situation this door exists
   for — a broken NAS, an operator in a hurry — is precisely when nobody checks. Check anyway.
4. A *different* warning ("the name on the certificate does not match") means something else: the certificate's IP
   subject-alternative names were generated when the NAS had different addresses. Run `break-glass cert -regenerate`.

**The fingerprint changes only when you change it.** The certificate is valid for 397 days, and nothing rotates it for
you: not a restart, not setting a password. Inside the last 30 days the app log and `break-glass status` say how many
days are left and name `break-glass cert -regenerate`; run it, restart the app, and compare the new fingerprint once,
deliberately. That is the point — a fingerprint that changed by itself would be indistinguishable from somebody
answering in the NAS's place, and an operator who has learned to shrug at a changed fingerprint has lost the only check
this door gives them. The one exception is a certificate that has already **expired**: no browser would open that door
at all, so the app replaces it at the next start and logs the new fingerprint as a generated one.
5. Enter the local administrator password in the form. There is no username — the break-glass account is the only
   identity this listener has. The session you get is an administrator session, and a persistent orange banner says that
   everything you create through it will be owned by root.

The session you get belongs to the **address you signed in from**: presented from anywhere else it is refused and the
refusal is audited, which is what keeps a browser that also talks to QTS on 443 from handing your emergency session to
whatever answers there. If your address changes — a new lease, a different machine, a VPN — sign in again.

**Reach the door directly, from another machine on the LAN — never through an SSH tunnel or a local port forward.** A
login that arrives from the NAS itself is refused outright, and "the NAS itself" means **any address this NAS answers
on**: loopback, and every address on every interface — including its own LAN address, which is what a forwarder running
on the NAS (`socat`, an SSH tunnel with a bind address) would make your browser look like. A relay pins the session to
an address every other service on the NAS shares, and the cookie is host-scoped, so the pin would be satisfied by the
very replay it exists to stop. The refusal is worded and timed exactly like a wrong password and it does not count
towards the lockout, so reaching the door the wrong way costs you nothing but the trip. The set of the NAS's own
addresses is re-read about once a minute, so an address that arrives after the app started is covered too.

Five wrong passwords lock the account for 60 seconds, doubling to a 30-minute cap; a restart of the app clears the
lockout. A locked account is told so — the answer is `429 locked_out` with a `Retry-After`, deliberately, because leaving
an operator to guess at a door that will not open for half an hour is worse than admitting the lockout. Attempts,
lockouts and logins are all in QuLog.

If you would rather not have the port at all, set `web.breakGlass.enabled` to `false` in the config (§7) and restart the
app. Nothing else depends on it.

## 5. Upgrade

Install the newer `.qpkg` the same way; App Center stops the app, replaces the tree and starts it again. Configuration,
logs and the audit log live under the install directory and survive.

Stop is given up to 60 seconds so per-user workers and running jobs can drain, so an upgrade during a large copy takes a
moment. Check the version afterwards in the app — `api/session` reports it — rather than trusting App Center's tile.

## 6. Removal

Remove from App Center as usual. Two things are **deliberately left behind**:

- **`.@qfm_trash` directories** at each volume root. They hold files somebody deleted and may still want back, and
  uninstalling a file manager is not a decision to destroy them. Remove them by hand if you mean to:
  `rm -rf /share/<VOLUME>_DATA/.@qfm_trash`.
- The install directory's `logs/` — including the audit trail — goes with the package. Copy `audit.jsonl` out first if
  you need to keep the record.

## 7. Where everything lives

With `QFM=$(/sbin/getcfg QNAPFileManager Install_Path -f /etc/config/qpkg.conf)`:

| Path | What |
|---|---|
| `$QFM/bin/qnapfilemanager` | the single static binary — daemon, worker and CLI in one |
| `$QFM/config/config.json` | the configuration, mode `0600` in a `0700` directory (it holds the break-glass hash) |
| `$QFM/config/breakglass-cert.pem`, `breakglass-key.pem` | generated when the break-glass password is set, or when the listener first binds; mode `0600` |
| `$QFM/logs/qfm.log` | the app log; rotated at 8 MiB with one previous generation kept |
| `$QFM/logs/startup.log` | truncated at every start — where a crash *before* the logger exists shows up |
| `$QFM/logs/audit.jsonl` | the audit log: two lines per operation, intent and result |
| `$QFM/qnapfilemanager.pid` | the daemon's pid |
| `/etc/config/qpkg.conf` | App Center's record: `Install_Path`, `WebUI`, `Proxy_Path`, `Enable` |

`logs/` is mode 0700, so a non-root SSH user cannot read it; use `sudo`. The app itself refuses to browse its own
`config/` and `logs/` directories — the password hash and the audit trail are not readable through the thing they audit.

There is no seeded configuration file: an absent config *is* the first-run state, and every key has a working default.
Edit `config.json` only with the app stopped, and restart afterwards; an unknown key is rejected at load rather than
silently ignored, because a silently ignored safety switch is exactly the failure this daemon must not have.

Useful keys: `readOnly` (the global switch, also in Settings), `trash.enabled`, `web.breakGlass.enabled`,
`web.breakGlass.addr`, `auth.local.cost`, `logging.quLog`, `worker.max`, `jobs.*`. The break-glass **password** is never
edited here by hand — use `break-glass set-password`, which writes the hash and the `updated` stamp together.

`web.breakGlass.certFile` and `web.breakGlass.keyFile` move the key pair somewhere else, and they come with a rule: the
key, and **every directory above it up to `/`**, must be owned by root and writable by nobody else. The key is what the
emergency door terminates TLS with, so anybody who can replace it — or replace a directory on the way to it, symlinks
included — can answer in the NAS's place on that port. A location that does not meet the rule is refused: the door does
not bind, the app log says which path and why, and `break-glass status` prints `fingerprint: refused`. Fix the directory
and the door comes up within a minute, without a restart. Leaving both keys out puts the pair in the QPKG's own
`config/`, which the installer already tightens, and is the recommended answer.

## 8. The audit log

Every operation writes two JSON lines: an `intent` line before anything is dispatched and a `result` line after, so an
operation interrupted halfway still left evidence that it was attempted. Each line carries the user, the door it came
through (`qts` for the QTS desktop session, `local` for the break-glass door), the operation, the paths, counts and the
outcome.

Milestones — sign-ins, the read-only toggle, every denial, every chown, large deletes, writes under `/etc/config`, and
everything the break-glass door does — are also mirrored to **QuLog Center**, where they sit beside QTS's own events.
Only *Alert* notification rules (severity plus keyword) can forward them onward; QNAP does not let a third-party package
raise a notification directly.

## 9. Troubleshooting

**A blank window, or a window that never finishes loading.**
Usually the shell loaded but `api/session` did not answer. Check `$QFM/logs/startup.log` first — a wrong-architecture
binary, a bad flag or an unparsable config all leave the daemon dead with the reason only there, while App Center still
shows the app as running. Then check `$QFM/logs/qfm.log`. If the daemon is up, confirm the proxy target:
`/sbin/getcfg QNAPFileManager Proxy_Path -f /etc/config/qpkg.conf` must read `/qnapfilemanager` and `WebUI` must read
`/qnapfilemanager/`, with the trailing slash. Restart the app from App Center after correcting either.

**502 (or 503) from the NAS's own web server.**
Apache is proxying to `127.0.0.1:8770` and nothing is listening there. The daemon is not running, or it failed to bind
because another package took the port. Check with `netstat -tlnp | grep 8770` and read `startup.log`. Restarting the app
from App Center is the fix in almost every case; if the port is genuinely taken, change `web.listen` — it must stay a
loopback address — and `QPKG_WEB_PORT` together.

**"Connection temporarily unavailable" with a `qts_unavailable` code.**
The app could not validate your session against QTS on loopback. This is what a unit with "Force secure connection
(HTTPS)" looked like before the app learned to retry over HTTPS on loopback. If it recurs, check that
`/cgi-bin/authLogin.cgi` answers on the NAS itself and that QuFirewall is not filtering loopback.

**A `changed` refusal on a perfectly ordinary shared folder.**
`changed` means "a symlink appeared in a path that had already been authorised as canonical" — the app refuses to follow
it rather than operating on something it did not check. QTS builds `/share/Public` as a symlink to
`/share/CACHEDEV1_DATA/Public`, and that is normal and supported: the front end resolves the symlink *before* the worker
walks the path `O_NOFOLLOW` per component. So a `changed` refusal on a plain share means that resolution is not happening
and is a bug worth reporting, not a configuration problem — note the exact path and the operation.

**Everything is refused with "Read-only mode is on".**
That is the default on a fresh install. **Settings → Read-only mode**, as an administrator. If the app *forced* itself
read-only, the log will say so: that happens when the configuration file could not be read while reconciling the switch,
and refusing writes is the deliberate fail-closed behaviour. Fix the file's permissions or contents and restart.

**A non-administrator sees an empty folder that is not empty.**
It should say so explicitly — *"You do not have permission to list this folder"*, with the owner and mode. If you get a
genuinely blank list instead, that is a bug; an empty folder and an unreadable one must never look the same.

**A move between two shared folders is slow, or warns about a "different filesystem".**
Expected on QuTS hero: every shared folder is its own ZFS dataset, so a move between shares is a copy-verify-delete, not a
rename. The dialog predicts this before the job starts. A move *within* one share is instant.

**Permissions changed, but not to what was asked.**
The app reports what the kernel actually did, not what was requested. A setgid bit dropped for a non-member, an ACL that
overrode the mode, or a recursive job finishing "changed N of M, K owned by others" are all real answers. See
[docs/identity.md §12](identity.md#12-what-the-kernel-decides-and-what-the-app-predicts-inv-2).

**A worker fails to start with "permission denied" on QTS.**
QTS enforces access to ext4 shared-folder contents beyond the POSIX mode, so a non-root worker cannot reach the `.qpkg`
tree at all. The app stages a root-owned copy of its binary on a safe tmpfs and execs workers from there. If this appears
after an upgrade, check `qfm.log` for the staging path it chose and whether it fell back.

**Collecting information for a bug report.** `$QFM/logs/startup.log` and the tail of `$QFM/logs/qfm.log`, the output of
`/sbin/getcfg QNAPFileManager Install_Path -f /etc/config/qpkg.conf` and `getcfg System Version`, whether the unit is QTS
or QuTS hero, and the exact path and operation. Do **not** attach `config.json` — it holds the break-glass password hash.

## 10. Releasing

The procedure for cutting a release, the tagging rule and the hardware checks are in
[docs/release-checklist.md](release-checklist.md).
