# Changelog

All notable changes to QNAPFileManager are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions below 1.0.0 were never tagged: `main` builds carry a `0.0.<run>` version stamped by CI, and the first tagged
release is 1.0.0. The milestone sections under it are the development history of that release, in user terms. The
reasoning behind any decision named here is in [PLAN.md](PLAN.md) and in `docs/design/`.

## [Unreleased]

### Added

- `LICENSE` (MIT, matching `QPKG_LICENSE`) and `THIRD_PARTY_NOTICES.md` (the BSD-3 notices for the Go standard library
  and `golang.org/x/crypto`), both shipped inside the QPKG beside the binary.

### Deferred to 1.1

Named here so a 1.0.0 tag is not read as a claim that they exist:

- **Trash janitor.** `trash.days` is validated and carried in the configuration but nothing enforces it. Trash is emptied
  only through "Empty Trash…".
- **Extract.** Archives can be created and downloaded but not unpacked; there is no design yet for zip-slip and conflict
  handling.
- **ACL editing** of any kind — POSIX and NFSv4 — and any "effective permissions" computation. 1.0 reports what ACL
  backend a path has and warns when a chmod may discard an ACL; it does not edit one.
- **Thumbnails** and image previews.
- **In-app drag-and-drop** — dragging items within the list, or onto the tree, to move or copy them. (Dragging files
  *from your desktop* onto the list to upload them already works; that shipped in M2-C.)
- **Editing text files.** The text route is read-only: 1.0 views a file up to the configured size limit, it does not
  write one back.
- **The credential-proxy sign-in form** (`identity-and-hero-plan` §5.3), a username-and-password door on the main
  listener for when the QTS desktop cookies do not arrive. 1.0 has two doors: the QTS desktop session and the
  break-glass account.
- Also deferred: TOTP on the break-glass account; any HTTP route that changes the break-glass password; SSE for job
  progress (polling stays); a dual-pane layout.

## [1.0.0] — not yet released

*The date is filled in when the tag is cut; see [docs/release-checklist.md](docs/release-checklist.md).*

A file manager for the QNAP QTS and QuTS hero desktop that can reach the whole filesystem — `/`, `/etc`, `/root`, the
`.qpkg` trees, raw volume mounts — and never needs SSH. Installed from App Center as a QPKG, opened as a window on the QTS
desktop with the QTS login, with every operation running as the signed-in user's own Linux identity.

### M4 — Polish and release

#### Added

- **A break-glass door.** A second listener on `0.0.0.0:8771`, TLS only, authenticating one local password — for the case
  where App Center or QTS's Apache is broken and the normal door therefore does not exist. It **does not bind until a
  password is set**, and the password can only be set from the NAS shell as root
  (`qnapfilemanager break-glass set-password`, with `disable`, `status` and `cert [-regenerate]`). There is no HTTP route
  that sets, changes, resets or reveals it. Set `web.breakGlass.enabled` to `false` to remove the port entirely.
  Setting the password is the whole of the setup: it generates the certificate as well, and the running daemon brings the
  listener up by itself without a restart.
- A self-signed certificate, generated on the NAS when the password is set or when the listener first binds, valid 397
  days and renewed automatically within 30 days of expiry, with its SHA-256 fingerprint printed to the app log at every
  start and by `break-glass status`, so it can be compared before a password is typed into a page the browser has warned
  about.
- **A reason for every greyed-out control.** One table answers "why can't I do this?" in a full sentence — read-only mode,
  the selection, a capability prediction, or the guard — and the sentence reaches a screen-reader user and a keyboard user,
  not just a mouse hovering over a tooltip.
- **Named empty states.** A folder you cannot read now says so, with the owner and mode the kernel reported, instead of
  looking exactly like an empty folder. Filters and searches that found nothing report how many entries they looked at.
- A full-width read-only banner, and a persistent banner on a break-glass session saying that everything created through
  it will be owned by root.
- `docs/identity.md`, `docs/qnap-install.md`, `docs/keyboard.md`, `docs/release-checklist.md`, and this changelog.

#### Changed

- The main listener is **loopback-only, enforced**: a non-loopback `web.listen` is refused at load, and `-addr` goes
  through the same validation. The break-glass listener is the only sanctioned non-loopback surface.
- `auth.mode` is narrowed to `qts` outside the development loop; the local account now has its own listener rather than
  being a second form on the main one.
- Dialogs, the listing grid and the toolbar were reworked for keyboard and screen-reader use, and the layout is a
  contract down to 768 px: secondary toolbar actions collapse into a menu rather than disappearing, which is what they
  used to do.
- Audit events record which **door** a session came through: `qts` for the QTS desktop session, `local` for the
  break-glass account.
- `config.json` now has two writers — the app, when an administrator changes the read-only switch, and the `break-glass`
  CLI from the shell — so they coordinate through a cross-process lock file. Neither can interleave with the other or
  corrupt the file; the visible cost is that `set-password` and `disable` can fail with *"the configuration file is being
  written by another process"* if a settings change is landing at that moment. Wait two seconds and run it again.

#### Security

- Every break-glass event is a forced QuLog milestone: the listener binding, certificate generation, every login success
  **and failure**, every lockout, session issue and destruction.
- Login attempts are bounded three ways — 10 per minute per source IP, a 5-failure account lockout doubling to 30
  minutes, and one bcrypt verification at a time. Every rejected password returns the same `401` body after the same
  minimum 400 ms, so "wrong password" and "no password is configured" are not distinguishable — the pair that matters,
  since the second would otherwise advertise that the door is unarmed. A **lockout is deliberately not concealed**: it
  answers `429 locked_out` with a `Retry-After`, because leaving an operator hammering a door that will not open for half
  an hour is the worse failure.
- `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` added; the break-glass page refuses to be framed at all.
  No HSTS on either listener, deliberately: pinning HTTPS for the whole NAS host from a self-signed emergency door would
  break the QTS desktop, which is the opposite of repair.

### M3 — Permissions and properties

#### Added

- **Change permissions and ownership**, on one item or recursively. Mode changes travel as a mask and a value, so a
  recursive change alters only the bits you touched.
- A **Properties** dialog with a streaming folder size.
- **Capability hints**: controls are annotated with what your uid and groups suggest will happen, without blocking the
  attempt.
- An **ACL badge** per path reporting what the filesystem actually has — none, POSIX, NFSv4, or a trivial NFSv4 ACL that
  is only the mode in another form — rather than a yes/no.

#### Changed

- The result of a chmod or chown is **what the kernel did**, read back from the inode and diffed against what was asked.
  A recursive job finishes with counts: "changed N of M, K owned by others". A per-item refusal is a skip, not a failure.
- A chmod that may discard an inherited ACL — a QuTS hero dataset with `aclmode=discard`, or one whose `aclmode` could
  not be read — demands a typed-phrase confirmation naming the dataset.
- A recursive chmod may clear a setuid/setgid/sticky bit but never set one.
- A recursive change over a hero share descends into nested datasets when crossing is enabled, and the confirmation grade
  is the worst one found below the roots.

### M2 — Jobs and transfer

#### Added

- **Copy and move**, as cancellable jobs with progress, per-item warnings and a destination picker, plus `Ctrl+C` /
  `Ctrl+X` / `Ctrl+V`. Conflicts are resolved up front: skip, overwrite, or keep both.
- A **cross-filesystem pre-flight**: on QuTS hero every shared folder is its own dataset, so a move between shares is a
  copy rather than a rename. That is predicted before the job starts and stated in the dialog, with quota exhaustion given
  its own message.
- **Trash.** Deleting moves to a per-volume `.@qfm_trash` with a per-user subdirectory, on the same device, so it is
  instant and restorable. Permanent delete is still available, one rung further up the confirmation ladder. QNAP's own
  `@Recycle` is never written to.
- **Recursive delete** and **folder size** as jobs, with a bounded pre-scan so the progress bar has an honest denominator.
- **Upload**, from the file picker or by **dragging files from your desktop onto the list**, and **archive download**: a
  zip or tar.gz of any selection, streamed as it is walked.
- **Search** across a subtree, bounded (1000 hits / 500,000 entries / 60 s), case-folded substring or glob, with its own
  results view (`Ctrl+F`).
- A jobs panel, a trash panel with restore and empty, and an "Include mounted sub-folders" option for walks that should
  cross into datasets of the same pool.

#### Changed

- Content an administrator creates — new folders, uploads, copies — is owned by the **real signed-in user**, not root, the
  way File Station behaves. Ownership is set without touching the mode, so setgid bits and inherited ACLs survive. A move
  performed by root preserves the source's owner and group instead.
- A move deletes its source only after every regular file has been byte-verified against its copy.
- A cancelled job does not roll back the work it already did; it reports itself as partial and says so.

#### Fixed

- A trashed folder's size is measured when it is trashed, so the Trash panel shows a real size instead of "—" and
  emptying the trash does not report 4 KiB per folder.
- Finished jobs stop animating, and stop showing a stale transfer rate and a "/ 0" denominator.
- A folder that looks empty but will not delete now names the entries that are blocking it, including entries whose names
  are not valid UTF-8.

### M1 — Safety spine and the first NAS install

#### Added

- **Read-only mode**: a global, persisted switch, **on by default at first install**, that rejects every mutating request
  in one place, so a newly added endpoint is safe by default.
- **The guard**: a table of protected paths. `/` and the first-level system directories cannot be deleted or renamed by
  anybody; writes under `/etc/config` and the DOM configuration are allowed but must be confirmed; the app's own
  configuration and logs cannot be read or written through the app; creating files on the QTS RAM disk is refused.
- **The confirmation ladder**, from a toast with Undo up to a typed phrase, with the server issuing a signed token
  carrying a real scan summary — so skipping the dialog does not skip the check.
- **An audit log** in JSON lines, two phases per operation (intent and result), with milestones mirrored to **QuLog
  Center**.
- New folder, rename, delete, and the settings panel.
- The QPKG itself: App Center integration, the desktop window, the reverse-proxy path, and a service script that reports
  a failed start instead of leaving App Center showing a dead app as running.

#### Changed

- **Administrators operate as root**, like File Station, with no separate arming step. The guard, read-only mode and the
  confirmation ladder still apply to them, so a dangerous operation is still deliberate.
- Every delete requires a redeemed confirmation token regardless of its size.
- The read-only switch is no longer gated by a password: under the QTS-session identity model the app holds no password of
  its own to re-challenge against. It is gated by an administrator session, CSRF, an Origin check, an explicit
  confirmation and a forced audit milestone instead.

#### Security

Four residuals were accepted rather than closed, each with the reasoning in [PLAN.md](PLAN.md):

- **§2.0** — a parent symlink swapped between the front-end guard check and the worker's own re-resolve is a residual
  race. It lets an already-root administrator skip a confirmation dialog; it grants no access.
- **§2.4** — where `renameat2(RENAME_NOREPLACE)` is unavailable, "do not overwrite" falls back to a check-then-rename with
  a narrow window.
- **§2.5** — the read path checks the requested spelling of a path only, not the resolved one, so a symlink into a
  protected read region is not caught on a read. Mutations check both.
- **§2.6** — if the audit sink is wedged for more than two seconds during a read-only toggle, a late "ok" line can claim a
  change that was in fact rolled back. The live switch and the persisted configuration can never disagree; only the
  narrative can.

### M0 — Browse the whole NAS as yourself

#### Added

- A window on the QTS desktop, opened from App Center, with **no login of its own**: identity comes from the QTS session
  (`NAS_USER` plus `qtoken` or `NAS_SID`, validated against `authLogin.cgi` on loopback), revalidated on a 60-second cache
  and unconditionally before any write. Signing out of QTS destroys the session here.
- **One worker process per user.** Every filesystem operation, listing included, runs in a process that has already
  dropped to that user's uid and groups, so the Linux kernel enforces permissions — the app never re-implements them.
  Downloads and uploads pass an open file descriptor up rather than letting the root process open anything.
- Browse the whole filesystem, with a tree, breadcrumbs, an editable path, sorting, filtering, hidden files, a text
  viewer, and listings that stay responsive on directories with hundreds of thousands of entries.
- One binary for QTS and QuTS hero, with a per-mount capability table read from `/proc/self/mountinfo`. No operation
  branches on "QTS or hero"; every operation asks what the mount underneath it can do.
- Packaging and CI: a single static binary with no cgo, both architecture trees, and CI jobs that run the permission
  tests as root and the ZFS tests against a real file-backed pool.

#### Security

- Fail-closed identity throughout: the `sid` door is honoured only when QTS's answer carries a username; a missing
  `isAdmin` yields a normal-user session; a disagreement between QTS and local group membership takes the lower
  privilege and logs it; a username that resolves to no uid is refused rather than falling back to root.
- A CSRF header bound to the session on every mutating request, an Origin/Referer check, and rejection of cross-site
  fetches — three independent locks, because any one of them can be weakened by a browser change.

#### Fixed (found on real hardware, both units)

- The QTS reverse proxy joins its target with a doubled slash, which produced an infinite redirect loop; doubled slashes
  are now collapsed before routing, and the shell uses absolute URLs under the proxy prefix.
- On a unit with "Force secure connection (HTTPS)" on, the loopback session validation received a redirect instead of
  XML and reported the app as unavailable; it now retries over HTTPS on loopback.
- On QTS's ext4 shared folders a non-root worker cannot reach the `.qpkg` tree at all, whatever the mode bits say, so
  workers could never start; the worker binary is now staged on a root-owned tmpfs and exec'd from there.

[Unreleased]: https://github.com/TheOmnilord/QNAPFileManager/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/TheOmnilord/QNAPFileManager/releases/tag/v1.0.0
