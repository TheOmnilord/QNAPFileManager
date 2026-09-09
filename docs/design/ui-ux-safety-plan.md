# QNAPFileManager — Web UI / UX, Feature Matrix and Safety Model

Design plan v1 (produced by the UI/safety design agent, 2026-09-09). Companion to `backend-packaging-plan.md`.
Target: Go stdlib-only daemon running as **root** on QTS/QuTS hero, delivered as a QPKG, UI embedded with `go:embed`, no npm, no framework.

---

## 0. Decisions taken up front

| Question | Decision | Why |
|---|---|---|
| Two-pane (Total Commander) layout? | **No for v1.** Tree + single list, like File Station 6. Dual-pane is a v3 "power mode". | Doubles focus/selection/keyboard state for a feature most NAS users never use; drag from list to tree covers 90% of the need. |
| One HTML file (GitBackup style) or split? | **Split**: `index.html` + `app.css` + ES modules under `static/js/`. | GitBackup's `index.html` is already 151 KB / 3093 lines and it's a settings form. A file manager is bigger. Splitting also lets us ship a CSP without `'unsafe-inline'` (§5). Still zero build step — `//go:embed static` and `http.FileServer` are unchanged. |
| Modules: IIFE or ES modules? | **ES modules** (`<script type="module" src="js/app.js">`). | True module scope with no globals and no bundler. Cap at ~8 module files so the LAN round-trips stay trivial. |
| Routing | `location.hash` (`#/share/Public`), **never** History API. | Under a QTS reverse-proxy mount `pushState` needs a base path and breaks inside the QTS desktop frame. Hash keeps every relative URL resolving against the same base. |
| Large directories | Server-paged (`offset`/`limit`) + client-side **windowed rendering** on a fixed row height. | A `.qpkg` dir or a photo share with 200k entries must not build 200k DOM nodes. Details in §2.4. |
| Playwright / headless smoke test | **No, not in v1.** Two pure-Go static-analysis tests replace most of its value (§7.2). | Keeping npm out of the repo is an explicit constraint. |
| Auth | QTS session (`authLogin.cgi` sid) **as the primary**, own password as fallback/standalone. Admin required. | A root file manager must not have a weaker credential than the NAS itself. Non-admin QTS users get **refused**, not degraded. |

---

## 1. Feature matrix

### 1.1 Parity with File Station 6

| Feature | v1 (M0–M4) | v2 | v3+ | Notes |
|---|---|---|---|---|
| Left tree of `/`, lazy-expanded | ✅ | | | `/share` auto-expanded with shares listed like File Station |
| Right list (name/size/type/modified/mode/owner) | ✅ | | | Columns toggleable, persisted |
| Breadcrumbs, click any segment | ✅ | | | Plus an editable path field (`Ctrl+L`) |
| Sort by column, asc/desc | ✅ | | | **Server-side** (client only holds a window) |
| Hidden-files toggle | ✅ | | | `Ctrl+H`; persisted per user |
| Multi-select (click, Ctrl, Shift, Ctrl+A) | ✅ | | | Marquee (rubber-band) deferred to v2 |
| Right-click context menu | ✅ | | | Also `Shift+F10` / Menu key |
| Keyboard shortcuts | ✅ | | | Table in §3.9 |
| New folder | ✅ M1 | | | |
| Rename | ✅ M1 | | | `rename(2)`, same dir only |
| Copy / Cut / Paste | ✅ M2 | | | As jobs, with conflict resolution |
| Delete → Trash | ✅ M2 | | | Per-volume trash, restore, retention |
| Permanent delete | ✅ M2 | | | Always a stronger confirm |
| Download single file | ✅ M0 | | | `Content-Disposition: attachment` |
| Download folder / multi-select as ZIP | | ✅ | | `archive/zip` streaming job |
| Upload with progress | ✅ M2 | | | Chunked `PUT`, resumable, per-file bars |
| Drag-and-drop **from desktop** to upload | ✅ M2 | | | |
| Drag-and-drop **within the app** (move/copy) | | ✅ | | Deliberately after the confirm ladder exists |
| Properties dialog (size calculation) | ✅ M3 | | | Recursive `du` runs as a cancellable job |
| Permissions dialog (rwx grid + octal) | ✅ M3 | | | The headline feature |
| Owner / group change | ✅ M3 | | | Dropdowns from `/etc/passwd`, `/etc/group` |
| Recursive apply + "files only / folders only" | ✅ M3 | | | |
| POSIX ACLs | | | ✅ | Needs xattr-level work; QuTS/ZFS differs from ext4 |
| Text viewer | ✅ M1 | | | Read-only first |
| Text editor (save) | ✅ M3 | | | mtime/size optimistic concurrency + `.bak` |
| Search by name in subtree | ✅ M2 | | | Streaming job, depth-capped, never follows symlinks |
| Search by content (grep) | | ✅ | | |
| Image preview / thumbnails | | ✅ | | jpeg/png only (stdlib) |
| Compress / extract | | ✅ | | zip, tar, tar.gz — all stdlib |
| Share link / public link | | | ❌ never | A security liability for a root tool |
| Media player, photo wall, Qsync | | | ❌ never | File Station's job |

### 1.2 What this tool does that File Station **cannot**

| Capability | Where it shows in the UI |
|---|---|
| **Browse the whole filesystem** — `/`, `/etc`, `/root`, `/opt`, `/mnt/HDA_ROOT`, `/usr`, `/var` | Tree rooted at `/`, labelled `/ (system root)`. |
| **See `.qpkg` and other dot-directories** | `/share/CACHEDEV1_DATA/.qpkg` reachable; installed QPKG dirs get a `qpkg` chip. |
| **See the raw volume mounts** File Station hides | At `/share`: shares first, then a collapsed group `Volume mounts (n)` revealing `CACHEDEV1_DATA`, `HDA_DATA`… each with an ⏏ badge. (Inverts GitBackup's rule which hides them.) |
| **Symlink targets, visible and resolvable** | Row shows `name → target` dimmed monospace, "Go to target" action. Broken links struck through and red. Ops never silently traverse them. |
| **Mount points and filesystem identity** | ⏏ badge; status bar shows `ext4 · /dev/mapper/cachedev1 · 4.1 TiB free · rw`. |
| **The `/share` tmpfs RAM disk** | Permanent amber banner at `/share`; `mkdir` there refused with GitBackup's `errShareRoot` sentence. |
| **chmod (rwx grid + octal), recursive** | Permissions dialog, §3.5. |
| **chown / chgrp** from real `/etc/passwd` and `/etc/group` | Same dialog. Numeric uid/gid shown when a name doesn't resolve. |
| **Edit `/etc/config/*.conf`** | Editor opens them; protected path → L2 confirm + automatic `.bak` before writing. |
| **setuid/setgid/sticky bits** | Explicit checkboxes plus `S`/`t` chip in the Mode column. |
| **Special files** (fifos, sockets, devices) | Listed with type icon; download disabled; italic name. |
| **Audit log of every mutation** | Settings → Audit, §3.8. |

---

## 2. UI architecture (no framework)

### 2.1 File layout

```
cmd\qnapfm\main.go
internal\web\server.go              # mux, middleware, //go:embed static
internal\web\session.go             # lifted from GitBackup
internal\web\static\index.html      # shell only: markup, no inline JS/CSS
internal\web\static\app.css
internal\web\static\favicon.svg
internal\web\static\js\app.js       # entry: wiring + hash router
internal\web\static\js\dom.js       # $, $$, esc, el(), a11y helpers
internal\web\static\js\api.js       # call/post/stream, error mapping, 401 handling
internal\web\static\js\state.js     # the single store + subscribe()
internal\web\static\js\list.js      # virtualised grid
internal\web\static\js\tree.js      # left tree
internal\web\static\js\ops.js       # copy/move/delete/rename/mkdir/upload
internal\web\static\js\jobs.js      # job panel, SSE/poll, conflict prompts
internal\web\static\js\dialogs.js   # properties, permissions, confirm, editor
internal\fsapi\                     # list, stat, read, write, walk
internal\safety\                    # protected paths, ramdisk, mountpoints, confirm rules
internal\jobs\                      # job engine, cancellation, conflict queue
internal\identity\passwd.go         # /etc/passwd + /etc/group parsing
internal\trash\
internal\audit\
internal\qnap\qnap.go               # lifted: IsQTS(), QuLog
qpkg\qpkg.cfg, qpkg\shared\QNAPFileManager.sh, qpkg\package_routines
docs\qnap-install.md, docs\safety-model.md, docs\api.md
```

### 2.2 State model

One store, one mutation path, no globals. `state.js` exports `get()`, `set(patch)`, `subscribe(keys, fn)`; renderers are pure functions of state slices.

```js
{
  session:  { user, isAdmin, viaQTS, framed },
  settings: { readOnly, systemWrite, trashEnabled, showHidden,
              theme:'auto'|'light'|'dark', columns:[], confirmLevel },
  cwd:      '/share/Public',
  cwdMeta:  { realPath, device, fsType, readonlyFS, free, isMount,
              isRamdisk, isProtected, isShareRoot, parent },
  page:     { entries:[…], offset, limit:500, total, loading, error },
  sort:     { key:'name', dir:'asc' },
  filter:   '',
  selection:{ mode:'include'|'exclude', names:Set, anchor:idx, cursor:idx },
  clipboard:{ op:'copy'|'cut', srcDir, paths:[…] },
  tree:     { expanded:Set(paths), children:Map(path→[nodes]), loading:Set },
  jobs:     Map(id → { id, kind, state, done, total, bytes, rate, eta, current, errors:[], conflict:null }),
  toasts:   [ { id, kind, text, action } ],
  dialog:   null
}
```

- **`selection.mode`**: "Select all" in a 200k-entry directory must not materialise 200k names. `mode:'exclude'` means everything except `names`; operations send `{path, select_all:true, except:[…]}`. Get this right in M1.
- **`clipboard` is paths, not entries.** The job resolves paths at execution time and reports `enoent` per item.

### 2.3 Routing

`#/<abs-path>` — e.g. `#/share/Public`, `#/etc/config`, `#/`. Percent-encode `#`, `?`, `%` in path segments only.
Secondary views: `#!settings`, `#!jobs`, `#!trash`, `#!audit`.

### 2.4 Rendering large directories

- Fixed row height `--row-h: 30px` (36px under `pointer: coarse`).
- Render window = visible rows ± 20; recycle row nodes.
- Server pages of `limit=500`; sparse `page.entries`; skeleton rows for unloaded regions; debounced 80 ms; `AbortController` on scroll.
- **Sorting and hidden-file filtering are server-side.** Quick-filter filters only loaded pages and says so.
- `role="grid"` + `aria-rowcount`, `aria-rowindex` absolute on rendered rows, roving `tabindex`. Never a real `<table>`.
- Below 2,000 entries skip windowing (`virtualise = total > 2000`).

### 2.5 What to lift from GitBackup

**CSS (verbatim)** from `C:\Dev\GitBackup\internal\web\static\index.html`: lines 13–33 (`:root` tokens + dark overrides, contrast-audited), 36 (`[hidden]`), 54–60 (buttons), 88–91 (`.visually-hidden`), 92–98 (inputs incl. dark-mode select fix), 111–118 (`.danger`), 119–123 (`.errbox`), 132–137 (`.rowbtn`), 144–151 (`dialog`), 175 (`:focus-visible`), 177–206 (media queries + reduced motion).
**Do not lift:** `body { max-width: 860px }` (full-bleed app shell).

**JS** into `dom.js` / `api.js`: `esc()` (1054), `call()`/`post()` (990–1004; add `code`, `AbortSignal`, `Retry-After`), the 401 interceptor that swaps in the login view **without a redirect** (975–981), `say()` (1008–1010), `askPassword()` (1017–1052; generalise to `ask({...})`), `fmtDur` (1058; add `fmtBytes`, `fmtRate`, `fmtMode`). The picker (2942–2985): concept only, rewrite.

**Go**: `/share` symlink rule (server.go 2082–2116, invert the hiding), `browsable()` (2173–2188; add `..` rejection after Clean and `/proc/<pid>` refusal), `defaultBrowseDir()` (2213–2226), `errShareRoot` text (2155), header middleware shape (664–684; **`X-Frame-Options: DENY` must go**; keep `nosniff`, `no-store` on `/api/`, `MaxBytesReader` except uploads), `session.go` (cookie flags per §5.1), `internal/qnap/qnap.go`, `internal/diskfree/diskfree_unix.go` `SameDevice()`.

---

## 3. Screens (ASCII wireframes, with element ids)

### 3.1 Main view

```
#app
+==============================================================================+
| #hdr  QNAPFileManager   [#chipReadonly READ-ONLY] [#chipSysWrite SYS-WRITE 43:12] |
|                                    #btnJobs(2)  #btnSettings  #userMenu ▾    |
+==============================================================================+
| #toolbar  (see 3.2)                                                          |
+==============================================================================+
| #crumbs  / › share › CACHEDEV1_DATA › .qpkg           [#pathEdit ✎]  #free   |
+---------------+--------------------------------------------------------------+
| #tree         | #list  role=grid  aria-rowcount=214338                        |
| (role=tree)   +--------------------------------------------------------------+
|               | #listHead ☐ | Name ▲ | Size | Kind | Modified | Mode | Owner |
| ▾ / 🛡        +--------------------------------------------------------------+
|   ▸ bin 🛡    | ☐ 📁 ..                                                       |
|   ▸ dev 🛡    | ☑ 📁 Public       →/share/CACHEDEV1_DATA/Public  🔗           |
|   ▾ etc 🛡    |          --   folder  2026-08-14 09:12  drwxrwxrwx  admin:adm |
|     ▸ config  | ☐ 📁 Multimedia   --   folder  2026-07-02 11:40  drwxrwx---   |
|   ▸ mnt       | ☐ 📄 notes.txt   1.4K  text    2026-09-01 22:03  -rw-r--r--   |
|   ▸ opt       | ☐ 🔗 www        →/share/Web  (broken)                         |
|   ▸ root 🛡   | ☐ ⚙ null        --   char dev 2026-01-01 00:00  crw-rw-rw-    |
|   ▾ share     |                                                               |
|     ▸ Public  |   ┄┄┄ Volume mounts (3) ▸  ⏏  ┄┄┄  [collapsed group]        |
|     ▸ Multi…  |                                                               |
|     ▸ Web     |                                                               |
|     ┄ mounts ⏏|                                                              |
|   ▸ usr 🛡    |                                                               |
+---------------+--------------------------------------------------------------+
| #status  3 of 214,338 selected · 1.2 GiB │ ext4 · /dev/mapper/cachedev1 · rw  |
|          · 4.1 TiB free            [#jobsMini ▓▓▓▓░░░ Copy 62% ✕]            |
+==============================================================================+
```

Ids: `#app #hdr #chipReadonly #chipSysWrite #btnJobs #btnSettings #userMenu #toolbar #crumbs #pathEdit #free #tree #list #listHead #listViewport #listSpacer #status #jobsMini #mountGroup`. Rows: `row-<idx>` with `data-name`, `data-kind`, `data-idx`.

### 3.2 Toolbar

```
| [◀ #btnBack] [▶ #btnFwd] [▲ #btnUp] [⟳ #btnRefresh] │
| [+ New folder #btnMkdir] [⬆ Upload #btnUpload] [⬇ Download #btnDownload]
| │ [Copy #btnCopy] [Cut #btnCut] [Paste #btnPaste] [Rename #btnRename]
| │ [Delete ▾ #btnDelete]  → { Move to Trash (Del) | Delete now (⇧+Del ⚠) }
| │ [Permissions #btnPerms] [Properties #btnProps]
| [🔍 #searchBox filter this folder…] [☐ #chkHidden Hidden] [▦ #btnView]
```

Every mutating button is `disabled` + `aria-disabled` with a `title` explaining *why* (read-only mode, empty selection, protected target with `systemWrite` off). Never hide a button for a state reason.

### 3.3 Context menu (`#ctxMenu`, `role="menu"`)

Open (Enter) · Open in new tab · Go to symlink target → (symlinks only) │ Download · Copy (Ctrl+C) · Cut (Ctrl+X) · Paste into folder (Ctrl+V) · Rename… (F2) │ Move to Trash (Del) · Delete permanently… (⇧+Del ⚠) │ Permissions… (F9) · Properties… (Alt+Enter) · Edit as text… (F4) │ Copy full path · Calculate size.
Opened by right-click, `Shift+F10`, Menu key; flips when it would overflow. Inapplicable items are removed (not disabled) inside the context menu.

### 3.4 Jobs panel (`#jobsPanel`, right-side drawer)

Per job: `<progress>` bar, percent, kind → destination, Cancel; second line `1,204 / 3,900 files · 8.2 / 14.1 GiB · 112 MiB/s · ~52 s left`; `now: <current file>`.
State `AWAITING INPUT` shows the conflict: existing vs incoming size/mtime, `[Overwrite] [Skip] [Keep both] ☐ Apply to all remaining (n)`.
Finished with errors: `[Show errors ▾] [Retry failed]` with an `.errbox` list of path + reason.
Ids: `#jobsPanel #jobsList #job-<id> #jobBar-<id> #jobCancel-<id> #jobConflict-<id> #jobErrors-<id> #btnJobsClear`.
Progress percentages are **not** announced to screen readers; only start, awaiting-input, completion.

### 3.5 Permissions dialog (`#dlgPerms`)

```
| Permissions — /share/CACHEDEV1_DATA/Public
| Applies to: 1 folder   (or "3 items — 2 folders, 1 file · mixed permissions")
|                Read      Write     Execute
|  Owner    #pOR ☑        #pOW ☑     #pOX ☑
|  Group    #pGR ☑        #pGW ☑     #pGX ☑
|  Others   #pTR ☑        #pTW ☐     #pTX ☑
|  Special  ☐ setuid #pSUID  ☐ setgid #pSGID  ☐ sticky #pSTICKY
|  Octal   [#pOctal 0755 ]        Symbolic: drwxr-xr-x
|  Owner   [#pOwner  admin (uid 0)          ▾]  ☐ #pOwnerChange
|  Group   [#pGroup  administrators (gid 0) ▾]  ☐ #pGroupChange
|  ☐ #pRecursive  Apply to all contents, recursively
|      Apply to: (•) #pApplyAll Everything ( ) #pApplyFiles Files only ( ) #pApplyDirs Folders only
|      ☑ #pSmartX Use 0644 for files and 0755 for folders
|      ☐ #pFollowLinks Follow symbolic links  ⚠ off by default
|  #pImpact  Will change 8,041 items (7,204 files, 837 folders). [Recount]
| ⚠ #pWarn  Inside a protected path. Type "Public" to confirm: [#pConfirmPhrase]
|                       [#pPreview Preview changes] [Cancel] [#pApply Apply]
```

- Octal field and grid are two views of one value; a `mode` module owns the conversion (Go authoritative, JS mirror, unit-tested).
- **Mixed selection**: checkboxes `indeterminate`, octal blank with placeholder `mixed`; only touched bits are applied (mask + value, `+`/`-` semantics).
- `#pSmartX` on by default for recursive ops ("recursive 0755" is the classic way to ruin a share).
- `#pImpact` counts via the size job before enabling Apply on a protected path; `#pPreview` runs `dry_run:true`.

### 3.6 Properties dialog (`#dlgProps`)

Tabs General / Permissions / Link. General: Kind, Location, Full path [copy], Real path [copy], Target [Go to target], Size (streaming `du` job with Stop/Recount, files/folders count), On disk, Created/Modified/Accessed, Mode (symbolic + octal), Owner/Group (name + id), Inode/Links/Device, Filesystem (type, device, rw, mount point), Flags (🛡 ⏏ 🔗). Footer `[#propPerms Permissions…] [Close]`. Size job cancelled when the dialog closes.

### 3.7 Destructive confirm (`#dlgConfirm`)

**Grade 1** (reversible, trash inside a share): lists items, total size, source, where they go and the retention, `[Cancel] [#cfOK Move to Trash]`.

**Grade 2** (irreversible, or anything under a protected path), `class="danger"`: `#cfTargets` (first few + "and n more"), `#cfImpact`, `#cfFlags` (🛡 system path; trash unavailable here), `#cfWhy` (plain-language consequence), *To confirm, type the folder name:* `[#cfPhrase]`, `☐ #cfAckBackup I have a backup or I accept losing this.` `#cfOK` disabled until the phrase matches exactly **and** the box is checked. The phrase is sent as `confirm_phrase` and **re-verified server-side**. Autofocus on `#cfPhrase`, never on `#cfOK`.

### 3.8 Settings (`#!settings`)

- **Safety**: `#setReadOnly` (turning it off asks for the password), `#setSystemWrite` Allow changes outside /share (off by default; disarms on restart and after `#setSystemWriteTTL` minutes; shows "armed, 43 min left" + `#btnDisarm`), `#setTrash` + `#setTrashDays` + usage + Empty Trash…, Confirmations Normal / Paranoid.
- **Display**: `#setHidden`, theme Auto/Light/Dark, columns, date format.
- **Access**: sign-in mode (QTS account admin-only / local password), session timeout, QuLog events on/off, `#setFrameAncestors` allowed embedding origins.
- **Audit log**: filter by op / path / time, table of `time user op path detail result`, `[Download .jsonl]`.

### 3.9 Keyboard shortcuts (`#dlgShortcuts`, opened with `?`)

`↑↓` move · `Shift+↑↓` extend · `Ctrl+↑↓` move keep selection · `Space` toggle · `Enter` open · `Backspace`/`Alt+←` up/back · `Home`/`End` · `PgUp`/`PgDn` · `Ctrl+L` edit path · `/` focus filter · `Ctrl+F` search subtree · `Esc` clear/close · `Shift+F10`/Menu context menu · `Ctrl+C/X/V` · `Ctrl+A` · `Ctrl+Shift+N` new folder · `F2` rename · `Del` trash · `Shift+Del` delete permanently · `F9` permissions · `Alt+Enter` properties · `F4` edit as text · `F5`/`Ctrl+R` refresh (never `preventDefault` `Ctrl+R`) · `Ctrl+H` hidden · `?` this list. Every shortcut has a mouse equivalent (QTS frames swallow some chords).

---

## 4. Safety UX for a root tool

### 4.1 Visual marking

| Condition | Marker |
|---|---|
| Protected system path | 🛡 badge + `--protected` left border + amber breadcrumb tint; `title` + `.visually-hidden` text |
| `systemWrite` disarmed and inside one | Amber bar: *"Read-only here — turn on 'Allow changes outside /share' in Settings"* + inline arm button |
| Mount point | ⏏ badge; status bar names device and fs type |
| `/share` RAM disk | Amber banner with GitBackup's `errShareRoot` sentence; `#btnMkdir` disabled there |
| Symlink / broken symlink | 🔗 + dimmed `→ target` / struck-through, `--fail` colour, `(broken)` |
| Read-only filesystem | 🔒 chip; mutating buttons disabled with that reason |
| Device / fifo / socket | type glyph + Kind, italic; download and edit disabled |
| QPKG install dir (ours and others) | `qpkg` chip; ours adds *"This is QNAPFileManager's own program folder"* |

No colour-only signals.

### 4.2 The confirmation ladder

| Level | Trigger | UI |
|---|---|---|
| **L0** none | navigate, read, download, copy to clipboard, new folder / rename inside a normal share | Toast with Undo where possible |
| **L1** simple confirm | move to Trash; overwrite on conflict; cross-device move; >100 items in one op | `#dlgConfirm` grade 1 |
| **L2** typed phrase + ack | permanent delete; **any** write under a protected path; recursive chmod/chown >500 items or any protected path; emptying Trash; deleting a mount-point root; >1 GiB or >1000 items | `#dlgConfirm` grade 2 / `#pConfirmPhrase` |
| **L3** impossible | see §4.5 | Disabled with tooltip; server 403 `forbidden_by_policy` |

"Paranoid" mode promotes L0 writes to L1 and L1 to L2.

### 4.3 Read-only mode and the system-write arming switch

**`readOnly`** (global, persisted, default off): a single middleware rejects every non-GET API route with `403 {code:"read_only"}`, so a new endpoint is safe by default. Turning it **off** requires re-entering the password.

**`systemWrite`** (session-scoped, default off, disarms on restart and after an idle TTL): the actual root superpower. While disarmed, everything outside `/share/**` and `/mnt/*_DATA/**` is a read-only view. `#chipSysWrite` shows a live countdown.

### 4.4 Undo via Trash

- One trash directory per volume: `<mount>/.qnapfm_trash/<uuid>/` — **same device**, so delete is a `rename(2)`. `SameDevice()` decides; if no same-device trash exists the UI switches to the L2 permanent-delete dialog and says why (never silently promoted to copy).
- Sidecar `meta.json`: original path, mode, uid/gid, mtime, size, deleted_at, job id, user.
- Restore recreates parents (asking first) and restores mode + owner; collisions reuse the conflict dialog.
- Unavailable on `/share` (tmpfs), read-only filesystems, and devices with no writable trash root.
- Toasts for trashed items carry an inline **Undo** for 15 seconds.

### 4.5 Impossible from the UI, regardless of the backend

Enforced in the UI **and** in `internal/safety`:

1. Delete, move, rename or chmod `/`, `/proc`, `/sys`, `/dev`, `/etc`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr`, `/var`, `/mnt`, `/share` **themselves**.
2. Recursive chmod/chown rooted at `/` or any first-level system directory.
3. Any write inside `/proc` or `/sys`.
4. Following symlinks while recursing (`openat` + `AT_SYMLINK_NOFOLLOW`); `#pFollowLinks` refused for protected paths.
5. Deleting or renaming the running QPKG's own install directory or its config/log files.
6. `chmod 000`, or chown to a nonexistent uid/gid, under a protected path.
7. Removing the execute bit recursively from `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib*`.
8. Creating anything directly under `/share` (tmpfs).
9. Overwriting a directory with a file or vice versa.
10. Emptying Trash or bulk ops on select-all at `/` without an L2 phrase.
11. Serving any file with an executable `Content-Type` in our origin — downloads are always `attachment` + `nosniff`; previews via a sandboxed route.
12. Paths that traverse `..` after cleaning, or UNC/remote paths.

---

## 5. QTS embedding, theming, accessibility, narrow layout

### 5.1 Running inside the QTS desktop — hard constraints

| Constraint | Rule |
|---|---|
| `X-Frame-Options` | **Must not be `DENY`** (GitBackup sets it at `server.go:666` — do not copy). Omit it; control framing with CSP. |
| CSP | `frame-ancestors 'self' <configured origins>` from `settings.frameAncestors` plus the request `Host` on the QTS ports. Never `*`. |
| Inline scripts/styles | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'` — the reason the UI is split into files. |
| Cookies | `SameSite=Strict` (GitBackup `session.go:105`) is not sent in a cross-site iframe. Use `SameSite=Lax`; set `Secure` **only** when the request arrived over TLS. |
| Framed auth fallback | If `window.self !== window.top` and a probe returns 401 despite a valid session, fall back to a bearer token held in a JS variable only (never `localStorage`) from `POST api/session/token`. |
| Top-level redirects | **Never.** Session expiry swaps the login view in place (GitBackup's `showLogin()` pattern). |
| Relative URLs | Every asset and `fetch` uses a relative path (`js/app.js`, `api/fs/list`), no leading slash — works under a proxy mount unchanged. |
| `alert`/`confirm`/`prompt` | Banned. Everything is `<dialog>`. |
| Downloads | `<a href download>` or hidden same-origin iframe navigation, never `window.open`. |
| Drag-and-drop | `dragover`/`drop` must `preventDefault()` **and** `stopPropagation()` or the QTS desktop intercepts. |
| Window size | Usable at **900×600**; tree collapses to an overlay below 60rem. |
| `postMessage` | Listen for nothing, post nothing. |

Docs state that opening in a new browser tab is the supported path; the embedded QTS window is best-effort.

### 5.2 Dark / light

Reuse GitBackup's token block with `color-scheme: light dark`; add `--protected`, `--warn`, `--link`, `--sel-bg`. Explicit Auto/Light/Dark setting writing `data-theme` on `<html>`; persisted **server-side** (localStorage only as a first-paint cache via an external `js/theme.js`). Use `Canvas`/`CanvasText`/`Field`/`FieldText` system colours for dialogs and selects.

### 5.3 Accessibility

Tree: `role="tree"`/`treeitem`, `aria-expanded`, `aria-level`, roving `tabindex`, arrow keys, type-ahead. List: `role="grid"`, `aria-rowcount`, `aria-multiselectable`, `aria-rowindex`, `aria-sort` on header buttons. Dialogs: native `<dialog>` + `showModal()`, `aria-labelledby`, focus to first input. Live regions: polite `#status` and `#announce`; errors `role="alert"`. Contrast ≥ 4.5:1 both themes; target size ≥ 24 px; reduced motion honoured; skip link to `#list`; no drag-only actions.

### 5.4 Narrow / mobile

< 60rem: tree becomes an off-canvas drawer; columns reduce to Name + Size + Modified. < 46rem: breadcrumbs collapse; toolbar secondary row into `⋯`; jobs panel full-screen sheet. < 30rem: single-line rows 44px, tap = open, long-press = context menu, explicit Select mode.

---

## 6. Error handling and messaging conventions

### 6.1 Wire format

```json
{ "code": "eacces", "error": "Permission denied", "path": "/share/Public/.locked",
  "hint": "The file may have the immutable flag set, or the volume is mounted read-only.",
  "detail": "chmod /share/Public/.locked: operation not permitted" }
```

### 6.2 Code → message table

| `code` | HTTP | Message | Hint / action |
|---|---|---|---|
| `eacces`/`eperm` | 403 | Permission denied — *path* | "You are root, so this is unusual: immutable flag, read-only volume, or ACL." + Show details |
| `enoent` | 404 | *name* no longer exists | Auto-refresh |
| `eexist` | 409 | *name* already exists here | Overwrite / Skip / Keep both |
| `enotempty` | 409 | The folder is not empty | "Delete its contents too?" → `recursive:true` at L2 |
| `exdev` | 409 | *src* and *dest* are on different volumes | **Copy and delete** / **Copy only** / Cancel. Never silent. |
| `ebusy` | 409 | *name* is in use | Mount point or open by a service. No force option. |
| `enospc` | 507 | Out of space on *volume* | Job pauses; Retry / Cancel |
| `erofs` | 403 | *path* is on a read-only filesystem | Names the mount point |
| `eloop` | 400 | Too many symbolic links | |
| `enametoolong` | 400 | Name too long | Shows the limit |
| `eisdir`/`enotdir` | 400 | *name* is a folder, not a file (or vice versa) | |
| `read_only` | 403 | Read-only mode is on | Link to Settings |
| `protected_path` | 403 | *path* is a system path and changes outside /share are not armed | Inline **Arm for 60 minutes** |
| `ramdisk` | 400 | GitBackup's `errShareRoot` sentence | |
| `needs_confirm` | 428 | (client bug if it surfaces) | |
| `forbidden_by_policy` | 403 | This is not something QNAPFileManager will do — *rule* | Link to `docs/safety-model.md` |
| `job_cancelled` | 200 | Cancelled after N of M items | Lists what changed |
| `conflict` | job | conflict prompt | |

### 6.3 Style rules

Sentence case; no jargon in `error` (it lives in `detail`); always name the path (middle-elided, full in `title` + copy button); never "An error occurred"; inline for the thing touched, toast for background completions, jobs panel for multi-item. Partial failure is first-class: `completed_with_errors` + **Retry failed only**. Unreachable service: *"Cannot reach the QNAPFileManager service — is it still running?"*

### 6.4 Conflict resolution

Job pauses (`awaiting_input`), emits `conflict` with both sides' size/mtime/kind. UI answers `POST api/jobs/{id}/answer {conflict_id, action:"overwrite"|"skip"|"rename"|"cancel", apply_to_all}`. "Keep both" → `name (2).ext`. Type mismatches drop Overwrite. Awaiting >10 min auto-cancels.

---

## 7. Test plan

### 7.1 Go `httptest` against the embedded UI and API

Stdlib `testing`, `httptest`, `t.TempDir()`. No browser.

**Static shell**: `/` 200 `text/html` containing `#app`; assets 200 with correct types; **`X-Frame-Options` absent or not `DENY`** (regression test); CSP has `frame-ancestors` reflecting settings; `nosniff` everywhere; `no-store` on `/api/`; download sets `attachment`; cookie `HttpOnly`, `SameSite=Lax`, `Secure` only under TLS.

**API contract**, table-driven over a fixture tree (nested dirs, dir symlink, file symlink, broken symlink, fifo, dot-file, 0600 file, 3000-entry dir; symlink/fifo cases `t.Skip` on Windows):
- paging invariants (`offset+len ≤ total`; pages concatenate to the unpaged listing; stable order per sort key);
- hidden filter, every sort key both directions, no `..` in entries;
- `/share` rule: shares listed, mounts flagged, `mkdir` at `/share` → `ramdisk`;
- symlinks: `target`, `target_broken`, recursion never follows;
- **read-only blanket test**: enumerate every mux route; every non-GET returns 403 `read_only` when set;
- **protected-path matrix**: ~20 paths × 6 ops against a golden table checked into the repo (the table *is* the safety model);
- confirm-phrase enforcement server-side;
- mode arithmetic exhaustive over 0..07777, mixed-selection mask semantics;
- job lifecycle: cancel leaves no partial (`.name.qnapfm-part` removed); conflict answer resumes; SSE frames parse;
- `EXDEV` via an injectable `deviceOf(path)`.

### 7.2 The two tests that replace a headless browser

1. **Element-id cross-check**: parse `index.html` for `id="…"` and `js/*.js` for `$('…')`/`getElementById`/`querySelector('#…')`; fail on ids referenced but undefined.
2. **Endpoint cross-check**: extract every `api/...` literal from `js/*.js`; assert each matches a registered mux pattern; warn on registered routes the UI never calls.

Playwright: not in v1. If wanted at v2: separate `e2e/` outside the Go module, `npx --yes playwright@<pinned>` on the runner only, `workflow_dispatch`, never required for merge, no root `package.json`.

### 7.3 Manual checklist (per release, on a real NAS; once in a tab, once in a QTS window)

App Center tile opens UI; sign-in/out without redirect · tree expands `/`, `/etc`, `/share` with shares first and mounts collapsed · RAM-disk banner and disabled New folder at `/share` · >50k-entry dir scrolls; sort correct across pages · Ctrl+A + Properties total, no hang · symlink target/Go to target/broken struck through · 4 GiB upload progress, cancel leaves no partial · cross-volume copy → `EXDEV` dialog · collision dialog + apply to all · Trash Undo; restore keeps mode/owner · permanent delete in `/etc/config` demands phrase · smart-X leaves files 0644 (verify over SSH) · chown from `/etc/passwd`; orphan uid numeric · edit `/etc/config/smb.conf` → `.bak` + audit entry · read-only mode; password to disable · `systemWrite` disarms on restart/TTL · keyboard-only pass · NVDA pass · dark/light; 900×600; 375px · QuLog entries · audit `.jsonl` export.

---

## 8. API endpoints assumed (for the backend)

All relative to the app base. Errors per §6.1.

```
GET    api/status                     → {version, host, isQTS, qtsVersion, root, readOnly, systemWrite:{armed,expiresAt}, trash:{enabled,days,bytes}}
GET    api/session                    → {user, isAdmin, viaQTS, expiresAt}
POST   api/login                      {user, pass} | {sid}
POST   api/logout
POST   api/session/token              → {token, expiresAt}      # framed/bearer fallback
POST   api/events/ticket              → {ticket}                # single-use, for EventSource

GET    api/fs/list?path=&offset=&limit=&sort=&order=&hidden=&group=
GET    api/fs/stat?path=
GET    api/fs/tree?path=&depth=1
GET    api/fs/shares
GET    api/fs/volumes
GET    api/fs/read?path=&max=          → {content, encoding, truncated, size, mtime, sha256}
GET    api/fs/download?path=           → stream, attachment
GET    api/fs/preview?path=&w=         → sandboxed (v2)
GET    api/identity/users              → [{uid,name,home,shell}]
GET    api/identity/groups             → [{gid,name}]

POST   api/fs/mkdir      {path, name, mode?}
POST   api/fs/rename     {path, newName}
POST   api/fs/write      {path, content, expectMtime, expectSize, backup:true, confirmPhrase?}
PUT    api/fs/upload?path=&name=&offset=&total=&id=   → chunked/resumable
POST   api/fs/upload/finish {id}

POST   api/jobs/copy     {sources[]|{path,selectAll,except[]}, dest, onConflict, preserve, followSymlinks:false}
POST   api/jobs/move     {…same…}
POST   api/jobs/delete   {paths[], mode:"trash"|"permanent", confirmPhrase?}
POST   api/jobs/chmod    {paths[], mode|{mask,value}, recursive, applyTo, fileMode?, dirMode?, followSymlinks:false, dryRun?, confirmPhrase?}
POST   api/jobs/chown    {paths[], uid?, gid?, recursive, applyTo, followSymlinks:false, dryRun?, confirmPhrase?}
POST   api/jobs/size     {paths[]}
POST   api/jobs/search   {root, query, glob?, maxDepth, content:false}
POST   api/jobs/compress / api/jobs/extract   (v2)
GET    api/jobs · GET api/jobs/{id} · POST api/jobs/{id}/cancel · POST api/jobs/{id}/answer · DELETE api/jobs/{id}
GET    api/events?ticket=              → SSE: job, conflict, notice, settings (poll api/jobs?since= fallback)

GET    api/trash?offset=&limit= · POST api/trash/restore {ids[], onConflict} · POST api/trash/empty {confirmPhrase}
GET    api/settings · POST api/settings · POST api/settings/arm {minutes} · POST api/settings/disarm
GET    api/audit?since=&op=&path=&limit= · GET api/audit/export → .jsonl
```

---

## 9. Milestones

**M0 — Skeleton + browse (read-only, safe by construction)**: repo, `go.mod`, `cmd/qnapfm`, `internal/web` with `go:embed`, mux + middleware (no `X-Frame-Options: DENY`), lifted CSS, shell, `dom.js`/`api.js`/`state.js`; `api/status`, `fs/list|stat|tree|shares|volumes|download|read`; tree + virtualised list + breadcrumbs + sort + hidden + multi-select + badges + status bar; hash routing; dark/light; text viewer. No mutating routes. Tests: static-shell, paging/sort invariants, `/share` rule, symlink metadata, both cross-checks. *Exit:* browse the whole NAS including `.qpkg` and `/etc`, 200k-entry dir scrolls smoothly.

**M1 — Basic operations + the safety spine**: `internal/safety` + golden test; read-only mode; `systemWrite` arming + chip; confirmation ladder + `#dlgConfirm`; `internal/audit`; QuLog; `mkdir`, `rename`; single-item permanent delete (L2 only); context menu, shortcuts, toasts. *Exit:* safety model real and tested before any bulk op exists.

**M2 — Jobs, copy/move/delete, upload/download, Trash, search**: `internal/jobs`, SSE + poll fallback, `#jobsPanel`; copy/move (`EXDEV` dialog)/delete; clipboard; chunked resumable upload + desktop DnD; ZIP download; `internal/trash` + restore + retention + Undo toast; subtree search. *Exit:* replaces File Station for day-to-day work.

**M3 — Permissions, properties, editor**: `internal/identity`, mode arithmetic, `#dlgPerms` complete, `#dlgProps` with streaming `du`, chown/chgrp, text editor with optimistic concurrency and `.bak`. *Exit:* the features that justify the project.

**M4 — QTS auth, packaging, polish**: `authLogin.cgi` validation, admin gate, local-password fallback, settings page, audit viewer; QPKG (`qpkg.cfg`, service script, `package_routines`), CI matrix x86_64/arm_64 with pinned QDK, qemu smoke; accessibility/narrow/QTS-window passes; docs. *Exit:* installable from App Center by someone who has never used SSH.

**Deferred**: in-app DnD, thumbnails, compress/extract, content search, dual-pane, ACLs, marquee, optional Playwright.
