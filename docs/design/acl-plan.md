# ACLs after v1.0 — display, then editing (plan only, 2026-09-17)

Written by Claude Fable 5.1 at the owner's request after the first M3 hardware report. Nothing here is implemented;
it is the answer to *"will the 'ACL not displayed' notice be addressed, and how"*. It refines PLAN.md decision 11
(*"Editing ACLs is v2 (POSIX) and v3 (NFSv4)"*), identity plan §4.4 and backend plan §2.9, and it inherits every
M3 contract clause it does not amend.

## 1. What the notice means today

The Permissions dialog for `/share/_Data/_IMAGES` said:

> This item has an extended ACL that this app does not display. The mode below is only the base permission set —
> editing it will not remove the ACL.

That is the POSIX badge (m3-contract §6.3): the worker found `system.posix_acl_access` on the folder, so the folder
carries entries beyond owner/group/other — named users or groups, and a mask. On QTS this is normal rather than
exotic: **Advanced Folder Permissions** (Control Panel → Privilege → Shared Folders) stores per-subfolder rights as
POSIX ACLs, and **Windows ACL support** makes Samba keep an NT ACL in `security.NTACL` and mirror it into a POSIX
ACL. On a unit with either switched on, most share folders badge, and the notice is doing its v1 job: it stops
`0775` from looking like the whole story.

The notice is also exactly right about what M3 does. The mode grid edits the base set; on a POSIX-ACL object the
group column becomes the ACL **mask** (the L1 warning in the ladder), so a mode change can *narrow* what named
entries grant, but it never removes the ACL and never edits its entries. The app shows the badge, the text and the
warnings, and shows nothing of what the ACL says — "does not display" is literal.

## 2. Yes: three steps, in this order

| Step | Ships as | What the user gets | Depends on hardware facts? |
|---|---|---|---|
| **A. Display** | first minor after v1.0.0 (M5) | the ACL entries, read-only, in Properties and Permissions; the notice becomes "this is the ACL; the grid edits only the base set" | no — parse only |
| **B. POSIX editing** | v2 (M6) | add/remove/edit named entries, the mask and a directory's default ACL; strip the ACL; apply to contents | yes, on QTS: Samba/NTACL interplay, File Station's view of our edits |
| **C. NFSv4 editing** | v3 (M7) | ACE editor on hero | yes, and blocking: whether QNAP's ZFS accepts `setxattr system.nfs4_acl` at all |

Step A is small and removes the sting the owner reported; B and C are real milestones with their own contracts and
their own Astra rounds. Nothing here moves before v1.0.0 is tagged.

### What never happens, at any step

- **No effective-permission calculator.** "Can `sveinung` write here, given the mode, the mask, three named entries,
  a deny ACE and the SMB layer" is the kernel's decision (INV-2). The app shows the entries and, where the format has
  one, the mask, and lets the reader read. The M3 `Caps` hints stay hints.
- **No `security.NTACL` editing, ever.** That attribute is Samba's private NT-ACL blob (`vfs_acl_xattr`); its
  mapping onto the POSIX ACL is Samba's, and rewriting it means re-implementing that mapping. Step A *detects* it
  (one size query, Properties only) and says so; nothing writes it.
- **No QTS "Advanced Folder Permissions" database.** QTS keeps its view in the ACLs themselves plus its own config;
  the app edits the kernel's ACL and says plainly that QTS's own UI may show the result differently until it
  re-reads.
- **No `setfacl`/`getfacl`/`nfs4_setfacl` dependency** for POSIX: the formats are fixed-width and are already parsed
  in `internal/fsops/acl_linux.go` and `internal/perm`. NFSv4 may need a bounded exec (§5) and that is the reason C
  waits.

## 3. Step A — display (M5)

**Worker.** `Props` (`fsops/props.go`, `wproto.ACLInfo`) gains the parsed entries. Read on the **held descriptor**
via `/proc/self/fd/N` (`lgetxattr` on that path reads the attribute of the inode the walk proved, exactly as M3's
chmod writes through it; `fgetxattr` on an O_PATH fd is `EBADF`). That removes residual 2's name/inode gap for the
dialog, which is the one place a wrong answer would mislead rather than merely mis-badge; the listing badge stays
the bounded pathname probe it is. Budget: one object, `ACLProbeMaxBytes` (64 KiB) per attribute, at most 512 entries
serialised — beyond that the response says `truncated: true` and the dialog says "showing the first 512 of N". POSIX
also reads `system.posix_acl_default` on directories (the inheritance template; `aclFactsFor` already knows it).

**Wire.** Numbers first, names as a courtesy (m3-contract §5.4 — the audit and the wire carry ids):

```go
type ACLInfo struct {
    Backend, Xattr, State, Aclmode, Dataset string  // as today
    Entries   []ACLEntry `json:"entries,omitempty"`
    Default   []ACLEntry `json:"default,omitempty"` // POSIX default ACL, directories only
    Truncated bool       `json:"truncated,omitempty"`
    NTACL     bool       `json:"ntacl,omitempty"`   // security.NTACL present (size > 0): SMB holds its own view
}
type ACLEntry struct {
    // POSIX: Tag is owner|user|owning-group|group|mask|other; Perms is "rwx" letters; ID for user/group.
    // NFSv4: Tag is "ace"; Type allow|deny|audit|alarm; Who is OWNER@|GROUP@|EVERYONE@ or an id spelled as the
    // xattr spells it; IsGroup from IDENTIFIER_GROUP; Access is the named bits; Flags the inheritance flags.
    Tag, Perms string
    ID         int      `json:",omitempty"`
    Name       string   `json:",omitempty"` // resolved where Entry.User/Group are resolved today; "" when unknown
    Type, Who  string   `json:",omitempty"`
    IsGroup    bool     `json:",omitempty"`
    Access     []string `json:",omitempty"` // read_data, write_data, append_data, execute, delete, delete_child,
                                            // read_attributes, write_attributes, read_xattr, write_xattr,
                                            // read_acl, write_acl, write_owner, synchronize
    Flags      []string `json:",omitempty"` // file_inherit, dir_inherit, no_propagate, inherit_only, inherited
}
```

The parser lives in `internal/perm` beside `NFS4State` so it is tested on Windows with golden blobs; the two CI jobs
(ext4 with `setfacl`, ZFS with a hand-written ACE) assert against real attributes. A parse failure keeps
`State: unknown`, sends no entries, and the dialog keeps the pessimistic text — the same direction M3 fails in.

**UI.** In `#dlgProps` a collapsible "Access control list" group after the permission rows: one line per entry
(`user backup (1003): rw-`, `mask: r-x`, `default: group staff (1010): rwx`; NFSv4 as `allow  OWNER@  read, write,
execute, … — file_inherit, dir_inherit`). In `#dlgPerms` the same list, collapsed, under the mode grid, and the POSIX
notice reworded: *"This item has an extended ACL (below). The grid edits only the base set; on this item the group
column is the ACL mask, which caps what the named entries grant."* The NFSv4 text keeps its discard/reduce warning
verbatim; it is still true. `NTACL: true` adds one line: *"QTS also holds a Windows ACL for this item (SMB). This
app shows and edits only the filesystem ACL."* The listing badge, glyphs and titles do not change.

**Not in A.** Any write; entries in listings; effective-access colouring; name lookup for domain ids beyond what the
session already resolved.

**Size.** About a third of M3; two Opus agents (worker+perm, UI) and the usual Astra rounds. Hardware check: a QTS
share with Advanced Folder Permissions shows the entries File Station's per-folder view implies; a hero share shows
`OWNER@/GROUP@/EVERYONE@` for a plain file and a named ACE where one was set.

## 4. Step B — POSIX ACL editing (M6, v2)

**Mechanism.** Serialise the fixed-width format (`version=2` header, 8-byte `tag,perm,id` entries, sorted the way
the kernel requires) and `lsetxattr` through `/proc/self/fd/N` of the held O_PATH descriptor — the same identity
proof as chmod. The kernel validates (`posix_acl_valid`): a malformed or duplicate entry is `EINVAL`, a non-owner is
`EPERM`, a filesystem without `acl` is `EOPNOTSUPP`; each is reported verbatim, never pre-judged. "Remove the ACL" is
`lremovexattr` of the access and default attributes. Requests, like `ChmodReq`, carry the **complete** intended ACL,
never a delta, and the route pins the pre-image: `SetACLReq{Path, Entries, Default, ExpectEntriesHash}` — the worker
re-reads on the held descriptor and refuses `changed` when the ACL differs from what the dialog showed.

**Mask.** The editor recomputes the mask as `setfacl` does (union of group-class entries) unless the user unticks
"recalculate mask"; the request carries the mask explicitly either way, so what is applied is what was shown.

**Post-call diff.** `perm.DiffOf` grows an ACL diff (entries added/removed/changed, mask before/after, and the mode's
group bits, which the kernel derives from the mask). Reported, never prevented (residual 6 extended).

**Recursive "apply to contents".** Reuses M3's recursive job whole: pre-scan bound, per-entry outcomes, hardlink
rule, `CrossMounts`, the >500-item L2, cancel leaves a half-changed tree. Per entry the worker applies the same
access ACL to files and directories and the default ACL to directories only, and skips objects whose current ACL
differs from the root's pre-image only when the user chose "only where the ACL matches" (the safe default is
"replace everywhere", stated in the dialog).

**Confirm ladder additions** (front-end table, as §7):

| Situation | Grade |
|---|---|
| any ACL change on a POSIX object | L1, listing the resulting entries |
| removing an ACL (strip), or replacing one with fewer named entries | L2 — named entries lose access and there is no undo |
| `NTACL` present | L1 text adds: SMB clients may keep seeing the Windows ACL until Samba rewrites it; QTS's own UI is not updated by this |
| under a protected path, recursive >500 | as M3 |

Token parts: `kind=sync|job`, `op=setacl|stripacl`, `acl=<sha256 of the canonical serialised access+default ACL>`,
`recursive`, `cross`, roots — a token issued for one ACL cannot be redeemed for another.

**Audit.** Intent and result carry the serialised before/after (bounded to 4 KiB each; larger ones carry the hash and
entry counts).

**Hardware first (QTS):** `mount` options for the share volume include `acl`; `lsetxattr system.posix_acl_access` from
a non-root worker on an owned file succeeds; with Windows ACL support on, whether Samba rewrites our POSIX ACL on
the next SMB permission change (expected: yes — say so in the dialog) and whether File Station's Advanced Folder
Permissions view reflects our edit without a QTS re-scan.

**Not in B.** NFSv4 objects (the editor is hidden where `Backend == nfs4`; the M3 warning stays); `security.NTACL`;
copying an ACL from another object; ACL templates.

## 5. Step C — NFSv4 ACL editing on hero (M7, v3)

**Blocked on one fact.** Upstream OpenZFS on Linux does not expose NFSv4 ACLs through an xattr; QNAP's fork
answers `lgetxattr system.nfs4_acl` (M3 relies on it; the hardware check in m3-contract §17 confirms it). Whether it
also accepts `lsetxattr system.nfs4_acl` is unknown. Two outcomes:

1. **It does** → the same shape as B: serialise the ACE list (big-endian count, ACEs of type/flag/mask/who with
   4-byte padding, exactly what `perm.NFS4State` reads), write through `/proc/self/fd/N`, kernel validates, diff
   after. Pure Go, no binary.
2. **It does not** → the only route is a bounded exec of QNAP's own ACL tool (`nfs4_setfacl`, `setfacl`, or a
   QNAP-specific binary — `command -v` on the unit) **as the user, inside the worker**, with argv built from the
   serialised entries and no shell. That is the `zfs get` precedent (identity plan §4.4), acceptable only if the
   binary ships in the base userland; if it does not, C stays deferred and the M3 warning remains the whole
   feature.

**Editor.** ACE list in on-disk order (order is semantic in NFSv4 — DENY before ALLOW — and the app never reorders;
it offers a move up/down). Per ACE: type, who (`OWNER@`/`GROUP@`/`EVERYONE@`/user/group), access presented as
`read / write / execute / full / custom` bundles over the 14 bits, inheritance flags. `aclmode` and `aclinherit`
shown beside the list. "Reset to trivial" writes the three special ACEs derived from the current mode.

**Ladder.** Any ACE change L1 with the entries listed; replacing or stripping a non-trivial ACL L2 (typed phrase, as
the `discard` chmod today); recursive as B. `aclmode=discard` gets a further sentence: a later chmod will destroy
what is being set now.

**Hardware first (hero):** the `setxattr` question above; whether `restricted`/`passthrough` datasets accept an ACL
write from the owner; how QNAP's fork spells a user ACE's who (name or number) so round-tripping is byte-exact.

## 6. Ordering and cost

Recommended: **A** right after v1.0.0 (it is the reported UX problem and it is parse-only); **B** when v2 opens;
**C** only once the hero `setxattr` question is answered on the unit, and never before B has settled the shared
machinery (pre-image pinning, ACL diff, ladder rows, audit shape). Trash janitor and extract remain deferred on
their own merits; A does not compete with them for hardware time.

Each step: contract under `docs/design/`, Opus implementation, Astra normal + adversarial rounds (ten per step), CI's
ext4-ACL and ZFS jobs as the real gate (INV-2: the dev box proves nothing about ACL semantics).

## 7. Interim (optional, before v1.0.0)

One wording change, no code: the POSIX notice could end *"… will not remove the ACL. Viewing and editing ACL
entries is planned for a later version."* It changes nothing the user can do; it only answers the question the
owner asked. Left to the owner.
