# M3 contract — permissions and properties (2026-09-13)

Fixed by the orchestrator before the implementers fan out, as M2-A, M2-B and M2-C were. Drafted by an Opus planning
agent and accepted by Fable 5.1; the gpt-6-astra review of this contract is **pending** (Astra paused by the owner
on 2026-09-13). Three pieces are built in parallel against it: the worker side (`internal/fsops`, `internal/worker`,
`internal/workerpool`), the web routes, and the UI — plus one new pure package, `internal/perm`, which both sides
import and which is the only part that is fully testable on the dev box. Anything not stated here follows the M2-C
precedent (`docs/design/m2c-contract.md`) and the copy engine's descriptor discipline (`internal/fsops/copy.go`
header). **ACL editing is not in M3** (PLAN decision 11: POSIX is v2, NFSv4 v3); M3 *detects, reports and warns
about* ACLs and never writes one.

Sources of intent: PLAN.md decision 11 (ACLs), decision 12 (chmod/chown for non-root), decision 8 (`Platform.For`,
never a family branch), the M3 milestone row; `identity-and-hero-plan` §3.1 (what the kernel actually does), §3.2
(`Caps`), §3.3 (UI messaging), §4.4 (ACL backends and `aclmode`); `backend-packaging-plan` §2.3 (properties), §2.8
(chmod/chown), §2.9 (ACL v1 badge), §2.14 (idmap pickers); `ui-ux-safety-plan` §3.5 (`#dlgPerms`), §3.6
(`#dlgProps`), §4.2 (the ladder), §4.5 (the impossible list). Where ui-ux §3.3 says a non-owner's rwx grid renders
read-only and PLAN decision 12 says "hints, never hard blocks", **PLAN governs**: the grid stays editable and the
kernel refuses (INV-2).

## 1. One representation for a mode change: `perm.ModeSpec`

1. **Mask and value, never an absolute mode on the wire.** `ModeSpec{Mask, Value uint32}` applies as
   `(cur &^ Mask) | (Value & Mask)`. An absolute set is `Mask: 07777`. This is what makes a *mixed selection*
   (`#dlgPerms` renders indeterminate checkboxes and applies only touched bits), a *recursive* apply over entries
   whose current modes the front end has never seen, and the three special-bit checkboxes one mechanism instead of
   three. The arithmetic lives in `internal/perm` (stdlib only, no I/O), is authoritative in Go, and is mirrored by a
   JS module with the same table of cases.
2. **"Apply to files only / folders only" is expressed by a zero mask.** A job carries `Files ModeSpec` and
   `Dirs ModeSpec`; folders-only is `Files.Mask == 0`. `#pSmartX` ("use 0644 for files and 0755 for folders") is a
   client-side preset — `Dirs{0777, 0755}`, `Files{0777, 0644}` — and the server has no smart-X mode of its own.
3. **A recursive chmod may CLEAR a special bit but never SET one.** `Mask & 07000` bits are accepted only where the
   matching `Value` bit is 0; a recursive request that sets setuid, setgid or sticky is `400 bad_request`. Setting
   setuid across a tree is the single most effective way to make a NAS exploitable, and no legitimate workflow needs
   it in one call. Clearing them recursively is the cleanup that *does* get needed, so it stays.
4. **Symlinks.** Linux has no `lchmod`, so chmod never touches a symlink: the single-item route refuses a symlink
   leaf with `415 unsupported` unless `follow:true` is passed explicitly and the route re-guards the *resolved*
   target as its own path; a recursive walk always skips symlinks with an `unsupported` warning and never follows
   one. Chown is the mirror image: it is **always** `lchown` — a symlink's own ownership is what changes — and
   `ChownReq.Follow` is refused as `unsupported` in M3, so there is exactly one chown semantics to reason about.

## 2. chmod and chown: what is proved before the call

1. **Route side, the M2-C settlement.** The path is resolved as the user (`Mutator.Resolve`, `followLeaf:false` —
   chmod and chown act on the named entry, not on a link's target); the guard is checked on **both** the requested
   and the resolved spelling with `worstGuard` (`guard.OpChmod` / `guard.OpChown`); the **resolved, canonical**
   spelling is what is dispatched.
2. **Worker side, the canonical walk.** The worker does **not** resolve again. It walks the canonical spelling
   `O_NOFOLLOW` per component from the jail root (`canonicalLeaf`); a symlink among the components means the tree
   changed after authorization and is `changed` (409), never followed. The leaf is held `O_PATH|O_NOFOLLOW`.
3. **The syscall addresses the descriptor, not a name.** chown is `fchownat(leaffd, "", uid, gid, AT_EMPTY_PATH)`;
   where `AT_EMPTY_PATH` is unavailable it falls back to `fchownat(parentfd, name, …, AT_SYMLINK_NOFOLLOW)`
   **after** re-proving `(dev, ino, btime)` against the held leaf, and refuses `changed` if they differ. chmod is
   `chmod("/proc/self/fd/N", mode)` on the held `O_PATH` descriptor — the established idiom in this tree
   (`unnamed_linux.go`) — which acts on that inode and refuses a symlink with `EOPNOTSUPP` exactly where `lchmod`
   would; where `/proc` is not mounted it falls back to `fchmod` on a readable re-open; where that open fails the
   kernel's own verdict is returned (a 0200 file is `permission`, INV-2 — amended round 2), and only an object
   with no readable route for anybody (ELOOP, ENXIO, ENODEV, EOPNOTSUPP) is `unsupported`; a pathname is never
   reached for.
4. **The post-call stat is on the same descriptor.** `fstat(leaffd)` before and after. Re-`lstat`ing by name would
   describe whatever answers to that name now, which is the whole class of bug the descriptor discipline exists to
   close — and it is the *diff* that the user is being shown, so a wrong object there is a lie, not a nuisance.

## 3. The post-call diff (INV-2, made visible)

1. `ModeResp` carries `Before`, `Entry` (after) and `Diffs []perm.Diff{Field, Want, Got}`. Fields: `mode`,
   `setuid`, `setgid`, `sticky`, `uid`, `gid`. **The worker computes the diff**, because it is the only side that
   holds the pre-call state of the same inode and INV-1 forbids the front end from looking.
2. The three silent cases identity plan §3.1 names are what this is for, and each gets a sentence the UI shows
   verbatim: a non-member's setgid **silently dropped** ("the setgid bit was not applied: you are not a member of
   group *team*"); a successful chown **clearing setuid, and setgid when the file is group-executable** ("the setuid
   bit was cleared by the change of owner — the kernel does this, and it cannot be kept"); a ZFS `aclmode=groupmask`
   chmod landing on different bits than asked.
3. **A call that succeeded with a diff is a 200 with `warnings`, never an error** — and the UI shows a *warning*
   toast, not a success toast. A call the kernel refused is the kernel's error, surfaced unchanged
   (`permission` → 403).
4. `Diffs` are also what a recursive job folds into `JobResult.Warns` per entry (`code: "unchanged"`), capped at
   `WarnCap`.

## 4. Recursive as a job, with per-entry outcomes

1. `JobChmod` / `JobChown`, class `ClassMetadata` (`jobs.KindChmod`/`KindChown` already exist). `fsops.Walk` on held
   descriptors with `Protect: ProtectWrite` (`.zfs` and `@Recycle` are never entered — a chmod is a mutation),
   `Mutating: false` (nothing is unlinked, so no `errRetryDir`), crossing by decision 9 and `CrossMounts`.
2. **Partial success is the normal outcome, not a failure** (identity plan §3.3). Every `EPERM` is one skipped entry
   plus a `warn` frame; the walk continues. The result reads *"Changed 412 of 8,003 items. 7,591 are owned by other
   users and were skipped. 0 other errors."* A job that failed wholesale on the first `EPERM` would be useless on a
   real NAS.
3. **Counts.** `Files` = entries actually changed, `Skipped` = refused or policy-skipped, `Dirs` = directories
   changed, `Bytes` = 0 (a chmod moves none, and reporting a fake number would be the only lie in the record).
   Pre-scan for `FilesTotal` is the same bounded scan delete and size use (30 s / 500 000 entries, else `-1` and an
   indeterminate bar). Phases `scanning` → `working`.
4. **Cancel leaves partial work and says so** (design §3, unchanged): `JobResult.Partial`, no rollback, and the
   detail states it. There is no undo for a permissions job and the dialog says that before it starts.
5. **A recursive root of `/` or any depth-1 path is refused `protected`, for every session including root**
   (ui-ux §4.5 item 2). It is the one place M3 adds a hard refusal rather than a confirmation, because there is no
   recursive chmod of `/` that anybody means.

## 5. Capability hints, per backend

1. `perm.Caps{Chmod, ChownUID bool, ChgrpTo []int, Reason string}` — `Chmod = root || uid == e.UID`;
   `ChownUID = root`; `ChgrpTo = root ? nil ("any") : (uid == e.UID ? session groups : nil)`. Computed in the
   **front end** from `sess.who` and the entry the worker returned: it is a pure function of data the front end
   already holds, it keeps UI vocabulary out of the worker, and it runs on Windows, which is where its tests live.
2. **They are hints and the route never enforces them.** An ACL, a read-only mount or an immutable attribute can
   grant or refuse where the uid arithmetic says otherwise, so the grid stays editable, Apply stays enabled, and the
   kernel decides (PLAN decision 12, superseding ui-ux §3.3). The dialog shows the §3.3 sentence — *"Owned by
   `backup` (uid 1003). Only the owner or an administrator can change permissions. You are signed in as
   `sveinung`."* — as an explanation of a likely refusal, not as a lock.
3. **Ownership is not `CreateAs`.** The admin-as-real-user rule (`wproto.CreateAs`) applies to content an admin
   *creates*; chown is the ownership operation itself, so the route never sends `As` and `ChownReq` has no such
   field. An admin's chown is plain root chown, guarded by the protected-path table and audited as a milestone.
4. **The wire carries numbers only.** A name resolved in the front end and the same name resolved in the worker can
   differ (NSS vs `/etc/passwd`), and the audit has to record what was actually applied. Names are a display concern.

## 6. The ACL badge, per entry, per backend

1. **Presence is the wrong question on ZFS.** Every object on a ZFS dataset carries `system.nfs4_acl`, so "the
   attribute exists" would badge the entire NAS. The badge therefore reports a **state**, not a boolean:
   `fsx.Entry.ACL` is `""` (not probed) | `"none"` | `"posix"` | `"nfs4"` | `"nfs4-trivial"` | `"unknown"`. `HasACL`
   stays as the boolean for compatibility and is true for `posix`, `nfs4` and `unknown`.
   - **POSIX (ext4/QTS)**: `posix` when `system.posix_acl_access` is present with a non-zero size — exactly the `+`
     in `ls -l`.
   - **NFSv4 (ZFS/hero)**: `nfs4-trivial` when the ACE list is only `OWNER@`/`GROUP@`/`EVERYONE@` with no
     inheritance flags (what the mode alone describes); `nfs4` when any ACE names somebody else or carries
     `FILE_INHERIT`/`DIRECTORY_INHERIT`. This is `ls -V`'s notion of trivial, and it is **our heuristic, not the
     kernel's**.
   - *Amended, Astra round 1 (#3):* "trivial" additionally requires every ACE to be **ALLOW** — a DENY, AUDIT or
     ALARM entry of any kind is non-trivial — and requires that `GROUP@`/`EVERYONE@` carry neither `WRITE_ACL` nor
     `WRITE_OWNER`, the bits a mode cannot express. The type and the mask were being ignored, so an
     `EVERYONE@ DENY DELETE` ACL passed as trivial and a `discard` chmod would have destroyed it without L2.
     *Round 2 (#3), restated round 3 (#1):* excluding two admin bits was not mode-equivalence, and neither was a
     subset rule (`EVERYONE@ ALLOW WRITE_NAMED_ATTRS` alone passed). An ALLOW for a special principal is trivial
     only if it is **exactly what a mode produces**: strip the base bits ZFS writes for that principal regardless
     of the mode — `READ_ATTRIBUTES`, `READ_NAMED_ATTRS`, `READ_ACL`, `SYNCHRONIZE` for every principal, and
     `WRITE_ATTRIBUTES`, `WRITE_NAMED_ATTRS`, `WRITE_ACL`, `WRITE_OWNER` for `OWNER@` only — and what remains must
     be one of the eight rwx combinations of `READ_DATA`, `WRITE_DATA|APPEND_DATA` (always together) and
     `EXECUTE`. Anything else — `DELETE`, `DELETE_CHILD`, an append-only grant, an owner-only base bit on
     `GROUP@`/`EVERYONE@` — is non-trivial. **Hardware check:** if QNAP's own trivial ACLs differ from upstream
     ZFS's (a `DELETE_CHILD` on directories, say), every hero chmod will ask for the typed phrase; the rule is then
     widened with the real bytes in hand, not guessed.
   - A read or parse failure is `unknown`, never `none`, and `unknown` shows the badge with the pessimistic text.
     The existing NFSv4 parser shapes in `internal/fsops/acl_linux.go` are reused; `internal/perm` holds the
     trivial/non-trivial judgement so it is testable everywhere.
2. **Probing is bounded and is a hint.** The listing probes only when the mount's `FSCaps.ACLBackend != "none"`,
   only when the route asks (`ListOptions.ACLProbe`), for at most **2000 entries per page** and **64 KiB of
   attribute bytes per page**; beyond either bound the remaining entries are left `""` and the listing carries the
   note *"ACL badges are not shown for very large folders."* The probe is `lgetxattr` on the entry's OS path — a
   pathname, deliberately, because there is no `fgetxattrat` and opening every file to read an attribute would need
   read permission the user may not have. A name re-pointed between `getdents` and the probe yields a wrong badge;
   that is acceptable *because the badge changes nothing the kernel does*, and it is listed as a residual.
3. **Badge text is per backend, verbatim from identity plan §4.4.** POSIX: *"This item has an extended ACL that this
   app does not display. The mode below is only the base permission set — editing it will not remove the ACL."*
   NFSv4: *"This item's real permissions are an NFSv4 ACL. The mode shown is a summary the filesystem derives from
   it. Changing the mode may **discard or reduce** the ACL, and that cannot be undone from this app."* `unknown`
   gets the NFSv4 text plus *"this app could not read the ACL to say more"*.
4. **Nothing branches on QTS vs hero.** The badge, the text and the ladder all ask the platform table for
   `ACLBackend` and `ZFSAclmode` (decision 8). *Amended, Astra round 1 (#2):* they ask through the **literal**
   lookup (`ForLiteral`, M2-C round 3), never `For`/`MountFor`, whose normalisation turns a backslash — an ordinary
   byte in a Linux filename — into a separator and cleans `..`, so `danger/..\safe/file` was graded on the wrong
   dataset. A path the literal lookup cannot place has unknown facts and is graded pessimistically.
5. *Added, Astra round 1 (#1):* a dataset mounted **after** start-up is probed on the next mount-table refresh,
   exactly as at start-up; until then, and whenever the backend of a storage mount is simply unknown (`""`), the
   ladder grades it as the worst case (L2 with the unknown suffix) rather than as "no ACL backend". *Round 2
   (#7, #13, #14):* the probe runs **asynchronously** after the refresh — `zfs get` has a 3 s timeout and a batch of
   new datasets probed inline would sit inside a 15 s request — and the unknown-is-pessimistic rule covers the gap.
   Only the **visible** row of a mount point is probed (the last mountinfo line, the rule the table already uses),
   and a result is published only if that row is still the one mounted there — two datasets stacked at one path
   were answering with the upper one's attribute and the lower one's `aclmode`. Start-up probes once,
   synchronously; a refresh never repeats a finished probe. *Round 3 (#10):* "still the one mounted there" is a
   per-mount **incarnation**, bumped whenever the row disappears or changes across a refresh, captured when the
   probe starts and required when it publishes — comparing row values admits an ABA remount (mount ids are
   reused, and a remounted dataset keeps every compared field while its `aclmode` changes). The accepted
   race is a mount that appears after the token is issued (§17.3), not one that existed before the request.

## 7. The `aclmode` confirm ladder

The ladder is decided in the **front end**, before dispatch, from its own mount table — it must be, because a
confirmation cannot be demanded after the change. The worker reports the same facts in `Props` for display. Both
read the same data-driven table, so they agree by construction (the trash-root argument, M2-A).

| Situation | Grade | What the dialog says |
|---|---|---|
| chmod, `ACLBackend == "posix"`, `ACL == "posix"` **or `unknown`** (Astra round 1 #9: jobs grade with `unknown`, and an uninspected POSIX ACL is not harmless) | **L1** | the mode's group bits become the ACL **mask**, so named entries may lose effective access; the ACL itself survives |
| chmod, `ACLBackend == "nfs4"`, `ACL` non-trivial or `unknown`, `ZFSAclmode` is `discard` **or empty (unknown)** | **L2** (typed phrase + ack) | names the **dataset** (`Mount.Source`) and states plainly that the ACL will be destroyed and cannot be restored from this app |
| same, `ZFSAclmode == "groupmask"` | **L1** | the ACL will be **silently reduced** to the group bits |
| same, `ZFSAclmode == "passthrough"` | **L1** | the mode is set and the owner/group/everyone entries are regenerated; other entries are kept |
| same, `ZFSAclmode == "restricted"` | **L1** | the kernel may refuse this chmod outright (`EPERM`); the post-call diff will say what happened |
| chmod/chown under a protected (warn-class) path | **L2** | the guard's path-free reasons, as everywhere |
| recursive chmod/chown over > 500 items (from the pre-scan) | **L2** | the measured count; "this cannot be undone" |
| any chown | **L1** minimum | setuid/setgid may be cleared by the kernel |
| setting setuid on a file outside guard-normal | **L2** | backend plan §2.8 |
| `ACL == "nfs4-trivial"` with `aclmode=discard` | normal rules | there is nothing to destroy, so no promotion |

`ZFSAclmode == ""` is treated as `discard`, never as `passthrough`: the pessimistic reading is the only honest one
when `zfs get` is unavailable (identity plan §4.4 is explicit — never guess). Token parts, ordered (amended round 3: a leading `kind=sync|job` part keeps a sync token from redeeming at the job
route and vice versa): `kind=sync|job`, `op=chmod|chown`,
`mask=<octal>`, `value=<octal>`, `dirs=<octal>/<octal>`, `uid=<n>`, `gid=<n>`, `recursive=<bool>`, `cross=<bool>`,
then the sorted resolved roots — so a token issued for 0755 cannot be redeemed for 4755, and one issued
non-recursively cannot be redeemed recursively. *Amended, Astra round 6 (#3):* an `acl=<grade>/<discards>/<aclmode>`
part carries the ACL verdict the sentence was built on, so a token issued for the L1 "other entries are kept"
sentence cannot be redeemed once the facts have aged into the L2 rung — the redemption re-grades, the parts differ,
and the user is challenged again with the sentence that is now true. A token's lifetime is bounded by the facts it
was issued on, not only by the clock. *Round 7 (#1, #2):* the part is a **digest of the per-dataset consequences**
(dataset → rung, sorted), not the deduplicated set of modes — with root `passthrough`, child A `discard`, child B
`passthrough`, the set `discard+passthrough` did not change when B flipped, and the old token would have
destroyed B's ACL without the warning naming B. And the client presents a *second* challenge in turn: a verdict
that changes while the dialog is open (expiry, a background probe) is a new sentence to acknowledge, not an error.

## 8. Properties

1. **`OpProps` is a plain op, not a job.** `PropsReq{Path, Follow}` → `PropsResp{Entry, Target *fsx.Entry, FS
   FSInfo, ACL ACLInfo, Identity FSIdentityResp}`. One canonical walk, one `fstat`, one `fstatfs` on the held
   descriptor, one xattr probe. `Follow` fills `Target` for a symlink (`StatFollow` semantics; a dangling link leaves
   it nil rather than erroring the whole dialog).
2. `FSInfo{FSType, Mount, Domain, Network, ReadOnly, Avail, Total}` — `ReadOnly` from the mount table's options,
   `Avail`/`Total` from `fstatfs` on the descriptor. On a per-share hero dataset those are the dataset's numbers,
   which is the right answer and better than the pool's.
3. `ACLInfo{Backend, Xattr, State, Aclmode, Dataset}` — the authoritative display copy, filled by the worker from
   `s.plat` and the held descriptor's mount identity. *Amended, Astra round 1 (#4, #5):* the state is read from the
   **held leaf** (`lgetxattr` on `/proc/self/fd/N`, the chmod idiom), not from the pathname — the listing badge may
   be a pathname probe because it is display only (§17.2); this answer feeds the ladder, so it may not. And because
   the chmod is a second RPC, the sync chmod route sends what it graded: `ChmodReq.Expect *ACLExpect{State,
   Identity}`; the worker re-proves the identity on the held descriptor and re-probes the state, and refuses
   `changed` if either differs. A worker that could not detect a backend answers unknown, and the route never lets
   the worker's answer downgrade a backend the daemon already knows. *Round 2 (#1, #6):* the expectation carries
   the state the worker **observed**, never the ladder's fallback grade — grading pessimistically and expecting
   pessimistically are different things, and confusing them made every legitimate chmod on an unplaced mount fail
   `changed`; with nothing observed the expectation carries identity only. Off Linux there is no inode to prove,
   so the worker proves the state alone (§14's best-effort loop stands). *Round 3 (#7, #8):* "identity only" is
   not "no probe" — on Linux an empty observation can mean the asynchronous mount probe had not finished, so the
   worker still re-probes and refuses `changed` when it now sees a state that is not harmless (`none`,
   `nfs4-trivial`): the ladder graded something it could not see, and the honest answer is to grade again. And a
   worker's facts lift the unknown-storage floor only when the worker's mount identification for the object
   matches the daemon's row for the path; a worker holding an older mount table answers for the enclosing mount,
   and that answer is unverified. *Round 4 (#1, #4, #5):* agreement decides only whether the worker's **state** is
   believed; its `aclmode` and dataset can never make the grade less severe than the daemon's — the rung is the
   worst of both observations, agreement or not, because either side may hold the older table — and a
   demonstrated mismatch is the unknown floor (L2) whatever backend the daemon's row claims. *Round 5 (#1):* "the
   unknown floor" means the **destructive rung** — on a mismatch the `aclmode` is treated as unknown (`discard`)
   even when both caches say `passthrough`, because neither cache describes the mount the descriptor is on.
4. **Size reuses the existing size job.** Opening the dialog on a directory submits `POST /api/jobs/size` for that
   one path, polls `/api/jobs` as every job is polled, and `POST /api/jobs/{id}/cancel` when the dialog closes or
   Stop is pressed; Recount resubmits. No new job kind, no new route, no second size implementation. `#pImpact` in
   the permissions dialog uses the same submission.

## 9. Wire — committed with this contract

```go
// internal/perm (stdlib only; imported by wproto, fsops and web — INV-1 safe)
type ModeSpec struct { Mask uint32 `json:"m"`; Value uint32 `json:"v"` }
func (s ModeSpec) Apply(cur uint32) uint32
func (s ModeSpec) SetsSpecial() bool          // any 07000 bit set to 1
type Diff struct { Field, Want, Got string }
func DiffOf(want ModeSpec, wantUID, wantGID int, before, after fsx.Entry) []Diff
type Caps struct { Chmod, ChownUID bool; ChgrpTo []int; Reason string }
func CapsFor(uid int, groups []int, root bool, e fsx.Entry) Caps
func Symbolic(mode uint32, dir bool) string   // "drwxr-sr-x"
func NFS4State(acl []byte) string             // "nfs4" | "nfs4-trivial" | "unknown"

// internal/wproto — ChmodReq/ChownReq/ModeResp already exist; they change:
type ChmodReq struct { Path []byte `json:"p"`; Spec perm.ModeSpec `json:"s"`; Follow bool `json:"f,omitempty"` }
// ChownReq unchanged (Path, UID, GID, Follow) — Follow is refused as unsupported in M3.
type ModeResp struct {
    Before fsx.Entry   `json:"b"`
    Entry  fsx.Entry   `json:"e"`
    Diffs  []perm.Diff `json:"d,omitempty"`
}

type ChmodJobReq struct {
    Paths [][]byte `json:"p"`; Files perm.ModeSpec `json:"fs"`; Dirs perm.ModeSpec `json:"ds"`
    Recursive bool `json:"r,omitempty"`; CrossMounts bool `json:"x,omitempty"`
}
type ChownJobReq struct {
    Paths [][]byte `json:"p"`; UID int `json:"u"`; GID int `json:"g"`
    Recursive bool `json:"r,omitempty"`; CrossMounts bool `json:"x,omitempty"`
}

type PropsReq  struct { Path []byte `json:"p"`; Follow bool `json:"f,omitempty"` }
type PropsResp struct {
    Entry fsx.Entry `json:"e"`; Target *fsx.Entry `json:"t,omitempty"`
    FS FSInfo `json:"fs"`; ACL ACLInfo `json:"acl"`; Identity FSIdentityResp `json:"id"`
}
type FSInfo  struct { FSType, Mount, Domain string; Network, ReadOnly bool; Avail, Total uint64 }
type ACLInfo struct { Backend, Xattr, State, Aclmode, Dataset string }

// fsx.Entry gains:
ACL string `json:"acl,omitempty"`   // "" | "none" | "posix" | "nfs4" | "nfs4-trivial" | "unknown"
// fsx.ListOptions gains:
ACLProbe bool `json:"aclProbe,omitempty"`
```

**M3 adds no new error codes.** Every refusal it can make already has one: `changed` (a symlink in a canonical
path), `unsupported` (chmod on a symlink without `follow`, chown with `follow`, a network mount, no writable route to
the inode), `permission` (the kernel, INV-2), `protected`, `readonly`, `confirm_required`, `bad_request` (a
recursive request that sets a special bit), `not_found`, `cancelled`. A new contract test enumerates every code the
worker can emit and asserts each appears in **both** `workerpool.RemoteError.Unwrap` and `web.statusCode`; the M2-C
loop found that gap three separate times (`owner_unset`, `too_large`, `changed`) and a table is cheaper than a
fourth.

## 10. Backend and HTTP

```go
// Mutator gains:
Chmod(ctx, who Principal, req wproto.ChmodReq) (wproto.ModeResp, error)
Chown(ctx, who Principal, req wproto.ChownReq) (wproto.ModeResp, error)
// Backend gains:
Props(ctx, who Principal, req wproto.PropsReq) (wproto.PropsResp, error)
```

```
POST /api/fs/chmod       {path|pathB64, mask, value, follow?, confirm?}         → 200 {before, entry, diffs, warnings}
POST /api/fs/chown       {path|pathB64, uid?, gid?, confirm?}                   → 200 {before, entry, diffs, warnings}
POST /api/jobs/chmod     {paths[], files:{mask,value}, dirs:{mask,value}, recursive, crossMounts, confirm?} → 202 {job}
POST /api/jobs/chown     {paths[], uid?, gid?, recursive, crossMounts, confirm?}                            → 202 {job}
GET  /api/fs/properties  ?path=&follow=                                         → 200 {entry, target, fs, acl, caps, class}
GET  /api/ids            ?kind=users|groups&q=<prefix>                          → 200 {items[], truncated}
```

Sync when it is one non-recursive item, a job otherwise (backend plan §5). `/api/fs/chmod` and `/api/fs/chown` join
`isMutationRoute`; all four join the read-only blanket test and the CSRF/Origin scheme unchanged. `/api/ids` is
**narrowed**: an admin gets the full local lists bounded at 2000 with `truncated`; a non-admin gets only their own
user entry and only the groups they belong to — the picker should offer exactly what the session may set, and the
full local user roster was a disclosure nobody asked for. It lists `/etc/passwd`/`/etc/group` only: there is no bulk
NSS API, and `getent passwd` on a domain-joined NAS is both enormous and slow, so a domain user does not appear in
the picker and the dialog accepts a **typed numeric uid/gid** instead, showing the number when a name does not
resolve.

## 11. Audit

Intent before the call, result after, exactly as mkdir and rename pair them for the sync routes and as delete pairs
them for the job routes (`jobIntentDetail`, `auditJobFinish`). `Op` is `chmod` or `chown`; `Detail` is path-free and
bounded, and records **what was asked and what landed**: `"mask=07777 value=02755 -> 0755 (setgid dropped)"`,
`"uid 0->1003 gid -1 (setuid cleared)"`, `"recursive: changed 412 of 8003, skipped 7591"`. Modes and ids are not
paths, so they may travel; a worker error may name a resolved spelling and stays in the server log alone
(`logRaw`), as everywhere.

**Every chown is a forced QuLog milestone**, sync or recursive (backend plan §6.5: "any chown"). chmod is a
milestone when it is recursive over more than 100 items, when the path is warn- or deny-class, or when the ladder
decided the ACL would be discarded — the three cases an operator would want to find afterwards.

## 12. UI

- `#dlgPerms` (F9) per ui-ux §3.5: the rwx grid and the octal field as two views of one `ModeSpec`; indeterminate
  checkboxes and a blank octal with placeholder `mixed` for a mixed selection; the three special-bit checkboxes;
  owner and group pickers (`<select>` from `/api/ids` plus a numeric field); `#pRecursive` with
  `#pApplyAll|Files|Dirs` mapped to the two masks and `#pSmartX` on by default for recursive; `#pImpact` from the
  size job. Apply → `runMutation`, re-posting with the token on `confirm_required`; the server's `why` sentences
  render in `confirmDialog`, danger class for L2.
- `#dlgProps` (Alt+Enter) per §3.6, with the streaming size job cancelled when the dialog closes and a footer
  button into `#dlgPerms`.
- The ACL badge is a glyph in the name cell (`badges.js`), title text chosen by `entry.acl`, plus a row in both
  dialogs carrying the full per-backend sentence.
- Diffs render as a **warning** toast plus a persistent line in the dialog, never a success toast.
- A recursive job shows in the Operations panel with a "Show skipped items" expander over the first 100 warnings.
- `REFRESH_KINDS` gains `chmod` and `chown` (both change what the list shows). `actionMessage` gains `unsupported`
  for the symlink refusals.

## 13. Caps and limits

Recursive pre-scan 30 s / 500 000 entries (as delete and size); roots capped at `maxJobRoots`; every path component
capped at NAME_MAX by `bodyPath`; `WarnCap` 100 folded into `JobResult`; ACL probe 2000 entries and 64 KiB per
listing page; `/api/ids` 2000 entries with a `q=` prefix filter; recursive root of `/` or depth 1 refused; recursive
special-bit *set* refused; job concurrency is the existing `ClassMetadata` semaphore (4). The properties and
chmod/chown routes are ordinary JSON routes under the 15 s handler context and the 1 MiB body cap — nothing in M3
streams, so nothing in M3 needs an admission slot.

*Amended, round 2:* the recursive pre-scan is bounded by the request context (the 15 s handler budget, with a margin
for the dispatch), not by a separate 30 s constant; a scan that runs out of budget reports `-1` and the ladder treats
that as large (L2). The measured count travels in the confirmation's summary and is reused when the token is
redeemed, so the tree is scanned once per confirmed job.

*Amended, Astra round 1 (#6, #10, #11):* "nothing in M3 needs an admission slot" was wrong about the pre-scan,
which is recursive work an unconfirmed POST can start at will. The pre-scan takes a `ClassMetadata` slot like the
job it precedes and carries the 500 000-entry budget on the wire (`MaxEntries`; a `Capped` result is `-1`; round
2 #8: the budget is the **remaining** allowance root to root, so the sum over a selection is what is capped); a `-1`
is remembered in the issued-cost ledger as an explicit capped outcome, so the confirmed repost reuses it instead of
walking the tree again. A recursive job is also checked for **containment** (`Guard.Contains` over every root, as
the transfer routes do) — a recursive change over an ancestor of the daemon's own installation is refused exactly as
naming it directly is.

## 14. Degradation off Linux (the dev loop)

`chmod_other.go` applies `os.Chmod` best effort (Windows mode bits are a fiction and the dev loop only needs the
route to answer); `chown_other.go` returns `unsupported`; the xattr probe returns `none`, so badges never appear and
the dialogs hide the ACL row; `fstatfs` is absent, so `FSInfo.Avail/Total` are omitted rather than invented
(`copy_other.go`'s rule: reporting "unknown" beats guessing). Permission-semantics tests skip on Windows and when
not root, by design (INV-2). What **is** fully exercised on the dev box is everything that decides behaviour without
the kernel: `internal/perm` in full, and the entire `aclmode` ladder — driven by `Platform.FromMountinfo` over the
captured hero mountinfo with an injected `ZFSAclmode`, since the ladder is front-end logic over a data table. That
is deliberate: the riskiest new judgement in M3 is testable without a NAS.

## 15. Tests

- **`internal/perm` (every OS):** `ModeSpec.Apply` table including every special bit; symbolic rendering against
  octal; `CapsFor` for admin / owner / group member / non-member / orphan uid; `DiffOf` for setgid dropped, setuid
  cleared by chown, gid unchanged at -1; `SetsSpecial`; `NFS4State` over crafted attribute bytes including a
  truncated one (→ `unknown`).
- **fsops, Linux, non-root:** canonical walk refuses a symlink component (`changed`); chmod on a symlink leaf
  without `follow` is `unsupported`; recursive walk refuses `.zfs` and `@Recycle`; crossing only with the flag;
  pre-scan bound; cancel yields a partial result; the `/proc`-unavailable fallback via a seam; the descriptor-exact
  chown path and its `AT_EMPTY_PATH`-unavailable fallback with an identity mismatch → `changed`.
- **fsops, Linux, root-only (`test-linux-root`):** fixture users `alice`/`bob`/`carol`, groups `team`/`other`.
  chmod by non-owner `EPERM`, by owner ok; chown uid by non-root `EPERM`; chgrp to a member group ok, to a
  non-member `EPERM`; **setgid silently dropped** — request 2755 as a non-member owner and assert both the post-call
  `fstat` shows 0755 *and* the response carries the diff; chown clears setuid; sticky-directory interaction;
  recursive chmod over a mixed-ownership tree finishes `done` with the right changed/skipped counts, not `failed`.
- **ZFS CI job:** `system.nfs4_acl` present on a plain file classifies `nfs4-trivial`; the same file with a named ACE
  written **directly as the xattr** (so the test depends on no `nfs4_setfacl` binary) classifies `nfs4`;
  `zfs get aclmode` parsed back for a dataset set to each of `discard`, `groupmask`, `passthrough`, `restricted`; a
  chmod on `aclmode=restricted` returns `EPERM` and the diff reports it. The assertion about `discard` is that **we
  warned first** — never that the kernel destroyed the ACL (INV-2: we do not test the kernel).
- **POSIX-ACL CI (ext4, `setfacl` in the image):** presence drives the `posix` state; a chmod rewrites the mask and
  the diff reports the mode landing as asked.
- **worker/workerpool:** `OpChmod`/`OpChown`/`OpProps` round trips through a real spawned worker;
  `JobChmod`/`JobChown` dispatch; cancel mid-job drains to the partial result; the new **code-coverage table test**
  — every code the worker can emit is in `remoteError` *and* `statusCode`.
- **web:** all four routes against a fake mutator/jobs — guard on both spellings, token parts and ordered
  redemption, the ladder driven by an injected platform table (golden hero mountinfo × each `aclmode` × each ACL
  state), the recursive-special-bit and depth-1 refusals, audit intent/result pairing, the forced chown milestone,
  `/api/ids` bounds and the non-admin narrowing, the properties route shape, the read-only blanket test over the new
  routes, the INV-1 import test unchanged.
- **node:** the `perm` mirror (octal ↔ grid, smart-X presets, mixed indeterminate), badge-text selection per
  `entry.acl`, diff rendering, the props ↔ size-job wiring.
- Plus the three-GOOS vet sweep and `gofmt` before any green is claimed.

## 16. Not in M3

ACL **editing** of any kind (POSIX v2, NFSv4 v3) and any "effective permissions" computation — that is
re-implementing the kernel, which INV-2 forbids. The text editor's save path with `.bak` and optimistic concurrency
(ui-ux put it in M3; PLAN's M3 row does not). `dryRun` / `#pPreview`. Resumable or batched chmod across selections
with per-item policies. `chattr` immutable/append-only attributes. QNAP's "Advanced Folder Permissions" / Windows ACL
layer. Following symlinks in a recursive job. Setting special bits recursively (refused, not deferred). Restoring an
ACL after a `discard` chmod — there is no such thing, which is why the confirmation is L2. Extract, thumbnails,
in-app drag-and-drop and the trash janitor stay deferred.

## 17. Residual risks

1. **§2.0 again.** The guard→worker dispatch race is unchanged: the canonical `O_NOFOLLOW` walk turns an ancestor
   swap into `changed` rather than a wrong target, but the window between the front end's resolve and the worker's
   walk still exists. Accepted on the same grounds as M1.
2. **The ACL badge is a pathname probe.** `lgetxattr` after `getdents` can describe an object that was replaced in
   between. It is display only and changes nothing the kernel does.
3. **`aclmode` is read once, at mount-table build time** — *narrowed, Astra round 4 (#6): re-read within 60 s.* A
   `zfs set aclmode=discard` afterwards, or a field-identical remount between two refreshes, is invisible until
   the mutable probe facts age out and the single-flight pass re-probes them, so the ladder can under-warn for at
   most that minute — *round 5 (#2, #3):* and not a second longer, because an expired `aclmode` is **masked** as
   unknown at lookup until the re-probe publishes, and the pass takes never-probed rows first, then the oldest,
   with a cursor across passes so a slow pool cannot starve its trailing datasets. *Round 6 (#2):* the expired
   **backend** is masked the same way (the unknown-storage floor), and the row identity includes the mount options,
   so an ext4 share remounted `noacl` → `acl` is a new incarnation rather than a cached `none`. Unknown is already treated as `discard`, which covers the far more likely failure (the `zfs`
   binary not being callable at all).
4. **"Trivial" is our heuristic.** A mis-classified trivial NFSv4 ACL under-warns. Parse failures fail towards the
   pessimistic side, which is the half that matters.
4a. **With crossing, a job's ACL rung is the worst of every dataset the mount table places below the roots at the
   moment the token is issued** (round-4 review): a hero pool is one dataset per share and often per sub-folder, so
   grading the selected root alone let a `passthrough` parent promise "other entries are kept" and then destroy a
   `discard` child's ACLs one directory down. A dataset mounted *after* the token was issued is not seen — the same
   window as residual 3, and accepted on the same grounds.
5. **A recursive permissions job has no undo,** and a cancelled one leaves a half-changed tree. Stated in the dialog
   and in the result.
6. **chown clears setuid/setgid,** and POSIX chmod rewrites the ACL mask. Both are reported after the fact, never
   prevented — preventing them would mean second-guessing the kernel.
7. **The dataset name in the L2 dialog** comes from `Mount.Source`; QNAP's ZFS fork may spell it differently from
   upstream. Verify on hardware before trusting the sentence.
8. **`/api/ids` still discloses the local user roster to an admin,** which is what a picker needs; the non-admin
   narrowing is new and should be checked against a real domain-joined unit, where a user may legitimately need to
   chgrp to a group `/etc/group` does not list.
9. **`fstatfs` on a hero dataset** reports the dataset's quota/reservation view, which can surprise a user who
   expects pool free space.
10. **No kernel semantics are exercised on the dev box** (INV-2), so local green means less for M3 than for any
    milestone so far. CI's root and ZFS jobs are the real gate.
11. **Hardlinks (round 2).** A recursive chmod applies to the inode an entry names, wherever else it is linked. When
    the worker is root (an administrator), non-directory entries with `nlink > 1` are skipped with a warning and
    must be changed by naming them directly — which also skips legitimate hardlink farms (rsync `--link-dest`
    backup trees) under an admin's recursive change. Non-root workers are left to the kernel, which refuses a
    chmod of an inode the user does not own. Recursive jobs also resolve a symlink root to its target and change
    that; a mount-point root is changed and descended (child mounts follow `CrossMounts`).
12. **Link target spelling (round 4).** `properties` without `follow` still reports `LinkResolved` from the worker's
    own resolution, as the listing has since M1; the `follow` refusal protects the target's attributes, not its
    spelling. Accepted as M1 behaviour.
13. **Nested directories and the post-order change (Astra round 1 #7, #8, #19, #20).** The walker closes a
    directory before its post-order chmod/chown; the reopen is now compared (dev, ino) with what was traversed and
    a substitution is reported as `changed` for that entry. A directory the worker cannot enumerate still gets the
    change on its held reference, with the listing failure reported beside it. A non-directory entry on another
    device (a regular-file bind mount) is a crossing under `crossMounts:false` and is skipped like a directory
    crossing. The recursive root is re-`fstat`ed before its own mode is built, so a special bit cleared elsewhere
    during the walk is not reinstated from a stale snapshot.
14. **A benign refresh re-challenges (Astra round 7).** An `aclmode` that was unknown when the challenge was issued
    and known by redemption changes the token's consequence part, so the user is asked again even though the new
    sentence is milder. That is the conservative side, and it is bounded by the probe TTL.
15. **Claim ownership follows the session the page observed (Astra round 7).** Pending size-job cancels are scoped
    by an owner epoch that moves on an observed sign-out or change of user; a same-user re-login the page never
    saw keeps the previous claims — the same person, the same walks, and nothing a different user could reach.
    A measurement's polling and completion follow the same epoch, so a same-user refresh mid-walk neither
    cancels nor orphans it.
16. **What the token does not re-grade (Astra round 7).** A job already running is not re-graded when the ACL
    facts change under it — the token bound its start, and a walk in progress is the kernel's. A size job whose
    202 the page never received, or whose tab was closed, is reaped by the server's job lifetime, not by a dialog.
    The pathname chown fallback where `/proc` is absent keeps the check/use window §2.3 already accepts.

**To confirm on hardware first (both units):** that `zfs get -Hp -o value aclmode` is callable at all as root on
hero and what it returns for an ordinary share — the entire L2 promotion hangs on it, and an empty answer means every
hero chmod asks for a typed phrase; then that `system.nfs4_acl` is readable as a non-root user on a share they own
(the badge degrades to `unknown`, i.e. pessimistic, if not); that an ordinary QTS share reports
`ACLBackend == "posix"` and an ordinary file reports `none`, not `posix`, so the badge is not universal; and that a
chmod reached through a share symlink (`/share/Public` → `/share/CACHEDEV1_DATA/Public`) succeeds — a `changed`
refusal on a plain share means the front end's resolution is not happening, the same tell as M2-C.
