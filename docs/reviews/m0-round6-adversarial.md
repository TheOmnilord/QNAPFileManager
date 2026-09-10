Reviewed `07d9d9c` against PLAN.md and both round-5 reviews. **Suitable for a supervised, read-only first hardware test, but not unrestricted shared use or M0 sign-off.** The reviewed changes introduce no confirmed privilege escalation or write path. Files remain unchanged; all 10 JavaScript tests passed. Go/Linux runtime tests were not run in this read-only Windows environment.

“A” below means the adversarial review’s numbered findings; “S” means the standard review’s bullets.

| Round-5 finding | Status | Evidence |
|---|---|---|
| A1: shared-proxy authentication lockout | **Partial** | Established sessions bypass failure budgets at [auth_limits.go:138](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:138), and logins leave two execution slots available at [auth_limits.go:225](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:225). Fresh-login recovery remains vulnerable; finding 2 below. |
| A2: first-login followers occupy execution slots | **Complete** | Deduplication wraps validation, identity resolution and insertion at [session.go:173](C:/Dev/QNAPFileManager/internal/web/session.go:173); followers consume waiting capacity at [auth_limits.go:302](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:302). Cancellation semantics still need improvement. |
| A3 / S2: listing through search-only ancestors | **Complete** for the reported permission defect | [open_linux.go:302](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:302) walks ancestors with O_PATH and opens only the final directory read-only. [perm_linux_test.go:127](C:/Dev/QNAPFileManager/internal/fsops/perm_linux_test.go:127) covers the readable-child case. This introduces finding 1. |
| S1: uncancellable preview | **Complete** for Linux pollable streams | [browse.go:288](C:/Dev/QNAPFileManager/internal/web/browse.go:288) prepares the stream; cancellation closes it, and interrupted output is marked truncated at line 316. Pipe cancellation/deadline tests cover this. Uninterruptible filesystem I/O remains outside that guarantee. |
| S3: expired authentication prevents shell loading | **Complete** | Embedded assets bypass authentication at [server.go:99](C:/Dev/QNAPFileManager/internal/web/server.go:99). API enforcement remains separate. |

The inherited round-4 fixes remain **complete and unchanged**: shutdown ([workerpool.go:410](C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:410)), dot-component rejection ([path.go:53](C:/Dev/QNAPFileManager/internal/fsx/path.go:53)), worker-fixture cleanup ([workerpool_test.go:171](C:/Dev/QNAPFileManager/internal/workerpool/workerpool_test.go:171)), and Windows drive roots ([root.go:84](C:/Dev/QNAPFileManager/internal/fsx/root.go:84)). None of the round-5 findings was wrong.

1. **P2 — New: directory metadata can escape the opened directory and configured jail.**  
   [open_linux.go:314](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:314) constructs an ordinary `os.NewFile` named by its absolute pathname; [fsops.go:417](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:417) calls `DirEntry.Info()`. Local Go source confirms ordinary directory entries lazily `Lstat(parent/name)`, whereas entries from `os.Root` obtain descriptor-relative metadata.

   After enumeration, rename `/jail/d` and replace it with a symlink to an outside directory containing matching names. The returned names describe the original directory, while size, ownership and mode can describe outside files. Ordinary concurrent renames can also produce missing or incorrect entries. Kernel checks still use the worker’s identity; this does **not** confer root access.

   **Minimal fix:** use `File.Readdir(readChunk)` and its returned `FileInfo` values—Linux performs descriptor-relative `fstatat`—or explicitly stat each child relative to the opened directory. Add a rename/symlink-replacement regression.

2. **P2 — Residual: attacker-controlled usernames and global recovery admission still permit login denial.**  
   [auth_limits.go:58](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:58) trusts the *presented*, merely syntactically valid username as the unattributed bucket key. Twenty distinct failed tokens for `alice` throttle Alice’s uncached login. The attacker can consume each one-per-second recovery opportunity before Alice arrives.

   Rotating usernames fills the 200-failure unattributed bucket. Its five-per-second allowance is also shared and first-come-first-served at [auth_limits.go:198](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:198), so continued traffic can deny fresh logins across users. This is rejection, not queued slow-down. Established sessions and positive cache hits remain protected. [auth_recovery_test.go:94](C:/Dev/QNAPFileManager/internal/web/auth_recovery_test.go:94) proves recovery when the legitimate request gets the next turn, not recovery under continued attack.

   **Minimal fix:** require and verify proxy-generated client attribution for shared deployment, then apply per-client admission. Unattributed traffic needs a bounded fair-admission design; increasing allowances cannot establish fairness.

3. **P2 — Residual: reserved slots protect only revalidation.**  
   [auth_limits.go:270](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:270) limits new logins but lets revalidations occupy all eight execution slots. An authenticated client with eight distinct sessions can repeatedly POST—even without valid CSRF—to force validation at [session.go:266](C:/Dev/QNAPFileManager/internal/web/session.go:266), before CSRF rejection. Combined with session followers occupying the shared waiting budget, fresh logins receive 503s.

   **Minimal fix:** reserve admission for both classes or schedule them fairly; reject invalid CSRF before forcing upstream revalidation. This is a remaining scheduling weakness, not a newly introduced privilege bypass.

4. **P3 — Deduplication extends leader-cancellation failure propagation.**  
   At [auth_limits.go:312](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:312), followers inherit the leader’s error. If the leader disconnects during identity resolution, a still-connected follower receives `context.Canceled`, which [server.go:127](C:/Dev/QNAPFileManager/internal/web/server.go:127) converts to 401. The UI consequently asks for QTS sign-in although credential validity was never disproved.

   **Minimal fix:** retry a cancelled leader’s flight within the follower’s remaining deadline, or return a transient error. Followers’ own cancellation/deadlines are bounded correctly; successful results are rechecked through session authentication.

5. **P3 — New anonymous rule confuses absent and malformed credentials.**  
   [anonymous.go:18](C:/Dev/QNAPFileManager/internal/web/anonymous.go:18) uses successful extraction to detect presence. For example, `NAS_USER=-bad; qtoken=expired` makes extraction fail and `/api/session` return anonymous 200 instead of 401.

   **Minimal fix:** detect raw presence of recognized credential fields independently of validation. This changes response semantics, not authorization: the anonymous response exposes version, platform family and read-only configuration, but no user identity or CSRF token; protected APIs still reject it.

Memory remains bounded: 4,096 client buckets, 20 credential hashes each, plus 200 unattributed hashes. Non-UTF-8 entry names retain their byte/base64 handling. Huge listings retain the pre-existing 50,000-entry cap and chunk cancellation checks; they are not complete directory snapshots. The smoke test’s anonymous 200/readOnly and unknown-API 401 expectations match [build.yml:192](C:/Dev/QNAPFileManager/.github/workflows/build.yml:192).

**Before a supervised hardware install:** no additional code fix is a confirmed security blocker, provided the trial has controlled access and does not rely on `-jail` as confinement. Fix finding 1 before relying on jail isolation, and finding 2 before shared exposure without verified client attribution. Findings 3–5 can wait until after that trial. Hardware authentication, proxy-header and kernel/ZFS behavior still require verification.