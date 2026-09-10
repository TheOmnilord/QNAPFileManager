Reviewed `7329336` and `b97af8d`. **No confirmed blocker for a supervised, access-controlled, read-only QTS/QuTS hero test.** Two bootstrap recovery defects remain, and the claim of total descriptor-relative containment needs qualification.

1. **P2 — Retained containment gap; newly identified, not introduced here.**  
   [fsops.go:616](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:616) calls `Platform.IsMountPoint`, whose fallback performs path-based, symlink-following `Stat` calls at [probe_linux.go:33](C:/Dev/QNAPFileManager/internal/platform/probe_linux.go:33). With a jail on the root filesystem and `/escape → /proc`, plain `Stat("/escape")` rejects target resolution but still probes `/proc` outside the jail and reports its mount status. Listing notes use the same fallback at [fsops.go:958](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:958). Additionally, [fsops.go:357](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:357) re-resolves the configured base using path-based `EvalSymlinks`. These are metadata lookups, not a demonstrated file-content escape or root-identity bypass.  
   **Minimal fix:** use mount-table-only classification from fsops, and establish any canonical base alias alongside initial handle acquisition instead of re-resolving its pathname during requests.

2. **P2 — Round-7 adversarial finding 2: accepted-as-residual.**  
   Unattributed failures still use attacker-presented usernames at [auth_limits.go:59](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:59); recovery admission remains first-come-first-served at [auth_limits.go:200](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:200). Bad-token traffic can delay legitimate uncached logins. Acceptance remains explicit in [PLAN.md:103](C:/Dev/QNAPFileManager/PLAN.md:103), verification item 10.  
   **Minimal fix before shared exposure:** verify trustworthy proxy client attribution and enforce per-client admission, or provide fair unattributed admission.

3. **P3 — Round-7 adversarial finding 4 / standard finding 3: partial.**  
   Scrubbing and bounded retries now work for 503, 504 and network failures. However, [bootstrap.js:17](C:/Dev/QNAPFileManager/internal/web/static/js/bootstrap.js:17) excludes 429, so [bootstrap.js:35](C:/Dev/QNAPFileManager/internal/web/static/js/bootstrap.js:35) discards the SID on temporary admission pressure. The server explicitly returns `429` with `Retry-After: 1` at [server.go:133](C:/Dev/QNAPFileManager/internal/web/server.go:133). I reproduced request parameters changing from `{sid:"valid"}` to `{}` on Retry. The updated test incorrectly treats 429 as definitive.  
   **Minimal fix:** retain the SID for bounded 429 retries and honor `Retry-After`. This recovery hole survives the rewrite.

4. **P3 — Newly introduced: cookie-based Retry becomes permanently disabled.**  
   [bootstrap.js:27](C:/Dev/QNAPFileManager/internal/web/static/js/bootstrap.js:27) permanently throws the failure recorded at line 38, including when the page never supplied a SID. After four transient failures, restoring service and clicking Retry makes no request; I reproduced this with the actual module.  
   **Minimal fix:** apply terminal credential exhaustion only to a pending SID bootstrap; allow a fresh bounded attempt for cookie-based authentication.

Fully fixed round-7 items:

- **Adversarial finding 1 / standard finding 1 — complete:** absolute and standalone dots survive mapping and receive traversal checks ([fsops.go:165](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:165), [fsops.go:309](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:309), [fsops.go:386](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:386)).
- **Adversarial finding 1’s test defect — complete:** the permission precondition appends a literal `/.` ([perm_linux_test.go:326](C:/Dev/QNAPFileManager/internal/fsops/perm_linux_test.go:326)).
- **Standard finding 2 — complete:** Linux acquires the jail with `O_PATH`; search-only-base coverage exercises stat, download, subdirectory listing and denied base listing ([jail_linux.go:75](C:/Dev/QNAPFileManager/internal/fsx/jail_linux.go:75), [perm_linux_test.go:231](C:/Dev/QNAPFileManager/internal/fsops/perm_linux_test.go:231)).
- **Adversarial finding 3 — complete:** unsafe first requests reject before creation; existing-session CSRF rejects before locking/revalidation; class reservations remain intact ([session.go:168](C:/Dev/QNAPFileManager/internal/web/session.go:168), [session.go:249](C:/Dev/QNAPFileManager/internal/web/session.go:249), [auth_limits.go:277](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:277)).
- **Carried A1/S1 — complete:** listing metadata remains descriptor-relative with per-entry closure ([open_linux.go:403](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:403)).
- **Carried A4 — complete:** interrupted-leader followers receive retryable 503 ([auth_limits.go:322](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:322), [server.go:125](C:/Dev/QNAPFileManager/internal/web/server.go:125)).
- **Carried A5 — complete:** raw credential presence remains independent of successful parsing ([anonymous.go:14](C:/Dev/QNAPFileManager/internal/web/anonymous.go:14)).

No prior finding is classified **wrong**.

The main Linux walker starts from the pinned descriptor, rejects symlink ancestors, and never submits `..` to `openat` ([open_linux.go:64](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:64)). Absolute targets re-enter that same jail after mapping. At the base, jailed `..` rejects; identity `/..` stays `/` ([fsops.go:173](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:173)). I found no new descriptor leak. `statFollowing` permits eight re-resolutions, each with the 40-link bound ([fsops.go:648](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:648)). Identity-root closure is intentionally a no-op: one process-lifetime descriptor survives in-process worker shutdown and is reclaimed on process exit ([root.go:41](C:/Dev/QNAPFileManager/internal/fsx/root.go:41), [root.go:116](C:/Dev/QNAPFileManager/internal/fsx/root.go:116)). No changed INV-1 boundary crossing was found.

**Further broad review rounds now have diminishing returns.** Fix the bounded recovery issues, verify those changes narrowly, and prioritize hardware evidence—especially proxy attribution and permission behavior. This is not unrestricted-deployment or M0 exit-criteria sign-off.

All 17 JavaScript tests passed; both additional recovery scenarios were reproduced in memory. Go tests, Linux runtime tests and cross-target vet were not run in this read-only Windows review. No files changed.