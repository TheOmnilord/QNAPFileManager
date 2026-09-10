Reviewed `6b8e08d`. **No confirmed blocker for a supervised, access-controlled, read-only QTS/QuTS hero test.** INV-1 remains intact; the incomplete dot handling still violates INV-2. This is not unrestricted-deployment or M0 sign-off.

“A” refers to the five numbered round-6 adversarial findings; “S” to the three standard findings. None was wrong.

1. **P2 — S2 partial: some symlink dots still bypass kernel checks.**  
   [fsops.go:151](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:151) correctly checks relative `file/.` and `locked/.`, using descriptor-relative traversal at [open_linux.go:474](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:474). However, [fsops.go:290](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:290) removes dots from absolute targets: `/share/locked/.` becomes `/share/locked`, and `/share/file/.` becomes `/share/file`. `StatFollow` can therefore report success where the kernel rejects the original target. A target consisting solely of `.` also disappears in [fsops.go:334](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:334).  
   **Minimal fix:** preserve symlink-target components separately from root-path normalization, including through absolute-target containment mapping. Add absolute and standalone-dot cases.

   **New test defect:** [perm_linux_test.go:236](C:/Dev/QNAPFileManager/internal/fsops/perm_linux_test.go:236) uses `filepath.Join(locked, ".")`, which removes the dot. Its precondition stats `locked` itself, normally succeeds, and skips the permission regression. Append the literal separator and dot without cleaning.

2. **P2 — A2 accepted-as-residual: uncached login denial remains.**  
   [auth_limits.go:59](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:59) still keys unattributed failures on attacker-presented usernames; [auth_limits.go:200](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:200) allocates recovery opportunities first-come-first-served. Continued bad-token traffic can deny a known user’s uncached login or consume global recovery opportunities. Acceptance is explicit at [PLAN.md:103](C:/Dev/QNAPFileManager/PLAN.md:103).  
   **Minimal fix before shared exposure:** verify that the proxy supplies trustworthy client attribution, then enforce per-client admission; otherwise implement fair unattributed admission. Established sessions bypass this failure budget.

3. **P2 — A3 partial: reservations fixed; invalid-CSRF first logins still contact QTS.**  
   Both classes now have six-of-eight execution limits, acquired before the shared execution slot at [auth_limits.go:224](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:224) and [auth_limits.go:273](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:273). Full shared waiting capacity does not prevent immediate use of free reserved execution capacity.

   Existing-session invalid-CSRF POSTs reject before locking or revalidation at [session.go:244](C:/Dev/QNAPFileManager/internal/web/session.go:244). But a POST carrying an uncached SID and no matching application session reaches `createSession` at [session.go:182](C:/Dev/QNAPFileManager/internal/web/session.go:182), including QTS validation and potentially session insertion, before that check.  
   **Minimal fix:** reject unsafe requests without an existing session before creating one; bootstrap through GET.

4. **P3 — S3 partial; new SID bootstrap retry/cleanup defect.**  
   Successful cookie-free bootstrap now works. However, [app.js:35](C:/Dev/QNAPFileManager/internal/web/static/js/app.js:35) consumes the SID before awaiting authentication. After a 503, timeout, or network failure before cookie issuance, Retry sends `{}` and becomes anonymous. The catch also displays “session ended” for a transient failure. I reproduced this using the actual `connect` function with mocked responses.

   Cleanup occurs only after authenticated success at [app.js:40](C:/Dev/QNAPFileManager/internal/web/static/js/app.js:40), leaving failed bootstrap credentials in the current URL/history entry. Reload can reuse them: “one-shot” applies only to that page’s in-memory request state.  
   **Minimal fix:** remove credential parameters immediately after capture; retain them in memory for bounded transient retries, clearing them after success or definitive rejection.

   [security.go:41](C:/Dev/QNAPFileManager/internal/web/security.go:41) supplies `no-referrer`, so I found no outgoing referrer leak. Initial navigation still transmits the SID URL. [bootstrap.js:9](C:/Dev/QNAPFileManager/internal/web/static/js/bootstrap.js:9) and URL-encoded API parameters introduce no confirmed open redirect or reflected-value injection.

- **A1 / S1 complete:** listing metadata uses directory-relative `O_PATH|O_NOFOLLOW` plus `fstat`; each child closes inside `lstatIn`, preventing per-chunk descriptor accumulation ([open_linux.go:358](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:358), [open_linux.go:385](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:385)).
- **A4 complete at the HTTP layer:** live followers receive transient 503/`Retry-After: 1` for cancelled/deadline-expired leaders; their own deadlines remain authoritative ([auth_limits.go:318](C:/Dev/QNAPFileManager/internal/web/auth_limits.go:318), [server.go:119](C:/Dev/QNAPFileManager/internal/web/server.go:119)).
- **A5 complete:** raw recognized cookie/header/query presence is independent of successful credential parsing ([anonymous.go:14](C:/Dev/QNAPFileManager/internal/web/anonymous.go:14)).

Listing scrutiny found no further confirmed correctness defect. Vanished entries are skipped at [fsops.go:451](C:/Dev/QNAPFileManager/internal/fsops/fsops.go:451); raw names retain byte/base64 handling. [open_linux.go:429](C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:429) matches local Go Linux mode conversion, including exact `S_IFMT` values, unknown-value fallback, and setuid/setgid/sticky. Approximately 150,000 metadata syscalls are required for 50,000 entries; hidden names are now statted before filtering, and cancellation remains chunk-granular. NAS latency needs measurement.

All 12 JavaScript tests passed. Go/Linux runtime tests and the vet sweep were not run in this read-only Windows review. No files changed.