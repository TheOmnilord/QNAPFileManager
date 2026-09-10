**M1 write-path verdict: not ready for sign-off.** Read-only review of `d73f65e`; no files modified or tests executed. Below, A1–A10 refer to the adversarial review; S1–S5 map the standard review.

1. **High confidence, high severity — A1/S1: partial; new policy regression.**  
   [routes_mutate.go:233](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:233), lines 307–308 and 435 check only resolved paths. Ordinary aliases into protected directories are now caught, and resolving the parent while preserving the leaf correctly distinguishes deleting *through* a link from deleting the link itself. However, resolution can erase protection: with `/etc/config -> /ordinary/config`, deleting `/etc/config/file` loses the `/etc/config` warning. An installation path containing a symlink similarly loses its lexical rule.  
   **Minimal fix:** combine requested-path and resolved-path verdicts, and canonicalize configured protected roots.

   **The race remains:** lines 242, 336 and 453 dispatch the original spelling; batch line 524 checks a resolution cached at line 484. Swap an allowed parent to a protected directory between checking and worker resolution, and the worker operates there without the corresponding guard verdict. Worker resolution occurs separately at [fsops/mutate.go:162](/C:/Dev/QNAPFileManager/internal/fsops/mutate.go:162). ENOENT, loops and missing intermediates do not establish a static successful bypass, but lexical fallback at [resolve.go:39](/C:/Dev/QNAPFileManager/internal/web/resolve.go:39) permits the same bypass when the namespace becomes usable before dispatch.  
   **Minimal fix:** have the worker prepare and retain parent descriptors, authorize that prepared operation, then execute against those descriptors; fail closed on unresolved preparation.

2. **High confidence, high severity — A2/S2: partial.**  
   [routes_mutate.go:316](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:316) correctly combines source `OpRename`, source `OpDelete`, and destination-parent `OpCreate`, with deny/read-only outranking confirmation. But destination `OpDelete` is conditional on a successful separate Stat at line 322. A transient worker/Stat failure followed by successful Rename skips replacement protection; a destination appearing after Stat also escapes that check. Dangling symlinks themselves are correctly detected by the production non-following Stat.  
   Destination-entry creation protection is also absent: renaming `/data/x` to absent `/data/.zfs` passes the parent check.  
   **Minimal fix:** always check destination deletion policy for `overwrite:true`, check destination-entry protection, and enforce no-overwrite atomically in the worker.

3. **High confidence — A3: complete.**  
   [server.go:114](/C:/Dev/QNAPFileManager/internal/web/server.go:114), lines 251 and 290 restrict mkdir/rename/delete/logout to POST and dispatch settings GET/HEAD to the reader. All remaining registered GET/HEAD handlers are reads; no other filesystem/settings mutation is reachable through HEAD. POST retains CSRF/Origin checks and forced revalidation at [session.go:276](/C:/Dev/QNAPFileManager/internal/web/session.go:276), line 298. No new read-route regression identified.

4. **High confidence — A4: complete.**  
   [confirm.go:91](/C:/Dev/QNAPFileManager/internal/guard/confirm.go:91) decodes raw URL Base64 and requires exact re-encoding equality at line 101. This rejects padding, whitespace/CRLF, alternative trailing bits, and standard-alphabet substitutions. Shared alphabet characters are identical encodings, not alternatives. The spent key is **all decoded token bytes**, not just the nonce, at line 120; equivalent encodings therefore collide. Redemption is mutex-protected.

5. **High confidence — A5: complete for operation binding.**  
   [routes_mutate.go:331](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:331), line 347 build tagged, ordered `from/to/overwrite` parts identically for issue and redemption. [confirm.go:156](/C:/Dev/QNAPFileManager/internal/guard/confirm.go:156) length-prefixes them, preventing delimiter ambiguity. Different direction, endpoints or overwrite values cannot reuse the token. Namespace/object changes remain covered by finding 1’s limitation.

6. **High confidence — A6/S4: complete for the reported mkdir bypass.**  
   [routes_mutate.go:217](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:217) rejects `parents:true`; lines 235–236 check parent and target, including `.zfs`. General resolution defects remain separate.

7. **High confidence — A7/S3: complete for ignored verdicts.**  
   [routes_mutate.go:502](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:502), lines 524–548 require actual redemption of the exact batch multiset before tolerating confirmation-required items and handle every denial/error. Read-only toggles stop subsequent checked items. Cached namespace resolution remains unsafe; an already-authorized dispatch is not synchronized with toggles.

8. **High confidence — A8/S5: complete.**  
   [routes_admin.go:66](/C:/Dev/QNAPFileManager/internal/web/routes_admin.go:66) holds `cfgMu` across persistence and live application, including memory-only guard toggles. Concurrent saves cannot apply in reverse order.

9. **High confidence, medium severity — A9: partial.**  
   [routes_mutate.go:442](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:442), line 485 obtain sizes through the user’s worker. [fsops/fsops.go:663](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:663) preserves final-link size: a link to a huge file does not misleadingly count the target. However, small permanent deletes still bypass confirmation, contrary to decision 10. [routes_admin.go:38](/C:/Dev/QNAPFileManager/internal/web/routes_admin.go:38) documents, but does not satisfy, decision 7’s password challenge.  
   **Minimal fix:** require permanent-delete confirmation regardless of size and implement QTS password reauthentication or obtain an explicit plan revision.

10. **High confidence, medium severity — A10: partial.**  
    [audit.go:152](/C:/Dev/QNAPFileManager/internal/audit/audit.go:152) still drops intent/result/milestones on overflow; writes proceed without acknowledgement. Sink counters improve visibility but cannot restore evidence. Confirmation failures still merely issue another token at [routes_mutate.go:149](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:149); general authentication failures remain unaudited.  
    **Minimal fix:** acknowledge durable intent before dispatch, protect milestone delivery, and audit authentication/confirmation failures.

**Additional introduced defects, high confidence:**

- [resolve.go:51](/C:/Dev/QNAPFileManager/internal/web/resolve.go:51): root `EvalSymlinks` traverses outside the jail **before** containment checking. Inside inaccessible `/private`, a guessed symlink targeting a protected directory produces a distinguishable guard response, potentially exposing its resolved target. **Fix:** bounded, jail-contained resolution as the user; return permission failures before guard details.
- [session.go:279](/C:/Dev/QNAPFileManager/internal/web/session.go:279): CSRF auditing reads mutable `old.who/admin` without `old.mu`, racing revalidation writes at lines 343–345. **Fix:** use a synchronized identity snapshot.

No nil-Root panic: `Root` is a value with a valid zero identity mapping.

**Residual risks:** static review only; new tests do not establish namespace-race or kernel-permission safety. Mount freshness, object/size changes after confirmation, overwrite races, and ambiguous RPC outcomes remain. Decisions 9/11 gain no new recursive/ACL coverage. M1 remains blocked by guard bypasses and incomplete confirmation/audit guarantees.