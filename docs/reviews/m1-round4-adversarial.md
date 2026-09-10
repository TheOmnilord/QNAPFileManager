Reviewed `d7e2c095` read-only. Thirteen targeted JavaScript tests passed. No Go or hardware tests run; no files modified.

**Findings, ranked by confidence and impact**

1. **P1 — Read-only rollback can undo another administrator’s successful safety change. High confidence.**  
   [routes_admin.go:76](C:/Dev/QNAPFileManager/internal/web/routes_admin.go:76) applies the toggle and releases `cfgMu` before auditing; failure later restores the old value at line 104. Starting writable: A enables read-only but its audit stalls; B successfully enables read-only; A times out and restores writable. Disabling also becomes live before durable acknowledgement, and rollback persistence errors are ignored at line 111.  
   **Minimal fix:** serialize the whole transition, durably record its intent before enabling writes, then persist/apply it. Avoid rollback based on an obsolete snapshot; report persistence failures.

2. **P2 — Resolved-path disclosure remains, including newly introduced Resolve failures. High confidence.**  
   [mutate.go:78](C:/Dev/QNAPFileManager/internal/fsops/mutate.go:78) and line 93 return errors containing canonical relative paths. [routes_mutate.go:344](C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:344) exposes them unchanged. Example: `/alias → /private/hidden`; resolving `/alias/missing` can return `private/hidden/missing` in `detail`. Worker `req.Path` does not sanitize `Message`: [codec.go:60](C:/Dev/QNAPFileManager/internal/wproto/codec.go:60). Batch resolution failures also copy this into audit Detail at line 831.

   Successful-resolution redaction is incomplete too: delete maps only the complete endpoint, while an `openat` failure can name an ancestor. The unrestricted replacements at [routes_mutate.go:178](C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:178) can rewrite their own output: mapping `/real → /tmp/real` subsequently replaces relative `real`, producing `/tmp/tmp/real`. Finally, “path-free” warnings still contain `/proc` and `/sys`: [guard.go:328](C:/Dev/QNAPFileManager/internal/guard/guard.go:328).  
   **Minimal fix:** return structured errno/code and render requested paths explicitly; remove arbitrary error-string substitution and filesystem paths from warning reasons.

3. **P2 — Overwrite destination protection still has the round-3 ENOENT gap. High confidence.**  
   [routes_mutate.go:542](C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:542) skips destination `OpDelete` checks after `not_found`. A root rename with `overwrite:true` into `/dev/example` can replace an entry created after that Stat, despite `/dev` deletion policy. This is neither the accepted parent-symlink race (§2.0) nor the unsupported-`RENAME_NOREPLACE` fallback (§2.4).  
   **Minimal fix:** always check destination deletion policy when overwrite is requested.

4. **P2 — Audit timeout bounds individual calls, not batch requests or shutdown. High confidence.**  
   [audit.go:219](C:/Dev/QNAPFileManager/internal/audit/audit.go:219) correctly shares one two-second timer across admission and completion, with at most four admitted writer goroutines. No semaphore lock-cycle deadlock found. However, [audit.go:275](C:/Dev/QNAPFileManager/internal/audit/audit.go:275) waits indefinitely for the drain and admitted writers: a wedged write/fsync holding `drainMu` prevents `Close` returning.

   Additionally, [routes_mutate.go:824](C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:824) never checks request cancellation while processing results/intents. A prepared 1,000-item batch encountering a wedged sink can spend roughly 2,000 seconds retrying audit admission despite the HTTP context’s 15-second deadline.  
   **Minimal fix:** make audit waits context-aware, stop the batch on cancellation/audit outage, and give shutdown a bounded drain with explicit failure reporting.

5. **P2 — Partial batch milestones still say `result:"ok"`. High confidence.**  
   [routes_mutate.go:911](C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:911) sets `"error"` only when zero items succeed. One successful deletion and 100 failures produces an `"ok"` milestone, although Detail and the HTTP response say `"partial"`.  
   **Minimal fix:** persist `outcome` directly and classify partial outcomes appropriately in QuLog.

**Round-3 disposition**

| Finding | Status and evidence |
|---|---|
| Standard P1: protected-delete warning | **Complete.** Warnings populated at `routes_mutate.go:712,786`; protected/large challenges require acknowledgement at `actions.js:138–141`. Large warnings include totals. |
| Standard P2: rename selection | **Complete.** `list.js:135` disables mismatched focus; `actions.js:169` uses `selectedOne()`. Regression test passed. |
| Standard P2: file flush | **Complete for the reported missing-fsync defect.** `audit.go:336` calls `logfile.Sync`; `logfile.go:105` calls `File.Sync` and returns its error. |
| Adversarial 1: durable audit/lifecycle | **Partial.** Bounded admission, error propagation and intent refusal work (`audit.go:224`, `routes_mutate.go:246,877`); settings and lifecycle defects remain above. |
| Adversarial 2: static permission bypass | **Complete.** Resolve uses the principal’s worker (`workerpool.go:721`, `worker.go:510`); credentials are installed at `spawn_linux.go:152`. O_PATH traversal and parent-search checks enforce kernel permissions. |
| Adversarial 3: disclosure/oracle | **Partial.** Requested audit Path/Dst and ordinary confirmation text improved; disclosure remains above. |
| Adversarial 4: silent confirmation | **Complete**, as standard P1. |
| Adversarial 5: replacement protection | **Partial.** Indeterminate Stat now triggers policy checks; Linux fallback checks the retained destination descriptor and rejects non-ENOENT errors (`mutate_linux.go:81,108`). ENOENT policy gap remains. |
| Adversarial 6: false batch success | **Partial.** Per-item/HTTP outcomes and successful totals are corrected (`routes_mutate.go:884–917`); milestone status remains wrong. |

Worker resolution has the correct leaf semantics, no lexical error fallback, and canonical dispatch. Its remaining parent-resolution race fits accepted §2.0. I found no new privileged existence oracle or Resolve RPC on the hot read path. Temporary audit-open failures are retried (`logfile.go:68`); refusing unaudited mutations during an outage is appropriate.

**Overall verdict: not ready for supervised M1 write-path hardware testing on QTS/QuTS hero. Fix the settings race, disclosure, and overwrite-policy gap first.**