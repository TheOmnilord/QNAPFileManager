Reviewed `a49bd78` read-only. Six selection/settings tests passed; no Go builds or hardware tests run.

**High-confidence findings, ordered by severity:**

1. **P1 — Durable intent is still not guaranteed; new unbounded background work.** [audit.go:181](/C:/Dev/QNAPFileManager/internal/audit/audit.go:181) starts a goroutine for every `WriteSync`, silently returns after two seconds, and returns no error. The sink ultimately calls `File.Write`, without `Sync` ([logfile.go:85](/C:/Dev/QNAPFileManager/internal/logfile/logfile.go:85)). Disk-full errors reach counters/stderr, but dispatch continues at [routes_mutate.go:349](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:349). A wedged sink accumulates unlimited goroutines; `Close` does not explicitly drain these writers. Settings becomes writable before its audit call.

   **Minimal fix:** bounded admission, acknowledged write-plus-fsync, propagated timeout/error, and refuse dispatch/toggle without successful durable intent. Join admitted writers during shutdown. No intrinsic lock-cycle deadlock found; the background work is unbounded.

2. **P1 — Canonical dispatch introduces a static requested-path permission bypass.** Root resolves `/private/link`, where `/private` is unsearchable by the user and `link` points into a user-writable directory. Mkdir dispatches the resolved directory directly ([routes_mutate.go:337](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:337), line 353); rename/delete do likewise. The worker never traverses `/private`. Delete’s failed requested-path Stat is ignored. Target permissions still apply, but the requested operation’s kernel traversal checks are skipped. This is **not** the accepted check-to-dispatch race.

   **Minimal fix:** resolve/prepare the requested operation in the user worker, then guard and execute that preparation.

3. **P2 — Resolved-path disclosure remains; the previous oracle fix is partial.** Rename’s substitutions contain full endpoints only ([routes_mutate.go:424](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:424)), while its guard checks the resolved destination **parent** at line 440. Renaming into `/alias/new`, with `/alias → /etc/config`, can expose `/etc/config` in the confirmation message and audit Detail. Worker errors also contain relative paths such as `etc/config/file`, which absolute-string replacement misses ([mutate_linux.go:100](/C:/Dev/QNAPFileManager/internal/fsops/mutate_linux.go:100)).

   Root still traverses before jail containment checking ([resolve.go:60](/C:/Dev/QNAPFileManager/internal/web/resolve.go:60)); distinguishable guard verdicts remain an oracle even with redacted text.

   **Minimal fix:** structured errors rendered using requested paths; worker-side contained resolution before policy disclosure. Audit Path/Dst use requested spellings, and current summaries contain no resolved paths.

4. **P2 — Protected-delete confirmation is silently approved.** Single and batch summaries populate counts/bytes but no warnings ([routes_mutate.go:573](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:573), line 634). [actions.js:130](/C:/Dev/QNAPFileManager/internal/web/static/js/actions.js:130) automatically redeems any challenge without warnings. Thus `/etc/config/file` receives only the initial generic delete dialog; the server’s protected-path explanation is suppressed. Scale details are suppressed too.

   **Minimal fix:** explicitly distinguish ordinary permanent-delete challenges from protected/large-delete challenges and display the latter’s reasons and totals.

5. **P2 — Rename replacement protection remains conditional; fallback checks can inspect the wrong directory.** [routes_mutate.go:450](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:450) skips destination deletion policy on ENOENT. A destination appearing afterward—e.g. `/dev/example`, where creation and deletion policies differ—can be overwritten without its deletion verdict.

   Separately, [mutate_linux.go:74](/C:/Dev/QNAPFileManager/internal/fsops/mutate_linux.go:74) re-walks the destination pathname despite already holding `toDir`, and treats every Stat error as absence. Moving that directory can make the check inspect a different namespace while rename uses the retained descriptor.

   **Minimal fix:** always guard overwrite destinations; fallback lstat relative to `toDir`, continuing only on ENOENT. The subsequent destination-creation TOCTOU still exists and is explicitly accepted by PLAN §2.4.

6. **P2 — Large-batch audit can falsely report success.** [routes_mutate.go:708](/C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:708) emits `result:"ok"` with all requested totals even if every deletion failed or was denied.

   **Minimal fix:** distinguish attempted/succeeded/failed totals and report partial/error outcomes.

Round-2 disposition:

| Finding | Status and evidence |
|---|---|
| Standard P1 / A1 | **Partial:** both spellings checked; canonical dispatch implemented; finding 2 remains beyond accepted §2.0. |
| Standard destination P2 / A2 | **Partial:** destination-entry creation checks present at `routes_mutate.go:441`; overwrite gap remains above. |
| Standard selection P2 | **Complete:** `list.js:27–39` fetches every missing selected page and rejects incomplete results; `actions.js:154` aborts on error. |
| Standard audit-totals P2 | **Partial:** totals/milestones added; findings 1 and 6 remain. |
| A3 | **Complete:** POST-only mutations and read-only HEAD settings dispatch, `server.go:114,295`. |
| A4 | **Complete:** canonical encoding, decoded-byte replay key, locked redemption, `confirm.go:101,120`. |
| A5 | **Complete:** ordered endpoint/overwrite binding, `routes_mutate.go:480`. |
| A6 | **Complete:** parents rejected; parent/entry checks, `routes_mutate.go:320,340`. |
| A7 | **Complete** for ignored verdicts: batch redemption and per-item denials enforced, `routes_mutate.go:635,663`. |
| A8 | **Complete:** persistence/application serialized, `routes_admin.go:66`. |
| A9 | **Partial:** every delete requires an exact requested-path/multiset token; protected UI confirmation regresses. Client-only settings confirmation is explicitly acceptable under revised decision 7. |
| A10 | **Partial; durability claim wrong:** confirmation failures audited; authentication auditing still excludes failed GET bootstrap and specialized error branches, `server.go:203–235`. |
| New round-2 oracle | **Partial:** finding 3. |
| New round-2 CSRF race | **Complete:** locked snapshot, `routes_mutate.go:88`; handlers receive immutable snapshots, `session.go:358`. |

No ordinary-operation over-confirmation, startup canonicalization error, supported-architecture renameat2 defect, or token loop found. Flag `1`, syscall numbers `316/276`, architecture selection, and ENOSYS/EINVAL fallback are correct. `runMutation` retries only once.

**Overall: not ready for a supervised M1 write-path hardware test. Fix the durability, permission-resolution, disclosure, and confirmation defects first.**