The settings rollback can override a newer safety decision, and slow QuLog mirroring incorrectly blocks otherwise durable mutations. The newly introduced installation read protections are also not enforced.

Full review comments:

- [P1] Serialize audit failure rollback with other settings changes — C:/Dev/QNAPFileManager/internal/web/routes_admin.go:103-110
  When two administrator sessions change read-only mode concurrently, an audit failure can undo a newer successful change. `cfgMu` is released before `WriteSync`, so another request can persist and acknowledge its setting before this request restores the stale `prevVal`. In particular, a failed request can turn writes back on after another administrator successfully enabled read-only. Serialize the entire settings transaction, including auditing and rollback, or condition rollback on a settings revision.

- [P2] Complete durable writes independently of QuLog mirroring — C:/Dev/QNAPFileManager/internal/audit/audit.go:341-345
  With QuLog enabled, a `log_tool` invocation taking longer than two seconds makes `WriteSync` return `ErrSyncTimeout` even though the audit record has already been written and synced. `qnap.Log` permits ten seconds, and this call holds `drainMu`, so a slow best-effort mirror also prevents subsequent mutation intents from completing. Settings changes are consequently rolled back and mutations refused despite a healthy audit file. Acknowledge durable persistence before mirroring, and move the bounded mirror work outside the sink lock.

- [P2] Enforce the new read protections at read endpoints — C:/Dev/QNAPFileManager/internal/guard/rules.go:64-65
  These `OpRead` and `OpTraverse` denials are never consulted by the listing, stat, text, or download handlers: those handlers still dispatch directly to the backend. Consequently an administrator's root worker can download the installation configuration and browse the audit logs through ordinary filesystem endpoints despite the newly declared protection. Wire read-side authorization into those handlers, checking both requested and resolved paths so aliases cannot bypass it.
