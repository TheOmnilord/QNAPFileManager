Windows tests and the three-target vet sweep pass, but the patch contains credential-revocation, jail-containment, transport, and resource-management defects. The production impersonation tests also never execute in the supplied CI workflow.

Full review comments:

- [P1] Replace workers when their credentials change — C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:502-506
  When a user's primary or supplementary groups change, session revalidation refreshes `sess.who`, but this lookup reuses the existing worker solely by UID. Its kernel credentials retain the old groups indefinitely while it remains active, allowing continued access through revoked memberships and denying newly granted access. Compare the requested credentials with the worker's credentials and retire mismatched workers before dispatching another operation.

- [P1] Finish partial stream writes without resending descriptors — C:/Dev/QNAPFileManager/internal/wproto/conn_linux.go:36-39
  On Linux, `WriteMsgUnix` can successfully write only part of a payload when it exceeds the socket's available send buffer; a supported 5,000-entry listing readily exceeds that buffer. Returning here abandons the remaining frame bytes, while the worker merely logs the error and leaves the connection open, causing timeouts or corrupting framing when another reply arrives. Keep the transport lock and write the remaining bytes without resending the ancillary data.

- [P1] Reject Windows traversal before joining the jail path — C:/Dev/QNAPFileManager/internal/fsx/root.go:60-64
  On Windows, `fsx.Clean` treats backslashes as filename characters, but `filepath.Join` subsequently treats them as separators. For example, with the development jail, `/..\..\PLAN.md` passes validation and maps to `C:\Dev\QNAPFileManager\PLAN.md`, outside the jail; listing and download endpoints accept the same input. Validate the native relative path and enforce containment before returning it, while preserving legitimate backslashes on Linux.

- [P1] Confine symlink traversal to the configured jail — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:87-88
  With `-jail` enabled, a directory symlink inside the jail pointing outside it is followed by this open. `List` can therefore enumerate the external directory, and `OpenRead` can download its children because `O_NOFOLLOW` protects only the final component. The `Root.API` check in `resolveLink` only suppresses a displayed path; it does not constrain access. Use race-safe, root-relative filesystem operations that reject escapes.

- [P2] Avoid blocking while opening a FIFO — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:258-262
  Requesting a readable FIFO with no writer blocks inside `os.OpenFile` before the regular-file check can reject it. Neither the HTTP timeout nor the pool timeout interrupts that syscall, so repeated requests can occupy all 64 worker slots and prevent further browsing. Open nonblocking on Linux and retain the descriptor-based type check; checking the pathname beforehand alone would remain racy.

- [P2] Count pending spawns against the worker limit — C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:570-572
  Concurrent first requests for different UIDs all pass this check before their workers finish spawning, because only `p.workers` is counted and reservations live separately in `p.spawning`. A local concurrency probe produced 22 workers with `Max: 1`. Include pending reservations in capacity accounting under the pool lock so simultaneous logins cannot exceed the configured process and memory limit.

- [P2] Charge failed startups to the restart budget — C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:544-548
  If a worker exits before completing its hello handshake, `spawn` returns an error and this branch performs no restart accounting. Because that worker never enters `p.workers`, the normal crash-accounting path cannot charge it either. Repeated requests can consequently launch failing processes without ever reaching the restart cooldown. Record startup and handshake failures against the UID's budget.

- [P2] Evict expired authentication-cache entries — C:/Dev/QNAPFileManager/internal/qtsauth/verifier.go:172-175
  Every distinct credential inserts an entry here, including failed authentication attempts, but expired entries are never removed unless that exact credential is explicitly invalidated. An unauthenticated caller can continually submit different `sid` values and permanently grow the root daemon's cache; normal session turnover also accumulates entries. Add expiration pruning and a bounded cache size rather than merely ignoring expired values during lookup.

- [P2] Avoid waiting on session locks while holding the global lock — C:/Dev/QNAPFileManager/internal/web/session.go:53-55
  A session holds its mutex while calling QTS verification and NSS identity resolution. Any concurrent request reaching this expiration sweep then waits for that session while holding `s.mu`, blocking authentication for every other user, including users with fresh cached sessions. Slow QTS or directory-service responses therefore stall the entire frontend. Perform expiration inspection without holding the global map lock across per-session waits.

- [P2] Align symlink file actions with the backend's open policy — C:/Dev/QNAPFileManager/internal/web/static/js/badges.js:3-3
  A symlink targeting a regular file is classified as readable here, enabling Open, View text, and Download. Those actions submit the symlink's own path, but Linux `OpenRead` deliberately uses `O_NOFOLLOW`, so all of them fail with `ELOOP`. Either resolve these actions to an explicitly supported target path or disable them and provide an appropriate target-navigation action.

- [P2] Account for the server's clamped page size — C:/Dev/QNAPFileManager/internal/web/static/js/list.js:21-24
  When the valid configuration `limits.listMax` is below 500, the server returns fewer entries than requested, but the UI still indexes and advances pages in blocks of 500. With a limit of 100, entries 100–499 are never requested and remain loading placeholders because page zero is already marked loaded. Negotiate the effective page size or fill each logical page using the actual number of returned entries.

- [P2] Pass the application logger into the production worker pool — C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:195-200
  The production constructor never supplies `Options.Logger`, so normalization replaces it with an `io.Discard` logger. Worker stdout and stderr, panic stacks, startup failures, and lifecycle diagnostics are consequently discarded even when the daemon was started with `-log`. Thread the configured application logger into the pool so production worker failures remain diagnosable.

- [P2] Execute the impersonation tests with Linux root privileges — C:/Dev/QNAPFileManager/.github/workflows/build.yml:42-42
  The Ubuntu test step runs as the unprivileged runner, so every real-process impersonation test guarded by `requireLinuxRoot` skips. There is no separate root job, and the packaging smoke test never authenticates or starts a worker, leaving the production credential boundary untested throughout CI. Add a privileged Linux test job and make packaging depend on it, as required by [CLAUDE.md:31–32](C:/Dev/QNAPFileManager/CLAUDE.md#L31-L32).
