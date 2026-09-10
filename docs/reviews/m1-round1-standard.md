The mutation routes contain actionable safety-policy bypasses involving symlinks, rename replacements, intermediate directory creation, and read-only transitions. Concurrent settings updates can also leave persisted and active safety settings inconsistent.

Full review comments:

- [P1] Check resolved paths before authorizing mutations — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:197-198
  When a parent path contains a symlink, the guard checks the supplied spelling but the worker resolves it before mutating. For example, an alias pointing to `/etc/config` allows deleting `alias/file` without confirmation; an alias to the installation directory similarly bypasses its write prohibition. Obtain the resolved parent through the worker and apply the guard to that location for mkdir, rename, and delete, while preserving final-component symlink semantics.

- [P1] Guard the rename destination itself before replacing it — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:266-271
  With `overwrite:true`, rename removes the existing destination, but only its parent receives an `OpCreate` check. A writable session can therefore rename an ordinary file over a device node such as `/dev/null`: creation under `/dev` is allowed even though deleting or writing the node is explicitly forbidden. Check the destination's replacement policy as well as creation in its parent before dispatch.

- [P1] Honor read-only errors during batch deletion — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:413-418
  If an administrator enables read-only mode while a batch is running, `Check` returns `ErrReadOnly`, but this loop ignores it and continues deleting. Worse, read-only short-circuits protected-path checks, so a later protected item can also reach the worker. Handle read-only and other denial results explicitly before each dispatch rather than accepting every error except `ErrProtected`.

- [P2] Check intermediate creations when parents is enabled — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:197-202
  A request with `dir:"/share/new"`, `name:"child"`, and `parents:true` passes the guard because `/share/new` is not the exact `/share` path. The worker then creates `/share/new` directly on the RAM disk, bypassing the explicit prohibition in [CLAUDE.md:57](C:/Dev/QNAPFileManager/CLAUDE.md#L57). Guard every intermediate creation, or reject `parents` until those checks are supported.

- [P2] Keep the live settings update inside the persistence lock — C:/Dev/QNAPFileManager/internal/web/routes_admin.go:64-71
  Concurrent settings requests can save opposite values in order but apply their guard updates in reverse order because `cfgMu` is released before `SetReadOnly`. The final config can then say read-only is enabled while the running daemon permits writes. Hold the same lock through both persistence and the live guard update so their ordering remains consistent.
