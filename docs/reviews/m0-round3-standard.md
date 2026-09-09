Existing Windows tests, JavaScript tests, and the three-target vet sweep pass, but focused probes reproduce deadline, shutdown, and HEAD-stream defects. The patch also introduces desktop interaction and Linux permission-semantics problems.

Full review comments:

- [P2] Preserve row elements during double-click selection — C:/Dev/QNAPFileManager/internal/web/static/js/list.js:100-101
  On desktop, the first click calls `select()`, which calls `render()` and replaces every row, removing the element whose double-click handler should open the item. The second click therefore targets a different element, breaking normal double-click opening of folders and files. Update selection on existing rows rather than replacing the click target.

- [P2] Open the parent directory without requiring read permission — C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:41-43
  On Linux, a user can read a known file inside a searchable but non-readable directory, such as a root-owned directory with mode 0711. This extra `O_RDONLY` directory open instead returns EACCES before the file is opened, making downloads and previews reject otherwise accessible files. Use a search-only/O_PATH parent handle and verify with real Linux credentials, following the permission-test guidance in [CLAUDE.md:31–32](C:/Dev/QNAPFileManager/CLAUDE.md#L31-L32).

- [P2] Include mutex acquisition in the transport write deadline — C:/Dev/QNAPFileManager/internal/wproto/transport.go:93-96
  When concurrent RPCs share a transport, `WriteWithin` waits unconditionally for the mutex and then starts a fresh timeout, excluding the entire queueing delay. Consequently, canceled or expired calls can still send requests after their deadline. A probe of the equivalent stream implementation completed a 20 ms write successfully after approximately 155 ms of contention. Bound lock acquisition and retain the original absolute deadline in both implementations.

- [P2] Wait for pending worker spawns during shutdown — C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:341-345
  If shutdown overlaps worker creation or its hello handshake, that worker is represented only in `p.spawning`, so neither collection includes it. `Shutdown` can therefore return success while the worker remains alive; cleanup occurs only after `spawn` returns and `get` notices `p.closed`. A concurrent-spawn probe reproduces this. Track and cancel pending spawns, then wait for their processes to exit within the shutdown context.

- [P2] Return streaming download headers without reading on HEAD — C:/Dev/QNAPFileManager/internal/web/browse.go:216-221
  A HEAD request for a zero-size or otherwise unseekable pseudo-file still enters `io.Copy`. Although net/http suppresses response bytes, it does not prevent these reads, so a headers-only request can consume the stream and retain its handler and descriptor indefinitely while awaiting data. A blocked-stream probe reproduces this. Return after writing headers for HEAD, matching the ordinary-file `ServeContent` behavior.
