Windows tests, JavaScript path tests, and the three-target vet sweep passed, but timeout enforcement, symlink resolution, session cleanup, and pseudo-file downloads still contain defects. Linux runtime behavior was not executed locally.

Full review comments:

- [P2] Bound transport writes by the RPC deadline — C:/Dev/QNAPFileManager/internal/workerpool/client.go:361-366
  If a worker stops reading and its socket buffer fills, this synchronous write blocks before the context select is reached. Consequently, HTTP cancellation and CallTimeout cannot release the request or worker reservation; cancelRemote has the same blocking-write problem. A net.Pipe probe remained blocked after 150 ms despite a 10 ms timeout. Make transport writes deadline-aware and close the connection when an interrupted write leaves framing uncertain.

- [P2] Preserve unresolved components in absolute symlink targets — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:169-174
  When an absolute symlink target contains another symlink followed by `..`, lexical cleaning selects the wrong file. For example, `/a/jump/../marker` with `/a/jump -> /b/sub` should resolve to `/b/marker`, but this code produces `/a/marker`. This affects directory browsing and the resolved target used by viewer/download actions. Preserve the target components until symlinks have been resolved, including through the subsequent Root.API conversion.

- [P2] Discard pending properties responses after sign-out — C:/Dev/QNAPFileManager/internal/web/static/js/viewer.js:24-25
  If sign-out or session expiry occurs while the stat request is pending, signInNotice clears the sensitive UI, but this continuation subsequently restores the previous user's metadata and reopens the dialog. This was reproducible with a delayed response while state.session was null. Capture the session/generation before requesting and discard the response if it has changed.

- [P2] Support downloading regular pseudo-files without SEEK_END — C:/Dev/QNAPFileManager/internal/web/browse.go:199-199
  Readable procfs files such as `/proc/meminfo` pass OpenRead's regular-file check, but do not support the SEEK_END operation ServeContent uses to determine length. Download therefore returns HTTP 500 even though text preview can read the same file; other pseudo-files can report misleading lengths. Provide a streaming download path for these files rather than requiring seek-based sizing.

- [P2] Gate packaging on real ZFS integration checks — C:/Dev/QNAPFileManager/.github/workflows/build.yml:102-103
  Packaging currently depends only on ordinary Linux, Windows, and impersonation tests. No job creates a ZFS pool or exercises real dataset boundaries, so synthetic mountinfo tests are the only verification of the hero-specific platform behavior. Add a file-backed ZFS integration job and require it before packaging, as mandated by [CLAUDE.md:31–32](C:/Dev/QNAPFileManager/CLAUDE.md#L31-L32).
