The patch still mishandles symlink resolution, search-only jail roots, and SID-bootstrap retries. Windows Go tests, JavaScript tests, and cross-target vet checks passed; Linux runtime behavior could not be tested locally.

Full review comments:

- [P2] Preserve directory checks when resolving symlink targets — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:288-292
  On Linux, an absolute symlink targeting `/some/file/.` loses its dot component here and resolves to the regular file, although the kernel returns ENOTDIR. Likewise, `/some/locked/.` can bypass the search-permission check and be advertised as a usable target. Preserve these components through `linkParts`, including its subsequent lexical normalization, so resolution performs the required checks. This follows [CLAUDE.md's INV-2](C:/Dev/QNAPFileManager/CLAUDE.md#L40-L41).

- [P2] Avoid requiring read permission on the jail root — C:/Dev/QNAPFileManager/internal/fsx/root.go:52-54
  When production uses `-jail` on a directory where the user has search permission but no read permission, every filesystem operation fails here: Go's `os.OpenRoot` opens the directory read-only. A readable known child should remain downloadable, and readable subdirectories should remain browsable, but the later O_PATH traversal never runs. Acquire the Linux confinement handle without requiring directory-listing permission, consistent with [CLAUDE.md's INV-2](C:/Dev/QNAPFileManager/CLAUDE.md#L40-L41).

- [P2] Retain the bootstrap SID until authentication succeeds — C:/Dev/QNAPFileManager/internal/web/static/js/app.js:34-37
  When the UI is opened with `?sid=...` without QTS cookies, a transient network error, 503, or authentication timeout consumes the only credential before a session cookie is established. Clicking Retry then sends an anonymous request because `bootstrapQuery` is already empty, despite the SID remaining in the document URL. Clear the bootstrap credential only after successful authentication so Retry can recover.
