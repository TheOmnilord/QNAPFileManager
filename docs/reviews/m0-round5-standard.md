The patch leaves cancellability, Linux directory-permission, and authentication-recovery defects. Existing Go and JavaScript tests and the three-target vet sweep passed, but focused probes reproduced the blocked preview and JSON-only expired-session page; Linux runtime testing was unavailable.

Full review comments:

- [P2] Make text preview reads honor request cancellation — C:/Dev/QNAPFileManager/internal/web/browse.go:287-289
  For readable, regular-mode pseudo-files such as `trace_pipe`, this read can block indefinitely waiting for data or EOF. The request's 15-second deadline does not interrupt `os.File.Read`, and the deferred close cannot run until the read returns. Closing the viewer therefore leaves a handler and descriptor behind. Unlike downloads, previews never prepare a cancellable stream; add equivalent cancellation handling or reject streaming pseudo-files.

- [P2] Traverse listing ancestors without requiring read permission — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:375-375
  On Linux, listing `/outer/child` fails when `outer` is search-only (0111) and `child` is readable/searchable (0755), although the kernel permits that listing. Go's `os.Root.OpenFile` opens intermediate directories with `O_RDONLY`, reintroducing the extra permission requirement already avoided by the `walkOPath` helpers for stat and downloads. Walk ancestors with `O_PATH` and require read access only on the listed directory, preserving [CLAUDE.md:40–41](C:/Dev/QNAPFileManager/CLAUDE.md#L40-L41)'s INV-2.

- [P2] Keep the application shell accessible after authentication fails — C:/Dev/QNAPFileManager/internal/web/server.go:121-124
  Opening the app with an expired session or after switching QTS users returns a JSON 401 for `/` before reaching the static handler. Consequently, the HTML and JavaScript containing the sign-in notice and Retry button never load; the desktop window displays raw JSON instead. Keep the public shell and assets available on authentication failure while retaining authentication enforcement for API requests.
