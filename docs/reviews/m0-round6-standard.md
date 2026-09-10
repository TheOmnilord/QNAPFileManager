The patch contains a Linux jail-confinement gap, incorrect symlink-resolution semantics, and a broken SID URL bootstrap. Windows tests, JavaScript tests, and the cross-target vet sweep passed; Linux runtime testing was unavailable.

Full review comments:

- [P2] Keep listing metadata lookups relative to the directory descriptor — C:/Dev/QNAPFileManager/internal/fsops/open_linux.go:312-314
  On Linux, this `os.NewFile` loses `os.Root`'s internal confinement marker, so `DirEntry.Info()` in `List` ordinarily calls `Lstat(osName + "/" + name)`. If the opened directory or an ancestor is replaced with a symlink, enumeration continues on the original descriptor while metadata comes from the replacement path—even outside `-jail`. This can disclose outside-file metadata and associate incorrect metadata with listed entries. Obtain entry metadata relative to the opened descriptor, for example through `File.Readdir` or an equivalent fd-relative stat.

- [P2] Preserve the kernel checks required by symlink dot components — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:125-126
  For a relative symlink targeting `file/.`, this branch discards the final dot and returns the regular file, although the kernel returns ENOTDIR. Similarly, `locked/.` succeeds in `StatFollow` when `locked` lacks search permission, where the kernel returns EACCES. Consequently, listings can advertise inaccessible or broken links as usable targets. Check the current directory's traversability and propagate any blocked-component error before discarding `.`; this preserves [CLAUDE.md's INV-2](C:/Dev/QNAPFileManager/CLAUDE.md#L40-L41).

- [P2] Forward the initial SID when establishing the browser session — C:/Dev/QNAPFileManager/internal/web/static/js/app.js:32-34
  Opening `/qnapfilemanager/?sid=<valid-token>` without QTS cookies never authenticates: the static handler bypasses authentication, and this fetch drops the document's query parameters. Thus the query-SID fallback described by `qtsauth.FromRequest` cannot bootstrap the UI, and Retry repeats the same anonymous request. Forward the initial SID to the session endpoint, then remove it from the browser URL after establishing the application cookie.
