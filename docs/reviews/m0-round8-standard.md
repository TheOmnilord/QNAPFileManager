Existing Windows Go tests, JavaScript tests, and cross-target vet checks passed, but focused probes reproduced identity-mapping and authentication-recovery defects. Symlink resolution also drops required directory semantics; Linux runtime tests were not executed locally.

Full review comments:

- [P1] Bind numeric NSS lookups to the authenticated username — C:/Dev/QNAPFileManager/internal/idmap/idmap.go:503-506
  For an authenticated numeric username absent from `/etc/passwd`, such as an LDAP user named `1000`, `getent passwd 1000` can perform a UID lookup and return another account, such as `alice:x:1000:...`. This code ignores the returned name and assigns Alice's UID/GID to the authenticated user; even a subsequent `id -G` failure still returns that identity successfully. Use a name-bound lookup or reject ambiguous numeric results before issuing worker credentials.

- [P2] Distinguish QTS outages from rejected credentials — C:/Dev/QNAPFileManager/internal/web/server.go:136-138
  When `authLogin.cgi` returns 503 or refuses the connection, verification produces `ErrBadResponse` or `ErrUnreachable`, but this falls through to HTTP 401. Revalidation also destroys the existing session for these errors. Consequently, `api.js` signs the user out and SID bootstrap discards its credential instead of performing transient retries. A probe confirmed that upstream 503 becomes frontend 401. Preserve the authentication state and return a transient failure without treating infrastructure errors as rejected credentials.

- [P2] Allow a fresh bootstrap SID to replace the old app session — C:/Dev/QNAPFileManager/internal/web/session.go:265-267
  Opening the app with a new valid query SID while an old `qfm_sid` cookie still identifies a stored session returns 401 here without validating the new SID. In the cookie-free QTS fallback, `sessionBootstrap` then clears that SID and Retry becomes anonymous, so a valid launch cannot authenticate. This also occurs when both SIDs belong to the same user. For safe bootstrap requests, discard the obsolete app session and validate the presented credential, or provide a retry response that preserves it.

- [P2] Preserve trailing-slash checks in symlink targets — C:/Dev/QNAPFileManager/internal/fsops/fsops.go:386-391
  On Linux, a symlink targeting `file/` is broken when `file` is regular: the kernel returns ENOTDIR. Trimming the separator here instead resolves it to `file`, so `StatFollow` succeeds and listings enable viewing/downloading an invalid link. Absolute targets lose the same constraint in `splitOSPath`. Preserve the directory-only requirement in both paths rather than erasing it, consistent with [CLAUDE.md's INV-2](C:/Dev/QNAPFileManager/CLAUDE.md#L40-L41).
