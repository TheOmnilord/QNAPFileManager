**Adopt per-session credential-dropped workers, QTS-only authentication, and same-origin desktop integration.** These requirements supersede the plan’s separate login, admin-only access, new-tab default, per-volume trash, and POSIX-only ACL detection. QTS integration and real-NAS validation belong in M0.

**1. Impersonation: use a worker process per authenticated session**

Keep the root daemon as an authentication, identity-resolution, and worker supervisor. Re-exec the static Go binary in worker mode using:

```go
SysProcAttr: &syscall.SysProcAttr{
    Credential: &syscall.Credential{
        Uid: uid, Gid: gid, Groups: groups,
        NoSetGroups: false,
    },
}
```

Go applies supplementary groups, GID, then UID before executing the child; cgo is unnecessary. Supply the complete group list explicitly, including clearing inherited groups when appropriate. Verify the worker’s real/effective/saved IDs and capabilities before accepting requests. [Go implementation](https://go.googlesource.com/go/+/ae43bdc3e3f87f8ba05ba12a17104ddbb0e6b30c/src/syscall/exec_linux.go)

Use an inherited Unix socketpair for bounded, typed RPC. Bind each worker permanently to a validated session, canonical principal, credential snapshot, and privilege mode. Never accept UID/groups from browser requests. Cap workers and concurrent jobs; expire idle workers and terminate them when authentication or membership changes.

**Every user filesystem operation belongs inside the worker**, including listings, previews, searches, metadata, trash, archive extraction, temporary-file creation, and final rename. The supervisor must not retry permission failures as root.

`SCM_RIGHTS` is useful, but passing a descriptor transfers an already-open file capability; it does not impersonate the sender. Prefer passing transfer pipes/socket endpoints so workers perform file reads and writes themselves. Never root-open a target and pass it downward: that defeats permission checks at open. If workers pass file descriptors upward for optimized streaming, document that as a relaxation of the literal “every operation runs as user” requirement. [Linux descriptor semantics](https://man7.org/linux/man-pages/man2/open.2.html)

| Alternative | Opinion |
|---|---|
| Per-session worker | Best default: amortizes process startup across interactive browsing; clean credential boundary. |
| Per-job process | Useful for large transfers/extraction and stronger cancellation isolation; excessive overhead for every small UI request. |
| In-process `setresuid`/`setfsuid` | Reject: process/thread credential interactions make concurrent request isolation fragile. `LockOSThread` alone is insufficient; Go’s credential wrappers can change all runtime threads. [Go source](https://go.dev/src/syscall/syscall_linux.go) |

Admins should normally use their own identity, with explicit root mode creating a separate worker. Audit both the QTS actor and effective Linux identity.

**2. Resolve identities through the NAS’s actual account mapping**

First establish **which user owns the validated session**. Tailscale’s SID branch validates `sid` alone, then returns the supplied `NAS_USER` cookie. That code does not establish a trustworthy SID-to-username binding for impersonation. **UNVERIFIED:** whether `authLogin.cgi` exposes a canonical authenticated username, or another supported endpoint can establish that binding. Block impersonation until verified; test mismatched cookies deliberately. Also verify qtoken/user binding and domain-name normalization. [Tailscale source](https://raw.githubusercontent.com/tailscale/tailscale/main/client/web/qnap.go)

For local-only accounts, parse authoritative passwd/group files, including primary and supplementary membership. Pure-Go `os/user` reads `/etc/passwd` and `/etc/group`; it does not provide general NSS/domain resolution. [Go documentation](https://pkg.go.dev/os/user)

For domain users, prefer NAS-installed, NSS-aware `getent passwd` and `id -u/-g/-G` helpers. **UNVERIFIED:** available paths, implementations, NSS support, and nested-group completeness on each firmware. Invoke fixed executable paths with argument arrays, timeouts, bounded output, and option-injection protection.

Where NSS helpers are inadequate, use the installed winbind tooling for canonical identity, UID/GID mapping, and group resolution. `wbinfo --user-groups` returns domain UNIX group IDs, but local supplementary memberships still need inclusion. Never derive UNIX IDs arithmetically from AD RIDs. [Samba documentation](https://www.samba.org/samba/docs/current/man-html/wbinfo.1.html)

This keeps the Go binary cgo-free while relying on NAS-native identity services. Fail closed on incomplete resolution; never silently use primary-group-only credentials. Cache briefly and recreate workers when the credential snapshot changes.

**3. QuTS hero requires different filesystem semantics**

- **Dataset boundaries:** Design around one ZFS dataset per shared folder: shares in the same pool can have different `st_dev`, so cross-share rename returns `EXDEV`. **UNVERIFIED:** exact mappings and exceptions across supported firmware. Discover mounts and share aliases; avoid `CACHEDEV*_DATA` assumptions. Use mount information alongside device IDs because bind mounts can share `st_dev`.
- **Moves:** Cross-dataset moves are copy-then-delete jobs, not atomic renames. Copy to a destination temporary name, complete required metadata and durability steps, then publish; delete source only after success. Report partial outcomes. Never silently lose ACLs during a move.
- **Trash:** Replace per-volume trash with private per-user trash within each share/dataset. Same-device rename remains required, and ordinary user permissions must permit it. **UNVERIFIED:** whether suitable trash directories can be provisioned without changing share ACL inheritance. Otherwise offer explicit permanent deletion; never elevate to make trash work.
- **RichACL:** QNAP confirms QuTS hero uses RichACLs that do not fully map to POSIX ACLs. Detect separately from POSIX access/default ACLs; absent POSIX xattrs do not mean “no ACL.” `system.richacl` is a candidate, but the exact QNAP xattr name, encoding, and tools are **UNVERIFIED**. Let the kernel enforce access. Disable misleading chmod controls on RichACL objects until their effects on allow/deny entries, masks, and inheritance are tested. [QNAP explanation](https://www.qnap.com/en/how-to/faq/article/why-cant-i-access-a-quts-hero-shared-folder-from-linux-after-i-create-the-folder-via-nfs)
- **Snapshots/recycle:** Exclude `.zfs` from ordinary recursion and trash operations; hidden snapshot directories are not an access-control boundary. Provide read-only snapshot browsing separately after validation. Protect `@Recycle`; the supplied research identifies QNAP-owned restore metadata, whose exact behavior remains **UNVERIFIED**. [OpenZFS properties](https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html)

**4. Same-origin proxy is the primary deployment**

Use `QPKG_USE_PROXY="1"`, a dedicated `QPKG_PROXY_PATH`, and `QPKG_DESKTOP_APP="1"` with a loopback-only backend. QDK documents these switches, but their generated routing needs testing. [QDK template](https://github.com/qnap-dev/QDK/blob/master/shared/template/qpkg.cfg)

An own-port UI is a different origin even when cookies accompany it. Secure cookies, framing, TLS, and origin checks make it unsuitable as the primary native experience.

**UNVERIFIED on real QTS and hero:** tile iframe URL; cookie scope; prefix rewriting; redirects/assets; framing headers; HTTPS enforcement; upload limits/buffering; Range downloads; SSE timeouts; logout expiry; non-admin tile visibility.

Validate sessions against a configured local QTS endpoint, never an arbitrary request-derived host. Retain CSRF tokens and origin checks.

**5. Highest risks and release gates**

1. **Session/user misbinding:** potentially grants another user’s or root access.
2. **Stale groups/session revocation:** workers and open descriptors retain authority; require bounded lifetimes and defined cancellation behavior.
3. **Kernel versus QTS policy:** SMB share restrictions/application privileges may exceed kernel ACLs. Their required equivalence is **UNVERIFIED**.
4. **Root confused-deputy and path races:** keep target operations in workers; use descriptor-relative traversal and protect aliases, mounts, and symlinks.
5. **Metadata loss and resource exhaustion:** RichACL moves, snapshot-retained space, quotas, worker counts, and transfer limits need real-NAS tests.

Windows fake-root tests cannot validate these boundaries. Require Linux credential tests and QTS/hero tests with local users, domain groups, explicit ACL denies, expired sessions, and cross-share moves before v1.

Codex session ID: 01a0868d-8925-75a0-a05c-58361619b01d
Resume in Codex: codex resume 01a0868d-8925-75a0-a05c-58361619b01d
