# M2-B copy/move — review round 1 (2026-09-13, gpt-6-astra, effort high)

Change under review: the M2-B stack against `docs/design/m2b-contract.md` — the engine (`internal/fsops/copy*.go`,
`fsid.go`), worker dispatch, `internal/web/routes_transfer.go`, and the UI (transfer dialog, tree picker, clipboard
keys). Normal review: 4 findings. Adversarial: 11 (4 overlap). Eleven distinct findings, all accepted.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the move's source delete re-walks the tree by pathname after the copy: content added or rewritten after its copy is deleted without ever reaching the destination (reproduced), and a root move can be redirected by a symlink swap of a parent into unlinking `/etc/passwd`. | engine | **Accepted.** Delete only entries whose lstat matches what was copied (identity, size, mtime), through the held descriptors, post-order; anything else is kept with a warning. |
| 2 | P1: `fchown` on an `O_PATH` directory fd is `EBADF` — every admin copy leaves directories root-owned; every root fallback move reports `owner_unset` and keeps its source. | engine | **Accepted.** `fchownat(fd, "", AT_EMPTY_PATH)`; the root-gated test must assert directory ownership. |
| 3 | P1: the recreated symlink is chowned by name; a sibling renamed over it gets chowned to the link's owner (root worker, non-sticky writable dir). | engine | **Accepted.** Pin with `O_PATH|O_NOFOLLOW`, prove S_IFLNK and creator ownership, then chown the fd. |
| 4 | P1: bind-mount alias defeats the lexical same-directory check; a move of `/alias/a` into `/real` with overwrite merges into itself then deletes both spellings. | engine | **Accepted.** Same-directory and dest-is-source decided by held-fd identity before placement. |
| 5 | P1: protected descendants under a source or destination root escape the root-only guard checks (merge into the install tree's config/log; firmware config warning bypassed; install tree copied out). | routes/guard | **Accepted.** Static containment predicate on the prefix rule table, checked at the route on both spellings (INV-1: the worker never sees the guard). |
| 6 | P1: a short copy (source truncated mid-copy) warns `changed` but still publishes the temp over the intact destination (reproduced). | engine | **Accepted.** Verification failure = failed transfer, temp removed, nothing published. |
| 7 | P1: the into-itself ancestry snapshot predates a 30 s scan; moving the destination into the source meanwhile makes the walk copy its own output. | engine | **Accepted.** Re-collect from the held destination fd before the first write; refuse the destination's identity during the walk. |
| 8 | P1: merging adopts an existing destination directory that is a mount point without a mount check, writing into a nested dataset/bind/network mount with CrossMounts off. | engine | **Accepted.** Mount identity of every adopted destination directory compared with its held parent; crossing refused. |
| 9 | P2: the free-space requirement for a mixed move counts rename-only roots. | engine | **Accepted.** Per-root check at the moment a root falls back to copying. |
| 10 | P2: Ctrl+V passes only the lossy display path, dropping `pathB64`. | UI | **Accepted.** The full path reference rides through the dialog. |
| 11 | (normal #2 = adversarial #6, normal #1 = #1/#4, normal #3 = #8, normal #4 = #10) | — | overlaps |
