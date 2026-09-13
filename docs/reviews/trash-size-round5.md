# Trash size fix — review round 5 (2026-09-13, gpt-6-astra, effort high)

Round 4's five findings were fixed (unique `O_EXCL` temp per rewrite with a litter sweep, directory fsync after the
rename, `maxTrashMeta` on the replacement, non-crossed mounts mark the measurement incomplete, transient sidecar-read
errors propagate). Normal: 1 finding; adversarial: 2 (one overlap). Judgement:

| # | Finding | Judgement |
|---|---|---|
| 1 | P2: `isTrashMetaTmp` accepts any `meta.json.*.new`, so a uid-owned regular file `meta.json.backup.new` inside an entry would be unlinked by the litter sweep. | **Accepted.** The predicate validates the exact `<pid>-<8 hex>` shape. (The entry directory only ever holds `meta.json`, `item` and our own temporaries, so the exposure is theoretical, but strictness costs nothing.) |
| 2 | P2: the payload lstat in `invalidateTrashSize` returns nil on any error; a transient EMFILE/EIO skips the invalidation while the empty proceeds. | **Accepted.** Only not-found means "nothing to invalidate"; other errors follow the warn-and-continue path with `stale` set. |
