# Trash size fix — review round 4 (2026-09-13, gpt-6-astra, effort high)

Round 3's two findings were fixed (`describes` rejects a nil half; a directory entry's known size is invalidated to
unknown before the first removal of an empty, warn-and-continue if the rewrite fails — an empty must work on a full
volume). Normal: 1 finding; adversarial: 5 (one overlap). Judgement:

| # | Finding | Judgement |
|---|---|---|
| 1 | P1: the rewrite's temp name is fixed (`meta.json.new`); two concurrent empties for one uid can rename each other's unwritten temp over `meta.json`, publishing malformed metadata and, after a crash, hiding a surviving payload from listing and restore. | **Accepted.** Unique per-invocation temp, `O_EXCL`, each invocation cleans only its own file. |
| 2 | P2: fsync of the temp does not durably publish the rename; without journal ordering a power loss can keep later removals and lose the invalidation. | **Accepted.** fsync the held entry directory after the rename, before the first removal; failure warns and continues. |
| 3 | P2: the re-marshalled sidecar can exceed `maxTrashMeta` (escaping growth, -1 replacing digits), after which every reader rejects the surviving entry. | **Accepted.** Length check before publication; oversized keeps the readable original with the rewrite-failure warning. |
| 4 | P2: a non-crossed local/bind mount beneath the tree is visited `Mount=true` without a warning, so `incomplete` stays false while the files hidden under the mount move with the rename unmeasured. | **Accepted.** A non-descended `Mount=true` item marks the scan incomplete (trash-only consumer). The comment claiming the kernel refuses to rename an ancestor of a mount point is to be corrected: only the mount point itself is `EBUSY`. |
| 5 | P2: a transient read error (EMFILE/EIO) during invalidation returns nil, so the empty proceeds with the old known total intact. | **Accepted.** Malformed → nothing to correct; transient → warn-and-continue with the "could not be updated" note. |
