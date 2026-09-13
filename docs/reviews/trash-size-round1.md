# Trash size fix — review round 1 (2026-09-13, gpt-6-astra, effort high)

Change under review: a trashed directory's tree size (bytes + entry count) is measured at trash time with the
bounded pre-scan and recorded in the sidecar; -1 means unknown; the panel shows folder sizes; Empty Trash sums only
known sizes and says how many are unknown; sidecars from earlier builds (no `files` field) present as unknown.

Normal review: 1 finding. Adversarial review: 4 findings (the first is the normal review's). Fable's judgement:

| # | Finding | Judgement |
|---|---|---|
| 1 | Incomplete walks recorded as known: `scanTrees(quiet=true)` discards per-item warnings and swallows root errors, so an unreadable subtree or a >256-deep payload (reproduced: size=0, files=257 persisted as known) yields an understated known size. | **Accepted.** The scan reports incompleteness; trash records -1/-1 on any warning. |
| 2 | The scanned directory may not be the renamed payload: rename-aside between the lstat, the by-name scan and the by-name `renameInto` persists an unrelated tree's totals. | **Accepted.** Identity (dev, ino) pinned across lstat → scan root → renamed payload; disagreement rewrites the sidecar as unknown. Same class as residual §2.4, but cheap to close here. |
| 3 | A hung hard-mounted NFS filesystem under the folder stalls the new scan; the old plain rename failed fast (EBUSY). The walker opens/lstats a child before judging the mount boundary. | **Accepted**, fixed at the walker so Size and the delete pre-scan benefit: consult the mount table by name before touching a child known to be a mount point that could not be crossed anyway; the fd-identity check stays as the fail-closed second line. |
| 4 | int64 overflow: sparse 1<<62 files with four hard links wrap the accumulator to a known zero. | **Accepted.** Checked accumulation; overflow is unknown. |

Implementer's own notes accepted without change: `TrashItem.Files` uses `json:"f"` (`"n"` was already `Name`); the
scan is silent (per-item counters would walk the job's progress backwards); `JobResult.Bytes` of a trash job is
unchanged; the felt behaviour of trashing a very large folder now includes up to 30 s of scanning before the rename,
cancellable and leaving nothing behind.
