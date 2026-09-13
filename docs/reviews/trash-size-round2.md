# Trash size fix — review round 2 (2026-09-13, gpt-6-astra, effort high)

Round 1's four findings were fixed (scan incompleteness flag; three-way identity pin with an atomic sidecar rewrite
to unknown; a table-first prefilter that skips Network mounts the walk may not cross, without touching them; checked
byte accumulation). Round 2 reviewed the fixes. Normal: 2 findings; adversarial: 4 (two overlap). Judgement:

| # | Finding | Judgement |
|---|---|---|
| 1 | The scan root's identity is the Depth-0 `WalkItem.Info`, taken from a pathname lstat BEFORE the walker opens the root: swap A→B between stat and open, restore A before the rename, and the persisted totals are B's while all three identities say A. A FileInfo snapshot after the scan's fd closes also cannot pin the inode against unlink + dev/ino reuse. | **Accepted.** The walker records the root identity from the fd it opened; `trashOne` holds its own `O_PATH` descriptor to the item across scan and rename as the reference identity. |
| 2 | `refusedByTable` goes through `normalizePath` (backslash→slash, Clean): a Linux file literally named `..\export` under `/tree` is skipped as the `/export` NFS mount (a recursive delete leaves it behind), and a real mount with a backslash in its name never matches its key. | **Accepted.** Byte-preserving literal lookup for this caller. |
| 3 | The Empty Trash summary sums known sizes unchecked; two 5 EiB trees wrap negative into the summary, `m.bytes` and the audit line. | **Accepted.** Checked accumulation; overflow disclosed. |
| 4 | An overflow-capped scan ends the whole `Size` job, which ignores `res.capped` and reports the truncated total as complete. | **Accepted** (round 1's "negligible" was wrong once the cap ends the scan early). `Size` warns `capped`. |

Implementer judgement calls from round 1, confirmed: the prefilter is narrowed to Network mounts (decision 9 says a
non-crossed local mount is still visited as an item, and only a network mount can block a syscall indefinitely);
the sidecar rewrite is temp + `renameOver` (an interrupted `O_TRUNC` rewrite would leave an unnameable, unrestorable
entry — the stray temp is the lesser residual, §2.4 class); a corrected size stays a visible `conflict` warning.
