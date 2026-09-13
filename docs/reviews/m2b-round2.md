# M2-B copy/move — review round 2 (2026-09-13, gpt-6-astra, effort high)

Round 1's eleven findings were fixed (verified descriptor-based source delete with a per-entry ledger; `fchownat
AT_EMPTY_PATH`; pinned symlinks/directories before chown; same-directory by held identity; failed verification never
publishes; ancestry refresh; destination mount check on merge; per-root space; `guard.Contains` at the route; pathB64
on paste). Round 2 adversarial: 7 findings. Normal: see below. Judgement:

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the source walk re-opens the root by pathname after the parent was held — a symlink swap of `/stage` copies the install directory's config out. | engine | **Accepted.** The walk starts from the held descriptor (`walkFrom`) or aborts at depth 0 on identity mismatch before any child is read. |
| 2 | P1: `createdByUs` for a directory checks only the owner uid; a pre-existing root-owned directory renamed over the fresh one gets chowned to the requested user. | engine | **Accepted.** Emptiness proof via an enumerable descriptor opened relative to the held O_PATH handle, as `leafProvenance`. |
| 3 | P1: the overwrite temp name can be unlinked and replaced during a long copy; the rename publishes the stranger's file, then the move deletes the source. | engine | **Accepted.** lstat-the-name vs fstat-the-fd immediately before `renameat`; mismatch fails the entry. The remaining window is a §2.4-class residual (no rename-by-fd). |
| 4 | P1: an equal-length in-place rewrite with `utimensat`-restored mtime matches the ledger (inode, size, mtime) and the new content is deleted — reproduced. | engine | **Accepted.** ctime joins the ledger: it moves on every write, utimensat, chmod and chown and cannot be set by an unprivileged user. |
| 5 | P1: renaming the fresh `/dst/a` into `/src/a/z` during the walk makes the copy recurse into its own output; only the container and its ancestry were refused. | engine | **Accepted.** The identity of every output directory created or adopted is refused when met by the source walk. |
| 6 | P2: a mount placed over a directory between mkdir and open is not checked because `created` suppresses the crossing check. | engine | **Accepted.** Every opened destination directory is checked. |
| 7 | P2: trimming the typed/picked destination loses a trailing-space directory name and bypasses the pathB64 fix. | UI | **Accepted.** Exact comparison with the picked spelling; no trimming. |

Normal review, round 2: 5 findings — #1/#2/#3 above (directory provenance, temp-name verification, walk from the
held descriptor) and #7 (whitespace) overlap; one new:

| 8 | P2: the OK button re-enables while the pre-flight request is pending (`paint()` on any edit), so a second click submits a duplicate transfer. | UI | **Accepted.** A pending flag gates both the button and `submit()`. |
