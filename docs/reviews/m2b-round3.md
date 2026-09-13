# M2-B copy/move — review round 3 (2026-09-13, gpt-6-astra, effort high)

Round 2's eight findings were fixed (`walkFrom` on the held descriptor with an aborting `Opened`; directory
provenance with emptiness; `publish()` proves the name before `renameat`, also on the direct-create path; ctime in
the ledger; every output directory refused when met; crossing checked on created levels; no trimming; submit lock).

Normal review: 3 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: two hard links to one inode in a moved tree — the job's own unlink of the first changes the shared ctime, so the second link fails the ledger and the move is left incomplete. | engine | **Accepted.** Re-baseline the inode's expected ctime right after the job's own unlink (ledger keyed by identity, nlink recorded); two-syscall residual documented. |
| 2 | P2: an `<input>` strips CR/LF on assignment, so a picked `/share/photos\n` can never compare equal and the sanitised text is sent. | UI | **Accepted.** The picked reference stays authoritative until the user edits the field; text comparison dropped. |
| 3 | P2: closing the dialog during the pre-flight does not cancel its continuation — the confirm dialog opens for a dismissed operation, and a late 202 closes a newly opened dialog. | UI | **Accepted.** Dialog generation counter gates every continuation. |

Adversarial review, round 3: 2 findings.

| 4 | P1: with coarse inode timestamps two updates in one tick share a ctime; a same-length rewrite with restored mtime inside the copy's tick passes the ledger and the source is deleted (no privileges needed). | engine | **Accepted.** The recorded ctime must lie strictly in the past of the filesystem's own clock: for recently changed files a scratch entry in the held destination directory shows when the tick has advanced; until then the record is not trusted. |
| 5 | P2: the output-directory identity map fails open when its 1 M bound fills — later output directories become invisible to the self-copy check. | engine | **Accepted.** Fail closed: stop the root (the job, for a move) when an identity cannot be recorded. |
