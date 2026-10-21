# Rename to Taproot — Astra round 1 (2026-10-21, gpt-6-astra, effort high)

Reviewed: the staged diff of commit 3a3f0f4 (`wip/rename`) against main 7ba8d5e — the whole rename, against
`docs/design/rename-contract.md`. Judged by Claude (Opus 5.5, conducting in place of Fable 5.1). The adversarial pass
looked for mismatched pairs (cookies, CSRF header, base meta, theme key, trash and temporary names, staging paths,
ZFS fixtures and gates), packaging that breaks on the NAS, break-glass discovery, behaviour hidden in the rename,
documents that disagree with the code, the safety of the pre-1.0 upgrade steps, and old names left behind.

Normal review: 0 findings — "No actionable regressions were found in the rename across code, packaging, and UI."

Adversarial review: 2 findings, both in the pre-1.0 upgrade steps; "No additional defects were found in protocol
pairs, filesystem guards, worker staging, ZFS naming, packaging/CI, or break-glass changes."

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the cleanup loop reads mount points from mountinfo, which escapes a space as `\040` (`Home\040Videos`, already in `hero_mountinfo.txt`); `read -r` keeps the escape, so the loop tests a different path and silently leaves the real empty `.@qfm_trash` behind. | D (qnap-install.md) | **Accepted.** Decode mountinfo's octal escapes without `eval`; keep `rmdir` as the empty-only safeguard; tested against a fixture with spaces and a backslash. |
| 2 | P3: a user who restores every item leaves an empty `.@qfm_trash/<uid>/` behind and Empty Trash is then disabled, so the top-level `rmdir` refuses. | D (qnap-install.md) | **Accepted.** Document removing only empty direct `<uid>` directories with `rmdir` first, never a non-empty one or a symlink. |

**CI on 3a3f0f4** (run 39571026659): every test job green — `test-windows`, `test-linux-root`, `test-zfs`, and the
`test` job's race and static checks — except the `test` job's govulncheck: GO-2026-6809 (crypto/x509 distrusts
compromised intermediate certificates), published after the 1.26.9 pin and fixed in Go 1.26.10, reachable from the
daemon. Not caused by the rename; `GO_VERSION` moved to 1.26.10 in 35d1a03 and the CHANGELOG's security entry with
it.

Unique findings this round: 2. Rejected: none.
