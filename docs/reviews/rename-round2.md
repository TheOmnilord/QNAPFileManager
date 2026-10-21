# Rename to Taproot — Astra round 2 (2026-10-21, gpt-6-astra, effort high)

Reviewed: the staged diff of commit fa35f73 (`wip/rename`, the round-1 fixes and the Go 1.26.10 pin) against main
7ba8d5e. Judged by Claude (Opus 5.5, conducting in place of Fable 5.1). The adversarial pass was asked to verify the
rewritten pre-1.0 cleanup snippet in `docs/qnap-install.md` under busybox semantics and to re-examine every category
of round 1.

Normal review: 0 findings — "No actionable regressions were found in the rename across code, UI, packaging, and
scripts."

Adversarial review: 1 finding; "No additional actionable defects were found in rename pairs, packaging/service/CI,
break-glass discovery, documentation, or the Go pin/changelog alignment."

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: on a share root other users can write to, one of them can rename `.@qfm_trash` away and put a symlink in its place after the snippet's checks and before `rmdir "$u"`; `rmdir` resolves parent components, so root removes an empty numbered child of whatever directory the link names. Empty-only still holds; confinement to the trash does not. | D (qnap-install.md) | **Accepted.** Pin the directory: in a subshell, `cd -P` into the trash root, verify `pwd -P` is the trash root's physical path (else skip and say so), remove children by relative path (`rmdir -- ./<uid>`, never a parent path resolved again, never a final symlink), then `cd -P ..` and `rmdir -- ./.@qfm_trash`. |

**CI on 35d1a03** (run 39572540978, #162): every job green — govulncheck on Go 1.26.10, race and static checks,
Windows, Linux root, ZFS, and the package job building the first `Taproot_<version>_<arch>.qpkg` pair.

Unique findings this round: 1. Rejected: none.
