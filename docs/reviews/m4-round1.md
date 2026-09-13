# M4 polish and release — review round 1 (2026-09-14)

Implementation fanned out to three Opus agents against `docs/design/m4-contract.md`: backend (`internal/breakglass`,
`internal/web/breakglass.go`, the `break-glass` CLI, `audit.Event.Door`, loopback-only `web.listen` validation,
security headers, CI single-dependency and `SHA256SUMS`), UI (`why.js` reason table, `empty.js`, `banners.js`,
`keys.js` keyboard map, `a11y.js`, `narrow.js` ⋯ overflow, the Shortcuts dialog) and docs (`docs/identity.md`,
`docs/qnap-install.md`, `docs/keyboard.md`, `docs/release-checklist.md`, `docs/nas-checklist.md`, `CHANGELOG.md`,
README).

Deviations accepted at this round: passwords over bcrypt's 72 bytes are refused (x/crypto v0.54 errors rather than
truncating); the certificate is generated when the listener will bind, not unconditionally at first start;
`DoorCredential` is defined but unused (no credential-proxy route exists); `auth.local.updated` is RFC3339Nano;
the `whyDisabled` ranking picks among disabling causes, a capability cause only when alone (INV-2); a sixth empty
state `listing-failed`; context-menu items shown-and-disabled with their reason; the keyboard map's authority is
`keys.js` (docs mirror it; `Ctrl+Shift+N`, `F2`, `Shift+Del` are named as not bound in 1.0); `docs/nas-checklist.md`
created (PLAN.md referenced a file that did not exist); no `LICENSE` file exists — `qpkg.cfg` says MIT; the README
says exactly that and flags it for the owner before any tag.

**gpt-6-astra is paused**; reviewer is an Opus adversarial pass. Linux CI: throwaway draft PR #4 on `wip/m4-ci`.

Linux CI, first run (34778338317 at cbfa5b7): root, ZFS and Windows green; the race job stopped at the new
single-dependency assertion, which used `go list -m all` and so saw x/crypto's own transitive module graph
(x/net, x/sys, x/term, x/text) although none of it is linked. The assertion now checks two halves — `go.mod`'s
require list and the modules `go list -deps ./...` actually links — both exactly `golang.org/x/crypto`. Rerun at
3bf5b00 recorded below.

Linux CI on the repaired workflow (34779000963 at 2962a64): root, ZFS and Windows green; the non-root race job
failed five `cmd/qnapfilemanager` CLI tests, which invoke `break-glass set-password`/`cert` in-process and hit the
new root requirement as uid 1001 (they pass on Windows, where the root check is announced, not enforced). Test
seam added with the round-1 fixes; the root gate itself keeps its own Linux-gated test.
