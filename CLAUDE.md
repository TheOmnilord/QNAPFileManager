# QNAPFileManager — working notes for Claude Code

## What this is

A root-capable, per-user web file manager for QNAP QTS and QuTS hero, delivered as a QPKG. A Go daemon started as root
by App Center spawns one worker process per QTS user and serves an embedded UI inside the QTS desktop through the QTS
reverse proxy. Everything File Station cannot reach (`/`, `/etc`, `.qpkg`, raw volume mounts) is in scope. Start with
[PLAN.md](PLAN.md); the design documents under `docs/design/` explain the reasoning.

## Working rules (set by the owner, 2026-09-09)

- **Claude Fable 5.1 is orchestrator and conductor.** It decomposes work, judges every review finding (agreeing or
  rejecting with a stated reason), and owns commits.
- **Opus and gpt-6-astra are the orchestra.** Implementation is fanned out to Opus subagents (`model: opus`) and to
  Codex running `gpt-6-astra` (the `codex-worker` project agent, or the Codex plugin `task --model gpt-6-astra`).
- **gpt-6-astra at high effort reviews everything Claude produces**, with a normal review and an adversarial review,
  iteratively, up to ten rounds per piece of work, extendable to fifteen when findings are still being accepted (owner, 2026-09-10):

  ```bash
  codex exec review -m gpt-6-astra -c model_reasoning_effort="high" --uncommitted
  ```

  Add a prompt argument for the adversarial pass (attack the change: security, data loss, root exposure, races).
  Findings go to Fable for judgement; accepted ones are fixed by the orchestra and re-reviewed.
- Reviews and design opinions from Codex/Astra are saved under `docs/design/` when they shape a decision.

## Conventions

- Go stdlib only, `CGO_ENABLED=0`, single static binary, `go:embed` UI split into `index.html` + `app.css` + `js/`.
  No npm, no framework. The only allowed dependency is `golang.org/x/crypto` (break-glass bcrypt).
- Tests: stdlib `testing`, table-driven, `t.TempDir()`. Permission-semantics tests skip on Windows and when not root
  (INV-2 in PLAN.md: never simulate the kernel). Root and ZFS behaviour is covered by the CI jobs.
- Platform split by file suffix (`_linux.go`, `_windows.go`, `_other.go`), not build tags.
- Before claiming green, run the three-GOOS sweep; `go vet ./...` on Windows silently skips Linux files:

  ```bash
  GOOS=linux go vet ./... && GOOS=windows go vet ./... && GOOS=linux GOARCH=arm64 go vet ./... && test -z "$(gofmt -l .)" && go test ./...
  ```

- Two invariants that tests enforce: INV-1 (`internal/web` never imports `internal/fsops`; user data is touched only in
  the worker) and INV-2 (kernel decides permissions; the app only predicts).
- Ports: 8770 is the loopback app port, 8771 the break-glass listener, 8899 the dev loop. 8765 belongs to GitBackup.
- Dev loop: `.claude/launch.json` runs `go run ./cmd/qnapfilemanager serve -config dev-config.json -jail testdata/fakeroot`.
  Always `go run`: a stale `go build` binary keeps serving embedded assets that were already edited.
- Shell scripts, `qpkg/package_routines` and `qpkg/qpkg.cfg` are LF (enforced by `.gitattributes`); they run under
  busybox sh on the NAS.

## Gotchas carried over from GitBackup

1. **Windows Smart App Control blocks freshly compiled test binaries at random.** A "flaky" failure with no assertion
   output is usually SAC (CodeIntegrity events 3077/3033). Try `go test -c -o /tmp/check.exe ./pkg && (cd pkg && /tmp/check.exe)`;
   if that is refused too, CI is the only way to run that package's tests. Say so; do not imply local green.
2. **`go:embed` hides UI edits behind a stale binary.** Use `go run`.
3. **`go vet` on Windows skips Linux files.** Run the three-GOOS sweep above.
4. **Line endings break patch matching.** Keep everything LF; `.gitattributes` pins it.
5. **Local green is not CI green.** Check the Actions run after pushing.
6. **`/share` on QTS is a RAM disk.** Never create files directly under `/share`; the guard refuses it.

## Commands

```bash
go run ./cmd/qnapfilemanager serve -config dev-config.json -jail testdata/fakeroot -addr 127.0.0.1:8899
go test ./...
powershell -File scripts/build-local.ps1
```

The full QPKG is built by GitHub Actions (QDK pinned by commit); there is no Docker or QDK on the dev box.
