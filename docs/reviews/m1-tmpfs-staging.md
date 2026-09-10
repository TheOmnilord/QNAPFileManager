**Staging is unsafe as implemented: an attacker-created directory enables root code execution.** Reviewed HEAD and the full staging file; no files modified.

1. **Critical — pre-created staging directory permits binary replacement and privilege escalation.** [internal/workerpool/spawn_linux.go:212](C:/Dev/QNAPFileManager/internal/workerpool/spawn_linux.go:212), also lines 217, 226–245, 86–91 and 151.

   **Exploit:** Before the first staging operation, a local user creates `/tmp/.qnapfilemanager`. `MkdirAll` accepts the existing directory; `Chmod(0755)` changes permissions but **does not change its attacker ownership**. The attacker therefore retains directory write permission and can unlink or rename the root-owned staged binary and replace it with their executable. They can wait until staging finishes and target a later spawn; winning the initial copy/exec race is unnecessary.

   Sticky `/tmp` protects entries directly inside `/tmp`, not files inside `.qnapfilemanager`. Moreover, the attacker owns the pre-created directory, so sticky semantics allow them to rename that directory itself. [Linux unlink semantics](https://man7.org/linux/man-pages/man2/unlink.2.html).

   Root workers take the same staged-first candidate list. With `who.Root`, `uid` becomes zero and `Credential` is omitted: the substituted executable inherits the root daemon’s credentials. An attacker need only wait for an administrator’s next root-worker spawn. Other worker spawns execute it as their respective users. A failed hello cannot undo code execution.

   `CreateTemp` protects initial file creation, **not subsequent pathname operations** in an attacker-owned directory. The attacker can also replace `tmpName` before pathname-based `Chmod` or `Rename`.

   A pre-created symlink to an attacker-controlled directory is another route wherever kernel symlink protections permit traversal: `MkdirAll` uses `Stat`, following the link, and `Chmod` follows it too. The plain-directory exploit does not depend on symlink protections. [Go implementation](https://go.dev/src/os/path.go).

   **Minimal fix:** Open the trusted staging parent and use `mkdirat`/`openat(O_DIRECTORY|O_NOFOLLOW)` for the staging directory. Before chmod or copying, `fstat` and reject anything not root-owned or writable by group/others. Perform temporary creation and rename relative to that verified descriptor, and chmod the open temporary file. Require a root-owned sticky `/tmp` parent, or use a trusted root-controlled parent outside `/tmp`. Do not adopt attacker-owned directories by chmod/chown.

2. **Medium — transient tmpfs exhaustion permanently disables staging for this pool.** [internal/workerpool/spawn_linux.go:177](C:/Dev/QNAPFileManager/internal/workerpool/spawn_linux.go:177), also lines 226–234.

   **Exploit:** A local user fills ordinary writable `/tmp` space before the first spawn, leaving insufficient room for the approximately 7.8 MB copy. Staging fails, but `sync.Once` permanently records completion with an empty `stagedExe`. The attacker can then free the space; subsequent spawns still use only the install path. On the described QTS configuration, non-root workers remain unavailable until the daemon/pool restarts.

   **Minimal fix:** Cache successful staging only; serialize and rate-limit retries after transient failures.

The remaining checks do not reveal additional security regressions:

- **If the directory actually is root-owned 0755 under root-owned sticky `/tmp`, staging is safe against non-root replacement, deletion, directory swapping, and copy/rename interference.** Non-root users cannot fill that directory. One staged copy is shared; they can still exhaust the surrounding tmpfs, as above.
- At [spawn_linux.go:89](C:/Dev/QNAPFileManager/internal/workerpool/spawn_linux.go:89), fallback can conceal a broken staged copy from callers, but logs the failure. It neither changes credentials nor invokes a shell. `childFile` is safely reusable: failed `Start` closes internally owned pipes, not caller-owned `ExtraFiles`; each retry builds a fresh command. [Go exec implementation](https://go.dev/src/os/exec/exec.go).
- Credential assignment, supplementary groups, cancellation, process-group termination, and `WaitDelay` remain intact. The [hello UID check](C:/Dev/QNAPFileManager/internal/workerpool/workerpool.go:986) and startup/shutdown accounting are unchanged. Hello verifies reported identity, not executable integrity.