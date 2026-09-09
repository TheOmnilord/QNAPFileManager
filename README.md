# QNAPFileManager

A file manager app for the QNAP QTS / QuTS hero desktop, installed from App Center as a QPKG and opened as a window in the
QTS desktop with the user's QTS login, exactly like File Station. Unlike File Station it can browse and manage the **whole**
filesystem (`/`, `/etc`, `/root`, `.qpkg` directories, raw volume mounts), edit permissions and ownership, and it never
needs SSH or Telnet. Every operation runs with the signed-in user's own Linux identity; administrators can switch to a
root mode for system paths.

Status: **M0 in progress**. Start with [PLAN.md](PLAN.md).

## Why

File Station and its HTTP API only accept paths inside shared folders. No maintained, QTS-integrated alternative exists
(see [docs/research/existing-tools.md](docs/research/existing-tools.md)). The mechanism is already proven by the sibling
project GitBackup: QTS App Center runs a package's service script as root, so a Go daemon can list the filesystem locally
and serve its own UI.

## Documents

- [PLAN.md](PLAN.md): decisions, milestones, verification, open questions.
- [docs/design/identity-and-hero-plan.md](docs/design/identity-and-hero-plan.md): per-user identity, worker processes, QuTS hero semantics, proxy embedding (rev 2 core).
- [docs/design/astra-per-user-review.md](docs/design/astra-per-user-review.md): GPT-6 Astra review of the per-user model.
- [docs/development.md](docs/development.md): using Codex and GPT-6 Astra as agents.
- [docs/design/backend-packaging-plan.md](docs/design/backend-packaging-plan.md): Go packages, API, guard rules, QPKG and CI.
- [docs/design/ui-ux-safety-plan.md](docs/design/ui-ux-safety-plan.md): feature matrix, wireframes, confirmation ladder, QTS-iframe rules.
- [docs/design/codex-independent-review.md](docs/design/codex-independent-review.md): independent critique and risk list.
- [docs/design/gitbackup-exploration.md](docs/design/gitbackup-exploration.md): what to lift from GitBackup.
- [docs/research/qts-integration-facts.md](docs/research/qts-integration-facts.md): verified QTS auth and packaging facts.
