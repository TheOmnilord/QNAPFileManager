# Security policy

Taproot runs as root on a NAS, and administrators operate as root through it. Please report a suspected
vulnerability privately — never in a public issue, pull request or discussion.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository: the **Security** tab, then **Report a vulnerability**,
or <https://github.com/TheOmnilord/QNAPFileManager/security/advisories/new>. The report is private to you and the
maintainer unless an advisory is published.

A useful report gives:

- the version you ran — the `.qpkg` file name carries it, and the running app's `api/session` reports it — or the
  commit, if you built it yourself;
- QTS or QuTS hero, the firmware version, and the NAS model or CPU architecture;
- the steps, and what they gain an attacker: whose identity, which files, from where on the network;
- what the attacker needs first: nothing, network access to the NAS, an ordinary QTS account, or an administrator's.

Do not attach `config.json`: it holds the break-glass password hash.

Nothing has been released yet. Until 1.0.0 is tagged, report against the current `main` branch; after that, against
the latest release.

This is a one-person project, and no response time is promised.

## Scope

[docs/identity.md](docs/identity.md) explains the identity model, the two doors and the guard; it is the quickest way to
tell a design decision from a flaw.

In scope:

- **The daemon** — the root process behind the app: its listeners, how a QTS session becomes an identity, sessions,
  the CSRF and Origin checks, the guard and its confirmation tokens, read-only mode, and the audit log.
- **The worker boundary** — anything that lets a QTS user read, change or learn what their own Linux account could
  not, or act as somebody else: through their worker process, through what passes between it and the daemon, or
  through a race between the two.
- **The break-glass door** — the TLS listener on port 8771, its password, lockout and sessions, its certificate, and
  the `break-glass` subcommand.
- **The QPKG** — the package's install, start and stop scripts, and the ownership and modes of what it installs and
  stages.

Not a vulnerability in this project:

- An administrator doing through the app what root can do. Administrators operate as root by design
  ([PLAN.md](PLAN.md) decision 6); the guard, read-only mode and the confirmation ladder stand between a mis-click and
  an irreversible change, not between an administrator and the system
  ([docs/identity.md §5](docs/identity.md#5-what-an-administrator-can-and-cannot-do)). A way for anybody else to make an
  administrator's session act — a forged request, a stolen or replayed session — is in scope.
- An attack that needs root on the NAS first.
- A flaw in QTS, QuTS hero, App Center or QTS's Apache. Those are QNAP's to fix.

## Known residuals

Some gaps are known, bounded and accepted, each with the reasoning for accepting it written down:

- [PLAN.md, "Accepted safety residuals"](PLAN.md#accepted-safety-residuals-m1): §2.0, §2.4, §2.5, §2.6 and §2.7;
- PLAN.md, "Must verify on the real NAS", item 10: without a client-attribution header from the QTS proxy, the
  authentication failure budget can key only on the presented username;
- the copy engine's residuals, named in PLAN.md's M2-B status and listed in the header of `internal/fsops/copy.go`;
- the break-glass door's residuals, in [docs/identity.md §13](docs/identity.md#13-known-residuals), which also
  summarises the rest.

A report that one of them is reachable by someone its reasoning assumed could not reach it, or does more than it says,
is a vulnerability.
