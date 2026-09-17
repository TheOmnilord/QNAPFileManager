# M4 contract — polish and release (2026-09-13)

Fixed by the orchestrator before the implementers fan out, as M2-A, M2-B, M2-C and M3 were. Drafted by an Opus
planning agent for Fable 5.1's judgement; the gpt-6-astra review of this contract is **pending** (Astra paused by the
owner on 2026-09-13). Four pieces are built against it and only the first has a hard ordering constraint: the
break-glass listener (a second `http.Server`, a second session store, one new package `internal/breakglass`), the
non-admin UX pass, the accessibility/keyboard/narrow pass, and the documentation + release mechanics. Anything not
stated here follows the M2/M3 settlement: every web-supplied path reaches the worker as the guard's **canonical**
spelling and the worker walks it `O_NOFOLLOW` per component (`changed`, never followed); admission slots and
deadlines bound every streaming response; INV-1 (`internal/web` never imports `internal/fsops`) and INV-2 (the kernel
decides, the app predicts) hold unchanged — the break-glass door adds a *way in*, never a way around either.

Sources of intent: PLAN.md's M4 milestone row, decision 1 (one dependency: `golang.org/x/crypto`), decision 3
(identity, the fallback chain, fail-closed), decision 7 and its 2026-09-10 deviation (there is no password on the
read-only toggle), decision 13 (CSRF/Origin), decision 14 (packaging and CI), and the first "Open question" near
line 298; `identity-and-hero-plan` §5.1 (listener policy, `web.breakGlass`), §5.3 (the first-request flow and the
fallback chain, ~line 569), §6 (the M4 line, ~line 623); `ui-ux-safety-plan` §3.2 (every mutating button carries a
*why*), §3.9 (the keyboard table), §4.1/4.2 (marking and the ladder), §5.1 (framing constraints), §5.3
(accessibility), §5.4 (narrow); `backend-packaging-plan` §4.3 (limits and timeouts), §4.4 (headers), §4.5 (CSRF),
§5.5 (the claim window — **superseded here**), §7 (packaging and CI). Where backend plan §5.5 puts first-run
bootstrap behind an HTTP claim window and this contract puts it behind a shell command, **this contract governs**:
§5.5 was written when the app had no identity model, and a 15-minute unauthenticated window on a root daemon is a
worse door than the one it was protecting.

## 1. The open question, answered: KEEP

**Decision: the break-glass listener stays**, per the design document's own recommendation (identity plan §5.1). The
argument is the one the design already makes and nothing since has weakened it: this is the tool an operator reaches
for when Apache or App Center is broken, and it must not depend on the thing it may have to repair. The alternative
on the table — a single `0.0.0.0` listener — is rejected outright: it would put the *whole* app, including the QTS
cookie door, on the LAN.

**The owner can reverse this with one config key and no code change**: `web.breakGlass.enabled = false`. Nothing else
in M4 depends on the listener existing; with it off the daemon is loopback-only and the local password is inert.
Recorded here as a decision rather than an assumption so the reversal is a setting, not a redesign.

What KEEP costs, stated plainly so the reversal can be judged: one LAN-reachable TCP port on a root daemon, one
credential that lives outside QTS's account policy and password rules, and a self-signed certificate the operator
must learn to recognise. §4, §5 and §13 are what buy that down; §18 is what is left.

## 2. What the second listener serves, and what it refuses

*Amended, round 1:* the credential-proxy form named in the identity plan (`authLogin.cgi?user=&pwd=`) was never
built; in 1.0 the doors are exactly two — the QTS desktop session on the loopback listener and the local
administrator on 8771. `audit.DoorCredential` stays defined for the vocabulary and is never issued.

1. **One door per listener, and they never mix.** The main listener (`web.listen`, loopback) serves the QTS session
   door and the credential-proxy form (`authLogin.cgi?user=&pwd=`). The break-glass listener serves **only** the
   local bcrypt account. A `qfm_sid` cookie presented on 8771 is ignored; a `__Host-qfm_bg` cookie presented on 8770
   is ignored; `qtsauth.FromRequest` is never called on the break-glass listener and the local password has no route
   on the main one. This is the whole security story of the feature in one sentence, and every test in §16.1 is a
   way of restating it.
2. **Consequence: `auth.mode` is narrowed to `qts` for v1.0.** Identity plan §5.3's fallback chain put the local
   account as door (c) *on the same listener*; M4 moves it entirely to its own listener, so `local` and `both` are
   refused by `config.Validate` unless `-dev` is set (where they log a warning and exist only for the Windows loop).
   The chain is unchanged in substance — QTS cookie, then the credential form, then the local account — but its last
   door is a different door rather than a different form on the same one. Reversible: widening the validation is a
   three-line change if a NAS turns up where the second port cannot be opened.
3. **Everything below the door is identical.** Same mux, same route table, same guard, same `readOnly`, same
   confirmation ladder, same audit, same worker pool. There is exactly one API surface; the listener decides only
   *who you are*, never *what you may do*. A second route table would be a second place to forget a check.
4. **A break-glass session is an administrator session** (that is what the account is for): `sess.admin = true`,
   `who.Root = true`, and it keys to the same `root` worker as any other admin session (decision 6). It is **not** a
   QTS user, so `wproto.CreateAs` is **empty** and content it creates is owned by `root:root` — the one place where
   the admin-as-real-user rule (M2-B, M3 §5.3) cannot apply, because there is no real user. The UI says so
   persistently (§8.3) and `docs/identity.md` says so in its own section, because a support tree full of root-owned
   files is the most likely lasting damage this door can do.
5. **The listener does not bind until a password exists.** An open port that can never authenticate is pure surface.
   With no hash configured the daemon logs *"break-glass is enabled but no password is set; run `qnapfilemanager
   break-glass set-password` on the NAS shell"* and binds nothing. This is also what replaces backend plan §5.5's
   claim window: there is no unauthenticated bootstrap path over HTTP at all, in any window, ever.

## 3. The certificate

1. **Generated at first start, persisted, never transmitted.** ECDSA P-256, self-signed, written to
   `<config dir>/breakglass-cert.pem` and `breakglass-key.pem` at mode `0600` in a `0700` directory (the QPKG's
   `config/`, which `package_routines` already tightens). `crypto/x509` + `crypto/ecdsa` — stdlib, no new dependency.
2. **Validity is 397 days, and the daemon regenerates within 30 days of expiry at start-up.** Not ten years: Apple's
   398-day ceiling makes a long-lived certificate a certificate Safari may simply refuse, and an emergency door that
   one family of browsers cannot open is not an emergency door. The regeneration happens in the process that is
   already running, so it costs an operator nothing; the fingerprint change is logged as a **forced milestone** and
   reported by `break-glass status`, because a silently changed fingerprint and a man-in-the-middle look identical.
3. **SANs**: `/etc/hostname`'s value, every non-loopback IP the host has at generation time, plus `127.0.0.1` and
   `::1`. IP SANs matter here — an operator with a broken desktop reaches this by IP, and a certificate with no IP
   SAN produces a *different*, scarier warning than the expected self-signed one.
4. **Trust is out-of-band and the docs say so.** The SHA-256 fingerprint of the DER certificate is printed to the app
   log at every start and by `break-glass status`; `docs/qnap-install.md` tells the operator to compare it before
   typing a password into a page the browser has warned about. `break-glass cert -regenerate` exists for an IP change
   or a suspected key compromise. **No HSTS on either listener** — pinning HTTPS for the NAS's whole host from a
   self-signed door would break the QTS desktop on that host, which is the opposite of repair.

## 4. The password: set from the shell, never over HTTP

1. **There is no HTTP route that sets, changes, resets or reveals the password.** Not an admin-only one, not a
   first-run one. The only writer is a CLI subcommand run as root on the NAS shell:

   ```
   qnapfilemanager break-glass set-password [-config <path>] [-cost <n>] [-stdin]
   qnapfilemanager break-glass disable            clear the hash (the listener then binds nothing)
   qnapfilemanager break-glass status             enabled, addr, hash present + set time, cost, cert fingerprint
   qnapfilemanager break-glass cert [-regenerate] print or regenerate the certificate
   ```

   `set-password` reads the password twice from the terminal with echo off (`term.ReadPassword` is not available
   without a dependency, so it shells out to `stty -echo` on Linux and falls back to a warned plain read elsewhere;
   `-stdin` reads one line for scripted use and is what CI exercises). It refuses a password shorter than **12
   characters** and refuses one that is only whitespace; no composition rules, per NIST. It refuses to run when
   `geteuid() != 0`, when the config file exists and is not owned by uid 0, or when it is group- or world-readable —
   a credential store with the wrong mode is a bug worth stopping for, not warning about.
2. **bcrypt cost 11 by default** (`-cost`, floor 10, ceiling 15). Cost 12 on the ARM cores these units ship is
   seconds, not milliseconds, and the verification is a CPU cost an unauthenticated caller controls; §5 bounds the
   concurrency, and the ceiling keeps an operator from configuring a self-inflicted denial of service.
3. **The daemon re-reads the hash rather than caching it**, guarded by an mtime+size check on the config file, so a
   password change from the shell takes effect on the next attempt without a restart — the operator who is already
   repairing a broken NAS should not have to restart the app they are repairing it with.
4. **Changing or clearing the password destroys every live break-glass session.** Sessions carry the
   `auth.local.updated` stamp they were issued under; a mismatch is a destroyed session on the next request. That is
   what makes `break-glass disable` an actual eviction and not a suggestion.
5. `golang.org/x/crypto/bcrypt` is the **first and only** `require` in `go.mod` (PLAN decision 1). A CI step asserts
   `go.mod` has exactly one require line and that `go mod tidy` is a no-op, because "only one dependency" is a
   property that decays the moment nobody is checking.

## 5. Rate limiting, lockout, and the timing floor

*Amended, round 2:* §5.1 governs where §5.2 seemed to disagree — a locked-out source is answered `429 locked_out` with
`Retry-After`, so "locked out" is announced by design (residual §18.7); "wrong password" and "no password
configured" remain indistinguishable in body and latency, and only a wrong password advances the ladder (a
missing credential does not: after `disable` on a running daemon that would let any peer lock the door before the
operator sets the new password). A queued verification that runs out of its wait answers `429 rate_limited`, not
the credential body.

1. **Three bounds, all in the break-glass listener alone** (the main listener keeps `auth_limits.go` unchanged):
   - **Per-source-IP token bucket**: 10 attempts per minute, burst 10, at most 256 tracked sources (LRU-evicted).
     The peer here is a real LAN address — this listener is not behind the QTS proxy — so unlike the main listener's
     budget (PLAN "must verify" item 10) it can key on something honest.
   - **Lockout, per source** (*amended, Astra round 1 #4* — it was per account): 5 consecutive failures from one
     source lock **that source** for 60 s, doubling per further failure to a 1800 s cap; a success from that source
     resets it. Locked answers `429 locked_out` with `Retry-After` and never reveals whether the password offered
     was right. The table is the bucket's bounded LRU (256 sources). An account-wide lockout let any LAN peer shut
     the emergency door for the operator — five wrong passwords, renewed at each expiry inside the peer's own
     budget, and a password change did not reset it — which is the worse failure for a door that exists for the
     moment the NAS is broken. The bound on guessing across many sources is the serialised bcrypt plus each source's
     bucket (§18.12).
   - *Added, Astra round 1 (#7):* the lockout verdict is read, and the outcome committed, **inside** the serialised
     verification, so queued attempts cannot act on a stale verdict — four wrong passwords behind a fourth failure
     enter one rung, not four, and a correct password queued behind a lockout-entering failure is refused as locked.
   - **One verification at a time**: a semaphore of 1 around `bcrypt.CompareHashAndPassword` with a queue depth of 4;
     the fifth concurrent attempt is `429 rate_limited`. bcrypt at cost 11 is the most expensive thing an
     unauthenticated caller can ask this process to do.
2. **A timing floor, not a constant-time comparison.** Every failed attempt — wrong password, no password
   configured, locked out, malformed body — returns after the same **minimum 400 ms** measured from request start,
   with the same body: `401 auth_failed`, *"That password was not accepted."* Without the floor, "no password is
   configured" and "wrong password" are distinguishable by latency, and so is "this account is locked". `bcrypt`'s
   own comparison is constant-time; the floor covers the paths that never reach it.
3. **Lockout state is in memory and a restart clears it.** Stated rather than fixed: persisting it would let an
   attacker lock the operator out of their own emergency door across restarts, which is the worse failure. Listed in
   §18.

## 6. Audit: the third door, and a milestone on every use

1. **`audit.Event` gains `Door string`** — `"qts"`, `"credential"` or `"local"` — set once at session creation and
   stamped on **every** event that session produces. Without it the audit log cannot answer the one question an
   operator will actually ask after an incident: *which door did this come through?*
2. **Every break-glass event is a forced milestone** (`ForceMilestone`, mirrored to QuLog): the listener binding at
   start-up, a certificate generation or regeneration with its fingerprint, every login **success and failure**,
   every lockout entered and left, session issue and destruction, and the password's `updated` stamp changing under a
   live daemon. "Milestone on every use" is meant literally — this door is rare by construction, so the QuLog volume
   is bounded by how often it is used, and an operator scanning QuLog Center for "who got in when Apache was down"
   must not have to reconstruct it from the JSON lines.
3. Detail strings stay **path-free and bounded**, as everywhere: `"door=local ip=192.168.1.40 cost=11"`,
   `"lockout 5 failures, 60s"`, `"cert regenerated, sha256=ab12…"`. The client IP is the real peer (no
   `X-Forwarded-For` trust on this listener — it is not behind a proxy, so a forwarded header there is a forgery).
4. The CLI subcommands write **nothing** to the audit log: they run as a different process, with no logger and no
   QuLog access, and a durable line written by a process that is not the daemon would be a second writer to a
   single-writer file. What they change is visible the moment the daemon notices (§4.3/4.4), and *that* is audited.

## 7. Non-admin UX: one reason table, consulted by every control

1. **`js/why.js` is the single source of every "why is this greyed out" sentence.** One pure function,
   `whyDisabled(action, ctx) -> {allowed, cause, sentence}`, over exactly four causes, in this precedence order:

   | Cause | Example sentence |
   |---|---|
   | `readonly` (global) | *"Read-only mode is on, so nothing can be changed. An administrator can turn it off in Settings."* |
   | `selection` (nothing selected, wrong kind, too many) | *"Select a file or folder first."* / *"This is a device file, so it cannot be edited as text."* |
   | `capability` (uid/gid arithmetic, `perm.CapsFor`) | *"Owned by `backup` (uid 1003). Only the owner or an administrator can change permissions. You are signed in as `sveinung`."* |
   | `guard` (protected path class) | the guard's own path-free reason, unchanged |

   *Amended, Astra round 1 (#6):* the `guard` cause applies to **mutating** actions only — View, Download, Properties
   and Search are never guard-disabled in the UI; the server answers `403 protected` itself where it must. And the
   listing's `class` (`browse.go`'s lexical `/etc`, `/usr`, `/var`… list) is a display hint, not the guard's verdict;
   it drives the badge and the path notice, never `guard.denied`. Reading it as a denial disabled the repair
   operations an administrator opens this app for.

   Every mutating control renders `disabled` **and** `aria-disabled="true"` **and** `title=sentence` **and** points
   `aria-describedby` at a `.visually-hidden` node holding the same sentence — `title` alone is invisible to a
   keyboard user and to a screen reader on a disabled button (ui-ux §3.2 asked for the title; M4 adds the two that
   make it reach everybody). **Never hidden for a state reason**, per §3.2.
2. **Capability hints stay hints, and the precedence above is deliberate.** `capability` ranks *below* `readonly` and
   `selection` because those two are certain; a uid/gid prediction is not (an ACL, a read-only mount or an immutable
   attribute can grant or refuse where the arithmetic says otherwise — PLAN decision 12, INV-2). So a control whose
   only reason is `capability` is **enabled with an explanatory title**, exactly as M3 settled for the permissions
   grid; only `readonly`, `selection` and `guard`-deny actually disable. M4's contribution is that the three places
   which currently decide this separately (toolbar, context menu, dialog footers) consult one function.
3. A golden test enumerates every mutating control id against every cause and asserts a non-empty, non-duplicated
   sentence — the M3 precedent of a table being cheaper than finding the gap a fourth time.

## 8. Empty states, and the read-only banner

1. **Five named empty states**, each one sentence plus at most one action, rendered into the list region with
   `role="status"`:

   | State | Sentence |
   |---|---|
   | empty folder | *"This folder is empty."* + **New folder** when the guard and `readOnly` allow it |
   | listing refused | *"You do not have permission to list this folder. It is owned by `root` and its mode is 0750."* (the kernel's verdict, reported — INV-2) |
   | filter matched nothing | *"No loaded name matches "x". 4,182 entries are loaded; press Ctrl+F to search the whole subtree."* |
   | search finished with no hits | *"No match under /share/Public. 312,004 entries were visited."* + the bound that stopped it, if one did |
   | trash empty | *"Trash is empty on this volume."* + the volume it is talking about |

   The listing-refused case is the load-bearing one: today a non-admin walking into `/etc/ssh` sees an empty list and
   concludes the app is broken. An empty folder and a folder you cannot read must never look the same.
2. **Numbers, never "some".** Every empty state that can name a count or a bound names it; that is what distinguishes
   "nothing is there" from "we stopped looking".
3. **The read-only banner** is a full-width bar above the list (not only the existing `#chipReadonly`) whenever
   `readOnly` is on: *"Read-only mode — no changes can be made."* For an admin it carries an inline link to Settings;
   for a non-admin it names what to ask for instead of offering a control that would 403. It is `role="status"`,
   announced once on change and not on every navigation, and it is **the same bar on both listeners** — a break-glass
   session sees the read-only state it is actually in, plus its own banner (§8.4).
4. **The break-glass banner** is persistent, `--warn`-coloured, never dismissible: *"Emergency access. You are signed
   in with the local administrator account, not a QTS user. Everything you create here will be owned by root."*

## 9. Accessibility, keyboard, narrow

1. **Focus order is declared, not emergent**: skip link → toolbar → path bar → tree → list → status. The list and the
   tree are single tab stops with roving `tabindex` (ui-ux §5.3, already in the shell); nothing inside a virtualised
   row is ever tabbable, because a list of 200,000 rows with focusable cells is a keyboard trap in practice.
2. **Dialogs**: native `<dialog>` + `showModal()` (the focus trap is the platform's, not ours), `aria-labelledby` on
   the title, `aria-describedby` on the consequence sentence — for L2 that is the danger text, which is the sentence
   a screen-reader user most needs before the typed-phrase field takes focus. Focus moves to the first input on open
   and **returns to the invoking control** on close; `Esc` closes and returns. `#dlgConfirm` autofocuses `#cfPhrase`,
   never `#cfOK` (ui-ux §3.8).
3. **The list**: `role="grid"`, `aria-rowcount` absolute, `aria-rowindex` absolute on rendered rows, `aria-selected`
   per row, `aria-sort` on the header buttons, `aria-busy="true"` while a page is loading. Progress percentages are
   **not** announced; start, awaiting-input and completion are (ui-ux §3.4). Errors are `role="alert"`; everything
   else goes through the polite `#announce`.
4. **The keyboard map is one table in `#dlgShortcuts` (`?`), and it is authoritative.** A node test cross-checks it
   against the handler's own binding table so a shortcut cannot be added, removed or re-bound without the dialog
   changing — the same shape as the existing element-id/endpoint cross-checks. README mirrors it for people who
   cannot open the app. `Ctrl+R` is never `preventDefault`ed; the QTS desktop swallows some chords, so every shortcut
   keeps a mouse equivalent (ui-ux §3.9).
5. **Narrow: ≤ 768 px is the contract, not an aspiration.** The QTS desktop window is the target, so the acceptance
   sizes are **1280×800, 1024×768, 900×600, 768×600 and 375×667**, and at each of them: the body never scrolls
   horizontally, every toolbar action is reachable (secondary actions collapse into a `⋯` menu rather than
   disappearing — today `#btnMkdir` and `#btnUpload` are `display:none` below 46rem, which *removes* function and is
   fixed here), every dialog fits with its own internal scroll and its action row pinned, and the tree drawer is
   dismissible by `Esc` and by a tap outside. The existing rem breakpoints stay; 48rem is added as the explicit
   768 px rung.
6. **What is automated and what is not, honestly.** There is no npm, so there is no axe run. Automated coverage is
   *structural*: a Go test parses the embedded `index.html` and asserts every `<dialog>` has `aria-labelledby`, every
   icon-only control has an accessible name, every `aria-describedby` resolves to an existing id, and no
   `tabindex > 0` exists. Contrast ratios are asserted arithmetically over the CSS token pairs in both themes
   (≥ 4.5:1). Everything else — an NVDA pass, a keyboard-only pass, the five viewport sizes — is a manual item on the
   hardware checklist (§19) and is stated as manual rather than implied to be covered.

## 10. Wire and config — committed with this contract

```go
// internal/config
type BreakGlass struct {
    Enabled  bool   `json:"enabled"`             // default true
    Addr     string `json:"addr"`                // default "0.0.0.0:8771"
    CertFile string `json:"certFile,omitempty"`  // default <config dir>/breakglass-cert.pem
    KeyFile  string `json:"keyFile,omitempty"`   // default <config dir>/breakglass-key.pem
}

type Local struct {                              // config.Auth gains Local
    Hash    string `json:"hash,omitempty"`       // bcrypt; written only by the CLI
    Cost    int    `json:"cost,omitempty"`       // default 11, floor 10, ceiling 15
    Updated string `json:"updated,omitempty"`    // RFC3339; bumping it evicts live sessions
}
```

| Key | Default | Meaning |
|---|---|---|
| `web.breakGlass.enabled` | `true` | §1. `false` makes the whole feature inert with no code change. |
| `web.breakGlass.addr` | `0.0.0.0:8771` | Forced to loopback under `-dev`. |
| `web.breakGlass.certFile` / `.keyFile` | beside the config | Generated if absent (§3). |
| `auth.local.hash` | `""` | No hash → the listener does not bind (§2.5). |
| `auth.local.cost` | `11` | §4.2. |
| `auth.local.updated` | `""` | Session eviction stamp (§4.4). |
| `auth.mode` | `qts` | `local`/`both` refused outside `-dev` (§2.2). |

```
POST /api/breakglass/login    {password}   → 204 + Set-Cookie __Host-qfm_bg   (break-glass listener only)
POST /api/breakglass/logout                → 204                              (break-glass listener only)
GET  /api/session                          → the existing shape plus "door":"qts"|"credential"|"local"
```

**Two new error codes, both web-only**: `auth_failed` (401) and `locked_out` (429, with `Retry-After`). M3's
code-coverage table test enumerates the codes the **worker** can emit; these are issued by the web layer and never
cross the RPC, so they are added to `web.statusCode`'s table and explicitly excluded from the worker table with a
comment saying why — otherwise the next person to read that test concludes the table is incomplete.

The login route is exempt from the CSRF header requirement (no session exists yet to bind a token to) and keeps the
`Origin`/`Referer` host check plus the `Sec-Fetch-Site: cross-site` rejection; the CSRF token is issued with the
session in the login response, exactly as the main listener issues it from `/api/session`.

## 11. Docs

Four documents, all under the repository root or `docs/`, all checked by the same link test that already covers
README:

1. **`docs/identity.md` (mandatory).** How identity is established, end to end: the QTS cookie pair and what
   `authLogin.cgi` is asked; the **fail-closed rules** (`sid` is honoured only when the response carries the
   username; a missing `isAdmin` yields a normal-user session; no uid resolves → refuse, never fall back to root;
   `isAdmin` disagreeing with local group membership takes the lower privilege and logs it); username → Linux
   identity, including domain users and the "groups incomplete" banner; **the two doors**, what each can do, and that
   they never mix (§2); what an administrator can and cannot do (root worker, guard and `readOnly` still apply, the
   ladder still applies, `/` and depth-1 recursive changes are refused for everybody); and **the ownership rules for
   admin-created content** — `CreateAs` makes an admin's uploads, copies and new folders owned by the real QTS user,
   chown is the exception because it *is* the ownership operation, and a break-glass session has no real user so its
   content is root-owned. The Origin/CSRF scheme (§13.3) is documented here rather than in a fifth file, because it
   is part of how a request is attributed to a person.
2. **`docs/qnap-install.md`.** Install from App Center (and the sideload path for an unsigned `.qpkg`), what the
   proxy path is and why the app appears under `/qnapfilemanager/`, the ports (8770 loopback, 8771 break-glass, and
   the note that 8765 belongs to GitBackup), break-glass setup as a numbered shell procedure including the
   fingerprint comparison, upgrade and removal (and that `.@qfm_trash` directories are deliberately left behind),
   where the logs are and what the audit log is.
3. **`CHANGELOG.md`.** Keep-a-Changelog shape, semver, `Added`/`Changed`/`Fixed`/`Security`, an `[Unreleased]`
   section at the top, and one entry per milestone M0–M4 reconstructed from the git history. `Security` is not
   decoration here: the accepted residuals (§2.0, §2.4–§2.7) are what a reader needs to find.
4. **README polish.** The status line currently says "M0 implemented"; it becomes a short accurate status, a
   screenshot-free feature list, the keyboard map, the two doors in three sentences, and links to the three documents
   above. The existing document index stays.

## 12. Release

1. **Version stamping already works** and is not touched: CI builds `0.0.<run>` from `main` and `${GITHUB_REF_NAME#v}`
   from a tag, and rewrites `QPKG_VER` in `qpkg/qpkg.cfg`. M4 adds one guard step: a tag that does not match
   `^v[0-9]+\.[0-9]+\.[0-9]+$` fails the build before anything is signed or uploaded.
2. **The tagging rule. The tag is the owner's call — this fixes how, not when.**
   - Tag **only** a commit on `main` whose `build` workflow concluded **success** (checked with `gh run list` against
     that exact SHA, not the branch head).
   - The tag is **annotated** (`git tag -a v1.0.0 -m "…"`), never lightweight, so the tagger and date are recorded;
     signed if the owner has a key configured.
   - One tag per released version, never moved. A bad release is superseded by `v1.0.1`, never by re-pointing
     `v1.0.0` — the QDK installer and the checksums file both take the version at its word.
   - `main` must be clean of uncommitted changes and the three-GOOS sweep must pass locally as well; local green is
     not CI green, but local red is definitely not releasable.
3. **Artifact naming.** QDK names the package from `qpkg.cfg`, so the release carries exactly
   `QNAPFileManager_<version>.qpkg` (one package, both architecture trees inside) plus `SHA256SUMS`. Pre-release
   builds from `main` stay workflow artifacts with 7-day retention and are never attached to a release — the
   account-wide artifact quota is the reason (`build.yml`).
4. **Release checklist** (also written into `docs/qnap-install.md` so it survives this contract):
   1. CI green on the release commit, including `test-linux-root`, the ZFS job, the race job, `test-windows`, the
      qemu smoke of both trees and `qbuild`.
   2. `CHANGELOG.md` has a dated section for the version, and the `Security` block names the accepted residuals.
   3. `docs/identity.md` and `docs/qnap-install.md` match the shipped behaviour (ports, defaults, subcommands).
   4. Hardware checklist (§19) run on **both** units against a package built from that commit.
   5. Annotated tag pushed; the release job attaches the `.qpkg` and `SHA256SUMS` with `--generate-notes`.
   6. Install the released artifact from a clean App Center install on one unit and confirm the version string in
      `api/session` matches the tag — a release nobody installed is a release nobody tested.

## 13. Final hardening sweep

1. **The main listener is loopback-only, asserted by a test.** `config.Validate` refuses a `web.listen` whose host is
   not a loopback literal (`127.0.0.0/8`, `::1`) — including `0.0.0.0:8770`, `:8770`, `[::]:8770` and any hostname —
   and `-addr` goes through the same validation rather than around it. There is no override key: the break-glass
   listener is the sanctioned non-loopback surface, and a second way to expose the main one is a second way to get it
   wrong. The test is a table of those spellings.
2. **Cookies.**

   | | main | break-glass |
   |---|---|---|
   | name | `qfm_sid` | `__Host-qfm_bg` |
   | `Path` | `<proxyPrefix>/` | `/` (required by the `__Host-` prefix) |
   | `Secure` | when TLS or `X-Forwarded-Proto: https` | **always** (the listener is TLS-only) |
   | `SameSite` | `Lax` (it is framed by the QTS desktop) | `Strict` (it is never framed) |
   | `HttpOnly` | yes | yes |

   The `__Host-` prefix is not cosmetic: it makes the browser refuse the cookie if anything ever tries to set it with
   a `Domain` or a narrower `Path`, which is exactly the confusion a second listener on the same host invites.
3. **Origin/CSRF, documented in `docs/identity.md` and unchanged in behaviour**: a required `X-QFM-CSRF` header bound
   to the session on every non-GET/HEAD (a cross-site `<form>` cannot set headers; a cross-site `fetch` that does
   triggers a preflight this server never answers), plus `Origin`/`Referer` host equal to `r.Host` when present, plus
   outright rejection of `Sec-Fetch-Site: cross-site`, plus `SameSite` per the table above. Three locks, and the
   document explains why `Content-Type: application/json` alone could not be the lock (uploads are
   `application/octet-stream`).
4. **Security headers** keep the current set (CSP with `frame-ancestors`, `nosniff`, `Referrer-Policy: no-referrer`,
   `Cache-Control: no-store` on `/api/` and the shell, no `X-Frame-Options`) and add
   `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`. **No HSTS** (§3.4).
   On the break-glass listener the CSP is the same except `frame-ancestors 'none'` — that page is never framed, and
   the one place a clickjacking frame would be most valuable is the password field.
5. **Server timeouts**, both listeners: `ReadHeaderTimeout: 10s`, `IdleTimeout: 2m`, `MaxHeaderBytes: 64 KiB`, no
   `ReadTimeout` and no `WriteTimeout` (multi-gigabyte uploads and downloads — backend plan §4.3). The break-glass
   server adds `TLSConfig{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}`: HTTP/2 is declined on
   purpose, because every streaming, admission and deadline argument in M2-C was reasoned over HTTP/1.1 semantics and
   a release is not the place to re-derive them. *Amended, Astra round 1 (#2):* `NextProtos` alone does not decline
   it — `ServeTLS` appends `h2` and a client offering only `h2` negotiated it — so the server sets `Protocols` to
   HTTP/1 only and an empty `TLSNextProto`, and the test dials with `h2` and asserts the negotiation, not the
   config. *Added (#8):* the JSON routes decode and drain their bounded body under a **read deadline**
   (`ResponseController.SetReadDeadline`), because neither `MaxBytesReader` nor the handler context interrupts a
   socket read; a drain that times out closes the connection rather than counting as consumed. *Added (#3):* a
   sessionless denial on a mutation route on this listener is accounted like a refusal — one audit line per source
   per window — never a forced milestone per packet. Shutdown drains both listeners inside the existing 20 s budget
   (`QPKG_TIMEOUT="30,60"`).
6. **A separate session store**, not a shared map with a flag: its own mutex, its own map, its own CSRF tokens, cap
   **8** live sessions, idle timeout **15 minutes**, absolute lifetime **4 hours**. A shared store with a `door`
   field would be one forgotten comparison away from a QTS cookie redeeming a break-glass session.

## 14. Caps and limits

Break-glass sessions 8, idle 15 min, absolute 4 h; login attempts 10/min per source IP over at most 256 tracked
sources; 5 consecutive failures from a source → 60 s lockout of that source doubling to 1800 s (Astra round 1 #4);
one bcrypt verification at a time with queue depth 4; minimum failure latency 400 ms; password **12–72 bytes when
set** (bcrypt's own limit — the CLI refuses a longer one rather than truncating; *corrected, Astra round 1 #19*: the
earlier "maximum 1024 with truncation" was wrong) and a login **candidate** of at most 1024 bytes, which is the
body bound, not a password rule; bcrypt cost 11 (10–15), and a stored hash must parse with a cost in that range
(#10); certificate validity 397 days, regenerated within 30 days of expiry by the daemon or `cert` — never by
`set-password`, which leaves a usable pair alone (#16); login body 4 KiB. Everything else is the existing budget: the 1 MiB JSON body cap, the 15 s handler
context, the admission slots and deadlines M2-C settled, `MaxHeaderBytes` 64 KiB.

## 15. Degradation off Linux (the dev loop)

Certificate generation, bcrypt, the lockout arithmetic, the reason table, the empty states and the structural
accessibility assertions are **fully exercised on the dev box** — all of it is pure Go or pure JS over stdlib, which
is deliberate: the riskiest new judgement in M4 (a credential on a LAN port) is testable without a NAS. What
degrades: `0600` on the certificate and key is approximate on Windows (the mode assertion is a Linux-only test);
`stty -echo` does not exist, so `set-password` warns that the password will echo and `-stdin` is the supported path;
`geteuid` is absent, so the root check is Linux-only and the CLI says so rather than pretending to have checked; and
`web.breakGlass.addr` is forced to `127.0.0.1:8771` under `-dev` so a development run never opens a LAN port. The
narrow and screen-reader passes are manual and are on the hardware checklist, not in CI.

## 16. Tests

1. **The two doors never mix (every OS).** A `qfm_sid` cookie on the break-glass listener is ignored and the request
   is unauthenticated; a `__Host-qfm_bg` cookie on the main listener likewise; `qtsauth.FromRequest` is never
   reached from the break-glass mux (asserted with a verifier that fails the test if called); `/api/breakglass/login`
   does not exist on the main listener (404, and the route table test asserts it); the local hash is never consulted
   by the main listener. This is the section to read first.
2. **`internal/breakglass` (every OS):** certificate generation, persistence, reload, the 30-day regeneration
   window, SAN contents, fingerprint stability across restarts; bcrypt verify against a known hash; the lockout
   ladder over an injected clock (5 → 60 s → 120 s → … → 1800 s cap, reset on success); the per-IP bucket and its
   LRU eviction; the verification semaphore's queue depth; the 400 ms floor measured on all four failure paths
   including "no hash configured".
3. **CLI (every OS, `-stdin`):** `set-password` writes a hash and an `updated` stamp and nothing else; cost bounds;
   the 12-byte minimum; the 72-byte bcrypt notice; `disable` clears the hash; `status` prints without the hash;
   `cert -regenerate` changes the fingerprint. **Linux-only:** the `0600`/owner/mode refusals and the `geteuid`
   refusal.
4. **web (every OS):** login success issues a session and a CSRF token; failure returns the identical body on every
   cause; a changed `auth.local.updated` evicts live sessions on their next request; the session cap, idle and
   absolute timeouts; the cookie attribute table above asserted field by field; the CSP difference between the two
   listeners; the read-only blanket test extended over the new routes; the loopback-only validation table; the INV-1
   import test unchanged.
5. **Audit (every OS):** `Door` is stamped on every event a session produces; every event in §6.2 is a forced
   milestone; the detail strings are path-free and bounded; a failed login is recorded before the response is
   written.
6. **UI, node:** the reason table over every control × every cause; the empty-state selection including
   listing-refused versus empty; the keyboard-map cross-check against the handler bindings; the break-glass banner's
   presence keyed on `door === "local"`.
7. **UI, Go over the embedded HTML:** every `<dialog>` has `aria-labelledby`; every icon-only control has an
   accessible name; every `aria-describedby` resolves; no positive `tabindex`; the CSS token contrast pairs in both
   themes.
8. **CI-only:** a TLS end-to-end test that starts the real listener on `127.0.0.1:0` with a generated certificate and
   logs in over HTTPS (Linux job); the `go.mod` single-dependency and `go mod tidy` no-op assertions; the qemu smoke
   test extended to assert that **8771 is not bound** when no hash is configured, which is the property §2.5 exists
   for and the one most likely to regress silently.
9. **Manual, on hardware (§19):** NVDA, keyboard-only, the five viewport sizes, the certificate warning flow in
   three browsers.
10. Plus the three-GOOS vet sweep and `gofmt` before any green is claimed.

## 17. Not in M4 / deferred to v1.1

The **trash janitor** (`trash.days` stays validated, carried and unenforced — owner, 2026-09-13); **extract** (no
design for zip-slip and conflicts yet); **ACL editing** of any kind (POSIX v2, NFSv4 v3) and any "effective
permissions" computation; **thumbnails** and image previews; **in-app drag-and-drop** (both within the list and from
the desktop). Also deferred: TOTP on the break-glass account; any HTTP route that changes the break-glass password;
letting a break-glass session act *as* a named user (`CreateAs` from a `-as` flag); trusting a forwarded header on
the break-glass listener; persisting lockout state; certificate pinning or a trust-on-first-use fingerprint store in
the UI; SSE for job progress (polling stays); the dual-pane layout; "paranoid" mode; a second auth door on the main
listener (`auth.mode=both`, refused — §2.2); and an automated accessibility audit (no npm, so structural assertions
plus a manual pass — §9.6).

## 18. Residual risks

*Added, final verification (certificate):* every writer of the key pair — the daemon's arm and re-arm, `set-password`,
`cert -regenerate` — holds the credential-store lock, and `Ensure` treats a cert/key pair that does not match
(`ErrPairMismatch`, a crash between the two renames) as absent and regenerates, so the door never stays unopenable
over a torn publication.

*Added, final verification:* the config lock is `flock(2)` on Linux — the kernel releases it when a holder dies, so
there is no stale state and no break — and the O_EXCL-plus-age-break implementation is confined to non-Linux (the
Windows dev loop), where its residual two-breaker race is documented and accepted because no real credential
lives there.

*Added, round 3:* on the login route the per-IP bucket is charged before the Origin check, so a wrong Origin buys
no free refusals; the consequence is that a peer sharing the operator's source address (NAT, a proxy on the
segment) can spend the operator's 10/min budget with malformed requests — accepted, since the alternative is
unbudgeted refusals, and a lockout is never caused this way (only a wrong password advances the ladder). The
refusal wrapper is keyed on whether the request body was consumed, not on the response status, so a 2xx that
reads no body (logout without a cookie) closes the connection as a refusal would.

*Added, round 2:* the daemon (read-only toggle) and the CLI (`set-password`, `disable`) both rewrite
`config.json`; they serialise through a lock file in the config directory with a bounded wait, and the operator is
told not to do both at once. A declared-but-unsent request body cannot park a connection on the
break-glass listener: the outermost wrapper keys on whether the body was consumed (round 3 superseded the
round-2 "every non-2xx" rule), and every route reads or drains its bounded body before answering (the same
net/http drain closed for GET and for uploads on the main listener). Successful mutations drain the remainder
after decoding so keep-alive is kept. Unauthenticated `/api/session` on 8771 says only `authenticated` and
`listener`. The credential store guard covers the directory as well as the file. `set-password` generates the
certificate and a running daemon binds the listener when a credential appears, so first run needs no restart.

1. **A root daemon now answers on the LAN.** Bounded by: TLS only, one credential, a 12-byte minimum, cost-11
   bcrypt, a 10/min per-IP bucket, a 5-failure lockout, one verification at a time, a 400 ms floor, a milestone on
   every attempt, and the listener not binding at all until a password exists. It is still one more port than zero,
   and it is the reason §1 is written as a reversible decision.
2. **The certificate is trust-on-first-use with no revocation.** An operator who clicks through the warning without
   comparing the fingerprint has no protection against a man in the middle on their own LAN — and the situation this
   door exists for (the NAS is broken, the operator is in a hurry) is exactly when nobody compares fingerprints.
   `docs/qnap-install.md` puts the comparison in the numbered procedure; that is mitigation, not a fix.
3. **The break-glass password lives outside QTS's account policy.** No expiry, no complexity policy, no
   two-factor, no central revocation, and it does not rotate when the QTS admin password does. An operator who sets
   it once and forgets it has left a permanent root credential on the NAS. `break-glass status` reports when it was
   set so an audit can find a stale one.
4. **Lockout is in memory**; a restart or a crash loop clears it (§5.3). Accepted deliberately — the alternative
   locks the operator out of their own emergency door.
5. **A break-glass session creates root-owned content** (§2.4), which is the most likely lasting damage: a support
   folder full of files the real user cannot then delete. Stated in the banner, in the docs, and in the audit line.
6. **bcrypt on a weak ARM core is a CPU cost an unauthenticated caller controls.** The semaphore of 1 plus queue
   depth 4 bounds it to one core's worth; on a two-core unit under an active job that is still noticeable.
7. **The 400 ms floor is a floor, not constant time.** A determined attacker measuring from the LAN may still
   distinguish paths that exceed it under load. Accepted: the information leaked is whether an account is locked,
   which the `Retry-After` on a `429` states outright anyway.
8. **The keyboard-map cross-check tests the table against the bindings, not against the browser.** A chord the QTS
   desktop swallows still passes CI; the mouse equivalent is what makes that survivable, and the manual pass is what
   finds it.
9. **Contrast is asserted arithmetically over token pairs**, which does not catch a token used against a background
   it was never paired with. Structural, not perceptual.
10. **Documentation drifts.** `docs/identity.md` describes fail-closed rules enforced in five packages; nothing
    executes the document. The release checklist's item 3 is a human reading it, and that is the weakest link in
    §12.
11. **Every M1–M3 residual stands unchanged** (PLAN §2.0, §2.4, §2.5, §2.6, §2.7, and the M3 list). M4 adds a door
    and a coat of paint; it closes none of them, and the CHANGELOG's `Security` section says so rather than letting a
    v1.0.0 tag imply they were fixed.
12. **A distributed guess is bounded by bcrypt, not by a lockout (Astra round 1 #4).** With the lockout per
    source, an attacker with many LAN addresses is limited only by the serialised verification (one bcrypt at a
    time, cost 11 — a few per second on NAS silicon) and each source's 10/min bucket. Against a 12-byte-minimum
    password that is hopeless; against a weak one the operator chose anyway, it is the residual. Every attempt is
    still a milestone, and a spray across sources is counted and reported (§5, the dropped-source summary).
13. **Explicit certificate and key paths are the operator's** (Astra round 1 #9, round 2 #1). The daemon refuses
    to arm unless the pair it actually **loads** is root-owned with no group/other bits on the key and every
    ancestor of the *resolved* path is root-owned and not group/other-writable — checked on the opened
    descriptors, with `O_NOFOLLOW` on the final component, so a root-owned symlink into a share does not pass on
    the strength of its own directory. It does not otherwise guard those locations, and an administrator who
    points the key at a share and then downloads it through the app has only exercised the root they already had.
    A refused arm is retried by the credential watcher on every tick (round 2 #2), so fixing the directory
    recovers the listener without a restart.
15. **The daemon never renews a certificate silently** (round 2 #3, superseding §3's "regenerated within 30
    days"). Start-up and late-bind both serve the existing pair while it is valid and log an audited warning
    inside the 30-day window — *run `break-glass cert -regenerate`* — so the fingerprint an operator was told to
    compare changes only by their own act or by expiry. An expired or torn pair is unusable and is regenerated,
    with the new fingerprint logged. A stored hash must be a complete bcrypt encoding — 60 bytes, `$2a$`/`$2b$`/
    `$2y$`, cost in range, 53 base64 characters, and a checksum tail whose two spare bits are zero — not merely a
    parsable header (round 2 #4, round 3 #4). The salt tail's spare bits are **not** checked (round 4 #4): bcrypt
    discards them on decode and verifies such a hash anyway, so refusing it would only lock out a working
    credential after an upgrade. A pair `set-password` or `cert` replaced while the daemon was running is printed
    as the *next* fingerprint with the restart the daemon needs (round 3 #1) — the one case where the door cannot
    be repaired without App Center, and it is stated rather than hidden.
14. **Sessionless denials on 8771 are throttled like refusals** (#3), so a flood of forged mutations shows as one
    line per source per window plus a summary, not as one line per packet — the operator sees that it happened and
    how often, not each packet.
16. **An ambiguous audit outcome loses a summary rather than duplicating it** (Astra rounds 4–6). A refusal
    summary whose line was appended but whose fsync failed, or whose write timed out after admission, is treated as
    in flight and its counters are not restored; if that line then never reached the disk, the burst is gone. The
    other choice reported the same refusals twice, which reads as a second attack; a lost summary reads as one
    fewer line in a log that still carries the per-source refusal itself. The durable write's own error is logged
    either way. Sessionless denial lines and their summaries take the **asynchronous** write path and are not
    forced milestones (round 6 #2, #4): a forged mutation is not a use of the door, and four slow QuLog calls
    from four forged sources must not hold the slots an operator's real mutation needs.
17. **A break-glass session is pinned to the address that logged in** (Astra round 6 #1). Browser cookies are
    host-scoped, not port-scoped — `__Host-` prefixes do not change that — so every browser-trusted HTTPS service on
    the NAS hostname at another port receives the root-session cookie. The door therefore refuses the cookie from
    any other peer address (audited as a sessionless denial), which turns a replay from the NAS itself, or from
    another machine, into a 401. An operator whose address changes mid-session signs in again; on a LAN that is
    rare and cheap.

**To confirm on hardware first (both units):** that **8771 is free** and QuFirewall does not block it — the whole
feature is inert otherwise, and `netstat -tlnp` before the first release is the check; that the listener **does not
bind** before `break-glass set-password` is run, and does bind within one restart after; that a browser on the LAN
reaches `https://<nas>:8771/`, shows the expected self-signed warning (not a *different* warning — a missing IP SAN
produces one, §3.3), and that the fingerprint in the page matches the one in the app log; that logging in yields an
**administrator** session whose banner says root-owned, and that a file created through it is in fact `root:root`;
that five wrong passwords lock **the source they came from** (a second machine still gets in) and that QuLog
Center shows the milestone lines for the attempts, the lockout and the login; that a correct password entered in
the page signs in without a manual reload (Astra round 1 #1 — the 204 was being treated as a failure); that `break-glass set-password` run while the daemon is up takes effect on the next attempt
and evicts a live break-glass session; that the QTS desktop window at its default size passes the 768 px rung with no
horizontal scroll and every toolbar action reachable; an NVDA pass over browse → select → permissions → confirm →
job; and finally that a package built from the tagged commit installs from a clean App Center install and reports the
tag's version in `api/session`.
