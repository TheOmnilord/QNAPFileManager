# M2-C upload / archive / search — review round 1 (2026-09-13, gpt-6-astra, effort high)

Change under review: the M2-C stack against `docs/design/m2c-contract.md` — engine (`internal/fsops/upload*.go`,
`archive.go`, `search.go`), worker (`upload.go`, `archive.go`, JobSearch), pool client methods, routes
(`routes_upload.go`, `routes_archive.go`, `routes_search.go`), UI (upload queue + drop target, archive menu, search
dialog + results view). Normal review: 6 findings, all accepted.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the pool releases the worker right after handing back the descriptor; an eviction mid-stream truncates an archive, and a `Finalize` after a replacement reaches a worker that has no such handle. | engine/pool | **Accepted.** The archive reader's Close releases the hold; `OpenWrite` pins the client until Finalize/Discard/expiry and `Finalize` routes to the same client (worker_gone otherwise). |
| 2 | P1: archive producers are unbounded per session — `MaxConcurrent` bounds nothing once the handler returns. | engine | **Accepted.** A per-session slot (2) reserved before the pipe is returned; beyond → queue_full. |
| 3 | P2: listing actions and shortcuts act on the hidden selection while results are shown. | UI | **Accepted.** Actions gated on the active view. |
| 4 | P2: `ERROR.txt` collides with a real member of that name (reproduced duplicate members). | engine | **Accepted.** The diagnostic member goes through the collision-free allocator. |
| 5 | P2: hidden entries bypass the search caps (returned before `visited`/deadline). | engine | **Accepted.** Every touched entry counts; the deadline is checked regardless. |
| 6 | P2: results are not keyboard-reachable (all rows `tabindex=-1`, no arrow movement). | UI | **Accepted.** Roving tabindex. |

Adversarial review, round 1: 8 findings, all accepted.

| 7 | P1: `zip.Writer` retains a header per member until Close; a million-file tree exhausts a small NAS from one download. | engine | **Accepted.** Member cap; beyond it the archive is ended truncated with a note. |
| 8 | P2: search `current`/`warnings` leak protected paths the terminal hits filter (reproduced). | routes | **Accepted.** The read-side filter applied to both channels. |
| 9 | P2: `claimUpload` consumes the pin on an already-cancelled context; the route's Discard then finds no pin (worker_gone) while the worker holds the upload. | pool | **Accepted.** The pin is consumed only once the frame was sent. |
| 10 | P2: worker-side handle expiry runs only on upload traffic; an abandoned handle survives while browsing keeps the worker alive. | engine | **Accepted.** Session ticker. |
| 11 | P2: a search/archive rooted AT `/proc`, `/sys`, `/dev` or inside `.zfs` bypasses the exclusions the walker applies to children. | engine | **Accepted.** Roots validated before traversal. |
| 12 | P2: the search deadline is checked only on successful visits; an unreadable-children directory runs unbounded. | engine | **Accepted.** Context deadline on every path plus the visit count. |
| 13 | P2: clean pipe EOF after a failed or truncated producer audits as `ok`. | engine + routes | **Accepted.** Worker records each producer's outcome; `OpArchiveStatus`; `backend.Archive` returns a stream with `Outcome()`; the route audits the real outcome. |
| 14 | P2: the duplicate-basename allocator returns a taken name after 100 collisions (reproduced). | engine | **Accepted.** A genuinely unique name or a skipped root, never a duplicate member. |

Round-1 fixes landed for all fourteen (engine/pool eleven, routes two, UI two — #13 on both sides). The routes'
archive-outcome change left the audit precedence inverted (the producer's "ok" could override this end's own abort)
and two fixtures mangled; the orchestrator fixed both: this end's abort/error is recorded first, and only a clean EOF
asks the producer (ok / truncated / unknown).
