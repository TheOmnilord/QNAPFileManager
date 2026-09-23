# M2-C contract — upload, archive download, search (2026-09-13)

Fixed by the orchestrator before the implementers fan out, as the M2-A and M2-B contracts were. Three pieces are
built in parallel against it: the worker side (`internal/fsops`, `internal/worker`, `internal/workerpool`), the web
routes, and the UI. Anything not stated here follows the M2-B precedent (`docs/design/m2b-contract.md`) and the
copy engine's discipline (`internal/fsops/copy.go` header). **Extract is deferred** (ui-ux plan §"Deferred"; there
is no design for zip-slip, conflicts or staging yet) — M2-C's "archive" is *download as archive*.

Sources of intent: PLAN.md M2 plan; backend-packaging-plan §2.10 (upload), §2.11 (archive), §2.13 (search), §4.5
(CSRF for non-JSON bodies); identity-and-hero-plan §2.5 (fds pass worker → front-end, never the reverse);
ui-ux-safety-plan §4 (upload progress, Ctrl+F). Where the UI plan (resumable chunked PUT) and the backend plan
(single POST) disagree, v1 takes the backend plan; resumable upload is a later refinement.

## 1. Upload

1. **Shape.** `POST /api/fs/upload?dir=<api path>&name=<base>&size=<bytes>&mtime=<unix>&conflict=skip|overwrite|rename`
   with a raw body (`application/octet-stream`, preferred) or `multipart/form-data` read with `r.MultipartReader()`
   (never `ParseMultipartForm`: QTS's temp dir is the RAM disk); one file per request. `dirB64` accepted like every
   path. The route is exempt from `MaxBytesReader(1<<20)` and from the 15 s handler context; uploads are bounded by
   free space, never by a fixed cap. CSRF is the existing three-lock scheme (`X-QFM-CSRF`, Origin/Referer == Host,
   `Sec-Fetch-Site`), which does not depend on the content type.
2. **The worker owns the file; the front-end only streams bytes into a descriptor the worker opened as the user.**
   `OpOpenWrite`: the worker resolves `dir` as the user, opens it (held), proves the destination the way the copy
   engine does, creates the file **unnamed** (`openUnnamed`, O_TMPFILE, mode `0644` under the umask — never chmod),
   proves the empty file (mode subset, expected group), installs ownership (`As` for an admin exactly as mkdir;
   nothing for a normal user), checks free space against `size` when given (`ensureSpace` on the held dirfd), and
   returns the descriptor with SCM_RIGHTS plus an opaque **handle** (`OpenWriteResp.Tmp` carries it) while KEEPING
   its own descriptor for the same inode. Fallback when O_TMPFILE is unavailable: a named `.qfm-upload-<16 hex>.part`
   created `O_EXCL` in the destination directory (the backend-plan shape), with the M2-B stat proofs; the named
   fallback's disclosure window is the documented residual.
3. `OpFinalize` (`FinalizeReq.Tmp` = the handle): the worker `fsync`s, `fstat`s and requires the size to equal the
   declared `size` when one was declared (else records what arrived), sets the mtime from `mtime` on the
   descriptor, and publishes by `linkUnnamed` (or `renameat2(RENAME_NOREPLACE)` for the named fallback) under the
   conflict policy: `skip` → `exists` and the inode is discarded; `overwrite` → link under an unguessable temp name
   then `publish` over the target with the kind re-check (a directory or symlink at the name is `conflict`);
   `rename` → keep-both `(2)` naming. `Discard: true` closes and forgets the handle (an unnamed inode simply
   vanishes; the named fallback is `unlinkIfOurs`). Handles are per worker session, expire after **10 minutes**
   without Finalize and on session end (closed and, for the named fallback, unlinked — same identity discipline).
4. **Route behaviour.** Guard on both spellings of `dir`: `OpCreate` on `dir` and on `dir/<name>`, `guard.Contains`
   on both, the `/share` ramdisk rule, read-only; `overwrite` is L1 (confirm) as in copy; protected is L2 via the
   ladder; `NeedsConfirm` does not apply (one file). The handler: authorize → `OpenWrite` → stream the body into the
   fd with a 1 MiB buffer and the request context (a client disconnect → `Finalize{Discard}`) → `Finalize` →
   `201 {entry, path}` (or `409 exists`/`conflict`, `507 no_space`). Audit: intent before OpenWrite (`op:"upload"`,
   the path, declared size), result after Finalize (bytes, outcome) — the sync-mutation pairing mkdir uses.
5. **UI.** The Upload button opens a file chooser (multiple); desktop drag-and-drop onto the list uploads into the
   current folder (the existing drop suppressor becomes the drop target; a dropped folder is refused with a note —
   directory uploads are a later refinement). Files upload **sequentially**, each as one XHR with `upload.onprogress`;
   the Operations panel shows them as local entries (kind `upload`, title `Uploading: <name>`, bytes / total,
   cancel = abort the XHR) merged with the server's jobs; a conflict `409` (exists) offers Skip / Overwrite / Keep
   both once per batch ("apply to all"). On completion the listing refreshes. Node tests for the pure parts (queue
   order, progress merge, conflict decision).

## 2. Archive download

1. **Shape.** `GET /api/fs/archive?path=<api path>&path=…&format=zip|tgz&name=<download name>` (paths repeated,
   `pathB64` variants accepted; cap `maxJobRoots`). Streams `application/zip` or `application/gzip` with
   `Content-Disposition: attachment`, no `Content-Length`, chunked, flushed every ~4 MiB. Exempt from the 15 s
   handler context like download.
2. **Every byte is read as the user.** New plain op `OpArchive` (`ArchiveReq{Paths, Format, CrossMounts}`): the
   worker validates the roots (resolved as the user; symlinks never followed; `ProtectSnapshots`; crossing by
   decision 9), creates a **pipe**, replies OK immediately with the pipe's **read end** passed by SCM_RIGHTS, and
   then — in a goroutine bounded by the session — walks the trees on held descriptors and writes the archive into
   the write end: `archive/zip` (Zip64 automatic; `Store` for `zip|gz|tgz|7z|rar|mp4|mkv|jpg|jpeg|png|heic|mp3|
   flac|aac|ogg|webm|webp|avif`, `Deflate` otherwise) or `archive/tar` + `gzip`. Entry names are the path relative
   to the selected root's parent, forward slashes, non-UTF-8 bytes kept (zip: raw bytes with the UTF-8 flag unset).
   Modes, mtimes and symlinks (as symlink entries) are recorded; FIFOs/sockets/devices skipped with a warning in
   `ERROR.txt`. A per-item read failure is recorded and the walk continues; a fatal error mid-stream writes a final
   `ERROR.txt` member listing what failed and **closes the pipe without the trailer**, so the client's unzip
   reports truncation (design §2.11). The reader going away (EPIPE) ends the walk. Nothing is written anywhere on
   disk.
3. **Route behaviour.** Guard `OpRead|OpTraverse` on every root, both spellings; `guard.Contains` on the sources
   (a tree holding a protected prefix is refused as protected — an archive of `/etc` is not a download). Audit one
   `archive` intent/result pair (roots, bytes streamed, outcome incl. `truncated`). The front-end copies the pipe
   to the response with `io.Copy` and periodic `Flush`.
4. **UI.** "Download as ZIP" / "Download as tar.gz" for one or more selected items (toolbar menu + context menu);
   a single file still uses the plain download. The browser shows the download progress; no job entry.

## 3. Search

1. **Shape.** `POST /api/jobs/search` `{roots:[pathRef…], query, glob?:bool, hidden?:bool, crossMounts?:bool,
   kind?: "any"|"file"|"dir"}` → `202 {job}`; results are in the terminal job result. `query` is a case-insensitive
   **substring** of the entry name (Unicode simple folding); `glob:true` treats it as a `path.Match` pattern on the
   name. Empty query → 422.
2. **Worker.** `JobSearch` with `SearchReq{Roots, Query, Glob, Hidden, CrossMounts, Kind, MaxHits, MaxVisited,
   MaxDuration}`; the route sends the caps (`1000` hits, `10 000 000` visited, `300 s`; raised from `500 000` and `60 s` on 2026-09-23, when a search of `/share` on the TVS-h1688X hit the visit bound before reaching the share it was looking in) — the worker also clamps to
   those maxima. Walk on held descriptors, never following symlinks, `ProtectSnapshots`, crossing by decision 9;
   `/proc`, `/sys`, `/dev` never entered (the walker's Storage rule). Progress: `Files` = visited, `FilesTotal` =
   -1, `Current` = the directory being scanned, prog frames coalesced by the worker as today. Result:
   `JobResult.Hits []fsx.Entry` (new, `omitempty`) in walk order, `JobResult.Detail` "first 1000 of many" when
   truncated, `Skipped` = unreadable directories, plus `SearchStats{Visited, Hits, Truncated, Reason}` folded into
   `Detail`. Cancel = partial hits with `Cancelled`.
3. **Route behaviour.** `OpTraverse` on every root, both spellings; `guard.Contains` does NOT refuse (searching a
   tree that contains a protected prefix is reading, and the worker cannot read what the user cannot) — but the
   route never lists hits under a Deny prefix the guard hides from listing today (apply the same read-side rule
   `browse` applies). Audit intent/result (roots, query, hits, truncated). Job kind `search`, class metadata.
4. **UI.** `Ctrl+F` and a toolbar "Search…" open a dialog: query, "match pattern", "include hidden", "include
   mounted sub-folders" (hero; on QTS as well since 2026-09-23, see PLAN.md decision 9), root = current folder (editable). Submit → job → when done, the list pane switches
   to a **results view** (path column, size, modified; click opens the parent and selects the item; Escape returns);
   the Operations panel shows the job with visited count; `Detail` shown as the results header. `REFRESH_KINDS`
   unchanged (search changes nothing).

## 4. Wire (`internal/wproto`) — committed with this contract

```go
// OpenWriteReq gains:
Size     int64      `json:"s,omitempty"` // declared length, for the free-space check; 0 = unknown
MTime    int64      `json:"mt,omitempty"`
Conflict string     `json:"c,omitempty"` // decided at Finalize; carried here for the named fallback's early refusal
As       *CreateAs  `json:"as,omitempty"`
// OpenWriteResp.Tmp is an opaque handle (not a path); the descriptor rides on the frame (NFD=1).
// FinalizeReq unchanged (Tmp = handle; Final = the wanted name; Mode ignored; MTimeUnix; Conflict; Discard).
// FinalizeResp unchanged.

OpArchive Op = "archive"
type ArchiveReq struct { Paths [][]byte `json:"p"`; Format string `json:"f"`; CrossMounts bool `json:"x,omitempty"` }
type ArchiveResp struct { Name []byte `json:"n"` } // the archive's suggested file name; the pipe's read end rides on the frame

type SearchReq struct {
    Roots [][]byte `json:"r"`; Query string `json:"q"`; Glob bool `json:"g,omitempty"`; Hidden bool `json:"h,omitempty"`
    CrossMounts bool `json:"x,omitempty"`; Kind string `json:"k,omitempty"`
    MaxHits int `json:"mh,omitempty"`; MaxVisited int64 `json:"mv,omitempty"`; MaxDuration int64 `json:"md,omitempty"` // seconds
}
// JobResult gains:
Hits []fsx.Entry `json:"hits,omitempty"`
```

## 5. Backend (`internal/backend`)

```go
// Mutator gains:
OpenWrite(ctx, who Principal, req wproto.OpenWriteReq) (*os.File, wproto.OpenWriteResp, error)
Finalize(ctx, who Principal, req wproto.FinalizeReq) (wproto.FinalizeResp, error)
// Backend gains:
Archive(ctx, who Principal, req wproto.ArchiveReq) (io.ReadCloser, wproto.ArchiveResp, error)
```
The pool implements both on the existing worker→pool descriptor path (`OpenRead`'s shape); jobs still refuse
descriptors on job frames.

## 6. Tests

- fsops: upload create/finalize under every conflict policy; unnamed vs named fallback (seam); the empty-file
  proofs; expired handle reaped; free-space refusal; archive: zip and tgz read back with `archive/zip`/`archive/tar`
  (names, modes, symlink entries, non-UTF-8 name, Store vs Deflate choice, `ERROR.txt` on an injected mid-stream
  failure, EPIPE ends the walk, never follows symlinks, no crossing without the flag); search: substring, glob,
  hidden, kind, caps (hits/visited/duration via seams), cancel partial, unreadable directory skipped and counted.
  ZFS: search across datasets only with CrossMounts; archive of a dataset.
- worker/workerpool: OpenWrite→stream→Finalize round trip through a real spawned worker (fd passed); Archive pipe
  round trip; JobSearch round trip; a handle that is never finalized is closed on session end.
- web: upload raw + multipart (fake backend recording bytes), the MaxBytesReader exemption (a 3 MiB body), guard both
  spellings + ramdisk + Contains, conflict codes, client disconnect → Discard, audit pairing; archive route
  streaming + flushing + guard + audit; search route (caps sent, roots guarded, hits in the job view).
- node: upload queue/progress/conflict helpers; search results view helpers; archive menu enablement.

## 7. Amendments from the review loop (2026-09-13)

- **Archive selection ticket** (round 4): a selection whose GET URL would exceed the server's header limit is
  submitted as `POST /api/fs/archive/select` (JSON, CSRF as every unsafe method) → `201 {sel}`, then
  `GET /api/fs/archive?sel=<token>`. The store keeps the REQUESTED spellings only, per session, bounded (16 entries,
  256 KiB per ticket, 8 MiB store-wide → `429 queue_full`), 60 s, single use, reaped on every select/consume and
  from the daemon's minute ticker; consumption runs the identical resolve + guard + containment pipeline as the
  direct form (`authorizeArchive`) — nothing decided at select time is trusted at stream time (round 5).
- The download `name` is capped at 255 bytes (`413 too_large`) on both entry points.
- The polled job list omits a search's `hits`; `GET /api/jobs/{id}` carries them (round 4).
- `Connection: close` on every upload refusal written before the body is consumed, installed before
  authentication for the upload path (rounds 1–2).
- The archive route audits the producer's real outcome via `OpArchiveStatus`, asked before the worker is released;
  this end's own abort/error takes precedence (rounds 1–2).
- **Retained search results** are bounded process-wide (32 MiB, 256 jobs); the oldest results are released first
  and the job's `Detail` then says "results no longer available (memory limit); run the search again"
  (`jobs.Manager.ReplaceResult`, round 6). The worker charges hits by encoded bytes against an 8 MiB budget and an
  oversized job reply is a `too_large` error, never a disconnect.
- The search `query` is capped at 1024 bytes (`400 bad_request`); job titles are display-clipped to 80 bytes and
  audit details are bounded. Every path component in a request body is capped at NAME_MAX (255 bytes) in
  `bodyPath`, and so are the names mkdir and rename invent (round 7).
- Upload admission: 4 concurrent uploads per session, 32 process-wide (`429 queue_full`, the UI backs off and
  retries); the copy buffer is allocated only once bytes flow; a body that stalls for 30 s is dropped as
  `cancelled` (round 9).
- **Bulk result reads** (round 11): a search's hits live in the web layer's retention ledger, not in
  `jobs.Manager`, so `GET /api/jobs` copies only summaries. `GET /api/jobs/{id}` splices the hits back in, and a
  response carrying more than 64 KiB of them is *admitted*: 2 per session, 6 process-wide, otherwise
  `429 queue_full` with `Retry-After` and `Connection: close` — the same shape as the upload refusal. Each admitted
  response is written under a deadline (30 s plus 1 s per MiB, capped at 5 minutes) that is cleared on the way out,
  because the daemon sets no `WriteTimeout` and a client that stops reading would otherwise pin a complete copy of
  the result for the life of the process. The ledger bounds what is *held*; this bounds what is *in flight*.
- **Eviction wins the handoff** (round 11): a search records its hits in the ledger, drops the lock and only then
  rewrites the manager's copy. A newer search can evict it inside that gap and write its loss notice, so the
  rewrite is followed by a second look at the ledger's per-job `dropped` mark: if the job was released meanwhile the
  notice is re-applied. `noteSearchResultDropped` is idempotent and always wins, so a job whose hits are gone can
  never read back as a search that simply found nothing.
- **Bulk admission follows the payload** (round 12): `GET /api/jobs/{id}` builds the spliced result first and admits on
  what that response actually weighs. Admitting on what the ledger held left a hole — a GET landing after a search went
  terminal but before the finish hook's ledger insert found nothing recorded, skipped the slot and the deadline, and
  served the hits out of `jobs.Manager`'s own copy unbounded. One code path, one measurement.
- **The response carries the eviction notice** (round 12): `searchResultOf` applies "results no longer available" from
  the ledger's per-job `dropped` mark rather than assuming the job snapshot in hand already has it. A snapshot taken
  before the eviction landed would otherwise describe a search that found nothing.
- **Archive downloads are admitted and time out on silence** (round 12): 2 per session, 4 process-wide
  (`429 queue_full` + `Retry-After` + `Connection: close`), the slot held until the handler returns — past `closeReader`,
  so it covers the worker hold and the pipe descriptors, not merely the 1 MiB copy buffer. The worker's own
  two-producer bound governs production only: its semaphore is released when the last byte reaches the pipe, while this
  end may still be blocked writing to a client that stopped reading (32 such responses were observed with no producer
  active). Each chunk write re-arms a 60 s deadline (`archiveWriter.arm`), so it is an idle limit and not a total: a
  genuine multi-gigabyte download over a slow link keeps extending it, and only silence ends it — as `aborted`, with
  the reader closed and the worker released.
- **A read that claims a body is refused before routing** (round 13): any GET or HEAD with `ContentLength != 0` or a
  `Transfer-Encoding` gets `400 bad_request` + `Connection: close` from the request pipeline (`bodiedRead` in
  server.go), before authentication and before any handler can take a slot. net/http drains an unread request body —
  up to 256 KiB — before writing response headers unless the response is already closeAfterReply, and nothing arms a
  read deadline for that drain: a GET with `Content-Length: 1` and no body therefore blocked its handler at the first
  write, holding an archive's admission slot, worker hold and pipe (audit pair unfinished) or a bulk-result slot. The
  archive and single-job-GET routes also set `Connection: close` themselves when a body is announced, so the drain is
  skipped even if a future entry point bypasses the middleware.
- **An upload is bound to the directory, not to its name** (round 13): `wproto.FSIdentityResp` gains `Ino` and
  `SameInode`, and `OpenWriteReq` gains `DirIdentity`. The front end takes the resolved directory's identity at
  authorization time — before any part is read — and the worker refuses with `changed` (409) if the directory it
  opens is not that inode. Authorization clears a pathname; the worker opens only when the file part's headers
  arrive, and the client owns the gap: rename the authorized directory away, put a symlink to the install tree in its
  place, then send the body. A front end that cannot identify the directory refuses the upload rather than proceeding
  unbound; a build with no job spine sends no identity and the worker opens by name as before.
- **A reaped search answers 404** (round 13): if the ledger has no entry AND the manager no longer has the job,
  `GET /api/jobs/{id}` answers `404 not_found` ("This job is no longer available."). The janitor can reap a job and
  prune its entry between the handler's snapshot and its hit lookup, and serving the stale summary then reports a
  successful search that found nothing — for a search that found matches. A job the manager still holds, with hits in
  its own copy, is served as before.
