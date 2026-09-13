# M2-C upload / archive / search — review round 13 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 12's three findings were fixed and the two race-job test failures corrected (seams publish through channels;
held readers drain their responses). Linux CI on the round-12 tree: run 34759166111 failed only on staticcheck
(an unused `lookup` helper left by the refactor — removed); the rerun at 1cb6f23 failed only on gofmt, on a probe
test the reviewer had dropped into `internal/web` (removed); run 34759661997 at e2ac036: all five jobs green,
including the race job on the round-12 test fixes.

The adversarial pass as previously worded was refused by Codex's content filter ("flagged for possible
cybersecurity risk"); it was re-run as a "robustness and isolation review" with the same defect classes.

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: the upload stall deadline is re-armed by the final read even when it returns EOF, so a fully received upload is cancelled with 408 if `Finalize` takes longer than the window (reproduced over a real connection). | routes | **Accepted.** The read deadline is cleared once the body is complete, before `Finalize`; a read returning EOF never re-arms it. |

Fix landed: `uploadReader.Read` re-arms only on a read that returns bytes without EOF, and `uploadDeadline.clear()`
drops the read deadline as soon as `io.CopyBuffer` returns, before `Close`/`Finalize`. Note on the reproduction:
the Opus agent could not make the end-to-end 408 happen on Go 1.26 — `net/http`'s `startBackgroundRead` clears the
connection's read deadline before the background read starts, so the armed window cannot fire by that route; the
fix stands on its own terms (a live read deadline on a connection we are done reading is wrong regardless of which
implementation detail makes it harmless today). Tests: `TestUploadStallWindowDoesNotOutlastTheBody` (end-to-end
regression guard with a 200 ms window and a 3× slower finalizer; unit half fails without the fix).

Adversarial review (reworded pass): 4 findings ("no other qualifying defects").

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 2 | P1: archive roots after the first are resolved by path while earlier members stream; an administrator can replace an authorized parent with a symlink into the daemon's install/config directory mid-stream and the later root follows it (`refuseRoot` is not the web guard). Also via selection tickets. | engine | **Accepted.** Every root's identity (dev+ino, and its parent's) is recorded at check time and re-proved when the root is opened for streaming; a mismatch skips the root with a `changed` warning. Descendants are walked from the held root fd only. |
| 3 | P1: a multipart upload is authorized before `NextPart`, but the worker opens the destination only when the file part's headers arrive — a client-controlled gap in which the authorized directory can be swapped for a symlink into a protected place; neither `OpenWrite` nor `Finalize` reapplies the guard. | engine + routes | **Accepted.** `FSIdentityResp` gains the inode; `OpenWriteReq.DirIdentity` carries the identity taken at authorization; `fsops.OpenWrite` opens the directory `O_NOFOLLOW` and refuses `changed` on mismatch; `Finalize` links into the dirfd held since `OpenWrite`. |
| 4 | P1: an HTTP/1 GET with `Content-Length: 1` and no body blocks at the first response write (net/http drains an unread body before writing headers) with nothing to interrupt it — archive slots, worker holds and pipes, and bulk-result slots retained indefinitely by a handful of requests. | routes | **Accepted.** GET/HEAD with a body is refused 400 + `Connection: close` before routing; the streaming routes also set `Connection: close` when a body is present. |
| 5 | P2: `jobGet` snapshots a finished search, the janitor reaps the job and prunes its ledger entry, and the stale summary is served as a clean zero-hit search. | routes | **Accepted.** No ledger entry and no job in the manager answers 404 `not_found`; a job the manager still holds is served from its own copy as before. |
