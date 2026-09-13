# M2-C upload / archive / search — review round 12 (2026-09-13, gpt-6-astra, effort high; extended budget)

Round 11's three findings were fixed. Linux CI on the round-11 tree (runs 34758168317, 34758328471): root, ZFS
and Windows jobs green; the non-root race job failed on two of the new tests themselves (a seam reset racing the
handlers that read it; held readers not draining under the runner's loopback buffering) — test fixes, no engine
change, handled before round 13.

Normal review: 2 findings. Adversarial review: 3 findings ("no other qualifying defects"); two of them are the
normal pass's two.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1 (both passes): a single-job GET landing between the job turning terminal and the ledger insert finds an empty ledger, skips admission and the write deadline, and still serves the manager-held hits in full (reproduced: 863 KB responses with zero slots). | routes | **Accepted.** Admission is measured on the payload actually served: build the spliced result first, admit on its hits size, then write. |
| 2 | P2 (both passes): an eviction landing after `jobGet` snapshots the hit-free summary but before the ledger lookup returns the pre-eviction summary without the loss notice. | routes | **Accepted.** `searchResultOf` carries the ledger's dropped state into the response instead of trusting the earlier snapshot. |
| 3 | P1: archive responses are unbounded through the final HTTP write — a client that stops reading holds the 1 MiB buffer, the pipe fds and the worker hold while the producer semaphore is already released (reproduced: 32 blocked responses, zero producers active). | routes | **Accepted.** Web-side per-session archive admission held until the handler returns, plus a rolling per-write deadline that cuts a stalled client, closes the reader and releases the worker. |
