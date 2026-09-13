# M2-C upload / archive / search — review round 4 (2026-09-13, gpt-6-astra, effort high)

Round 3's four findings were fixed. Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P2: revealing a hit under an active quick filter selects a hidden row; Delete/Copy/Move then act on the invisible selection. | UI | **Accepted.** The filter is cleared before the reveal. |
| 2 | P2: the polled job list serialises every retained search's hits — megabytes per 500 ms poll after a few large searches. | routes + UI | **Accepted.** Hits omitted from the list, kept on the single-job endpoint; the UI reads them there. |

Adversarial review, round 4: 1 finding.

| 3 | P2: a valid multi-file archive selection (500 long names) makes the GET URL exceed `MaxHeaderBytes` (64 KiB) → 431 before the handler (reproduced). | routes + UI | **Accepted.** A per-session, single-use, 60-second selection ticket (`POST /api/fs/archive/select` → `GET /api/fs/archive?sel=`); the UI uses it whenever the direct URL would be long. |
