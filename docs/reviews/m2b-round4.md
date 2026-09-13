# M2-B copy/move — review round 4 (2026-09-13, gpt-6-astra, effort high)

Round 3's five findings were fixed (hard-link ctime re-baselined from a pinned descriptor; recent records trusted
only after the filesystem clock has visibly advanced, via a scratch entry in the held destination; the output
identity set fails closed with `too_many`; the picked byte reference outlives the field's text; a dialog generation
gates every continuation).

Normal review: 2 findings.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: `settled` runs after publication, so it proves the tick ended but not that the content read belongs to the settled ctime — a same-tick rewrite between the read and the tick's end still deletes the newer source. | engine | **Accepted.** Baseline → wait for the clock to pass it → re-check → then read; the recorded ctime is the settled one. |
| 2 | P1: failure cleanup unlinks the destination name (direct or temp) without the identity check `publish` has; an unrelated file saved under the name after our in-progress file was renamed aside is deleted (reproduced). | engine | **Accepted.** One `unlinkIfOurs` helper on every cleanup path. |

Adversarial review, round 4: 4 findings (#1 overlaps the normal pass's #1).

| 3 | P1: the ctime adopted after the job's own unlink of a hard link is itself unsettled; a same-tick rewrite of the sibling after `restat` passes and the remaining link is deleted. | engine | **Accepted.** The rebase goes through the same settle proof as a fresh record; if the clock cannot be shown to advance, the remaining links are kept. |
| 4 | P2: the UI's into-itself gate compares lossy display text — `/src/\xff` and `/src/\xfe` both show as `/src/�` and submission is disabled. | UI | **Accepted.** Byte comparison when both sides carry `pathB64`; ambiguity defers to the server. |
| 5 | P2: a stale paste continuation clears a newer clipboard marking. | UI | **Accepted.** Clear only the marking this submission consumed. |
