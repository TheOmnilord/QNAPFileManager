# M2-B copy/move — review round 9 (2026-09-13, gpt-6-astra, effort high)

Round 8's three findings were fixed (every recorded destination re-verified before its source is unlinked;
destination directories created from `Visitor.Opened` with metadata from the enumerated descriptor; a source
changed during the read is never published).

Normal review: 1 finding.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: a published destination rewritten in place with the same length passes the identity+length check; the source is deleted (reproduced). | engine | **Accepted.** The destination's size/mtime/ctime are recorded at publish (ctime settled on the destination directory's clock, cached per tick) and must be unchanged at delete time. |

Implementer's deviation, accepted: the destination ctime is settled at the DELETE rather than at publication —
equivalent for what timestamps can prove (a rewrite in a later tick), and one scratch per root instead of one
sleep per file on a coarse-timestamp kernel. Residual recorded: a rewrite of a published copy inside its own
publication tick is invisible to timestamps; the writer needs write access to the copy, the access they had to the
source. A second bug found by the reviewer's transient probe file and fixed: a cancellation arriving while the last
root finished was reported as success (`Copy` re-checks `ctx.Err()` before reporting).

Adversarial review, round 9: 1 finding. No M2-A regression found.

| 2 | P1: `copyUnchangedSince` stats both sides, then the destination-clock wait may sleep; a change during the wait is compared against stale stats and the source is deleted. | engine | **Accepted.** Settle first, then stat; every wait audited for the same stat-then-sleep order. |
