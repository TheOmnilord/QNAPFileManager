# M2-B copy/move — round 19, targeted closing review of `acl.go` (2026-09-13, gpt-6-astra, effort high)

Round 18's two findings were fixed (ordered one-to-one comparison with DENY semantics; expected child inherit
flags). A single targeted pass over the inheritable-ACL judgement asked one question: can any child sequence that
passes grant MORE than the destination's inheritance would, and does the model REFUSE a legitimate directory?

**No over-granting sequence was found.** Two legitimate-refusal cases:

| # | Finding | Judgement |
|---|---|---|
| 1 | P2: ZFS `aclinherit=noallow`/`discard` omit ALLOW entries entirely; a child with fewer entries is refused as unproved. | **Accepted.** Ordered subsequence match in which only ALLOW entries may be absent (omitting an ALLOW only removes access); every DENY must remain, in order; extras refuse. |
| 2 | P2: a `DIRECTORY_INHERIT|INHERIT_ONLY` entry loses `INHERIT_ONLY` on the child directory; the model kept the parent's flag and refused. | **Accepted.** The expected child clears `INHERIT_ONLY` on `DIRECTORY_INHERIT` entries; both forms accepted, since either grants exactly what the parent said. |

The loop closes here: nineteen passes, 101 distinct findings, every one accepted and fixed or recorded as a
residual in `copy.go`'s header. The one thing only hardware can answer is whether an ordinary QuTS hero share
stages ("private") or falls back ("shared, one warning") rather than refusing — PLAN.md names it as the first
check of the M2-B hardware test.
