# M2-B copy/move — review round 18 (2026-09-13, gpt-6-astra, effort high; final verification pass)

Round 17's fixes (inheritable ACL of the staging directory proved against the destination; transfer routes in the
denial-audit classifier). Linux CI on the round-17 tree (run 34745213909): all five jobs green.

Normal review: 2 findings, both in the new inheritable-ACL comparison.

| # | Finding | Owner | Judgement |
|---|---|---|---|
| 1 | P1: the per-entry match ignores NFSv4 ordering and applies the subset allowance to DENY entries; a dropped or reordered DENY, or a DENY with a reduced mask, passes and grants more than the destination. | engine | **Accepted.** Ordered one-to-one comparison; ALLOW may narrow, DENY may only widen. |
| 2 | P2: a files-only inheritable ACE legitimately gains `INHERIT_ONLY` on a child directory; the raw-flag comparison refuses it, so ordinary hero shares with such ACEs would be refused as unverified. | engine | **Accepted.** Compare against the expected child flags per the NFSv4 inheritance rules. |

Adversarial review, round 18: 2 findings — identical to the normal pass's #1 (DENY ordering/coverage) and #2
(expected child inherit flags). Nothing else. After the fix, a targeted review of `acl.go` alone closes the loop.
