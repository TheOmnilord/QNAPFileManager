# Trash size fix — review round 6 (2026-09-13, gpt-6-astra, effort high) — converged

Round 5's two findings were fixed (exact temp-name shape; `noTrashPayload` classification). Round 6, normal and
adversarial: **no actionable findings** — no regression to trash/restore/empty and no path that shows a -1 or a
wrapped total as known.

Tally: 1+4, 2+4 (2 overlap), 1+2 (1 overlap), 1+5 (1 overlap), 1+2 (1 overlap), 0+0 — 16 distinct findings, all
accepted and fixed. What the round trip bought beyond the reported bug:

- the walker never touches a Network mount it may not cross (table-first prefilter, byte-preserving key lookup) —
  a hung NFS mount under a folder no longer stalls a trash, a size or a delete pre-scan;
- checked byte accumulation everywhere a scan counts, with `capped` surfaced by Size and the delete pre-scan;
- the scan's root identity comes from the descriptor it enumerates (`Visitor.Opened`), and trash pins the item with a
  held `O_PATH` reference across scan, rename and verification;
- the sidecar rewrite is atomic, uniquely named, durable (directory fsync) and bounded by `maxTrashMeta`; an empty
  invalidates a known directory size before its first removal and sweeps its own temp litter — closing round 1's
  residual.
