# Review — admin-content-ownership mkdir fix

Reviewer: gpt-6-astra, **high** reasoning effort (the owner set Astra reviews to
high on 2026-09-12). Two passes, normal and adversarial, over commit `6a4918e`
(new content an admin creates is chowned to the real user). CI for that commit
was green on all five jobs. The four M1/M2 residuals (§2.0/§2.4/§2.5/§2.6/§2.7)
were off-limits.

## Findings — five, all accepted

- **A [P1] Directory-substitution TOCTOU** (`mutate_linux.go`). Between
  `mkdirat` and the re-open, an attacker who can rename in the parent can move a
  pre-existing directory over the just-created leaf; `O_NOFOLLOW` rejects
  symlinks, not directory substitutions, so root would chown/chmod a foreign
  directory (a root-owned one holding data → exposed). Same class as §2.7. Fix:
  before chowning, verify the opened directory on its fd is a directory, owned
  by uid 0, and **empty** — a substituted directory with data is refused, an
  empty one exposes nothing. No mtime check (it caused slow-FS false failures in
  §2.7 and here would wrongly leave a legitimate folder root-owned).
- **B [P1] ACL disturbance from `fchmod(0770)`.** On a QNAP ACL share a blind
  chmod widens the POSIX ACL mask; on a hero dataset with `aclmode=discard` it
  discards inherited ACLs — without the level-2 confirmation decision 12
  requires. Fix: **drop the chmod entirely.** Chowning alone fixes the reported
  bug (the admin becomes the owner and can write), preserves ACLs and the
  inherited setgid bit, and defers group-write for other admins to the M3
  ACL-aware permissions feature.
- **C [P2] Classification checked on the resolved parent only.** A warn/protected
  requested parent that is a symlink to a normal location resolves normal and
  wrongly gets the admin's uid. Fix: require BOTH the requested and the resolved
  parent to classify normal (stricter-of-both, §2.0/§2.5).
- **D [P2] `fchmod` cleared the inherited setgid bit.** Moot once B drops the
  chmod; a test now asserts the setgid bit survives.
- **E [P2] Partial-state reporting.** A chown failure after the folder exists
  showed a refusal without refreshing, so a retry hit `exists`. Fix: accurate
  error phase, and `newFolder` refreshes the listing on error and explains that
  the folder was created but left system-owned.

## Confirmed sound (adversarial)

Clients cannot supply `As` or a uid through the body; `UID`/`Root` derive from
the verified identity; the initial `EEXIST` correctly skips the ownership
change; leaf symlinks are refused; no new import cycle; the `-1` sentinels
survive the `wproto.CreateAs` ↔ `fsops.Owner` translation.

## Disposition

All five accepted; one Opus hardening pass (fsops + web + the newFolder UI). A
high-effort re-review follows.
