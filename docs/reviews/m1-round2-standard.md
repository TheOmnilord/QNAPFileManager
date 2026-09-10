The mutation paths retain a protected-path authorization race and omit destination-entry protection for rename. Selection handling and audit milestone reporting also have concrete gaps. Targeted guard, filesystem, web, and audit tests passed locally.

Full review comments:

- [P1] Dispatch mutations against the paths checked by the guard — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:335-336
  When a parent symlink changes after `resolveForGuard`, the worker resolves the original request path again and can mutate a different, protected location. For example, switching an alias from an ordinary directory to `/etc/config` between authorization and dispatch allows deletion without the required confirmation. The worker's descriptor walk does not close this earlier front-end-to-worker window. Bind dispatch to the checked resolution and reject namespace changes that invalidate it; apply this to mkdir, rename, and batch deletion as well.

- [P2] Check creation protection on the rename destination entry — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:316-320
  When the destination does not exist, only its parent is checked. Renaming `/data/folder` to `/data/.zfs` therefore succeeds even though mkdir explicitly rejects creating that protected entry. The resulting directory then cannot be renamed or deleted through this API. Check the destination's entry-specific creation protection independently of whether overwrite is requested or the destination exists.

- [P2] Reject or resolve selections containing unloaded entries — C:/Dev/QNAPFileManager/internal/web/static/js/list.js:20-22
  In directories larger than 2,000 entries, Shift-selection can span pages that were never loaded: selection stores every index, but this function silently filters out entries missing from `state.pages`. Delete then operates on only the loaded subset and reports success while other selected files remain. Fetch all selected entries before constructing the request, or explicitly refuse deletion until the selection is fully loaded.

- [P2] Pass deletion totals into the audit milestone classifier — C:/Dev/QNAPFileManager/internal/web/routes_mutate.go:121-125
  For a deletion exceeding 1 GiB or a batch exceeding 100 files, the routes calculate confirmation totals but never populate audit `Files` or `Bytes`, and every deletion calls this helper with `milestone=false`. Consequently `audit.isMilestone` never recognizes ordinary large deletions and they are not mirrored to QuLog. Emit a batch-level milestone with the measured totals, and include the measured size for single-file deletions.
