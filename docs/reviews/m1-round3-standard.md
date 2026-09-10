Protected-location deletion warnings are silently bypassed, toolbar rename can target an unselected entry, and synchronous audit writes do not provide the claimed durability.

Full review comments:

- [P1] Populate deletion warnings before silently redeeming tokens — C:/Dev/QNAPFileManager/internal/web/static/js/actions.js:130-133
  Deleting a warn-class file such as `/etc/config/smb.conf` never displays the protected-location warning: neither `deleteSingle` nor `deleteBatch` populates `summary.warnings`, so this callback always silently redeems the token. The user sees only the ordinary delete prompt, not the firmware-configuration warning. Populate warnings from the guard checks for both single and batch deletes, and require explicit acknowledgement when they exist.

- [P2] Require the focused entry to be selected before enabling rename — C:/Dev/QNAPFileManager/internal/web/static/js/list.js:129-130
  After selecting one file and moving focus to another with Ctrl+Arrow, the selection count remains one, so Rename stays enabled. Its handler calls `renameEntry(focused())`, which renames the unselected file instead of the selected one. Use the existing `one` predicate, as Properties does, or resolve the actual selected entry for the rename handler.

- [P2] Flush synchronous audit records to durable storage — C:/Dev/QNAPFileManager/internal/audit/audit.go:251-254
  `WriteSync` acknowledges completion after `emit`, but `emit` only calls `logfile.Writer.Write`, which ultimately performs an ordinary `os.File.Write` without `Sync`. Consequently, acknowledged mutation intents and safety-setting milestones can remain in the OS page cache and disappear during a NAS power failure or kernel crash. Add a synchronized flush operation to the sink and complete the durable audit path only after that flush finishes.
