package guard

// defaultRules builds the protected-path table from docs/design/
// backend-packaging-plan.md §6.2. It is data, not behaviour: guard.Check and
// guard.Classify walk this slice. Two regions are handled outside the table —
// the never-write component rule for .zfs/proc/sys (guard.go, neverWriteReason)
// and mount-point roots (the injected checker) — because neither can be
// expressed as a static prefix: .zfs appears at any depth, and volume roots are
// named dynamically (CACHEDEV1_DATA, ZFS530_DATA, legacy HDA_DATA…).
func defaultRules(installDir string, shareIsRAM bool) []Rule {
	rules := make([]Rule, 0, 32)

	// Root and every first-level system directory: deleting or renaming one of
	// these breaks the running system. Exact, so their children are untouched.
	systemDirs := []string{
		"/",
		"/bin", "/etc", "/lib", "/lib64", "/sbin", "/usr", "/var",
		"/home", "/root", "/opt", "/mnt", "/share", "/dev", "/proc", "/sys",
	}
	for _, d := range systemDirs {
		rules = append(rules, Rule{
			Prefix: d,
			Deny:   OpDelete | OpRename,
			Reason: "a top-level system directory",
			Exact:  true,
		})
	}

	// /dev: device nodes must not be written, deleted or renamed; changing their
	// mode or owner is unusual enough to confirm.
	rules = append(rules,
		Rule{Prefix: "/dev", Deny: OpDelete | OpRename | OpWrite, Warn: OpChmod | OpChown, Reason: "deleting or writing a device node breaks the running system"},
	)

	// /etc/config and the DOM config: editing firmware configuration is a
	// legitimate reason to use this app, so writes warn rather than deny; the
	// directory itself must not be deleted.
	rules = append(rules,
		Rule{Prefix: "/etc/config", Warn: OpCreate | OpWrite | OpDelete | OpChmod | OpChown | OpRename, Reason: "QTS firmware configuration"},
		Rule{Prefix: "/etc/config", Deny: OpDelete, Reason: "the QTS firmware configuration directory", Exact: true},
		Rule{Prefix: "/mnt/HDA_ROOT/.config", Warn: OpCreate | OpWrite | OpDelete | OpChmod | OpChown | OpRename, Reason: "firmware configuration on the DOM"},
		Rule{Prefix: "/mnt/HDA_ROOT/.config", Deny: OpDelete, Reason: "the firmware configuration directory on the DOM", Exact: true},
	)

	// RAM-disk trap: when /share is the QTS system tmpfs, anything created
	// directly under it is lost on reboot. Checked against the parent directory
	// (/share) with OpCreate, so it is Exact. Overridable only with a
	// confirmation token issued by the caller.
	if shareIsRAM {
		rules = append(rules, Rule{
			Prefix: "/share",
			Deny:   OpCreate,
			Reason: "the NAS system RAM disk, where files are lost on reboot",
			Exact:  true,
		})
	}

	// The daemon's own installation directory: it must not delete or rewrite
	// itself mid-request, and its config (password hash) and logs (audit trail)
	// must not even be read through the file manager.
	if installDir != "" {
		rules = append(rules,
			Rule{Prefix: installDir, Deny: writeOps, Reason: "the file manager's own installation directory"},
			Rule{Prefix: installDir + "/config", Deny: writeOps | OpRead | OpTraverse, Reason: "the file manager's configuration, which holds the password hash"},
			Rule{Prefix: installDir + "/logs", Deny: writeOps | OpRead | OpTraverse, Reason: "the file manager's own logs, including the audit trail"},
		)
	}

	return rules
}
