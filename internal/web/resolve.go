package web

import (
	"path/filepath"

	"qnapfilemanager/internal/fsx"
)

// resolveForGuard hardens an API path against parent-symlink aliasing before it
// reaches guard.Check. The guard reasons lexically over the spelled path, but
// the worker resolves symlinks in an operation's directory before it touches
// the filesystem — so an alias such as /tmp/x -> /etc/config would let a write
// slip past a prefix rule that names the real location. This resolves the path
// in the root front-end (INV-1 permits EvalSymlinks/Lstat/statfs/mountinfo as
// guard metadata work) through the jail mapping and returns the canonical API
// path to guard on.
//
// resolveLeaf true resolves the whole path — used for mkdir's parent directory,
// which already exists. resolveLeaf false resolves only the parent and keeps the
// final component unresolved: that is the correct semantics for delete (which
// removes the link itself, not its target) and rename (which operates on the
// named entry). filepath.EvalSymlinks resolves against the real OS path r.OS
// produces; r.API refuses a resolution that escaped the jail. On any failure
// (ENOENT, a path outside the jail, an EvalSymlinks error) it falls back to the
// cleaned input so the worker returns the honest kernel error rather than the
// guard inventing one.
func resolveForGuard(r fsx.Root, apiPath string, resolveLeaf bool) string {
	if resolveLeaf {
		if resolved, ok := evalToAPI(r, apiPath); ok {
			return resolved
		}
		return apiPath
	}
	parent := fsx.Parent(apiPath)
	leaf := fsx.Base(apiPath)
	if resolvedParent, ok := evalToAPI(r, parent); ok {
		return fsx.Join(resolvedParent, leaf)
	}
	return apiPath
}

// evalToAPI maps an API path to its OS spelling, resolves every symlink in it,
// and maps the result back to an API path. It reports false when any step fails
// — a path that does not exist, one that resolves outside the jail, or a host
// that refuses the spelling — so the caller can fall back to the lexical path.
func evalToAPI(r fsx.Root, apiPath string) (string, bool) {
	osPath, err := r.OS(apiPath)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(osPath)
	if err != nil {
		return "", false
	}
	if api, err := r.API(resolved); err == nil {
		return api, true
	}
	// EvalSymlinks may spell the jail base differently than the operator did — a
	// Windows 8.3 short name expanded, a /tmp symlink resolved on a Mac, a jail
	// itself reached through a symlink — so a direct API map reads as an escape.
	// Retry through the canonical-base alias, which names the same jail under its
	// resolved spelling (fsx.Root.CanonicalAlias). An unjailed (identity) Root
	// has no alias and never needs one.
	if alias, ok := r.CanonicalAlias(); ok {
		if api, err := alias.API(resolved); err == nil {
			return api, true
		}
	}
	return "", false
}
