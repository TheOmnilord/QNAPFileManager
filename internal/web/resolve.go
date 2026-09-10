package web

import (
	"context"
	"path/filepath"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
)

// resolveForGuard hardens an API path against parent-symlink aliasing before it
// reaches guard.Check, resolving it AS THE USER inside the worker (INV-2) rather
// than as root in the front-end. The worker resolves symlinks in an operation's
// directory before it touches the filesystem — so an alias such as
// /tmp/x -> /etc/config would let a write slip past a prefix rule that names the
// real location — and the resolution runs under the user's own credentials, so a
// component the user cannot search returns the kernel's permission error rather
// than a root-resolved canonical path. This closes both the static requested-path
// permission bypass (round-3 finding 2: root resolving through a directory the
// user cannot traverse) and the root-resolution oracle: an unsearchable
// component yields EACCES, not a leaked target.
//
// followLeaf true resolves the whole existing path — used for mkdir's parent
// directory. followLeaf false resolves only the parent and keeps the final
// component literal: the correct semantics for delete (which removes the link
// itself, not its target) and rename (which operates on the named entry). The
// error is surfaced to the caller unchanged (mapped by fsx.Code): a permission
// error, ErrOutsideRoot, or any other kernel failure is returned to the client;
// there is deliberately no lexical fallback and no root-side resolution.
func (s *Server) resolveForGuard(ctx context.Context, who backend.Principal, apiPath string, followLeaf bool) (string, error) {
	return s.mutator.Resolve(ctx, who, apiPath, followLeaf)
}

// ResolveAPIPath resolves every symlink in an API path through the jail mapping
// and returns the canonical API path, or false when the path does not resolve
// (absent, or escaping the jail). It exists so the guard can canonicalize its
// protected roots at startup (guard.CanonicalizeRoots) using the same front-end
// symlink resolution INV-1 permits, without importing internal/web internals.
func ResolveAPIPath(r fsx.Root, apiPath string) (string, bool) {
	return evalToAPI(r, apiPath)
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
