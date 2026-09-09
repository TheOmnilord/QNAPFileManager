package fsx

import (
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Root is the -jail mapping between API paths (always absolute and
// slash-separated, as if on the NAS) and OS paths (whatever the host uses).
// The zero Root is the identity used in production: "/etc/passwd" maps to
// "/etc/passwd".
//
// Every syscall in the filesystem layer goes through Root.OS; nothing else in
// the codebase constructs an OS path. That is what lets the whole daemon run
// on Windows against testdata\fakeroot, gives every test a sandbox for free
// with NewRoot(t.TempDir()), and makes "-jail /share/CACHEDEV1_DATA" a real
// defence-in-depth option for a cautious operator.
type Root struct {
	base string // "" means identity; otherwise a cleaned absolute OS path
}

// NewRoot builds a Root from a jail directory. An empty base — and "/", which
// is what an operator naturally writes for "no jail" — is the identity. The
// directory does not have to exist yet; the first syscall reports that.
func NewRoot(base string) (Root, error) {
	if base == "" || base == "/" {
		return Root{}, nil
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return Root{}, fmt.Errorf("jail root %q: %w", base, err)
	}
	abs = filepath.Clean(abs)
	// Trim a trailing separator so the prefix arithmetic in API is uniform,
	// but never down to the empty string ("/" on Linux, "C:\" on Windows both
	// survive as something usable).
	for len(abs) > 1 && isPathSeparator(abs[len(abs)-1]) {
		abs = abs[:len(abs)-1]
	}
	return Root{base: abs}, nil
}

// Jailed reports whether this Root rewrites paths at all.
func (r Root) Jailed() bool { return r.base != "" }

// Base is the OS directory the jail is rooted at, empty when not jailed.
func (r Root) Base() string { return r.base }

// OS maps an API path to the OS path to hand to a syscall. The argument is
// cleaned defensively: OS never returns a path outside the jail, whatever it
// is given.
func (r Root) OS(apiPath string) string {
	c := path.Clean("/" + strings.TrimPrefix(apiPath, "/"))
	if !r.Jailed() {
		return filepath.FromSlash(c)
	}
	rel := strings.TrimPrefix(c, "/")
	if rel == "" {
		return r.base
	}
	return filepath.Join(r.base, filepath.FromSlash(rel))
}

// API is the inverse of OS. It fails with ErrOutsideRoot for an OS path that
// is not under the jail, which is how a resolved symlink pointing out of the
// fake root is caught.
func (r Root) API(osPath string) (string, error) {
	if osPath == "" {
		return "", fmt.Errorf("empty OS path: %w", ErrNotAbsolute)
	}
	p := filepath.Clean(osPath)
	if !r.Jailed() {
		return path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(p), "/")), nil
	}
	b := r.base
	if pathEqual(p, b) {
		return "/", nil
	}
	if len(p) > len(b) && isPathSeparator(p[len(b)]) && pathEqual(p[:len(b)], b) {
		return path.Clean("/" + filepath.ToSlash(p[len(b)+1:])), nil
	}
	// A drive root such as "C:\" keeps its separator after NewRoot's trim, so
	// "C:\x" against base "C:" is handled by the branch above; anything else
	// really is outside.
	return "", fmt.Errorf("%q is outside the jail root %q: %w", osPath, b, ErrOutsideRoot)
}

// pathEqual compares two OS path fragments, case-insensitively on Windows
// where "C:\Fake Root" and "c:\fake root" name the same directory. The check
// is a runtime one rather than a build tag so both branches are vetted on
// every GOOS.
func pathEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// isPathSeparator accepts both separators on Windows and only "/" elsewhere,
// matching filepath's own rule without importing os for one predicate.
func isPathSeparator(c byte) bool {
	if c == '/' {
		return true
	}
	return runtime.GOOS == "windows" && c == '\\'
}
