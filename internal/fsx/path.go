package fsx

import (
	"fmt"
	"path"
	"strings"
)

// Clean normalises an API path: absolute, slash-separated, no "." or ".."
// elements left in it. API paths are always Linux-shaped, even when the
// process is running on Windows against a -jail directory; the conversion to
// an OS path happens in exactly one place, Root.OS.
//
// It rejects the empty string, a relative path, an embedded NUL (which the
// kernel would truncate at), and a leading "//" — path.Clean would collapse
// that to a plain absolute path, but on a UNC-aware host it names a server,
// so it must not be silently accepted here and re-expanded later.
//
// A "..", once the path is absolute, cannot escape: path.Clean resolves
// "/a/../../b" to "/b". Note this is purely lexical, so callers doing a write
// must still resolve the parent's symlinks before trusting the result.
func Clean(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path: %w", ErrNotAbsolute)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path contains a NUL byte: %w", ErrBadName)
	}
	if strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("%q looks like a UNC path: %w", p, ErrBadName)
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%q is not absolute: %w", p, ErrNotAbsolute)
	}
	c := path.Clean(p)
	// Belt and braces: unreachable for an absolute path today, but the check
	// costs nothing and is the invariant the guard depends on.
	for _, el := range strings.Split(c, "/") {
		if el == ".." {
			return "", fmt.Errorf("%q escapes the root: %w", p, ErrBadName)
		}
	}
	return c, nil
}

// Join appends elements to an already-clean API path. Names coming from a
// client must be checked with ValidName first; Join is lexical only.
func Join(base string, elem ...string) string {
	all := make([]string, 0, len(elem)+1)
	all = append(all, base)
	all = append(all, elem...)
	return path.Join(all...)
}

// Parent is the containing directory of an API path. Parent("/") is "/".
func Parent(p string) string {
	return path.Dir(p)
}

// Base is the last element of an API path.
func Base(p string) string {
	return path.Base(p)
}

// ValidName checks a single path component supplied by a client — a new
// directory name, the target of a rename. A backslash is deliberately allowed:
// it is an ordinary character in a Linux filename, and QNAP shares written
// from Windows clients do contain them.
func ValidName(name string) error {
	switch name {
	case "":
		return fmt.Errorf("empty name: %w", ErrBadName)
	case ".", "..":
		return fmt.Errorf("%q is not a usable name: %w", name, ErrBadName)
	}
	if strings.ContainsRune(name, '/') {
		return fmt.Errorf("%q contains a path separator: %w", name, ErrBadName)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%q contains a NUL byte: %w", name, ErrBadName)
	}
	return nil
}

// IsWithin reports whether p is prefix itself or lies underneath it, comparing
// whole path elements. That boundary is the whole point: "/etc/configuration"
// is not within "/etc/config", though a plain strings.HasPrefix says it is,
// and the guard's protected-path table is built out of exactly such prefixes.
//
// Both arguments are cleaned first, so callers may pass raw API paths.
func IsWithin(p, prefix string) bool {
	p = path.Clean(p)
	prefix = path.Clean(prefix)
	if prefix == "/" {
		return strings.HasPrefix(p, "/")
	}
	if p == prefix {
		return true
	}
	return strings.HasPrefix(p, prefix+"/")
}
