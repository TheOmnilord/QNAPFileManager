package fsx

import (
	"fmt"
	"path"
	"strings"
)

// Clean checks and tidies an API path: absolute, slash-separated, with no "."
// or ".." component anywhere in it. API paths are always Linux-shaped, even
// when the process is running on Windows against a -jail directory; the
// conversion to an OS path happens in exactly one place, Root.OS.
//
// It rejects the empty string, a relative path, an embedded NUL (which the
// kernel would truncate at), and a leading "//" — collapsing that to a plain
// absolute path would be wrong on a UNC-aware host, where it names a server,
// so it must not be silently accepted here and re-expanded later. Duplicate
// slashes elsewhere and a trailing slash are collapsed, because those name the
// same file to the kernel.
//
// A "." or a ".." is refused rather than normalised, and that is the whole
// point of this function. path.Clean is pure lexical arithmetic and the kernel
// is not: it resolves each component in turn, so "/dangling/../report" is
// ENOENT and "/locked/../report" is EACCES for a user who cannot search
// "locked", while a lexical clean turns both into "/report" and answers about a
// different file — one the request never named and the user may not be entitled
// to. Cleaning also cancels a symlink against the "..'" that follows it, which
// the kernel resolves the other way round.
//
// Nothing legitimate loses by this: the UI only ever sends canonical absolute
// paths (it builds them from the entries the worker returned), so a "." or ".."
// arriving here is a hand-made request, and the honest answer to it is
// bad_request rather than a guess at what the caller meant.
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
	var b strings.Builder
	b.Grow(len(p))
	for _, el := range strings.Split(p, "/") {
		switch el {
		case "":
			// A duplicate or trailing slash: the kernel ignores it, so do we.
			continue
		case ".", "..":
			return "", fmt.Errorf("%q contains a %q component, which only the kernel may resolve: %w", p, el, ErrBadName)
		}
		b.WriteByte('/')
		b.WriteString(el)
	}
	if b.Len() == 0 {
		return "/", nil
	}
	return b.String(), nil
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
