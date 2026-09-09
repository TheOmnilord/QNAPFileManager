package fsx

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Root is the -jail mapping between API paths (always absolute and
// slash-separated, as if on the NAS) and OS paths (whatever the host uses).
// The zero Root is the identity used in production: "/etc/passwd" maps to
// "/etc/passwd".
//
// Root is the API↔OS path mapper and the owner of the one *os.Root every
// filesystem syscall goes through (see Open). Nothing else in the codebase
// constructs an OS path or opens a jail. That is what lets the whole daemon run
// on Windows against testdata\fakeroot, gives every test a sandbox for free
// with NewRoot(t.TempDir()), and makes "-jail /share/CACHEDEV1_DATA" a real
// defence-in-depth option for a cautious operator.
//
// A Root is copied by value all over the tree; the descriptor behind Open is
// shared by every copy, so copying is free and closing is done once.
type Root struct {
	base string // "" means identity; otherwise a cleaned absolute OS path
	h    *handle
}

// identityDir is the directory an unjailed Root operates in: the filesystem
// root. On Windows that is the root of the current drive, which is the same
// thing the identity mapping has always produced ("/etc/passwd" → "\etc\passwd").
const identityDir = "/"

// identityRoot is the shared *os.Root of the unjailed mapping. It is a package
// singleton because there is only ever one of it, it costs a single descriptor
// for the life of the process, and the zero Root — which production uses and
// which no constructor ever touched — has to be usable as it stands.
var identityRoot = sync.OnceValues(func() (*os.Root, error) { return os.OpenRoot(identityDir) })

// handle is the lazily opened *os.Root behind a jailed Root, held by pointer so
// that every copy of the Root shares one descriptor.
type handle struct {
	dir  string
	once sync.Once
	r    *os.Root
	err  error
}

func (h *handle) open() (*os.Root, error) {
	h.once.Do(func() { h.r, h.err = os.OpenRoot(h.dir) })
	return h.r, h.err
}

// close releases the descriptor, and makes a later open fail rather than hand
// out a fresh one: after shutdown there is nothing left to serve.
func (h *handle) close() error {
	h.once.Do(func() { h.err = fmt.Errorf("the jail root %q is closed: %w", h.dir, os.ErrClosed) })
	if h.r == nil {
		return nil
	}
	return h.r.Close()
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
	// Trim a trailing separator so the prefix arithmetic is uniform, but never
	// below the volume root: "C:\" must stay "C:\", because "C:" on Windows
	// names the drive's current directory, not its root (a -jail C:\ once
	// listed the repository instead of the drive).
	vol := filepath.VolumeName(abs)
	for len(abs) > len(vol)+1 && isPathSeparator(abs[len(abs)-1]) {
		abs = abs[:len(abs)-1]
	}
	return Root{base: abs, h: &handle{dir: abs}}, nil
}

// Open returns the *os.Root that every filesystem operation is performed
// against: the jail directory, or the filesystem root when unjailed. It is
// opened once and shared, so callers must not close what it returns — Close
// does that, once, when the pool shuts down.
//
// The point of the type is that os.Root resolves each path component relative
// to a directory descriptor it holds, refusing any component that would leave
// the tree. That is what makes the jail a real one rather than a lexical
// check: a symlink inside it can no longer point the operation at /etc, and
// there is no window between checking a path and using it in which a component
// could be swapped for one. The unjailed production case goes through the same
// call so there is exactly one code path.
func (r Root) Open() (*os.Root, error) {
	if r.h != nil {
		return r.h.open()
	}
	return identityRoot()
}

// Close releases the jail's descriptor. Closing an unjailed Root is a no-op:
// the identity root is shared by the whole process.
func (r Root) Close() error {
	if r.h == nil {
		return nil
	}
	return r.h.close()
}

// Rel maps an API path to the name to hand a method of the *os.Root from Open:
// slash-separated, relative to the base, and "." for the base itself. It
// applies the same defensive cleaning and the same Windows backslash refusal as
// OS, so a path can never climb out of the tree even before os.Root looks at it.
func (r Root) Rel(apiPath string) (string, error) {
	c, err := r.cleanAPI(apiPath)
	if err != nil {
		return "", err
	}
	rel := strings.TrimPrefix(c, "/")
	if rel == "" {
		return ".", nil
	}
	return rel, nil
}

// cleanAPI is the shared front half of OS and Rel: clean the path to an
// absolute API path and refuse what this host would misread.
//
// The refusal is not belt and braces on Windows. fsx.Clean is a POSIX cleaner,
// so a backslash is an ordinary filename character to it — but filepath.Join
// then treats it as a separator, which turned "/..\..\PLAN.md" into a path
// above the jail. A backslash in an API path is therefore refused on Windows
// and left legal on Linux, where QNAP shares written from Windows clients
// really do contain one.
func (r Root) cleanAPI(apiPath string) (string, error) {
	c := path.Clean("/" + strings.TrimPrefix(apiPath, "/"))
	if runtime.GOOS == "windows" && strings.ContainsRune(c, '\\') {
		return "", fmt.Errorf("%q contains a backslash, which this host would read as a path separator: %w", apiPath, ErrOutsideRoot)
	}
	return c, nil
}

// Jailed reports whether this Root rewrites paths at all.
func (r Root) Jailed() bool { return r.base != "" }

// Base is the OS directory the jail is rooted at, empty when not jailed.
func (r Root) Base() string { return r.base }

// OS maps an API path to the OS path it names. The argument is cleaned
// defensively and the result is verified: OS never returns a path outside the
// jail, whatever it is given, and says ErrOutsideRoot instead.
//
// This is a name, not a handle. Syscalls go through Open and Rel, which the
// kernel resolves against the jail's descriptor; OS is for the things that
// need to talk about a path rather than open it — the mount table, the log
// line, the identity files an operator configured.
func (r Root) OS(apiPath string) (string, error) {
	c, err := r.cleanAPI(apiPath)
	if err != nil {
		return "", err
	}
	if !r.Jailed() {
		return filepath.FromSlash(c), nil
	}
	rel := strings.TrimPrefix(c, "/")
	if rel == "" {
		return r.base, nil
	}
	osPath := filepath.Clean(filepath.Join(r.base, filepath.FromSlash(rel)))
	if !r.Contains(osPath) {
		return "", fmt.Errorf("%q maps to %q, which is outside the jail root %q: %w", apiPath, osPath, r.base, ErrOutsideRoot)
	}
	return osPath, nil
}

// Contains reports whether a cleaned OS path is the jail base or lies under
// it, comparing whole path elements (and case-insensitively on Windows). An
// unjailed Root contains everything.
func (r Root) Contains(osPath string) bool {
	if !r.Jailed() {
		return true
	}
	p, b := filepath.Clean(osPath), r.base
	if pathEqual(p, b) {
		return true
	}
	// A drive root such as "C:\" keeps its separator, so the element boundary
	// is either the separator the base already ends with or the one that
	// must follow it.
	if isPathSeparator(b[len(b)-1]) {
		return len(p) > len(b) && pathEqual(p[:len(b)], b)
	}
	return len(p) > len(b) && isPathSeparator(p[len(b)]) && pathEqual(p[:len(b)], b)
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
	if r.Contains(p) {
		rest := strings.TrimLeft(p[len(b):], string(filepath.Separator))
		return path.Clean("/" + filepath.ToSlash(rest)), nil
	}
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
