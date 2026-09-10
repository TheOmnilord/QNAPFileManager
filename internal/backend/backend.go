// Package backend defines the boundary between the root front-end (internal/web)
// and whatever executes filesystem operations on behalf of a user. In production
// the implementation is internal/workerpool, which forwards every call to a
// worker process running with the user's own credentials (PLAN.md INV-1). Tests
// and the Windows dev loop use an in-process implementation.
//
// Paths are API paths: absolute, slash-separated, already passed through
// fsx.Clean. Non-UTF-8 names travel as raw bytes inside the strings; callers
// must not assume valid UTF-8.
package backend

import (
	"context"
	"os"
	"strconv"

	"qnapfilemanager/internal/fsx"
)

// Principal is the resolved identity a request runs as. Root is true only for
// an administrator session that has explicitly armed root mode; every other
// session carries its own uid, gid and supplementary groups.
type Principal struct {
	User   string
	UID    int
	GID    int
	Groups []int
	Root   bool
}

// Key returns the pool key for this principal: "root" for root mode, otherwise
// the uid. Workers are shared per key, never per session.
func (p Principal) Key() string {
	if p.Root {
		return "root"
	}
	return "uid:" + itoa(p.UID)
}

// Backend executes read-only filesystem operations as a principal. Mutating
// operations are added in M1 (see docs/design/identity-and-hero-plan.md §2.5).
type Backend interface {
	// List returns one page of a directory listing.
	List(ctx context.Context, who Principal, dir string, opts fsx.ListOptions) (fsx.Listing, error)
	// Stat returns a single entry without following the final symlink.
	Stat(ctx context.Context, who Principal, path string) (fsx.Entry, error)
	// Readlink returns the raw target of a symlink.
	Readlink(ctx context.Context, who Principal, path string) (string, error)
	// OpenRead opens a regular file for reading as the principal. The kernel
	// performs the permission check at open time; the caller only streams
	// bytes and must Close the file.
	OpenRead(ctx context.Context, who Principal, path string) (*os.File, fsx.Entry, error)
	// Ping checks that the principal's worker is alive (spawning it if needed).
	Ping(ctx context.Context, who Principal) error
}

// Mutator executes the M1 filesystem mutations as a principal: create a
// directory, rename (or move within the jail), delete a single item. It is a
// separate interface from Backend, not an extension of it, so internal/web
// keeps compiling against Backend alone until the write routes are wired; the
// production *workerpool.Pool satisfies both.
//
// As with Backend, every path is an API path already through fsx.Clean, and
// non-UTF-8 names travel as raw bytes inside the strings. The kernel makes
// every permission decision inside the worker (INV-2); these methods surface
// its errors unchanged, mapped to the shared vocabulary by fsx.Code.
type Mutator interface {
	// Mkdir creates <dir>/<name> and returns the new entry. mode 0 means 0755
	// (less the worker's umask); parents creates missing intermediates.
	Mkdir(ctx context.Context, who Principal, dir, name string, mode os.FileMode, parents bool) (fsx.Entry, error)
	// Rename moves from to to, which may be in different directories. An
	// existing destination is refused unless overwrite is set; a rename across
	// filesystems is fsx.ErrCrossDevice.
	Rename(ctx context.Context, who Principal, from, to string, overwrite bool) error
	// Delete removes one item: a file, an empty directory, or a symlink (the
	// link itself). A non-empty directory is refused (not_empty); recursion and
	// trash are M2.
	Delete(ctx context.Context, who Principal, path string) error
	// Resolve returns the canonical API path for path, resolved as the principal
	// inside the worker so the O_PATH walk enforces the user's own traversal
	// permissions (INV-2) — closing the front-end's static requested-path bypass
	// (round-3 finding 2). followLeaf resolves the whole path (an existing
	// directory, such as mkdir's dir); when it is false the parent is resolved
	// and the final component kept literal (a named entry to create, rename or
	// delete). A component the user cannot search surfaces as the kernel's
	// permission error; a non-existent leaf under !followLeaf is not an error.
	Resolve(ctx context.Context, who Principal, path string, followLeaf bool) (string, error)
}

func itoa(i int) string { return strconv.Itoa(i) }
