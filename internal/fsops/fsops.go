// Package fsops is the only package in the tree that touches user data. Every
// call here runs inside a per-user worker process whose credentials the kernel
// applied at fork time, which is what makes INV-1 ("no filesystem read of user
// data ever executes in the root front-end") a property of the process tree
// rather than of anybody's discipline. internal/web must never import it; an
// import-graph test in this package enforces that.
//
// M0 covers the read side only: List, Stat, Readlink and OpenRead. Mutation
// arrives in M1 and the recursive walks (TreeSize, copy, delete) in M2.
//
// Paths in and out are API paths — absolute, slash-separated, already the
// shape fsx.Clean produces. The single conversion to an OS path is fsx.Root.OS
// and it happens here, once per syscall.
package fsops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
)

// readChunk is how many directory entries are pulled out of the kernel at a
// time. It doubles as the cancellation granularity: a listing of a directory
// with a million entries notices a disconnected client within one chunk.
const readChunk = 256

// idMap is the uid/gid → name resolver. It is a process-wide value rather than
// a parameter because it is a property of the machine, not of a request: the
// worker sets it once at hello time, before it serves anything, and every
// listing in that process resolves names the same way. A nil map is fully
// supported and yields numeric ownership only.
var idMap atomic.Pointer[idmap.Map]

// SetIDMap installs the name resolver. Call it once, at worker startup.
func SetIDMap(m *idmap.Map) { idMap.Store(m) }

// IDMap returns the installed resolver, or nil.
func IDMap() *idmap.Map { return idMap.Load() }

// resolveWithin maps an API path to its OS path and, when a jail is
// configured, refuses one that leaves the jail through a symlink.
//
// fsx.Root.OS is lexical: it cannot see that a directory inside the jail is a
// symlink to /etc, and open(2) and ReadDir follow such a link happily — which
// is how a jailed daemon used to enumerate and download the whole host
// filesystem. Every component is therefore resolved with filepath.EvalSymlinks
// and the result must still be under the base. A path that does not exist is
// let through so the caller's own syscall reports the honest ENOENT, after the
// deepest ancestor that does exist has been checked.
//
// Accepted TOCTOU window: this is a check, not a lock. Between EvalSymlinks
// here and the syscall the caller makes next, a component could be replaced by
// a symlink pointing out of the jail, and the operation would follow it. The
// window is accepted for M0 and documented in
// docs/design/backend-packaging-plan.md §2.0: the jail is defence in depth
// behind the kernel's own permission check — the worker already runs as the
// signed-in user — rather than the only thing between a request and the host.
// The race-free version (openat2 with RESOLVE_IN_ROOT, or an O_PATH walk) is
// M1 work, when the mutating operations arrive and the stakes change.
func resolveWithin(r fsx.Root, apiPath string) (string, error) {
	osPath, err := r.OS(apiPath)
	if err != nil {
		return "", err
	}
	if !r.Jailed() {
		return osPath, nil
	}
	resolved, err := filepath.EvalSymlinks(osPath)
	if err != nil {
		parent := filepath.Dir(osPath)
		if parent == osPath {
			return osPath, nil
		}
		if resolved, err = filepath.EvalSymlinks(parent); err != nil {
			// Nothing along the path resolves, so there is nothing to reach
			// through it either; the caller's syscall will say so.
			return osPath, nil
		}
	}
	if !insideBase(r, resolved) {
		return "", fmt.Errorf("%q leaves the jail root through a symlink: %w", apiPath, fsx.ErrOutsideRoot)
	}
	return osPath, nil
}

// resolveParentWithin is resolveWithin for an operation that must not follow
// the final component itself: Stat and Readlink describe the link, not its
// target, so a symlink pointing out of the jail is a legitimate thing to
// report on. The directories leading to it still have to stay inside.
func resolveParentWithin(r fsx.Root, apiPath string) (string, error) {
	osPath, err := r.OS(apiPath)
	if err != nil {
		return "", err
	}
	if !r.Jailed() {
		return osPath, nil
	}
	if parent := fsx.Parent(apiPath); parent != apiPath {
		if _, err := resolveWithin(r, parent); err != nil {
			return "", err
		}
	}
	return osPath, nil
}

// insideBase reports whether a symlink-resolved OS path is still under the
// jail. The base is resolved too when the direct comparison fails: a jail
// reached through a symlink (/tmp on a Mac) or spelled as a Windows 8.3 short
// name resolves to a different string than the one the operator configured,
// and refusing the entire jail over a spelling would be worse than useless.
func insideBase(r fsx.Root, osPath string) bool {
	if r.Contains(osPath) {
		return true
	}
	real, err := filepath.EvalSymlinks(r.Base())
	if err != nil {
		return false
	}
	rr, err := fsx.NewRoot(real)
	if err != nil {
		return false
	}
	return rr.Contains(osPath)
}

// List returns one page of a directory listing (backend plan §2.1).
//
// The listing is read with one getdents pass and one Info per entry — on Linux
// DirEntry.Info is the data getdents already returned, so this is a single
// syscall per chunk, not an Lstat per file. A symlink's own metadata is never
// followed: Size is the length of the link text and Mode is the link's mode,
// exactly as ls -l reports them. os.Stat is called for a symlink only when
// opts.ResolveLinks asks for the target's type, or at /share where the
// share/volume-root classification depends on it.
//
// opts.ShowHidden is the one filter applied here, because hiding entries after
// the fact would break paging. opts.ShowVolumeRoots is deliberately *not* a
// filter: §2.2 says /share returns everything with ShareLink and VolumeRoot
// set and lets the UI decide what to show, so a page of a /share listing is
// the same page whichever way that toggle is set.
//
// plat may be nil, in which case no entry is flagged as a mount point or a
// volume root. It is used, never mutated.
func List(ctx context.Context, r fsx.Root, plat *platform.Platform, dir string, o fsx.ListOptions) (fsx.Listing, error) {
	clean, err := fsx.Clean(dir)
	if err != nil {
		return fsx.Listing{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Listing{}, err
	}

	osDir, err := resolveWithin(r, clean)
	if err != nil {
		return fsx.Listing{}, err
	}
	f, err := os.Open(osDir)
	if err != nil {
		// A directory we cannot read is an error, not a partial listing: a
		// half-shown /proc/<pid> that silently dropped what it could not read
		// would be worse than saying so.
		return fsx.Listing{}, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return fsx.Listing{}, err
	} else if !fi.IsDir() {
		return fsx.Listing{}, fmt.Errorf("%q is not a directory: %w", clean, fsx.ErrBadName)
	}

	shareDir := clean == "/share"
	volRoots := volumeRootNames(plat, shareDir)
	mounts := childMountPoints(plat, osDir)
	ids := IDMap()

	entries := make([]fsx.Entry, 0, 64)
	capped := false
	for !capped {
		des, readErr := f.ReadDir(readChunk)
		for _, de := range des {
			name := de.Name()
			hidden := strings.HasPrefix(name, ".")
			if hidden && !o.ShowHidden {
				continue
			}
			fi, err := de.Info()
			if err != nil {
				// The entry was unlinked between getdents and the stat. That
				// is a normal race in a live directory, not a failure of the
				// listing.
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return fsx.Listing{}, err
			}
			child := fsx.Join(clean, name)
			e := newEntry(child, []byte(name), fi, ids)
			if mounts[name] {
				e.MountPoint = true
			}
			if e.IsSymlink {
				// A name this host cannot express as a path (a backslash on
				// Windows) is still listed; only its target stays unresolved.
				if childOS, err := r.OS(child); err == nil {
					resolveLink(&e, r, childOS, o.ResolveLinks || shareDir, o.ResolveLinks)
				}
			}
			if shareDir {
				// §2.2: at /share we return everything and label it. The
				// symlinks are the registered shared folders; the storage
				// mounts beside them are the raw volume roots that File
				// Station will not show. Hiding either is the UI's choice.
				if e.IsSymlink && e.TargetType == "dir" {
					e.ShareLink = true
				}
				if volRoots[name] {
					e.VolumeRoot = true
					e.MountPoint = true
				}
			}
			entries = append(entries, e)
			if len(entries) >= fsx.MaxListLimit {
				capped = true
				break
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fsx.Listing{}, readErr
		}
		if err := ctx.Err(); err != nil {
			return fsx.Listing{}, err
		}
	}

	sortEntries(entries, o)

	total := len(entries)
	off, limit := page(o, total)
	out := make([]fsx.Entry, 0, min(limit, total-off))
	if off < total {
		out = append(out, entries[off:min(off+limit, total)]...)
	}

	l := fsx.Listing{
		Path:      clean,
		Parent:    fsx.Parent(clean),
		Entries:   out,
		Total:     total,
		Truncated: capped || off+len(out) < total,
		Notes:     dirNotes(plat, clean, osDir, capped),
	}
	return l, nil
}

// Stat returns one entry without following a final symlink.
func Stat(ctx context.Context, r fsx.Root, plat *platform.Platform, p string) (fsx.Entry, error) {
	return statPath(ctx, r, plat, p, false)
}

// StatFollow is Stat through the final symlink, for the properties dialog's
// "target" column. A dangling link is an error, as stat(2) says it is.
func StatFollow(ctx context.Context, r fsx.Root, plat *platform.Platform, p string) (fsx.Entry, error) {
	return statPath(ctx, r, plat, p, true)
}

func statPath(ctx context.Context, r fsx.Root, plat *platform.Platform, p string, follow bool) (fsx.Entry, error) {
	clean, err := fsx.Clean(p)
	if err != nil {
		return fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Entry{}, err
	}
	var osPath string
	if follow {
		// The follow variant reaches the target, so the target has to be
		// inside the jail; the plain one only describes the link itself.
		osPath, err = resolveWithin(r, clean)
	} else {
		osPath, err = resolveParentWithin(r, clean)
	}
	if err != nil {
		return fsx.Entry{}, err
	}
	var fi os.FileInfo
	if follow {
		fi, err = os.Stat(osPath)
	} else {
		fi, err = os.Lstat(osPath)
	}
	if err != nil {
		return fsx.Entry{}, err
	}
	e := newEntry(clean, []byte(fsx.Base(clean)), fi, IDMap())
	if e.IsSymlink {
		resolveLink(&e, r, osPath, true, true)
	}
	if plat != nil && plat.IsMountPoint(osPath) {
		e.MountPoint = true
	}
	if fsx.Parent(clean) == "/share" {
		if e.IsSymlink && e.TargetType == "dir" {
			e.ShareLink = true
		}
		if volumeRootNames(plat, true)[fsx.Base(clean)] {
			e.VolumeRoot = true
			e.MountPoint = true
		}
	}
	return e, nil
}

// Readlink returns the raw target text of a symlink, byte for byte.
func Readlink(ctx context.Context, r fsx.Root, p string) (string, error) {
	clean, err := fsx.Clean(p)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	osPath, err := resolveParentWithin(r, clean)
	if err != nil {
		return "", err
	}
	return os.Readlink(osPath)
}

// OpenRead opens a regular file for reading as this process's identity — which
// in production is the signed-in user, because the worker is that user. The
// kernel performs the permission check at open(2) time, which is the whole
// point: the descriptor that comes back can only be something the user was
// allowed to open, so the root front-end may safely stream from it.
//
// On Linux the open carries O_NOFOLLOW, so a symlink as the final component is
// refused (ELOOP) rather than followed. Off Linux that flag does not exist and
// the final component is followed; the dev loop is the only place that
// happens, and it never runs as root over real user data.
//
// Directories, devices, fifos and sockets are refused with fsx.ErrUnsupported:
// a download is bytes, and opening a fifo would block the worker forever.
//
// "Would block forever" is not hypothetical, which is why the Linux open also
// carries O_NONBLOCK: open(2) on a fifo with no writer blocks inside the
// syscall, where neither the HTTP deadline nor the pool's call timeout can
// reach it, and 64 such requests would take every worker slot in the daemon.
// The descriptor is put back into blocking mode only once fstat has proved it
// is a regular file — the check has to be on the descriptor, since checking
// the name first would just be a race.
func OpenRead(ctx context.Context, r fsx.Root, p string) (*os.File, fsx.Entry, error) {
	clean, err := fsx.Clean(p)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fsx.Entry{}, err
	}
	osPath, err := resolveWithin(r, clean)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	f, err := os.OpenFile(osPath, openReadFlags(), 0)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fsx.Entry{}, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fsx.Entry{}, fmt.Errorf("%q is a %s, not a regular file: %w",
			clean, fsx.TypeString(fi.Mode()), fsx.ErrUnsupported)
	}
	if err := clearNonblock(f); err != nil {
		f.Close()
		return nil, fsx.Entry{}, fmt.Errorf("restoring blocking mode on %q: %w", clean, err)
	}
	return f, newEntry(clean, []byte(fsx.Base(clean)), fi, IDMap()), nil
}

// newEntry fills everything that comes from a single FileInfo. The FileInfo
// must be lstat data for a symlink to describe the link rather than its target.
func newEntry(apiPath string, name []byte, fi os.FileInfo, ids *idmap.Map) fsx.Entry {
	var e fsx.Entry
	e.SetName(name)
	e.SetPath([]byte(apiPath))
	m := fi.Mode()
	e.Type = fsx.TypeString(m)
	e.Size = fi.Size()
	e.Mode = fsx.ModeOctal(m)
	e.ModeStr = fsx.ModeString(m)
	e.MTime = fi.ModTime()
	e.IsSymlink = m&fs.ModeSymlink != 0
	e.Hidden = len(name) > 0 && name[0] == '.'
	if uid, gid, nlink, ok := statDetail(fi); ok {
		e.UID, e.GID, e.Nlink = uid, gid, nlink
		if ids != nil {
			e.User = ids.User(uid)
			e.Group = ids.Group(gid)
		}
	}
	return e
}

// resolveLink fills the three symlink fields. target says whether to spend an
// os.Stat learning the target's type; resolved says whether to spend the full
// EvalSymlinks walk on top of that. A target outside the jail leaves
// LinkResolved empty rather than leaking a host path.
func resolveLink(e *fsx.Entry, r fsx.Root, osPath string, target, resolved bool) {
	if t, err := os.Readlink(osPath); err == nil {
		e.LinkTarget = t
	}
	if !target {
		return
	}
	st, err := os.Stat(osPath)
	if err != nil {
		return // dangling or unreadable; TargetType stays empty, as documented
	}
	e.TargetType = fsx.TypeString(st.Mode())
	if !resolved {
		return
	}
	rp, err := filepath.EvalSymlinks(osPath)
	if err != nil {
		return
	}
	if api, err := r.API(rp); err == nil {
		e.LinkResolved = api
	}
}

// typeRank orders the "type" sort so a directory listing reads the way a file
// manager is expected to: containers, then content, then the odd ones.
func typeRank(t string) int {
	switch t {
	case "dir":
		return 0
	case "symlink":
		return 1
	case "file":
		return 2
	case "fifo":
		return 3
	case "socket":
		return 4
	case "device":
		return 5
	}
	return 6
}

// sortEntries orders a listing. Every comparison falls through to the name,
// which is unique within one directory, so the order is total: two pages of
// the same listing can never overlap or drop an entry, whatever the sort key.
func sortEntries(es []fsx.Entry, o fsx.ListOptions) {
	key := o.Sort
	if !fsx.ValidSortKey(key) || key == "" {
		key = fsx.SortName
	}
	less := func(a, b *fsx.Entry) bool {
		switch key {
		case fsx.SortSize:
			if a.Size != b.Size {
				return a.Size < b.Size
			}
		case fsx.SortMTime:
			if !a.MTime.Equal(b.MTime) {
				return a.MTime.Before(b.MTime)
			}
		case fsx.SortType:
			if ra, rb := typeRank(a.Type), typeRank(b.Type); ra != rb {
				return ra < rb
			}
		}
		return a.Name < b.Name
	}
	sort.SliceStable(es, func(i, j int) bool {
		a, b := &es[i], &es[j]
		if o.DirsFirst {
			// Directories first is applied before Desc on purpose: reversing
			// it would put files above folders, which nobody means by
			// "sort descending".
			ad, bd := a.Type == "dir", b.Type == "dir"
			if ad != bd {
				return ad
			}
		}
		if o.Desc {
			return less(b, a)
		}
		return less(a, b)
	})
}

// page normalises Offset and Limit against the caps in fsx.
func page(o fsx.ListOptions, total int) (off, limit int) {
	limit = o.Limit
	if limit <= 0 {
		limit = fsx.DefaultListLimit
	}
	if limit > fsx.MaxListLimit {
		limit = fsx.MaxListLimit
	}
	off = o.Offset
	if off < 0 {
		off = 0
	}
	if off > total {
		off = total
	}
	return off, limit
}

// volumeRootNames is the set of names directly under /share that are storage
// mounts — CACHEDEV1_DATA on QTS, ZFS530_DATA on hero, the legacy HDA_DATA.
// It is keyed by name rather than by OS path so it still answers correctly
// under -jail, where the mount table describes the host and the API path is
// the fiction the dev loop is built on.
func volumeRootNames(plat *platform.Platform, want bool) map[string]bool {
	if !want || plat == nil {
		return nil
	}
	roots := plat.VolumeRoots()
	if len(roots) == 0 {
		return nil
	}
	out := make(map[string]bool, len(roots))
	for _, m := range roots {
		out[path.Base(m.MountPoint)] = true
	}
	return out
}

// childMountPoints is the set of names in osDir that the mount table calls
// mount points. The table is consulted once per listing rather than per entry:
// Platform.IsMountPoint falls back to a pair of stat calls, which is the right
// answer for a single entry and the wrong price for ten thousand.
func childMountPoints(plat *platform.Platform, osDir string) map[string]bool {
	if plat == nil {
		return nil
	}
	parent := slashClean(osDir)
	if parent == "" {
		return nil
	}
	out := map[string]bool{}
	for _, m := range plat.Mounts() {
		if m.MountPoint == "" || m.MountPoint == "/" {
			continue
		}
		if path.Dir(m.MountPoint) == parent {
			out[path.Base(m.MountPoint)] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dirNotes are the human-readable remarks about the directory itself.
func dirNotes(plat *platform.Platform, apiPath, osPath string, capped bool) []string {
	var notes []string
	if capped {
		notes = append(notes, fmt.Sprintf("more than %d entries; the listing was capped", fsx.MaxListLimit))
	}
	if plat == nil {
		return notes
	}
	if plat.IsMountPoint(osPath) {
		notes = append(notes, "mount point")
	}
	if plat.For(osPath).Tmpfs {
		if apiPath == "/share" {
			notes = append(notes, "/share is the QTS RAM disk: anything created directly in it is lost on reboot")
		} else {
			notes = append(notes, "on a RAM disk: the contents do not survive a reboot")
		}
	}
	return notes
}

// slashClean renders an OS path in the slash form the mount table uses.
func slashClean(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(strings.ReplaceAll(filepath.ToSlash(p), `\`, "/"))
}
