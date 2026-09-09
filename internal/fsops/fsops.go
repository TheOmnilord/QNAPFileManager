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
// Paths in and out are API paths — absolute, slash-separated, already the shape
// fsx.Clean produces. Every entry point here passes what it was given through
// fsx.Clean, which refuses a "." or a ".." component rather than resolving it:
// only the kernel may resolve those, one component at a time, against the
// symlinks and the search permissions that are actually there.
// Every syscall goes through the *os.Root that fsx.Root.Open
// holds: the kernel resolves each component against that directory's descriptor
// and refuses one that would leave it, so the jail is enforced by openat rather
// than by string comparison. The unjailed production case is the same code path
// with the filesystem root as its base.
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
	"runtime"
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

// maxLinkHops bounds symlink following in resolve. It is deliberately the
// kernel's own SYMLOOP_MAX, so a cycle inside the jail ends the same way a
// cycle outside it would rather than spinning in this process.
const maxLinkHops = 40

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

// jailPath is one API path resolved against the jail: the open root every
// syscall goes through, the name to hand its methods, and the API path that
// names the result.
type jailPath struct {
	rt  *os.Root
	rel string // slash-separated and relative to rt, "." for the base itself
	api string // the API path rel corresponds to
}

// resolve walks an API path inside the jail's *os.Root, one component at a
// time, and returns what to operate on.
//
// os.Root would happily do the walk itself — but it refuses an absolute symlink
// target outright, and QTS is built out of them (/share/Public pointing at
// /share/CACHEDEV1_DATA/Public is the whole share layout). So the links are
// followed here: a relative target is spliced into the remaining components and
// resolution continues inside the root, and an absolute one is read as the host
// path it is, checked against the jail base, and re-entered from the top of the
// root. Every individual lookup is still an openat against the root's
// descriptor, so no step of this can address anything outside the jail.
//
// followFinal says whether the last component is followed. Stat, Readlink and
// OpenRead describe the link itself, so they pass false: a symlink pointing out
// of the jail is a legitimate thing to report on, as long as nothing reaches
// through it. A component that does not exist is kept as written, so the
// caller's own syscall reports the honest ENOENT.
//
// Accepted TOCTOU window: this is a resolution, not a lock. Between the lstat
// that classifies a component here and the operation the caller makes next, a
// component could be replaced. What that can no longer do is escape — the
// operation is still an openat inside the root — so the worst case is that the
// caller reads a different file inside the jail than the one that was resolved,
// which is the same race any two-syscall sequence has against a concurrent
// rename. Removing it entirely (openat2 with RESOLVE_IN_ROOT, or an O_PATH walk
// that hands the operation a descriptor rather than a name) is M1 work, when
// the mutating operations arrive and the stakes change.
func resolve(r fsx.Root, apiPath string, followFinal bool) (jailPath, error) {
	rt, err := r.Open()
	if err != nil {
		return jailPath{}, err
	}
	rel, err := r.Rel(apiPath)
	if err != nil {
		return jailPath{}, err
	}

	done := make([]string, 0, 8)
	rest := splitRel(rel)
	hops := 0
	// blocked is the failure of the first component the walk could not traverse
	// — missing, unreadable, or not a directory. Resolution carries on past it
	// so the caller's own syscall reports the honest errno for a path that only
	// names something that is not there yet, but a ".." after it cannot be
	// applied: the kernel resolves "/missing/../x" to ENOENT, and popping the
	// component here instead would quietly turn it into "/x".
	var blocked error
	for len(rest) > 0 {
		part := rest[0]
		rest = rest[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if blocked != nil {
				return jailPath{}, blocked
			}
			if len(done) == 0 {
				// Unjailed this is "/..", which the kernel answers with "/", so
				// the walk stays where it is. Under -jail it is not: the base is
				// an ordinary directory with a real parent, and "/jail/../report"
				// names the host's /report. Staying at the base instead silently
				// substituted /jail/report — a different file, served under the
				// name of one that should have been refused.
				if r.Jailed() {
					return jailPath{}, fmt.Errorf("%q climbs above the jail root: %w", apiPath, fsx.ErrOutsideRoot)
				}
				continue
			}
			// Everything in done is already resolved — every symlink among
			// them has been followed to where it points — so ".." is
			// unambiguous here in a way it never is on an unresolved path. It
			// is still the kernel's to allow: ".." is resolved *inside* the
			// directory it is written in and needs search permission on it,
			// which an Lstat of that directory from outside never tested. So
			// the permission is asked for before the component is popped, and
			// "locked/../report" fails for a user who cannot traverse "locked"
			// exactly as it would in the shell (INV-2).
			if err := checkTraversable(rt, relOf(done)); err != nil {
				return jailPath{}, err
			}
			done = done[:len(done)-1]
			continue
		}
		if len(rest) == 0 && !followFinal {
			done = append(done, part)
			continue
		}
		cand := relJoin(relOf(done), part)
		fi, err := statAt(rt, cand, false)
		if err != nil {
			// Not there at all, or not readable: keep the component as written
			// so the caller's syscall reports it, and remember why.
			if blocked == nil && len(rest) > 0 {
				blocked = err
			}
			done = append(done, part)
			continue
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if blocked == nil && len(rest) > 0 && !fi.IsDir() {
				blocked = fmt.Errorf("%q is not a directory: %w", "/"+cand, fsx.ErrBadName)
			}
			done = append(done, part)
			continue
		}
		hops++
		if hops > maxLinkHops {
			return jailPath{}, fmt.Errorf("%q: too many levels of symbolic links: %w", apiPath, fsx.ErrUnsupported)
		}
		link, err := readlinkAt(rt, cand)
		if err != nil {
			return jailPath{}, err
		}
		parts, absolute, err := linkParts(r, apiPath, link)
		if err != nil {
			return jailPath{}, err
		}
		if absolute {
			done = done[:0]
		}
		rest = append(parts, rest...)
	}
	return jailPath{rt: rt, rel: relOf(done), api: apiOf(done)}, nil
}

// linkParts turns one readlink(2) result into the components resolution should
// continue with, and says whether they start again from the jail base.
//
// An absolute target names a host path, which is how the kernel would read it
// too. Under -jail it therefore has to land inside the base or the link is an
// escape and is refused; unjailed, everything is inside by definition.
//
// The target is deliberately not cleaned first. filepath.Clean is a lexical
// rewrite, and a symlink target is not a lexical object: with
// /share/A/link → /share/B/dir, the kernel reads "/share/A/link/../report" as
// /share/B/report, because it follows link before it applies "..". Cleaning
// removes the "link/.." pair and lands on /share/A/report — a different file,
// which the UI would then happily download under the name of the one that was
// asked for. So the components go back into the walk as written and ".." is
// applied to whatever they resolve to, exactly as in the kernel.
func linkParts(r fsx.Root, apiPath, link string) (parts []string, absolute bool, err error) {
	if link == "" {
		return nil, false, fmt.Errorf("%q is a symlink with an empty target: %w", apiPath, fsx.ErrBadName)
	}
	if !isAbsLink(link) {
		return splitRel(filepath.ToSlash(link)), false, nil
	}
	osTarget := filepath.FromSlash(link)
	comps := splitOSPath(osTarget)
	// Containment is decided on the literal head of the target — everything up
	// to its first ".." — because that is the deepest point whose location is
	// known without resolving anything. Everything from the first ".." on is
	// walked inside the root, where it cannot address anything outside the jail
	// whatever it says.
	head := comps
	for i, c := range comps {
		if c == ".." {
			head = comps[:i]
			break
		}
	}
	vol := filepath.VolumeName(osTarget)
	osHead := filepath.Join(append([]string{vol + string(filepath.Separator)}, head...)...)
	base, ok := baseFor(r, osHead)
	if !ok {
		return nil, false, fmt.Errorf("%q leaves the jail root through a symlink: %w", apiPath, fsx.ErrOutsideRoot)
	}
	api, err := base.API(osHead)
	if err != nil {
		return nil, false, err
	}
	parts = splitRel(strings.TrimPrefix(api, "/"))
	return append(parts, comps[len(head):]...), true, nil
}

// splitOSPath breaks an absolute OS path into its components, volume name
// dropped and empty components (a doubled separator, a trailing one) with it.
// Both separators count on Windows, where a symlink target may be written
// either way; "." and ".." are kept, because the walk is what decides what they
// mean.
func splitOSPath(p string) []string {
	p = p[len(filepath.VolumeName(p)):]
	fields := strings.FieldsFunc(p, func(c rune) bool {
		return c == '/' || (runtime.GOOS == "windows" && c == '\\')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "." {
			out = append(out, f)
		}
	}
	return out
}

// isAbsLink reports whether a symlink target is absolute on this host. On
// Windows that includes both "C:\x" and the volume-relative "\x", either of
// which filepath.Join would treat as leaving the current directory.
func isAbsLink(link string) bool {
	if link == "" {
		return false
	}
	if link[0] == '/' {
		return true
	}
	return runtime.GOOS == "windows" && (filepath.IsAbs(link) || link[0] == '\\')
}

// baseFor returns the Root an absolute symlink target should be mapped through,
// or false when the target is outside the jail altogether. The jail base is
// re-resolved when the direct comparison fails: a jail reached through a symlink
// (/tmp on a Mac) or spelled as a Windows 8.3 short name resolves to a
// different string than the one the operator configured, and refusing the
// entire jail over a spelling would be worse than useless.
func baseFor(r fsx.Root, osPath string) (fsx.Root, bool) {
	if r.Contains(osPath) {
		return r, true
	}
	real, err := filepath.EvalSymlinks(r.Base())
	if err != nil {
		return r, false
	}
	rr, err := fsx.NewRoot(real)
	if err != nil {
		return r, false
	}
	return rr, rr.Contains(osPath)
}

// splitRel splits a root-relative path into components. "." and "" are no
// components at all, which is how the base itself is spelled.
func splitRel(rel string) []string {
	if rel == "" || rel == "." {
		return nil
	}
	return strings.Split(strings.Trim(rel, "/"), "/")
}

// relOf renders resolved components as the name an os.Root method takes.
func relOf(parts []string) string {
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, "/")
}

// relJoin names a child of a root-relative directory.
func relJoin(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

// apiOf renders resolved components as an API path.
func apiOf(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

// List returns one page of a directory listing (backend plan §2.1).
//
// The listing is read with one getdents pass and one Info per entry — on Linux
// DirEntry.Info is the data getdents already returned, so this is a single
// syscall per chunk, not an Lstat per file. A symlink's own metadata is never
// followed: Size is the length of the link text and Mode is the link's mode,
// exactly as ls -l reports them. The target is stat'ed for a symlink only when
// opts.ResolveLinks asks for its type, or at /share where the share/volume-root
// classification depends on it.
//
// The directory is opened with O_DIRECTORY where the platform has it, so a fifo
// named in the request is refused by the kernel before open(2) can block on it:
// a readable fifo with no writer would otherwise hold a worker slot until the
// process died, and sixty-four of them would take the whole worker.
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

	tg, err := resolve(r, clean, true)
	if err != nil {
		return fsx.Listing{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Listing{}, err
	}
	f, err := tg.rt.OpenFile(tg.rel, openDirFlags(), 0)
	if err != nil {
		// O_DIRECTORY reports "this is not a directory" as ENOTDIR, which the
		// API vocabulary spells bad_request. An lstat tells that apart from a
		// genuine failure without depending on an errno that differs per
		// platform.
		if fi, serr := statAt(tg.rt, tg.rel, false); serr == nil && !fi.IsDir() {
			return fsx.Listing{}, fmt.Errorf("%q is not a directory: %w", clean, fsx.ErrBadName)
		}
		// A directory we cannot read is an error, not a partial listing: a
		// half-shown /proc/<pid> that silently dropped what it could not read
		// would be worse than saying so.
		return fsx.Listing{}, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return fsx.Listing{}, err
	} else if !fi.IsDir() {
		// The platforms without O_DIRECTORY get the same answer, one syscall
		// later.
		return fsx.Listing{}, fmt.Errorf("%q is not a directory: %w", clean, fsx.ErrBadName)
	}

	shareDir := clean == "/share"
	volRoots := volumeRootNames(plat, shareDir)
	osDir, _ := r.OS(tg.api) // for the mount table only; never for a syscall
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
				// The parent is already resolved, so the link is addressed
				// directly beneath it rather than resolved again per entry.
				resolveLink(&e, r, tg.rt, relJoin(tg.rel, name), child, o.ResolveLinks || shareDir, o.ResolveLinks)
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
	// The follow variant reaches the target, so the target has to be inside the
	// jail; the plain one only describes the link itself.
	tg, err := resolve(r, clean, follow)
	if err != nil {
		return fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Entry{}, err
	}
	var fi os.FileInfo
	if follow {
		fi, err = statAt(tg.rt, tg.rel, true)
	} else {
		fi, err = statAt(tg.rt, tg.rel, false)
	}
	if err != nil {
		return fsx.Entry{}, err
	}
	e := newEntry(clean, []byte(fsx.Base(clean)), fi, IDMap())
	if e.IsSymlink {
		resolveLink(&e, r, tg.rt, tg.rel, clean, true, true)
	}
	if osPath, err := r.OS(tg.api); err == nil && plat != nil && plat.IsMountPoint(osPath) {
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
	tg, err := resolve(r, clean, false)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return readlinkAt(tg.rt, tg.rel)
}

// OpenRead opens a regular file for reading as this process's identity — which
// in production is the signed-in user, because the worker is that user. The
// kernel performs the permission check at open(2) time, which is the whole
// point: the descriptor that comes back can only be something the user was
// allowed to open, so the root front-end may safely stream from it.
//
// The final component is never followed, and on Linux that is the kernel's
// answer rather than this package's: openFinal opens the parent directory
// through the root and then the last component relative to that descriptor with
// O_NOFOLLOW, which openat really does honour. os.Root.OpenFile cannot be used
// for it — it follows a symlink that stays inside the tree and gives the
// caller's O_NOFOLLOW no say. An lstat still classifies the name first, so the
// refusal is a plain "that is a symlink" rather than an ELOOP, and the
// descriptor is checked back against that lstat with os.SameFile, which is what
// covers the platforms with no openat.
//
// Directories, devices, fifos and sockets are refused with fsx.ErrUnsupported:
// a download is bytes, and opening a fifo would block the worker forever.
// "Would block forever" is not hypothetical — open(2) on a fifo with no writer
// blocks inside the syscall, where neither the HTTP deadline nor the pool's
// call timeout can reach it, and 64 such requests would take every worker slot
// in the daemon. The lstat refuses one before the open; O_NONBLOCK on Linux is
// the backstop for the case where the name became a fifo in between. The
// descriptor is put back into blocking mode once fstat has confirmed it is a
// regular file after all.
func OpenRead(ctx context.Context, r fsx.Root, p string) (*os.File, fsx.Entry, error) {
	clean, err := fsx.Clean(p)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fsx.Entry{}, err
	}
	tg, err := resolve(r, clean, false)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fsx.Entry{}, err
	}
	before, err := statAt(tg.rt, tg.rel, false)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	if before.Mode()&fs.ModeSymlink != 0 {
		return nil, fsx.Entry{}, fmt.Errorf("%q is a symlink and the last component of a download is never followed: %w",
			clean, fsx.ErrUnsupported)
	}
	if !before.Mode().IsRegular() {
		// Refused before the open rather than after it: opening a device or a
		// fifo has effects of its own, and there is no reason to have them for
		// something that was never going to be downloaded.
		return nil, fsx.Entry{}, fmt.Errorf("%q is a %s, not a regular file: %w",
			clean, fsx.TypeString(before.Mode()), fsx.ErrUnsupported)
	}
	f, err := openFinal(tg.rt, tg.rel)
	if err != nil {
		return nil, fsx.Entry{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fsx.Entry{}, err
	}
	if !fi.Mode().IsRegular() {
		// The same answer from the descriptor itself, which is the one that
		// counts if the name was swapped after the lstat above.
		f.Close()
		return nil, fsx.Entry{}, fmt.Errorf("%q is a %s, not a regular file: %w",
			clean, fsx.TypeString(fi.Mode()), fsx.ErrUnsupported)
	}
	if !os.SameFile(before, fi) {
		f.Close()
		return nil, fsx.Entry{}, fmt.Errorf("%q was replaced between the check and the open: %w", clean, fsx.ErrUnsupported)
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

// resolveLink fills the symlink fields of an entry whose own lstat data is
// already in place. rel names the link inside rt; apiPath is the same link as
// the API sees it. wantType says whether to spend the walk that learns the
// target's type, wantResolved whether to report where it lands.
//
// A target outside the jail leaves both empty rather than leaking a host path:
// the link itself stays fully visible, because hiding it would be lying about
// the directory, but where it points is not this daemon's to disclose.
func resolveLink(e *fsx.Entry, r fsx.Root, rt *os.Root, rel, apiPath string, wantType, wantResolved bool) {
	if t, err := readlinkAt(rt, rel); err == nil {
		e.SetLinkTarget([]byte(t))
	}
	if !wantType {
		return
	}
	tg, err := resolve(r, apiPath, true)
	if err != nil {
		return // out of the jail, or a loop
	}
	// The path is fully resolved by now, so lstat is the target's own metadata
	// and needs no second pass through the link.
	st, err := statAt(tg.rt, tg.rel, false)
	if err != nil {
		return // dangling or unreadable; TargetType stays empty, as documented
	}
	e.TargetType = fsx.TypeString(st.Mode())
	if !wantResolved {
		return
	}
	e.SetLinkResolved([]byte(tg.api))
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
