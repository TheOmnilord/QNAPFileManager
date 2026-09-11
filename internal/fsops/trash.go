package fsops

// Trash: delete as a same-device rename into the nearest enclosing storage
// mount's .@qfm_trash (PLAN.md decision 10, identity plan §4.2).
//
// Four rules shape every function here.
//
//   - The trash directory is never created by this package. The root front-end
//     creates <mountRoot>/.@qfm_trash once, mode 1777, as an audited and
//     disclosed act; a worker running as an ordinary user could not create it
//     inside a share it does not own anyway. If it is not there — or if it is
//     not a directory — the answer is "no_trash" and the item is left exactly
//     where it is. A trash that cannot be reached must never become a delete.
//   - The move is a rename and nothing else. The trash root is the nearest
//     enclosing mount of the item, so the rename is same-device by
//     construction; an EXDEV here means the mount table and the filesystem
//     disagree, and the honest response is to report no_trash and leave the
//     item alone rather than to fall back to a copy the user did not ask for.
//   - The sidecar is written before the item is moved. A crash between the two
//     leaves a meta.json with nothing beside it, which TrashList skips and
//     TrashEmpty removes. The other order would leave an item nobody could name.
//   - @Recycle is never written to. It is QTS's own recycle bin, its restore
//     metadata is a firmware-private format, and an entry we put there is one
//     File Station would list and could not restore (backend plan §2.7). It
//     stays an ordinary read-only directory in the listing.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

const (
	// TrashDirName is the per-mount trash directory the front-end creates 1777.
	TrashDirName = ".@qfm_trash"
	// trashMetaName is the sidecar inside one entry directory.
	trashMetaName = "meta.json"
	// trashEntryMode is the mode of a user's trash subdirectory and of every
	// entry inside it: private to the user who deleted the item.
	trashEntryMode = 0o700
	// maxTrashMeta bounds a sidecar read. A meta.json is a few hundred bytes;
	// anything near this is not one of ours.
	maxTrashMeta = 64 << 10
	// trashEntryAttempts bounds the retries when a freshly generated entry id
	// already exists. With 32 bits of randomness per second-resolution stamp,
	// one collision is already remarkable.
	trashEntryAttempts = 8
	// trashListCap bounds one trash listing, for the same reason a directory
	// listing is capped: a panel is not a place to render a million rows.
	trashListCap = 5000
)

// ErrNoTrash means there is no usable trash directory for a path: it is not on
// a storage mount, the mount is a network one, the mount root is outside the
// jail, or .@qfm_trash is missing or is not a directory. Every caller turns it
// into a "no_trash" warning and leaves the item alone — it is never an excuse
// to delete something permanently.
var ErrNoTrash = errors.New("there is no trash directory for this path")

// trashMeta is the sidecar written beside a trashed item.
//
// OrigPath is the API path the item had. It is also carried base64-encoded
// whenever it is not valid UTF-8, because JSON cannot hold arbitrary bytes and
// a Linux filename is arbitrary bytes: without OrigPathB64 a restore of
// "/share/Public/caf\xe9" would put the item back under a mangled name. The
// same reasoning is why every path on the wire is []byte (wproto).
type trashMeta struct {
	OrigPath    string `json:"origPath"`
	OrigPathB64 string `json:"origPathB64,omitempty"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	MTime       int64  `json:"mtime"`
	Size        int64  `json:"size"`
	DeletedAt   int64  `json:"deletedAt"`
}

// orig returns the original API path as the bytes it really was.
func (m trashMeta) orig() ([]byte, error) {
	if m.OrigPathB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(m.OrigPathB64)
		if err != nil {
			return nil, fmt.Errorf("the sidecar's origPathB64 is not base64: %w", fsx.ErrBadName)
		}
		return raw, nil
	}
	if m.OrigPath == "" {
		return nil, fmt.Errorf("the sidecar names no original path: %w", fsx.ErrBadName)
	}
	return []byte(m.OrigPath), nil
}

// trashLoc is one .@qfm_trash directory: the API path it is known by and the
// already-resolved, jail-relative name every syscall against it uses.
type trashLoc struct {
	api  string
	jail fsx.Jail
	rel  string
}

// trashFor resolves the trash directory that serves apiPath.
//
// The mount lookup is a pure mount-table question (Platform.TrashRootFor): the
// NEAREST enclosing mount, which must itself be Storage and not Network, never
// climbing past a pseudo-filesystem to a storage parent. That is what makes the
// root front-end (which creates the directory) and this worker (which renames
// into it) agree on the same root without either of them stat'ing anything.
//
// The directory itself is then resolved with the leaf kept literal and lstat'ed:
// a symlink standing where .@qfm_trash should be is refused rather than
// followed, because following it would move a user's files wherever it pointed.
func trashFor(r fsx.Root, plat *platform.Platform, apiPath string) (trashLoc, error) {
	if plat == nil {
		return trashLoc{}, fmt.Errorf("no mount table is available: %w", ErrNoTrash)
	}
	osPath, err := r.OS(apiPath)
	if err != nil {
		return trashLoc{}, err
	}
	mountRoot, _, ok := plat.TrashRootFor(osPath)
	if !ok {
		return trashLoc{}, fmt.Errorf("%q is not on a storage mount: %w", apiPath, ErrNoTrash)
	}
	rootAPI, err := r.API(mountRoot)
	if err != nil {
		// Under -jail the enclosing mount can be above the jail base, which
		// means there is no trash this worker may reach.
		return trashLoc{}, fmt.Errorf("the mount root %q is not reachable: %w", mountRoot, ErrNoTrash)
	}
	return openTrashDir(r, fsx.Join(rootAPI, TrashDirName))
}

// openTrashDir resolves an existing .@qfm_trash directory and refuses anything
// that is not one.
func openTrashDir(r fsx.Root, trashAPI string) (trashLoc, error) {
	tg, err := resolve(r, trashAPI, false)
	if err != nil {
		return trashLoc{}, fmt.Errorf("%q: %w", trashAPI, ErrNoTrash)
	}
	fi, err := statAt(tg.jail, tg.rel)
	if err != nil {
		// Not created yet. The front-end creates it 1777 on demand; a worker
		// must not, and must not delete the item either.
		return trashLoc{}, fmt.Errorf("%q is not there: %w", trashAPI, ErrNoTrash)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return trashLoc{}, fmt.Errorf("%q is a %s, not a directory: %w", trashAPI, fsx.TypeString(fi.Mode()), ErrNoTrash)
	}
	return trashLoc{api: tg.api, jail: tg.jail, rel: tg.rel}, nil
}

// userDir returns the jail-relative name of this uid's subdirectory inside the
// trash, creating it 0700 if it is not there.
//
// The ownership check is the point of the function. The trash directory is
// sticky and world-writable, so the kernel stops one user removing or renaming
// another's entries — but it does not stop a user creating the *name* of
// somebody else's subdirectory first. A directory called "1001" that belongs to
// somebody else, or a symlink standing in its place, would make this worker
// move uid 1001's files somewhere its owner can read them. So the entry is
// lstat'ed after the mkdir and refused unless it is a real directory owned by
// this uid. Off Linux there is no ownership behind a FileInfo (statDetail
// reports none) and the dev box has one user, so the check degrades to the type
// test there.
func (t trashLoc) userDir(uid int) (string, error) {
	name := strconv.Itoa(uid)
	rel := relJoin(t.rel, name)
	if err := mkdirAt(t.jail, t.rel, name, trashEntryMode, false); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := statAt(t.jail, rel)
	if err != nil {
		return "", err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return "", fmt.Errorf("%s/%s is a %s, not a directory: %w", t.api, name, fsx.TypeString(fi.Mode()), ErrNoTrash)
	}
	if owner, _, _, ok := statDetail(fi); ok && owner != uid {
		return "", fmt.Errorf("%s/%s belongs to uid %d, not to uid %d: %w", t.api, name, owner, uid, ErrNoTrash)
	}
	return rel, nil
}

// newEntryDir creates <trash>/<uid>/<unix>-<8 hex> and returns its id and its
// jail-relative name. The id is time-ordered so the panel can sort without
// reading a sidecar, and random so two workers cannot collide inside a second.
func newEntryDir(j fsx.Jail, userRel string) (id, rel string, err error) {
	for attempt := 0; attempt < trashEntryAttempts; attempt++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", "", err
		}
		id = strconv.FormatInt(time.Now().Unix(), 10) + "-" + hex.EncodeToString(b[:])
		err = mkdirAt(j, userRel, id, trashEntryMode, false)
		if err == nil {
			return id, relJoin(userRel, id), nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", "", err
		}
	}
	return "", "", fmt.Errorf("could not find a free trash entry name after %d attempts: %w", trashEntryAttempts, fsx.ErrUnsupported)
}

// writeTrashMeta writes the sidecar into an entry directory, before the item is
// moved in beside it.
//
// It is fsync'ed. The ordering this file depends on — sidecar first, rename
// second — is program order, and program order survives a power cut only for
// data that has actually reached the disk. The cost is one fsync per *selected
// item*, not per file: trashing a directory of a million files is one rename
// and one sidecar.
func writeTrashMeta(j fsx.Jail, entryRel string, m trashMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := openFileAt(j, entryRel, trashMetaName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readTrashMeta reads one sidecar. A missing, oversized or malformed one is an
// error the caller skips over: a trash panel that refused to open because of
// one unreadable entry would be worse than one that lists the rest.
func readTrashMeta(j fsx.Jail, entryRel string) (trashMeta, error) {
	f, err := openFileAt(j, entryRel, trashMetaName, os.O_RDONLY, 0)
	if err != nil {
		return trashMeta{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTrashMeta+1))
	if err != nil {
		return trashMeta{}, err
	}
	if len(data) > maxTrashMeta {
		return trashMeta{}, fmt.Errorf("%s is larger than %d bytes: %w", entryRel, maxTrashMeta, fsx.ErrBadName)
	}
	var m trashMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return trashMeta{}, fmt.Errorf("%s: %w", entryRel, err)
	}
	return m, nil
}

// metaFor describes an item about to be trashed.
func metaFor(apiPath string, fi os.FileInfo) trashMeta {
	name := fsx.Base(apiPath)
	m := trashMeta{
		OrigPath:  apiPath,
		Name:      name,
		Type:      fsx.TypeString(fi.Mode()),
		Mode:      fsx.ModeOctal(fi.Mode()),
		UID:       -1,
		GID:       -1,
		MTime:     fi.ModTime().Unix(),
		Size:      fi.Size(),
		DeletedAt: time.Now().Unix(),
	}
	if !utf8.ValidString(apiPath) {
		// JSON would replace the invalid bytes with U+FFFD, so the authoritative
		// copy goes in base64 and origPath keeps whatever a human can read.
		m.OrigPathB64 = base64.StdEncoding.EncodeToString([]byte(apiPath))
	}
	if uid, gid, _, ok := statDetail(fi); ok {
		m.UID, m.GID = uid, gid
	}
	return m
}

// Trash moves each path into the nearest .@qfm_trash as this worker's user.
//
// A path with no usable trash is reported as no_trash and SKIPPED — never
// deleted. That is the whole safety property of this function: "delete to
// trash" that quietly became "delete" the moment the mount table said something
// unexpected would be the worst kind of data loss, because the user asked for
// the reversible operation.
func Trash(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int, paths []string, emit Emit) (wproto.JobResult, error) {
	var res wproto.JobResult
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		clean, err := fsx.Clean(p)
		if err != nil {
			emit.warnErr(p, err)
			res.Skipped++
			continue
		}
		name := fsx.Base(clean)
		if err := fsx.ValidName(name); err != nil {
			emit.warnErr(clean, err)
			res.Skipped++
			continue
		}
		loc, err := trashFor(r, plat, clean)
		if err != nil {
			emit.warn(clean, "no_trash", err.Error(), fsx.Errno(err))
			res.Skipped++
			continue
		}
		if fsx.IsWithin(clean, loc.api) {
			emit.warn(clean, "no_trash",
				fmt.Sprintf("%q is inside the trash itself; empty the trash instead", clean), 0)
			res.Skipped++
			continue
		}
		if err := trashOne(r, loc, uid, clean, name, &res, emit); err != nil {
			return res, err
		}
	}
	return res, nil
}

// trashOne moves one item. Every failure after the entry directory exists
// removes it again, so a refusal leaves no litter behind.
func trashOne(r fsx.Root, loc trashLoc, uid int, clean, name string, res *wproto.JobResult, emit Emit) error {
	src, err := resolve(r, fsx.Parent(clean), true)
	if err != nil {
		emit.warnErr(clean, err)
		res.Skipped++
		return nil
	}
	fi, err := statAt(src.jail, relJoin(src.rel, name))
	if err != nil {
		emit.warnErr(clean, err)
		res.Skipped++
		return nil
	}
	userRel, err := loc.userDir(uid)
	if err != nil {
		emit.warn(clean, "no_trash", err.Error(), fsx.Errno(err))
		res.Skipped++
		return nil
	}
	id, entryRel, err := newEntryDir(loc.jail, userRel)
	if err != nil {
		emit.warn(clean, "no_trash", err.Error(), fsx.Errno(err))
		res.Skipped++
		return nil
	}
	if err := writeTrashMeta(loc.jail, entryRel, metaFor(clean, fi)); err != nil {
		removeEntryDir(loc.jail, userRel, entryRel, id)
		emit.warn(clean, "no_trash", err.Error(), fsx.Errno(err))
		res.Skipped++
		return nil
	}
	// NOREPLACE: the entry directory was just created, so nothing can legitimately
	// be standing at this name — and if something is, overwriting it would destroy
	// whatever it was.
	if err := renameAt(src.jail, src.rel, name, loc.jail, entryRel, name, true); err != nil {
		removeEntryDir(loc.jail, userRel, entryRel, id)
		if errors.Is(err, fsx.ErrCrossDevice) || errors.Is(err, syscall.EXDEV) {
			emit.warn(clean, "no_trash",
				fmt.Sprintf("%q and its trash are on different filesystems, so it was left alone", clean), fsx.Errno(err))
		} else {
			emit.warnErr(clean, err)
		}
		res.Skipped++
		return nil
	}
	if fi.IsDir() {
		res.Dirs++
	} else {
		res.Files++
		res.Bytes += fi.Size()
	}
	emit.prog(wproto.Prog{
		Files:   res.Files + res.Dirs,
		Bytes:   res.Bytes,
		Current: []byte(clean),
		Phase:   wproto.PhaseWorking,
	})
	return nil
}

// removeEntryDir undoes a half-made trash entry: the sidecar, then the
// directory. Failures are ignored — the caller is already reporting why the
// trash did not happen, and a leftover empty entry directory is litter rather
// than damage (TrashEmpty removes it).
func removeEntryDir(j fsx.Jail, userRel, entryRel, id string) {
	_ = unlinkAt(j, entryRel, trashMetaName, false)
	_ = unlinkAt(j, userRel, id, true)
}

// trashRoots enumerates every .@qfm_trash this worker can reach: one per
// Storage, non-network mount in the table, skipping the ones with no trash
// directory and the ones outside the jail.
func trashRoots(r fsx.Root, plat *platform.Platform) []trashLoc {
	if plat == nil {
		return nil
	}
	var out []trashLoc
	seen := map[string]bool{}
	for _, m := range plat.Mounts() {
		if m.MountPoint == "" || seen[m.MountPoint] {
			continue
		}
		seen[m.MountPoint] = true
		caps := plat.For(m.MountPoint)
		if !caps.Storage || caps.Network {
			continue
		}
		rootAPI, err := r.API(m.MountPoint)
		if err != nil {
			continue
		}
		loc, err := openTrashDir(r, fsx.Join(rootAPI, TrashDirName))
		if err != nil {
			continue
		}
		out = append(out, loc)
	}
	return out
}

// TrashList returns the caller's own trashed items, newest first.
//
// Only <trash>/<uid>/ is read, on every trash root: one user's panel never
// enumerates another's entries, even though the sticky directory above is
// world-readable. An entry whose sidecar is missing, unreadable or malformed is
// skipped, and so is one whose item is not there — the half-written entry a
// crash between the sidecar and the rename leaves behind. TrashEmpty clears
// both.
func TrashList(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int) ([]wproto.TrashItem, error) {
	out := make([]wproto.TrashItem, 0, 16)
	name := strconv.Itoa(uid)
	for _, loc := range trashRoots(r, plat) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		userRel := relJoin(loc.rel, name)
		if fi, err := statAt(loc.jail, userRel); err != nil || !fi.IsDir() {
			continue
		}
		d, err := openDirRef(loc.jail, userRel)
		if err != nil {
			continue
		}
		items, err := listTrashDir(ctx, d, loc, userRel, len(out))
		d.close()
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(out) >= trashListCap {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DeletedAt != out[j].DeletedAt {
			return out[i].DeletedAt > out[j].DeletedAt
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// listTrashDir reads one <trash>/<uid>/ directory.
func listTrashDir(ctx context.Context, d *dirRef, loc trashLoc, userRel string, already int) ([]wproto.TrashItem, error) {
	var out []wproto.TrashItem
	for already+len(out) < trashListCap {
		ids, readErr := d.names(readChunk)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entryRel := relJoin(userRel, id)
			meta, err := readTrashMeta(loc.jail, entryRel)
			if err != nil {
				continue
			}
			raw, err := meta.orig()
			if err != nil {
				continue
			}
			itemName := fsx.Base(string(raw))
			if _, err := statAt(loc.jail, relJoin(entryRel, itemName)); err != nil {
				// The sidecar is there and the item is not: a crash between the
				// two writes. Not listed, because a restore of it would fail.
				continue
			}
			out = append(out, wproto.TrashItem{
				ID:        id,
				Name:      []byte(itemName),
				OrigPath:  raw,
				Type:      meta.Type,
				Size:      meta.Size,
				DeletedAt: meta.DeletedAt,
				Trash:     []byte(loc.api),
			})
			if already+len(out) >= trashListCap {
				break
			}
		}
		if errors.Is(readErr, io.EOF) || len(ids) == 0 {
			break
		}
		if readErr != nil {
			break
		}
	}
	return out, nil
}

// TrashRestore moves items back to where they came from.
//
// v1 does not recreate a missing original parent: a restore that had to invent
// three directories to put a file back is a different operation from the one
// the user asked for, and the honest answer is not_found with the path named.
// An original path that is occupied again is "exists" and is left alone rather
// than overwritten — the rename is NOREPLACE, so the kernel enforces that
// rather than a check that could be raced.
func TrashRestore(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int, ids []string, emit Emit) (wproto.JobResult, error) {
	var res wproto.JobResult
	locs := trashRoots(r, plat)
	userName := strconv.Itoa(uid)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := fsx.ValidName(id); err != nil {
			emit.warnErr(id, err)
			res.Skipped++
			continue
		}
		loc, entryRel, ok := findTrashEntry(locs, userName, id)
		if !ok {
			emit.warn(id, "not_found", fmt.Sprintf("there is no trash entry %q", id), 0)
			res.Skipped++
			continue
		}
		restoreOne(r, loc, relJoin(loc.rel, userName), entryRel, id, &res, emit)
	}
	return res, nil
}

// findTrashEntry locates one entry id across the trash roots this worker can
// reach.
func findTrashEntry(locs []trashLoc, userName, id string) (trashLoc, string, bool) {
	for _, loc := range locs {
		entryRel := relJoin(relJoin(loc.rel, userName), id)
		if fi, err := statAt(loc.jail, entryRel); err == nil && fi.IsDir() {
			return loc, entryRel, true
		}
	}
	return trashLoc{}, "", false
}

// restoreOne puts one entry back and then removes the entry directory.
func restoreOne(r fsx.Root, loc trashLoc, userRel, entryRel, id string, res *wproto.JobResult, emit Emit) {
	meta, err := readTrashMeta(loc.jail, entryRel)
	if err != nil {
		emit.warnErr(id, err)
		res.Skipped++
		return
	}
	raw, err := meta.orig()
	if err != nil {
		emit.warnErr(id, err)
		res.Skipped++
		return
	}
	orig, err := fsx.Clean(string(raw))
	if err != nil {
		emit.warnErr(id, err)
		res.Skipped++
		return
	}
	name := fsx.Base(orig)
	if err := fsx.ValidName(name); err != nil {
		emit.warnErr(orig, err)
		res.Skipped++
		return
	}
	fi, err := statAt(loc.jail, relJoin(entryRel, name))
	if err != nil {
		emit.warnErr(orig, err)
		res.Skipped++
		return
	}
	dst, err := resolve(r, fsx.Parent(orig), true)
	if err != nil {
		emit.warnErr(orig, err)
		res.Skipped++
		return
	}
	if _, err := statAt(dst.jail, dst.rel); err != nil {
		// resolve() defers the errno of a missing or unsearchable component to
		// the caller's own syscall; this is that syscall.
		if errors.Is(err, fs.ErrNotExist) {
			emit.warn(orig, "not_found",
				fmt.Sprintf("the folder %q is gone, so %q cannot be put back where it was", fsx.Parent(orig), name), 0)
		} else {
			emit.warnErr(orig, err)
		}
		res.Skipped++
		return
	}
	if err := renameAt(loc.jail, entryRel, name, dst.jail, dst.rel, name, true); err != nil {
		if errors.Is(err, fs.ErrExist) {
			emit.warn(orig, "exists", fmt.Sprintf("%q is there again, so the trashed copy was left in the trash", orig), 0)
		} else {
			emit.warnErr(orig, err)
		}
		res.Skipped++
		return
	}
	if err := unlinkAt(loc.jail, entryRel, trashMetaName, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
		emit.warnErr(orig, err)
	} else if err := unlinkAt(loc.jail, userRel, id, true); err != nil {
		emit.warnErr(orig, err)
	}
	if fi.IsDir() {
		res.Dirs++
	} else {
		res.Files++
		res.Bytes += fi.Size()
	}
	emit.prog(wproto.Prog{
		Files:   res.Files + res.Dirs,
		Bytes:   res.Bytes,
		Current: []byte(orig),
		Phase:   wproto.PhaseWorking,
	})
}

// TrashEmpty permanently removes everything in the caller's own trash, on every
// trash root this worker can reach. It is a plain recursive delete of
// <trash>/<uid>/ — the directory is recreated the next time something is
// trashed — and it is the one operation here that destroys data, which is why
// the front-end puts it behind the same confirmation ladder a permanent delete
// has.
func TrashEmpty(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int, emit Emit) (wproto.JobResult, error) {
	name := strconv.Itoa(uid)
	var targets []string
	for _, loc := range trashRoots(r, plat) {
		userRel := relJoin(loc.rel, name)
		if fi, err := statAt(loc.jail, userRel); err != nil || !fi.IsDir() {
			continue
		}
		targets = append(targets, fsx.Join(loc.api, name))
	}
	if len(targets) == 0 {
		return wproto.JobResult{}, nil
	}
	// CrossMounts is off: a trash directory lives on one filesystem by
	// construction, so anything mounted underneath one is somebody else's
	// problem and must not be emptied.
	return DeleteTree(ctx, r, plat, targets, DeleteOptions{Recursive: true}, emit)
}
