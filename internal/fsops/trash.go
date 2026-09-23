package fsops

// Trash: delete as a same-device rename into the nearest enclosing storage
// mount's .@qfm_trash (PLAN.md decision 10, identity plan §4.2).
//
// The threat model is what shapes every function here, and it is worth stating
// plainly because it is not the usual one. .@qfm_trash is mode 1777: a sticky
// directory SHARED by every uid on the volume. Any local user may create
// entries in it, including entries named for somebody else's uid, and an
// administrator's worker runs as ROOT (PLAN.md decision 6) — so root's own trash
// is <trash>/0/, a name any user can get to first. The sticky bit stops one user
// renaming or unlinking another's entries; it stops nothing about what they may
// create, and the OWNER of a sticky directory is exempt from its restrictions
// altogether. So:
//
//   - Every check is made on a HELD DESCRIPTOR (openat then fstat), never on a
//     pathname, because a pathname inside a directory somebody else can write to
//     is a pathname they can swap between the check and the use (F2).
//   - Nothing is consumed that is not OWNED by the uid consuming it: <uid>/ must
//     be a directory owned by exactly that uid, each entry directory likewise,
//     and meta.json must be a regular file owned by it (F1, F8). Anything else is
//     an untrusted trash entry and is skipped — never listed, never restored,
//     never deleted.
//   - Ownership is not authenticity (B1, B2). A uid-owned directory or sidecar
//     that is group- or other-WRITABLE is one another identity can still change:
//     the payload swapped under a valid sidecar, or the sidecar's origPath
//     re-pointed at a destination of the attacker's choosing. So every one of
//     those objects must also have no write bit outside its owner. The worker
//     creates them 0700 and 0600, so its own are never refused.
//   - The trash root itself must be a directory owned by uid 0 with the sticky
//     bit set (F2). An attacker-owned sticky directory standing at that name is
//     refused outright, because its owner may rename anything inside it.
//
// Four rules of the older design still hold.
//
//   - The trash directory is never created by this package. The root front-end
//     creates <mountRoot>/.@qfm_trash once, mode 1777, as an audited and
//     disclosed act (internal/trashroot). If it is not there — or is not the
//     directory described above — the answer is "no_trash" and the item is left
//     exactly where it is. A trash that cannot be reached must never become a
//     delete.
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
//     stays an ordinary read-only directory in the listing (never_write.go).

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
	"strings"
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
	// trashMetaTmpPrefix and trashMetaTmpSuffix bracket the name a REWRITTEN
	// sidecar is built under before it replaces the one beside it
	// (rewriteTrashMeta): "meta.json.<pid>-<8 hex>.new".
	//
	// The unique middle is not decoration. Two of this user's own jobs can be
	// emptying the same trash at once — the manager runs four metadata jobs in
	// parallel — and with ONE fixed temporary name they interleave: A writes its
	// temporary, B unlinks that name and creates its own empty one, and A then
	// renames B's unwritten file over meta.json. What is published is a sidecar
	// that will not parse, and the entry it describes is about to lose its
	// payload. A name only one invocation can have makes that impossible, and the
	// O_EXCL create means a collision fails rather than clobbers.
	trashMetaTmpPrefix = trashMetaName + "."
	trashMetaTmpSuffix = ".new"
	// trashMetaTmpHex is how many hex characters name the random half: four
	// bytes, eight characters (trashMetaTmpName), and the count is spelled out
	// here because isTrashMetaTmp has to demand exactly that many.
	trashMetaTmpHex = 8
	// trashMetaTmpPIDDigits bounds the decimal pid in the middle. Ten digits
	// hold every pid a 32-bit pid_t can produce, and a bound is what keeps the
	// predicate from accepting an arbitrarily long run of digits somebody chose.
	trashMetaTmpPIDDigits = 10
	// trashItemName is the FIXED internal name the trashed item itself is stored
	// under inside its entry directory (F9).
	//
	// It used to keep its original basename, and that was two bugs in one. An
	// item literally called "meta.json" could not be trashed at all — the
	// NOREPLACE rename collided with the sidecar that had just been written
	// beside it — and a crash between the sidecar and the rename left an orphan
	// meta.json that a listing had to tell apart from a payload by name. With a
	// fixed name the payload and the sidecar can never collide, the original
	// basename lives in the sidecar where it belongs, and "is the payload there"
	// is one lstat of one known name.
	trashItemName = "item"
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
// jail, or .@qfm_trash is missing, is not a directory, is not sticky, or does
// not belong to root. Every caller turns it into a "no_trash" warning and leaves
// the item alone — it is never an excuse to delete something permanently.
var ErrNoTrash = errors.New("there is no trash directory for this path")

// ErrUntrustedTrash means something inside the shared sticky trash directory is
// not this user's to consume: a <uid>/ subdirectory, an entry directory or a
// meta.json that somebody else owns, or a sidecar that is not a regular file
// (F1, F8). It wraps fsx.ErrProtected, so it reaches the client as "protected" —
// the app refused it, the kernel did not.
//
// The consequence of getting this wrong is the reason it exists. Anyone may
// create <trash>/0/<id>/ with a payload and a meta.json naming any destination
// they like; a root worker that listed it would offer an administrator a restore
// that writes an attacker's file to an attacker's chosen path.
var ErrUntrustedTrash = fmt.Errorf("untrusted trash entry: %w", fsx.ErrProtected)

// trashRootUID is the uid .@qfm_trash must belong to: root, because the root
// front-end is the only thing that creates it (trashroot.Ensure).
//
// It is a variable solely so that this package's own tests can run as an
// ordinary user, where t.TempDir() can never produce a root-owned directory —
// the same reason platform.mountProbe is one. Production never assigns to it,
// and the CI root job runs the tests with it at zero.
var trashRootUID = 0

// trashMeta is the sidecar written beside a trashed item.
//
// OrigPath is the API path the item had. It is also carried base64-encoded
// whenever it is not valid UTF-8, because JSON cannot hold arbitrary bytes and
// a Linux filename is arbitrary bytes: without OrigPathB64 a restore of
// "/share/Public/caf\xe9" would put the item back under a mangled name. The
// same reasoning is why every path on the wire is []byte (wproto).
//
// Name is the original basename, and since F9 it is the ONLY place the item's
// real name exists: on disk the payload is called "item".
type trashMeta struct {
	OrigPath    string `json:"origPath"`
	OrigPathB64 string `json:"origPathB64,omitempty"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	MTime       int64  `json:"mtime"`
	// Size is the bytes of the WHOLE item — the whole tree, for a directory —
	// and -1 when they could not be counted. Files is how many entries that is:
	// 1 for a plain file, and for a directory the count of everything under it
	// INCLUDING itself, so a measured directory is never 0.
	//
	// Size used to be fi.Size() of the item itself, which for a directory is the
	// inode's own size (4096 on ext4) and not the size of anything a user asked
	// about; trashSizeOf measures the tree instead, and trashItemOf is where an
	// older build's sidecar — one with no "files" at all — is recognised.
	Size      int64 `json:"size"`
	Files     int64 `json:"files"`
	DeletedAt int64 `json:"deletedAt"`
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
// already-resolved, jail-relative name a descriptor for it is opened from.
//
// It holds no descriptor of its own. Each operation opens one, validates it, and
// keeps it for the whole of that operation (F2); a handle cached across
// operations would be a handle nobody re-checked.
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
	return locateTrash(r, fsx.Join(rootAPI, TrashDirName))
}

// locateTrash resolves where a .@qfm_trash would be, with the leaf kept literal
// so a symlink standing there is never followed. It decides nothing about what
// is actually at that name: that is trashLoc.open's job, on a descriptor.
func locateTrash(r fsx.Root, trashAPI string) (trashLoc, error) {
	tg, err := resolve(r, trashAPI, false)
	if err != nil {
		return trashLoc{}, fmt.Errorf("%q: %w", trashAPI, ErrNoTrash)
	}
	return trashLoc{api: tg.api, jail: tg.jail, rel: tg.rel}, nil
}

// open opens the trash root and proves, on the descriptor, that it is the
// directory the root front-end made (F2).
//
// The open is O_DIRECTORY|O_NOFOLLOW through the jail's own primitives, so a
// symlink at the name is ELOOP rather than something followed and a fifo is
// ENOTDIR rather than a blocked worker. The fstat that follows is the check
// itself, and it asks three questions: is this a directory, does it belong to
// uid 0, and is the sticky bit set. The ownership question is the one that is
// easy to miss — the owner of a sticky directory is exempt from its
// restrictions, so an attacker-owned 1777 directory is not a trash with a
// safety property, it is an attacker's directory wearing the same mode bits.
//
// Everything the caller does afterwards is done RELATIVE TO the descriptor this
// returns, never by re-naming the path.
func (t trashLoc) open() (*dirRef, error) {
	d, err := openDirRef(t.jail, t.rel)
	if err != nil {
		// Both errors are wrapped: the caller distinguishes "it is simply not
		// there" (fs.ErrNotExist, which is silence) from "it is there and it is
		// not ours to use" (which is worth saying out loud).
		return nil, fmt.Errorf("%q cannot be opened as a directory: %w: %w", t.api, err, ErrNoTrash)
	}
	fi, err := d.stat()
	if err != nil {
		d.close()
		return nil, fmt.Errorf("%q cannot be described: %w: %w", t.api, err, ErrNoTrash)
	}
	if err := checkTrashRoot(t.api, fi); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

// checkTrashRoot is the fstat half of trashLoc.open, split out so it can be
// stated once and tested directly.
//
// Off Linux there is no ownership and no sticky bit behind a FileInfo
// (statDetail reports none), so the check degrades to the type test there. That
// is the dev box, not the kernel (INV-2); the CI root job runs the real thing.
func checkTrashRoot(api string, fi os.FileInfo) error {
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%q is a %s, not a directory: %w", api, fsx.TypeString(fi.Mode()), ErrNoTrash)
	}
	owner, _, _, ok := statDetail(fi)
	if !ok {
		return nil
	}
	if owner != trashRootUID {
		return fmt.Errorf("%q belongs to uid %d rather than to uid %d, so it is not the trash the front-end made: %w",
			api, owner, trashRootUID, ErrNoTrash)
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%q is not sticky (mode %v), so one user could take another's deleted files: %w",
			api, fi.Mode().Perm(), ErrNoTrash)
	}
	return nil
}

// ownedDir proves, on a held descriptor, that it refers to a directory owned by
// exactly uid and writable by nobody else (F1, B1). It is the check every
// consuming path makes — on <uid>/ and on each entry directory inside it —
// before anything in it is read, restored or removed.
//
// B1 is the half round 1 missed: ownership alone is not authenticity. A uid-owned
// entry directory that is group- or other-writable is a directory somebody else
// may write into, and writing into it is all an attacker needs — they replace the
// payload under a sidecar that is still perfectly valid, and the owner's worker
// (root's, for an administrator) then restores THEIR content to the destination
// the sidecar names. The mode is therefore part of the identity: the worker
// creates <uid>/ and every entry directory 0700 (trashEntryMode), so a legitimate
// one always passes, and anything that does not is an untrusted entry.
//
// Off Linux there is no uid and no real mode behind a FileInfo — statDetail
// reports none and a Windows directory answers 0777 — so both questions are
// skipped there rather than answered wrongly (INV-2: this is the dev box, not
// the kernel). The CI Linux jobs run the real thing.
func ownedDir(d *dirRef, api string, uid int) error {
	fi, err := d.stat()
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is a %s, not a directory: %w", api, fsx.TypeString(fi.Mode()), ErrUntrustedTrash)
	}
	owner, _, _, ok := statDetail(fi)
	if !ok {
		return nil
	}
	if owner != uid {
		return fmt.Errorf("%s belongs to uid %d, not to uid %d: %w", api, owner, uid, ErrUntrustedTrash)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		// B1: writable by a group or by everyone. Whoever can write here can
		// swap the payload out from under a sidecar this worker trusts.
		return fmt.Errorf("%s is mode %#o, so somebody other than uid %d may write in it: %w",
			api, perm, uid, ErrUntrustedTrash)
	}
	return nil
}

// userDirIn returns a held descriptor for <trash>/<uid>/, creating it 0700 if it
// is not there.
//
// The ownership check is the point of the function, and it is made on the
// descriptor rather than on the name (F1, F2). The trash directory is sticky and
// world-writable, so the kernel stops one user removing or renaming another's
// entries — but it does not stop a user creating the *name* of somebody else's
// subdirectory first. A directory called "0" that belongs to somebody else, or a
// symlink standing in its place, would make a root worker move an
// administrator's deleted files somewhere its planter can read them.
func userDirIn(root *dirRef, trashAPI string, uid int) (*dirRef, error) {
	name := strconv.Itoa(uid)
	if err := root.mkdir(name, trashEntryMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return openUserDir(root, trashAPI, uid)
}

// openUserDir opens an EXISTING <trash>/<uid>/ and validates it. It is what the
// consuming paths use — list, restore, empty — which must never create anything.
func openUserDir(root *dirRef, trashAPI string, uid int) (*dirRef, error) {
	name := strconv.Itoa(uid)
	d, err := root.child(name)
	if err != nil {
		return nil, err
	}
	if err := ownedDir(d, fsx.Join(trashAPI, name), uid); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

// newEntryDir creates <trash>/<uid>/<unix>-<8 hex> relative to the held <uid>/
// descriptor and returns its id and a descriptor for it. The id is time-ordered
// so the panel can sort without reading a sidecar, and random so two workers
// cannot collide inside a second.
func newEntryDir(user *dirRef, userAPI string, uid int) (id string, entry *dirRef, err error) {
	for attempt := 0; attempt < trashEntryAttempts; attempt++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", nil, err
		}
		id = strconv.FormatInt(time.Now().Unix(), 10) + "-" + hex.EncodeToString(b[:])
		err = user.mkdir(id, trashEntryMode)
		if err == nil {
			d, oerr := user.child(id)
			if oerr != nil {
				_ = user.unlink(id, true)
				return "", nil, oerr
			}
			// Belt and braces: the directory was just created inside a 0700
			// directory this uid owns, so nothing else could have got there — but
			// the check costs one fstat and the answer is the one the rest of the
			// file depends on.
			if cerr := ownedDir(d, fsx.Join(userAPI, id), uid); cerr != nil {
				d.close()
				_ = user.unlink(id, true)
				return "", nil, cerr
			}
			return id, d, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("could not find a free trash entry name after %d attempts: %w", trashEntryAttempts, fsx.ErrUnsupported)
}

// writeTrashMeta writes the sidecar into an entry directory, through that
// directory's held descriptor, before the item is moved in beside it.
//
// It is fsync'ed. The ordering this file depends on — sidecar first, rename
// second — is program order, and program order survives a power cut only for
// data that has actually reached the disk. The cost is one fsync per *selected
// item*, not per file: trashing a directory of a million files is one rename
// and one sidecar.
func writeTrashMeta(entry *dirRef, m trashMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := entry.openFile(trashMetaName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return writeAndSync(f, data)
}

// rewriteTrashMeta replaces an entry's existing sidecar, through that entry's
// held descriptor.
//
// It is written to a temporary name in the same directory and RENAMED over
// meta.json rather than truncated in place, and the reason is F14's: a reader
// must see the old sidecar or the new one and never a half-written file. A
// truncate that is interrupted — a crash, a full filesystem — leaves a sidecar
// that will not parse, and an entry whose sidecar will not parse is one
// TrashList skips: the payload is still sitting there holding the user's data
// and nothing can name it or restore it any more. The rename cannot do that;
// its own failure leaves the ORIGINAL sidecar exactly as it was.
//
// Only the temporary THIS invocation created is ever unlinked, and it is
// unlinked on every failure path. The one window that outlives this process is a
// crash between the create and the rename, which leaves a stray
// meta.json.<pid>-<hex>.new behind; an empty recognises those and clears them
// (removeSidecarLitter), and until one runs the entry is listable and restorable
// throughout. That residual is the class PLAN.md §2.4 accepts: narrow,
// disclosed, and far less dangerous than what it replaces.
//
// The size of the REPLACEMENT is checked before anything is published. A sidecar
// is accepted up to maxTrashMeta and re-marshalling can grow one — JSON escapes
// what the kernel allows in a name, and a re-escaped near-limit sidecar can
// cross it — and publishing an oversized one would make readTrashMeta refuse the
// entry from then on: listing, restore and the empty's own B6 check all reject
// it, which for a payload that is still there is exactly the loss F14 exists to
// prevent. Refusing to publish keeps the original, which is merely out of date.
func rewriteTrashMeta(entry *dirRef, m trashMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data) > maxTrashMeta {
		return fmt.Errorf("the rewritten sidecar would be %d bytes, more than the %d a sidecar may be: %w",
			len(data), maxTrashMeta, fsx.ErrUnsupported)
	}
	tmp, err := trashMetaTmpName()
	if err != nil {
		return err
	}
	f, err := entry.openFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := writeAndSync(f, data); err != nil {
		_ = entry.unlink(tmp, false)
		return err
	}
	if err := entry.renameOver(tmp, trashMetaName); err != nil {
		_ = entry.unlink(tmp, false)
		return err
	}
	// The file's own fsync put its BYTES on the disk; this one puts the rename
	// there. Without it a filesystem that does not order the two can come back
	// from a power cut having kept the removals that follow and lost the sidecar
	// that was supposed to precede them — the old, whole-tree total standing
	// beside a half-emptied entry, which is the single state this rewrite exists
	// to make impossible.
	return syncDir(entry)
}

// trashMetaTmpName is one invocation's private name for a sidecar being
// rewritten. The pid names the process and the random half separates two
// rewrites inside it, so no two can collide and each can only ever remove its
// own.
func trashMetaTmpName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return trashMetaTmpPrefix + strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(b[:]) + trashMetaTmpSuffix, nil
}

// isTrashMetaTmp recognises a sidecar temporary by name alone.
//
// It demands the WHOLE shape trashMetaTmpName produces — "meta.json.", a
// decimal pid, "-", exactly eight lowercase hex characters, ".new" — and
// nothing else, because the one thing this predicate is used for is deciding
// what removeSidecarLitter may unlink. A prefix-and-suffix test would have
// accepted "meta.json.backup.new", a name this package can never write and a
// user's file might be; matching only what a rewrite can actually leave behind
// means the sweep can only ever clear up after itself.
//
// The name is still not authority on its own: what is removed is also decided
// on the lstat (a regular file, this uid's).
func isTrashMetaTmp(name string) bool {
	mid, ok := strings.CutPrefix(name, trashMetaTmpPrefix)
	if !ok {
		return false
	}
	mid, ok = strings.CutSuffix(mid, trashMetaTmpSuffix)
	if !ok {
		return false
	}
	pid, random, ok := strings.Cut(mid, "-")
	if !ok || pid == "" || len(pid) > trashMetaTmpPIDDigits || len(random) != trashMetaTmpHex {
		return false
	}
	for i := 0; i < len(pid); i++ {
		if pid[i] < '0' || pid[i] > '9' {
			return false
		}
	}
	for i := 0; i < len(random); i++ {
		// Lowercase only: hex.EncodeToString writes lowercase, so anything else
		// is a name this package did not make.
		if c := random[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// writeAndSync writes one sidecar's bytes and gets them onto the disk, closing
// the file whatever happens. The fsync is the same one writeTrashMeta makes and
// for the same reason: the ordering this file depends on is program order, and
// program order survives a power cut only for data that actually reached the
// platter.
func writeAndSync(f *os.File, data []byte) error {
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

// readTrashMeta reads one sidecar, and treats it as what it is: a file inside a
// world-writable sticky directory, which means a file an attacker may have put
// there (F8).
//
// Four things are therefore proved before a byte is parsed, all of them on the
// descriptor the openat returned rather than on the name:
//
//   - it is a REGULAR file. A planted fifo would otherwise park this worker
//     inside open(2) with no writer, where no deadline in this process can reach
//     it, which is why the open carries O_NONBLOCK and the blocking mode is put
//     back only once the fstat has answered;
//   - it is not a symlink, which O_NOFOLLOW settled in the kernel;
//   - it belongs to the uid reading it;
//   - nobody else may WRITE it (B2). A uid-owned meta.json that is group- or
//     other-writable is a file whose origPath another identity can rewrite, and
//     origPath is the destination a restore renames to — so a world-writable
//     sidecar in root's own <trash>/0/ is an attacker choosing where a root
//     worker writes. The worker creates it 0600, so a legitimate one passes;
//   - it is no larger than maxTrashMeta, taken from the fstat rather than
//     discovered by reading 64 KiB of somebody's choosing.
//
// A missing, oversized, foreign or malformed sidecar is an error the caller
// skips over: a trash panel that refused to open because of one bad entry would
// be worse than one that lists the rest.
func readTrashMeta(entry *dirRef, entryAPI string, uid int) (trashMeta, error) {
	f, err := entry.openFile(trashMetaName, readSidecarFlags, 0)
	if err != nil {
		return trashMeta{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return trashMeta{}, err
	}
	if err := checkTrashMeta(fi, entryAPI, uid); err != nil {
		return trashMeta{}, err
	}
	// Proved regular, so the descriptor is not registered with the runtime
	// poller and the non-blocking flag can come back off for an ordinary read.
	if err := clearNonblock(f); err != nil {
		return trashMeta{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTrashMeta+1))
	if err != nil {
		return trashMeta{}, err
	}
	if len(data) > maxTrashMeta {
		return trashMeta{}, fmt.Errorf("%s/%s grew past %d bytes while it was being read: %w",
			entryAPI, trashMetaName, maxTrashMeta, ErrUntrustedTrash)
	}
	var m trashMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return trashMeta{}, fmt.Errorf("%s/%s: %w", entryAPI, trashMetaName, err)
	}
	return m, nil
}

// checkTrashMeta is the identity half of readTrashMeta, made on the fstat of the
// held sidecar descriptor and split out so that emptying can ask the same
// question without parsing anything (B6).
//
// The four properties are the ones readTrashMeta's comment states: a regular
// file, owned by the uid consuming it, writable by nobody else (B2), and no
// larger than a sidecar may be. Off Linux there is no uid behind a FileInfo and
// a mode is not the kernel's, so statDetail reports none and the middle two are
// skipped rather than answered wrongly (INV-2).
func checkTrashMeta(fi os.FileInfo, entryAPI string, uid int) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s/%s is a %s, not a regular file: %w",
			entryAPI, trashMetaName, fsx.TypeString(fi.Mode()), ErrUntrustedTrash)
	}
	if owner, _, _, ok := statDetail(fi); ok {
		if owner != uid {
			return fmt.Errorf("%s/%s belongs to uid %d, not to uid %d: %w",
				entryAPI, trashMetaName, owner, uid, ErrUntrustedTrash)
		}
		// B2: ownership is not authenticity. A sidecar anybody else may write is
		// a sidecar anybody else may re-point at a destination of their choosing.
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s/%s is mode %#o, so somebody other than uid %d may rewrite the path it names: %w",
				entryAPI, trashMetaName, perm, uid, ErrUntrustedTrash)
		}
	}
	if fi.Size() > maxTrashMeta {
		return fmt.Errorf("%s/%s is %d bytes, more than the %d a sidecar may be: %w",
			entryAPI, trashMetaName, fi.Size(), maxTrashMeta, ErrUntrustedTrash)
	}
	return nil
}

// trustedSidecar proves that an entry's EXISTING sidecar is this uid's own
// before anything in the entry is destroyed (B6).
//
// It is the check emptying was missing. An entry directory belongs to this uid
// and is 0700 — ownedDir has just said so — and yet the meta.json inside it can
// still be somebody else's: root's own trash is <trash>/0/, a name any local
// user may get to first, and a pre-planted entry directory can be handed over
// with `chown` by whoever made it, or a sidecar inside a legitimate entry left
// group-writable by a bad umask. Listing and restoring already refuse such an
// entry (readTrashMeta makes exactly these checks), so an empty that destroyed
// it anyway would be the one operation in this file acting on a record the rest
// of it calls untrusted — permanently, and without the user ever having seen the
// entry in their panel.
//
// A MISSING sidecar is a different thing and is deliberately NOT an error: that
// is the orphan payload a crash between the sidecar and the rename leaves
// behind, which nothing can list or restore, and clearing it is one of the
// things an empty is for.
//
// The open is the same one readTrashMeta makes — O_RDONLY|O_NONBLOCK through the
// held entry descriptor, with openFile adding O_NOFOLLOW|O_CLOEXEC — so a fifo
// planted at the name returns rather than parking this worker inside open(2) and
// a symlink is ELOOP rather than something followed. Nothing is read: the fstat
// answers the whole question.
func trustedSidecar(entry *dirRef, entryAPI string, uid int) error {
	f, err := entry.openFile(trashMetaName, readSidecarFlags, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return checkTrashMeta(fi, entryAPI, uid)
}

// trashScanMaxEntries bounds the trash-time measurement of a directory. It is
// the recursive delete's own pre-scan bound (backend plan §3), because it is the
// same pass and a user waiting for a number has the same patience either way.
//
// It is a variable solely so that this package's own tests can drive the capped
// branch without building half a million files — the same reason trashRootUID is
// one. Production never assigns to it.
var trashScanMaxEntries int64 = scanMaxEntries

// trashSize is one trash-time measurement: the numbers, and the object they
// were actually taken from.
//
// scanned is what makes the second half possible, and it is the fstat of the
// DESCRIPTOR the scan enumerated (Visitor.Opened) rather than of the pathname it
// was reached by. The scan reaches the tree by NAME (Walk re-resolves the path
// it is given) and the rename looks the item up by name again, so the thing
// counted and the thing moved are separate lookups with a gap between them —
// and a pre-open lstat would not even prove which of them the scan itself
// counted.
type trashSize struct {
	bytes   int64
	files   int64
	scanned os.FileInfo
}

// unknown reports a measurement that never produced a number, so there is
// nothing for the identity check to protect.
func (s trashSize) unknown() bool { return s.files < 0 }

// describes reports whether this measurement really is of payload — the item
// that ended up in the trash entry — given the reference the trash is holding.
//
// All three have to be one object: the held O_PATH descriptor the item was
// selected through, the descriptor the scan enumerated, and the payload lstat'ed
// through the entry's own descriptor after the rename. Anything else means
// somebody moved a directory aside between two of those lookups and the numbers
// describe a tree that is not the one now in the trash.
//
// A MISSING half is a refusal on every platform, and that is a contract rather
// than an accident: a payload nothing could describe is not the object that was
// measured, whatever the host can or cannot compare. The unanswerable case is
// only the one where two real objects cannot be told apart — off Linux
// sameObject reports nothing, and a question that cannot be asked must not be
// answered "no", or the dev box would rewrite every sidecar as unknown (INV-2;
// the CI Linux jobs make the real comparison).
func (s trashSize) describes(selected, payload os.FileInfo) bool {
	if s.scanned == nil || selected == nil || payload == nil {
		return false
	}
	for _, other := range []os.FileInfo{selected, payload} {
		same, known := sameObject(s.scanned, other)
		if known && !same {
			return false
		}
	}
	return true
}

// trashSizeOf measures what the sidecar is about to record: the bytes of the
// item and how many entries those bytes are.
//
// Anything that is not a directory is already answered by the stat it was
// reached with — one item, st_size bytes, which for a symlink is the length of
// its link text exactly as everywhere else here.
//
// A directory is the case this function exists for. The rename moves the whole
// tree, so the honest size of a trashed folder is the tree's, and this is the
// only moment it can be taken: the sidecar is written BEFORE the rename (the
// ordering the whole file depends on), and afterwards the item lives under a
// fixed internal name inside an entry directory. The tree is therefore counted
// here, with the bounded pass a recursive delete uses for its denominator —
// 30 s or trashScanMaxEntries entries, whichever comes first.
//
// Past either bound, or on ANY incompleteness at all — a subdirectory that could
// not be read, a tree deeper than maxWalkDepth, a network mount left untouched,
// a root that could not be reached — the answer is UNKNOWN and not a floor: a
// partial total presented as a size would be a smaller and far more plausible
// lie than the 4096 this replaces, so both halves come back as -1 and every
// layer above says so. That is the difference between this caller and the other
// two: Size and the delete pre-scan SHOW their number for a minute beside the
// warnings that explain it, and this one writes it into a sidecar that will be
// read for as long as the entry exists.
//
// Three things the scan is deliberately not given:
//
//   - crossMounts is false. Anything mounted underneath the item is another
//     filesystem's data: emptying the trash refuses to cross into it
//     (removeTrashTree), so counting it would promise bytes that emptying can
//     never free. It does not follow that what is left is a whole answer, and
//     this is where the trash parts company with a size job: Linux refuses to
//     rename a mount point ITSELF (EBUSY) and not an ancestor of one, so a tree
//     with a mount inside it moves — and a mount over a populated directory
//     hides files that are on this very volume, move with the rename, and were
//     never counted. A mount the scan did not enter therefore makes the
//     measurement incomplete, and incomplete means unknown.
//   - ProtectSnapshots, which is Size's rule and not a delete's: this counts,
//     it never writes. ".zfs" is skipped — a snapshot directory holds the whole
//     history of a share — and "@Recycle" is counted, because its bytes really
//     are inside the tree that is about to move.
//   - a silent Emit. These counters belong to the sidecar, not to the job:
//     restarting them for each selected item would walk the panel's progress
//     backwards, and an EACCES on one file inside the tree is not a failure of
//     THIS trash — the rename moves the tree whole whatever the scan could read.
//     What such a failure does change is the answer: the scan comes back
//     incomplete and the size is recorded as unknown, which says so without
//     claiming the delete went wrong.
//
// The error return is cancellation and nothing else.
func trashSizeOf(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string, fi os.FileInfo) (trashSize, error) {
	if !fi.IsDir() {
		return trashSize{bytes: fi.Size(), files: 1, scanned: fi}, nil
	}
	lim := scanLimits{deadline: time.Now().Add(scanMaxDuration), maxEntries: trashScanMaxEntries}
	scan, serr := scanTrees(ctx, r, plat, []string{apiPath}, false, false, Emit{}, lim, true, ProtectSnapshots)
	if cerr := ctx.Err(); cerr != nil {
		return trashSize{}, cerr
	}
	if serr != nil || scan.capped || scan.incomplete || scan.rootInfo == nil {
		return trashSize{bytes: -1, files: -1}, nil
	}
	// The named directory is counted itself, as in Size, so a directory that was
	// really measured always has at least one entry. That is what lets a files of
	// zero mean "a build that never measured wrote this" in trashItemOf.
	return trashSize{bytes: scan.bytes, files: scan.files + scan.dirs, scanned: scan.rootInfo}, nil
}

// metaFor describes an item about to be trashed. bytes and files are what
// trashSizeOf found, both -1 when the tree could not be counted.
func metaFor(apiPath string, fi os.FileInfo, bytes, files int64) trashMeta {
	name := fsx.Base(apiPath)
	m := trashMeta{
		OrigPath:  apiPath,
		Name:      name,
		Type:      fsx.TypeString(fi.Mode()),
		Mode:      fsx.ModeOctal(fi.Mode()),
		UID:       -1,
		GID:       -1,
		MTime:     fi.ModTime().Unix(),
		Size:      bytes,
		Files:     files,
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

// trashWarn reports why one item could not be trashed. An untrusted entry is the
// app's own refusal and reaches the client as "protected"; everything else is
// "no_trash", which is what the front-end turns into "this would be a permanent
// delete, confirm it".
func trashWarn(emit Emit, apiPath string, err error) {
	if errors.Is(err, ErrUntrustedTrash) {
		emit.warnErr(apiPath, err)
		return
	}
	emit.warn(apiPath, "no_trash", err.Error(), fsx.Errno(err))
}

// Trash moves each path into the nearest .@qfm_trash as this worker's user.
//
// A path with no usable trash is reported as no_trash and SKIPPED — never
// deleted. That is the whole safety property of this function: "delete to
// trash" that quietly became "delete" the moment the mount table said something
// unexpected would be the worst kind of data loss, because the user asked for
// the reversible operation.
//
// The entry ids it created come back in JobResult.TrashIDs, in the order the
// paths were given and only for the items actually trashed. They are what makes
// the front-end's Undo exact: without them the toast has to guess which entries
// this delete produced by matching original paths and a timestamp against the
// whole trash listing, which is a guess that a second delete of the same name,
// or a clock a second out, can get wrong. A skipped item contributes no id, and
// a cancelled job keeps the ids of what it did manage to move — those entries
// are real, and undoing them is exactly what a user who cancelled will want.
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
		// F10: the never-write component rule. A trash is a rename out of where
		// the item lives, so .zfs (read-only in the kernel) and @Recycle
		// (decision 10: never written) are refused here as the guard refuses
		// them, rather than attempted and reported as a kernel error.
		if reason, hit := neverWritePath(clean); hit {
			emit.warnErr(clean, neverWriteErr(clean, reason))
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
		if err := trashOne(ctx, r, plat, loc, uid, clean, name, &res, emit); err != nil {
			return res, err
		}
	}
	return res, nil
}

// trashOne moves one item, through held descriptors at every step (F2). Every
// failure after the entry directory exists removes it again, so a refusal leaves
// no litter behind.
func trashOne(ctx context.Context, r fsx.Root, plat *platform.Platform, loc trashLoc, uid int,
	clean, name string, res *wproto.JobResult, emit Emit) error {
	root, err := loc.open()
	if err != nil {
		trashWarn(emit, clean, err)
		res.Skipped++
		return nil
	}
	defer root.close()

	src, err := resolve(r, fsx.Parent(clean), true)
	if err != nil {
		emit.warnErr(clean, err)
		res.Skipped++
		return nil
	}
	// The selected item is opened O_PATH|O_NOFOLLOW and HELD from here until this
	// function returns — past the scan, past the rename, past the check that
	// compares them (verifyTrashPayload).
	//
	// A stat would not have been enough. It is a snapshot of a name: the inode it
	// described can be unlinked while the scan runs and its (dev, ino) handed
	// straight back to a file somebody else creates, at which point comparing
	// identities compares two different objects that agree. A held O_PATH
	// descriptor is a reference to the inode itself, so for as long as this
	// function runs that number cannot be reused, and its fstat is the one
	// identity everything else here is measured against.
	ref, err := trashItemRefOf(src.jail, relJoin(src.rel, name))
	if err != nil {
		emit.warnErr(clean, err)
		res.Skipped++
		return nil
	}
	defer ref.close()
	fi := ref.fi
	// The tree is measured here, before anything has been created. It has to
	// happen before the sidecar is written, because the sidecar is what carries
	// the number and it is written before the rename; doing it before the entry
	// directory exists as well means a cancellation in the middle of a long scan
	// leaves no half-made entry behind for TrashEmpty to tidy up.
	size, err := trashSizeOf(ctx, r, plat, clean, fi)
	if err != nil {
		// Cancellation and nothing else: the item has not been touched.
		return err
	}

	user, err := userDirIn(root, loc.api, uid)
	if err != nil {
		trashWarn(emit, clean, err)
		res.Skipped++
		return nil
	}
	defer user.close()

	userAPI := fsx.Join(loc.api, strconv.Itoa(uid))
	id, entry, err := newEntryDir(user, userAPI, uid)
	if err != nil {
		trashWarn(emit, clean, err)
		res.Skipped++
		return nil
	}
	// Closed twice on the paths that remove the entry: os.File.Close on an
	// already-closed file is ErrClosed and nothing else, and the close has to
	// happen before the rmdir because a Windows directory with an open handle
	// cannot be removed.
	defer entry.close()

	meta := metaFor(clean, fi, size.bytes, size.files)
	if err := writeTrashMeta(entry, meta); err != nil {
		removeEntryDir(user, entry, id)
		trashWarn(emit, clean, err)
		res.Skipped++
		return nil
	}
	// F9: the payload goes in under a fixed internal name, so an item called
	// "meta.json" cannot collide with the sidecar beside it.
	//
	// NOREPLACE: the entry directory was just created, so nothing can legitimately
	// be standing at this name — and if something is, overwriting it would destroy
	// whatever it was.
	if err := entry.renameInto(src.jail, src.rel, name, trashItemName); err != nil {
		removeEntryDir(user, entry, id)
		if errors.Is(err, fsx.ErrCrossDevice) || errors.Is(err, syscall.EXDEV) {
			emit.warn(clean, "no_trash",
				fmt.Sprintf("%q and its trash are on different filesystems, so it was left alone", clean), fsx.Errno(err))
		} else {
			emit.warnErr(clean, err)
		}
		res.Skipped++
		return nil
	}
	verifyTrashPayload(entry, fsx.Join(userAPI, id), meta, size, fi, clean, emit)
	if fi.IsDir() {
		res.Dirs++
	} else {
		res.Files++
		res.Bytes += fi.Size()
	}
	// The rename is the point of no return, so the id is recorded here and
	// nowhere earlier: every path above this one removes the entry it made, and
	// an id for an entry that no longer exists would be an Undo that fails.
	res.TrashIDs = append(res.TrashIDs, id)
	emit.prog(wproto.Prog{
		Files:   res.Files + res.Dirs,
		Bytes:   res.Bytes,
		Current: []byte(clean),
		Phase:   wproto.PhaseWorking,
	})
	return nil
}

// trashItemRefOf opens and holds the item a trash is about to move, and
// trashPayloadOf lstats the payload that landed in the entry afterwards. They
// are the two ends of the identity check.
//
// Both are variables for one reason: the race they exist to catch needs a second
// process swapping a directory for another between two syscalls, which a test
// cannot stage reliably, so a test hands back a different object instead and
// proves the sidecar is rewritten (the same reason identityFor and liveTableOf
// are variables). Production never assigns to either.
var trashItemRefOf = openItemRef

// trashPayloadOf lstats the payload that landed in an entry, through that
// entry's own held descriptor.
var trashPayloadOf = func(entry *dirRef) (os.FileInfo, error) { return entry.lstat(trashItemName) }

// verifyTrashPayload proves that the numbers just written into the sidecar
// describe the item that is actually in the entry, and rewrites them as unknown
// when it cannot.
//
// This is F2 carried one step further than the rename. The measurement resolved
// the item by NAME and so did the rename, which leaves a gap another writer on
// the same volume can use: move the selected directory aside between the two and
// what gets renamed into the trash is a different tree, described by a sidecar
// that states somebody else's totals as fact. The payload is therefore lstat'ed
// through the entry descriptor — the one object nothing can swap — and compared
// with the stat the trash started from and the root the scan really opened.
//
// A mismatch is not a failure of the trash: the item is in the trash, it is
// listable and it is restorable, and the ONLY thing that can be wrong is the
// size. So the size alone is corrected, to -1/-1, which is what every layer
// above already renders as "not known".
//
// A rewrite that fails is a warning and nothing more. Losing the entry over a
// wrong byte count would be the cure killing the patient — the sidecar that
// stays is the one that makes the user's data restorable — so the old number
// survives, disclosed through the warning rather than hidden.
func verifyTrashPayload(entry *dirRef, entryAPI string, m trashMeta, size trashSize, selected os.FileInfo, apiPath string, emit Emit) {
	if size.unknown() {
		// Nothing was measured, so there is nothing that could describe the wrong
		// tree.
		return
	}
	payload, err := trashPayloadOf(entry)
	if err == nil && size.describes(selected, payload) {
		return
	}
	m.Size, m.Files = -1, -1
	if rerr := rewriteTrashMeta(entry, m); rerr != nil {
		emit.warnErr(apiPath, fmt.Errorf(
			"%q was moved to the trash, but its recorded size could not be corrected and may describe a different folder: %w",
			apiPath, rerr))
		return
	}
	// The wording covers both ways in: the payload was a different object, or it
	// could not be described at all. Either way the number is not this item's.
	emit.warn(apiPath, "conflict", fmt.Sprintf(
		"%q could not be matched to the tree that was measured, so %s records its size as unknown", apiPath, entryAPI), 0)
}

// removeEntryDir undoes a half-made trash entry: the sidecar, then the
// directory, both through the descriptors that were just used to make them.
// Failures are ignored — the caller is already reporting why the trash did not
// happen, and a leftover empty entry directory is litter rather than damage
// (TrashEmpty removes it).
func removeEntryDir(user, entry *dirRef, id string) {
	_ = entry.unlink(trashMetaName, false)
	// The handle goes before the directory: on Windows an open handle keeps a
	// directory from being removed at all.
	_ = entry.close()
	_ = user.unlink(id, true)
}

// trashRoots enumerates every place a .@qfm_trash could be for this worker: one
// per Storage, non-network mount in the table, skipping the ones outside the
// jail. Whether anything usable is actually AT that name is decided later, on a
// descriptor (trashLoc.open).
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
		loc, err := locateTrash(r, fsx.Join(rootAPI, TrashDirName))
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
// world-readable. Every step is validated on a held descriptor (F1, F2) — the
// trash root belongs to root and is sticky, <uid>/ belongs to this uid, each
// entry directory belongs to this uid, and its meta.json is a regular file
// belonging to this uid — because a forged <trash>/0/<id>/ that a root session
// LISTED would be an attacker's entry offered to an administrator as their own.
//
// An entry that fails any of those checks is skipped, and so is one whose
// sidecar is missing, unreadable or malformed, and one whose payload is not
// there — the orphan sidecar a crash between the sidecar and the rename leaves
// behind (F9). TrashEmpty clears them.
//
// Unlike every other function here this one has no Emit to warn through: it is a
// plain request/response RPC, not a job (wproto.OpTrashList). A skipped entry is
// therefore silent, which is the right trade for a panel — the alternative is a
// panel that will not open.
func TrashList(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int) ([]wproto.TrashItem, error) {
	out := make([]wproto.TrashItem, 0, 16)
	for _, loc := range trashRoots(r, plat) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		root, err := loc.open()
		if err != nil {
			continue
		}
		user, err := openUserDir(root, loc.api, uid)
		root.close()
		if err != nil {
			continue
		}
		items, err := listTrashDir(ctx, user, loc, uid, len(out))
		user.close()
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

// listTrashDir reads one already-validated <trash>/<uid>/ descriptor.
func listTrashDir(ctx context.Context, user *dirRef, loc trashLoc, uid, already int) ([]wproto.TrashItem, error) {
	var out []wproto.TrashItem
	userAPI := fsx.Join(loc.api, strconv.Itoa(uid))
	for already+len(out) < trashListCap {
		ids, readErr := user.names(readChunk)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			item, ok := trashItemOf(user, loc, userAPI, id, uid)
			if !ok {
				continue
			}
			out = append(out, item)
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

// trashItemOf describes one entry directory, or reports that it is not one this
// user may consume.
func trashItemOf(user *dirRef, loc trashLoc, userAPI, id string, uid int) (wproto.TrashItem, bool) {
	if err := fsx.ValidName(id); err != nil {
		return wproto.TrashItem{}, false
	}
	entry, err := user.child(id)
	if err != nil {
		return wproto.TrashItem{}, false
	}
	defer entry.close()
	entryAPI := fsx.Join(userAPI, id)
	if err := ownedDir(entry, entryAPI, uid); err != nil {
		return wproto.TrashItem{}, false
	}
	meta, err := readTrashMeta(entry, entryAPI, uid)
	if err != nil {
		return wproto.TrashItem{}, false
	}
	raw, err := meta.orig()
	if err != nil {
		return wproto.TrashItem{}, false
	}
	itemName := fsx.Base(string(raw))
	if err := fsx.ValidName(itemName); err != nil {
		return wproto.TrashItem{}, false
	}
	// F9: the payload has a fixed name, so "is it there" is one lstat of one
	// known entry. The sidecar is there and the item is not means a crash
	// between the two writes, and a restore of it could only fail.
	if _, err := entry.lstat(trashItemName); err != nil {
		return wproto.TrashItem{}, false
	}
	size, files := trashSizeOfMeta(meta)
	return wproto.TrashItem{
		ID:        id,
		Name:      []byte(itemName),
		OrigPath:  raw,
		Type:      meta.Type,
		Size:      size,
		Files:     files,
		DeletedAt: meta.DeletedAt,
		Trash:     []byte(loc.api),
	}, true
}

// trashSizeOfMeta is the ONE place a sidecar's size is turned into the size the
// rest of the app reports, because it is also the one place an older sidecar has
// to be recognised.
//
// Builds before this change recorded fi.Size() of the item itself. For a file
// that is still exactly right and always will be. For a DIRECTORY it was the
// inode's own size — 4096 on ext4 — presented to the user as the size of a
// folder, and there are sidecars like that on real NAS boxes right now. They can
// be told apart with certainty and without a version stamp: they carry no
// "files" field at all, and a directory this build measured always counts at
// least itself (trashSizeOf), so files == 0 on a directory means "written before
// the tree was ever counted". The honest answer for those is that the size is
// not known — not the inode figure, which describes nothing the user can see.
func trashSizeOfMeta(m trashMeta) (size, files int64) {
	if m.Type != "dir" {
		// A single item is one item whether or not the sidecar spells it out.
		return m.Size, 1
	}
	if m.Files == 0 {
		return -1, -1
	}
	return m.Size, m.Files
}

// TrashRestore moves items back to where they came from.
//
// v1 does not recreate a missing original parent: a restore that had to invent
// three directories to put a file back is a different operation from the one
// the user asked for, and the honest answer is not_found with the path named.
// An original path that is occupied again is "exists" and is left alone rather
// than overwritten — the rename is NOREPLACE, so the kernel enforces that
// rather than a check that could be raced.
//
// The entry it restores FROM is validated the same way TrashList validates what
// it shows (F1): an entry directory or a sidecar that belongs to somebody else
// is not restored, because a restore is a write to a destination the sidecar
// chose, and that sidecar would be theirs.
func TrashRestore(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int, ids []string, emit Emit) (wproto.JobResult, error) {
	var res wproto.JobResult
	locs := trashRoots(r, plat)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := fsx.ValidName(id); err != nil {
			emit.warnErr(id, err)
			res.Skipped++
			continue
		}
		loc, user, entry, ok := findTrashEntry(locs, uid, id)
		if !ok {
			emit.warn(id, "not_found", fmt.Sprintf("there is no trash entry %q", id), 0)
			res.Skipped++
			continue
		}
		restoreOne(r, loc, user, entry, id, uid, &res, emit)
		entry.close()
		user.close()
	}
	return res, nil
}

// findTrashEntry locates one entry id across the trash roots this worker can
// reach and hands back held, validated descriptors for <uid>/ and for the entry
// itself. The caller closes both.
func findTrashEntry(locs []trashLoc, uid int, id string) (trashLoc, *dirRef, *dirRef, bool) {
	for _, loc := range locs {
		root, err := loc.open()
		if err != nil {
			continue
		}
		user, err := openUserDir(root, loc.api, uid)
		// The trash root has served its purpose — it was the descriptor <uid>/
		// was opened relative to — and the validated <uid>/ handle is what the
		// rest of the restore addresses.
		root.close()
		if err != nil {
			continue
		}
		entry, err := user.child(id)
		if err != nil {
			user.close()
			continue
		}
		entryAPI := fsx.Join(fsx.Join(loc.api, strconv.Itoa(uid)), id)
		if err := ownedDir(entry, entryAPI, uid); err != nil {
			entry.close()
			user.close()
			continue
		}
		return loc, user, entry, true
	}
	return trashLoc{}, nil, nil, false
}

// restoreOne puts one entry back and then removes the entry directory.
func restoreOne(r fsx.Root, loc trashLoc, user, entry *dirRef, id string, uid int, res *wproto.JobResult, emit Emit) {
	entryAPI := fsx.Join(fsx.Join(loc.api, strconv.Itoa(uid)), id)
	meta, err := readTrashMeta(entry, entryAPI, uid)
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
	// F10: the sidecar names the destination, and the sidecar is a file. A
	// restore into .zfs or @Recycle is refused for the same reason a delete of
	// one is.
	if reason, hit := neverWritePath(orig); hit {
		emit.warnErr(orig, neverWriteErr(orig, reason))
		res.Skipped++
		return
	}
	fi, err := entry.lstat(trashItemName)
	if err != nil {
		emit.warnErr(orig, err)
		res.Skipped++
		return
	}

	parent := fsx.Parent(orig)
	dst, err := resolve(r, parent, true)
	if err != nil {
		emit.warnErr(orig, err)
		res.Skipped++
		return
	}
	// F6: the original parent must still be reachable with NO symlink component.
	// resolve() follows links, and what it hands back is where they led; if that
	// is not the path the sidecar named, then something on the way has become a
	// symlink since the item was trashed, and putting the file back "where it
	// came from" would put it wherever that link now points. The original
	// location changed, which is a conflict rather than a restore.
	if dst.api != parent {
		emit.warn(orig, "conflict",
			fmt.Sprintf("%q is now reached through a symlink to %q, so %q was left in the trash",
				parent, dst.api, name), 0)
		res.Skipped++
		return
	}
	if _, err := statAt(dst.jail, dst.rel); err != nil {
		// resolve() defers the errno of a missing or unsearchable component to
		// the caller's own syscall; this is that syscall.
		if errors.Is(err, fs.ErrNotExist) {
			emit.warn(orig, "not_found",
				fmt.Sprintf("the folder %q is gone, so %q cannot be put back where it was", parent, name), 0)
		} else {
			emit.warnErr(orig, err)
		}
		res.Skipped++
		return
	}
	// F9: the payload comes back out from under its fixed internal name and
	// regains the basename the sidecar recorded.
	if err := entry.renameOut(trashItemName, dst.jail, dst.rel, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			emit.warn(orig, "exists", fmt.Sprintf("%q is there again, so the trashed copy was left in the trash", orig), 0)
		} else {
			emit.warnErr(orig, err)
		}
		res.Skipped++
		return
	}
	if err := entry.unlink(trashMetaName, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
		emit.warnErr(orig, err)
	} else {
		// The handle goes before the directory, as in removeEntryDir.
		_ = entry.close()
		if err := user.unlink(id, true); err != nil {
			emit.warnErr(orig, err)
		}
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
// trash root this worker can reach. It is the one operation here that destroys
// data, which is why the front-end puts it behind the same confirmation ladder a
// permanent delete has.
//
// The validation comes first and on descriptors (F1, F2): the trash root must
// belong to root and be sticky, <uid>/ must belong to this uid, and so must each
// entry directory AND the sidecar inside it (B6) — the same entry a listing or a
// restore would refuse is the same entry an empty leaves alone. A <uid>/
// somebody else owns is NOT emptied — emptying it would be this worker deleting
// another user's files on their behalf, or, for a root session, deleting
// whatever an attacker had pre-created under the name "0" and chose to have
// removed at that moment.
//
// It used to be one recursive DeleteTree of <trash>/<uid>/, and that was finding
// 14 of the round-1 review. A post-order tree delete treats meta.json as an
// ordinary file, so the sidecar could be unlinked BEFORE the payload beside it —
// and if the payload then failed to go (EPERM on one file inside it, a
// cancellation stopping the walk), the entry was left with a payload nobody
// could name: TrashList skips an entry with no sidecar, so it vanished from the
// panel and could never be restored. Emptying destroyed the very thing the trash
// exists to protect.
//
// So the trash is emptied ENTRY BY ENTRY, each against its own held descriptors,
// in the one order that is safe to interrupt:
//
//	payload first (recursively, if it is a directory), then the sidecar,
//	then the entry directory itself.
//
// Every prefix of that sequence leaves a state the rest of this file understands.
// Stop before the payload is gone and the entry is untouched. Stop after the
// payload is gone but before the sidecar is — a window of one unlink, and the
// entry is the orphan sidecar a crashed trash already leaves, which TrashList
// skips and the next empty clears. What can no longer happen is the reverse: an
// entry that is still on disk, still holding the user's data, and no longer
// listable or restorable.
//
// A payload that cannot be fully removed therefore keeps its sidecar and its
// directory, is reported as a warning, and is still there — listed and
// restorable — when the empty finishes. Cancellation is the same story for every
// entry the job never reached.
//
// An entry that survives like that is no longer the tree its sidecar measured,
// which is why the SIZE is invalidated before the first removal rather than
// corrected afterwards (invalidateTrashSize): "afterwards" is a moment a
// cancellation or a crash can land in front of, and what it would leave behind
// is a half-emptied entry still claiming the total it had when it was whole.
func TrashEmpty(ctx context.Context, r fsx.Root, plat *platform.Platform, uid int, emit Emit) (wproto.JobResult, error) {
	var res wproto.JobResult
	for _, loc := range trashRoots(r, plat) {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		root, err := loc.open()
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				// A trash root that is there but is not ours to use is worth
				// saying out loud; one that simply is not there is not.
				trashWarn(emit, loc.api, err)
			}
			continue
		}
		err = emptyUserTrash(ctx, root, loc, uid, &res, emit)
		root.close()
		if err != nil {
			// Cancellation, and nothing else: a per-entry failure is a warning.
			return res, err
		}
	}
	return res, nil
}

// emptyUserTrash empties <trash>/<uid>/ on ONE trash root, through the validated
// descriptor for the root itself.
//
// The pass loop is the same discipline delete_tree.go's post hook has, for the
// same reason: a directory enumerated while it is being emptied can skip entries
// on a filesystem that renumbers getdents offsets, so a pass that removed
// something is followed by another from a FRESH handle — and that re-open goes
// through openUserDir's ownership check again rather than trusting the first
// one. A pass that removes nothing ends it, so entries that were deliberately
// kept cannot spin the loop.
func emptyUserTrash(ctx context.Context, root *dirRef, loc trashLoc, uid int, res *wproto.JobResult, emit Emit) error {
	name := strconv.Itoa(uid)
	userAPI := fsx.Join(loc.api, name)
	for attempt := 0; attempt < maxDirAttempts; attempt++ {
		user, err := openUserDir(root, loc.api, uid)
		if err != nil {
			if attempt == 0 && errors.Is(err, ErrUntrustedTrash) {
				emit.warnErr(userAPI, err)
			}
			// Anything else means this user has nothing here any more.
			return nil
		}
		removed, perr := emptyPass(ctx, user, userAPI, uid, res, emit)
		user.close()
		if perr != nil {
			return perr
		}
		if removed == 0 {
			break
		}
	}
	// The user's own subdirectory goes when it is empty — it is recreated the
	// next time something is trashed. An ENOTEMPTY here is the correct answer
	// rather than a failure: it means an entry was kept, which is what keeping
	// it was for.
	_ = root.unlink(name, true)
	return nil
}

// emptyPass walks one already-validated <uid>/ handle once, emptying each entry
// it names. It returns how many entries it removed; the error is cancellation
// and nothing else.
func emptyPass(ctx context.Context, user *dirRef, userAPI string, uid int, res *wproto.JobResult, emit Emit) (int, error) {
	removed := 0
	for {
		ids, readErr := user.names(readChunk)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return removed, err
			}
			gone, err := emptyEntry(ctx, user, userAPI, id, uid, res, emit)
			if err != nil {
				return removed, err
			}
			if gone {
				removed++
			}
		}
		if readErr != nil || len(ids) == 0 {
			break
		}
	}
	return removed, nil
}

// emptyEntry empties one <trash>/<uid>/<id>/, payload first (F14). It reports
// whether the entry is gone; the error is cancellation and nothing else.
func emptyEntry(ctx context.Context, user *dirRef, userAPI, id string, uid int, res *wproto.JobResult, emit Emit) (bool, error) {
	entryAPI := fsx.Join(userAPI, id)
	if err := fsx.ValidName(id); err != nil {
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}
	fi, err := user.lstat(id)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Removed by another of this user's workers between the read and now.
			return false, nil
		}
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}
	if !fi.IsDir() {
		// Not an entry at all: a stray file or symlink directly inside a 0700
		// directory this uid owns. Nothing can restore it and it can hold
		// nothing, so it goes as the file or the link it is.
		if err := user.unlink(id, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
			emit.warnErr(entryAPI, err)
			res.Skipped++
			return false, nil
		}
		res.Files++
		res.Bytes += fi.Size()
		emptyProgress(res, emit, entryAPI)
		return true, nil
	}
	entry, err := user.child(id)
	if err != nil {
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}
	// F1: an entry directory somebody else owns is not this user's to destroy,
	// even inside their own <uid>/ — the name could have been pre-created.
	if err := ownedDir(entry, entryAPI, uid); err != nil {
		entry.close()
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}
	// B6: and neither is an entry whose SIDECAR is somebody else's. The entry
	// directory passing ownedDir says nothing about the meta.json inside it, and
	// an entry the listing and the restore both refuse as untrusted must not be
	// the one thing an empty quietly destroys. An entry with no sidecar at all is
	// still emptied — that orphan is what an empty is for (trustedSidecar).
	if err := trustedSidecar(entry, entryAPI, uid); err != nil {
		entry.close()
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}

	// The recorded size stops being true the moment anything under the entry
	// goes, so it is given up BEFORE the first removal rather than corrected
	// after the last one. A failure here is a warning and the empty carries on:
	// see invalidateTrashSize for why refusing to empty would be the worse of the
	// two, and stale is what makes the consequence visible if the entry survives.
	stale := false
	if err := invalidateTrashSize(entry, entryAPI, uid); err != nil {
		emit.warn(fsx.Join(entryAPI, trashMetaName), fsx.Code(err),
			fmt.Sprintf("the recorded size of %q could not be updated before it was emptied, so it may be larger than what is left: %v",
				entryAPI, err), fsx.Errno(err))
		stale = true
	}

	// The order F14 exists for. Everything below is reported through warnings
	// that leave the entry exactly as listable and as restorable as it was.
	if err := emptyItem(ctx, entry, entryAPI, res, emit); err != nil {
		entry.close()
		if cerr := ctx.Err(); cerr != nil {
			return false, cerr
		}
		msg := fmt.Sprintf("%q could not be emptied, so its record was kept and it can still be restored from the Trash", entryAPI)
		if stale {
			// The one case where a size on display can now be wrong, said out loud
			// at the only moment it can be known: the entry is still here.
			msg += ", though its recorded size could not be updated and may be larger than what is left"
		}
		emit.warn(entryAPI, "not_empty", msg, fsx.Errno(err))
		return false, nil
	}
	// The payload is gone, so the entry is going. Anything a crashed rewrite left
	// beside the sidecar goes with it, or the rmdir below would refuse this
	// directory for as long as it exists.
	removeSidecarLitter(entry, uid)
	if err := entry.unlink(trashMetaName, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
		entry.close()
		emit.warnErr(fsx.Join(entryAPI, trashMetaName), err)
		res.Skipped++
		return false, nil
	}
	// The handle goes before the directory, as in removeEntryDir: on Windows an
	// open handle keeps a directory from being removed at all.
	entry.close()
	if err := user.unlink(id, true); err != nil && !errors.Is(err, fs.ErrNotExist) {
		emit.warnErr(entryAPI, err)
		res.Skipped++
		return false, nil
	}
	res.Dirs++
	emptyProgress(res, emit, entryAPI)
	return true, nil
}

// invalidateTrashSize gives up an entry's recorded size before an empty starts
// taking the tree it describes apart.
//
// The number in the sidecar is the size of a WHOLE item, and an empty is the one
// operation that can leave a part of one behind: a protected component inside it
// (F10), one file the kernel will not let go, a cancellation between two
// unlinks. Correcting it afterwards would be correcting it at a moment a crash
// or a cancellation can land in front of, so it is given up first — one rename
// per entry actually being emptied — and the panel then says "—" for an entry
// that is no longer what it was measured as.
//
// Two narrowings keep the cost where the risk is:
//
//   - only a DIRECTORY payload can be partly removed. A file or a symlink goes
//     in one unlink that either happens or does not, so its recorded size is
//     true in both outcomes.
//   - only a sidecar whose measurement is KNOWN to a reader (trashSizeOfMeta) is
//     worth rewriting. One that already reports unknown — an older build's, or
//     one this build could not measure — has nothing on display to correct, and
//     one that cannot be read at all is an entry TrashList already refuses to
//     show.
//
// A failure to rewrite is a warning and not a refusal to empty the entry, and
// that is a deliberate trade. The rewrite CREATES a small file, which is exactly
// what a full volume refuses — and a full volume is when a user empties their
// trash. Making the one operation that frees space conditional on a few hundred
// bytes being writable would take the escape hatch away at the moment it is
// needed, to protect a number on a panel. The residual is that a size may read
// high for an entry the empty could not finish, which is said out loud at the
// only moment it can be known (emptyEntry); an entry that IS fully removed takes
// its sidecar with it and leaves nothing to be wrong about.
//
// TrashRestore needs none of this. It renames the payload out whole and removes
// the entry in the same breath, so there is no state in which a record survives
// describing a tree that is no longer what it says: either the entry is still
// there untouched, or it is gone.
func invalidateTrashSize(entry *dirRef, entryAPI string, uid int) error {
	fi, err := entry.lstat(trashItemName)
	switch {
	case err == nil:
	case noTrashPayload(err):
		return nil
	default:
		// The payload could not be described — EMFILE, EIO — which is not the
		// same as there being nothing to describe. Treating it as "nothing to
		// invalidate" would let the empty take a tree apart underneath a sidecar
		// still claiming the whole of it, which is precisely the state this
		// function exists to prevent, so the caller is told instead.
		return err
	}
	if !fi.IsDir() {
		return nil
	}
	meta, err := readTrashMeta(entry, entryAPI, uid)
	if err != nil {
		if sidecarNotOnDisplay(err) {
			return nil
		}
		// Everything else is the read failing rather than the record being
		// unusable — EIO on the block that holds it, EMFILE because this worker is
		// out of descriptors. The sidecar is still there, TrashList still shows the
		// number in it, and the empty is about to make that number wrong: the
		// caller is told so rather than being left to assume there was nothing to
		// correct.
		return err
	}
	if size, files := trashSizeOfMeta(meta); size < 0 && files < 0 {
		return nil
	}
	meta.Size, meta.Files = -1, -1
	return rewriteTrashMeta(entry, meta)
}

// noTrashPayload reports that an entry holds nothing a removal could take apart
// PART of, so there is no recorded size an empty could make untrue.
//
// ENOENT is the orphan sidecar a crash between the sidecar and the rename leaves
// behind: there is no payload at all. ENOTDIR and ELOOP say the name does not
// lead to a directory, and anything that is not a directory goes in one unlink
// that either happens or does not — its size is true in both outcomes.
//
// Everything else is the lstat FAILING rather than answering, and that is not a
// reason to skip an invalidation.
func noTrashPayload(err error) bool {
	return errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ELOOP)
}

// sidecarNotOnDisplay reports that a sidecar which could not be read is one no
// reader was showing anyway, so there is no number in a panel to correct.
//
// Three things qualify, and they are the three TrashList itself refuses: no
// sidecar at all (the orphan payload a crashed trash leaves), one that is not
// this uid's or is otherwise untrusted (F8, B2), and one whose contents are not
// the JSON this wrote. Anything else — an I/O error, a descriptor limit — is the
// READ failing, not the record being unusable, and must not be mistaken for
// "nothing to do".
func sidecarNotOnDisplay(err error) bool {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrUntrustedTrash) {
		return true
	}
	var syntax *json.SyntaxError
	var mismatch *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &mismatch)
}

// removeSidecarLitter clears sidecar temporaries out of an entry that is being
// emptied: the meta.json.<pid>-<hex>.new a crash between a rewrite's create and
// its rename leaves behind (rewriteTrashMeta).
//
// Without it that litter is permanent in the only way that matters — the entry's
// final rmdir reports the directory as not empty, for ever, and the user is left
// with a trash entry nothing can clear. It is cleared here rather than anywhere
// else because this is the one moment the entry is known to be going.
//
// The name is only a filter. What is actually removed has to be a REGULAR file
// (so never a directory to recurse into, and the lstat does not follow a
// symlink) that belongs to the uid doing the removing — the same two questions
// every other consuming path in this file asks, because the entry directory is
// 0700 but its name was once creatable by anybody in a 1777 trash.
func removeSidecarLitter(entry *dirRef, uid int) {
	for {
		names, readErr := entry.names(readChunk)
		for _, name := range names {
			if !isTrashMetaTmp(name) {
				continue
			}
			fi, err := entry.lstat(name)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if owner, _, _, ok := statDetail(fi); ok && owner != uid {
				continue
			}
			_ = entry.unlink(name, false)
		}
		if readErr != nil || len(names) == 0 {
			return
		}
	}
}

// emptyItem removes the payload of one entry — the fixed-name item, recursively
// if it is a directory — through the entry's held descriptor.
//
// A missing payload is success, not a failure: that is the orphan sidecar a
// crash between the sidecar and the rename leaves behind, and clearing it is one
// of the things an empty is for.
func emptyItem(ctx context.Context, entry *dirRef, entryAPI string, res *wproto.JobResult, emit Emit) error {
	fi, err := entry.lstat(trashItemName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		emit.warnErr(fsx.Join(entryAPI, trashItemName), err)
		res.Skipped++
		return err
	}
	return removeTrashTree(ctx, entry, entryAPI, trashItemName, fi, 0, res, emit)
}

// removeTrashTree removes one name below a held descriptor, descending into it
// first if it is a directory. It is a small private recursion rather than a call
// into Walk/DeleteTree because the whole point of F14 is that the entry is
// addressed through the descriptor it was validated on, not through a pathname
// inside a directory the world may write to.
//
// The three refusals of the general delete are kept, and for the same reasons:
// the depth bound (one open descriptor per level), the never-write component
// rule (F10), and the mount boundary — decided on the OPENED descriptor (F4),
// never crossed, because a trash lives on exactly one filesystem and anything
// mounted underneath one is somebody else's data.
func removeTrashTree(ctx context.Context, dir *dirRef, dirAPI, name string, fi os.FileInfo, depth int, res *wproto.JobResult, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	itemAPI := fsx.Join(dirAPI, name)
	if !fi.IsDir() {
		// A symlink is unlinked as the link it is, never followed.
		if err := dir.unlink(name, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
			emit.warnErr(itemAPI, err)
			res.Skipped++
			return err
		}
		res.Files++
		res.Bytes += fi.Size()
		emptyProgress(res, emit, itemAPI)
		return nil
	}
	if depth >= maxWalkDepth {
		err := fmt.Errorf("%q is nested deeper than %d levels and was left alone: %w", itemAPI, maxWalkDepth, fsx.ErrUnsupported)
		emit.warnErr(itemAPI, err)
		res.Skipped++
		return err
	}
	for attempt := 0; attempt < maxDirAttempts; attempt++ {
		child, err := dir.child(name)
		if err != nil {
			emit.warnErr(itemAPI, err)
			res.Skipped++
			return err
		}
		childID, parentID := identityFor(child), identityFor(dir)
		// B4: emptying the trash destroys data, so it is held to the mutating
		// walk's rule — a child whose mount the kernel will not name is left
		// alone rather than compared by st_dev, which a bind mount defeats.
		if unidentifiedMount(childID, parentID) {
			child.close()
			err := fmt.Errorf("the kernel would not name the mount %q is on, so it was left alone: %w", itemAPI, fsx.ErrProtected)
			emit.warnErr(itemAPI, err)
			res.Skipped++
			return err
		}
		if childID.differsFrom(parentID) {
			child.close()
			err := fmt.Errorf("%q is a mount point and was left alone: %w", itemAPI, fsx.ErrProtected)
			emit.warnErr(itemAPI, err)
			res.Skipped++
			return err
		}
		removed, cerr := removeTrashChildren(ctx, child, itemAPI, depth, res, emit)
		child.close()
		if cerr != nil {
			return cerr
		}
		err = dir.unlink(name, true)
		switch {
		case err == nil:
			res.Dirs++
			emptyProgress(res, emit, itemAPI)
			return nil
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case isNotEmpty(err) && removed > 0:
			// Emptied while it was being enumerated: read it again from a fresh
			// handle, which is re-checked exactly as the first one was.
			continue
		default:
			emit.warnErr(itemAPI, err)
			res.Skipped++
			return err
		}
	}
	err := fmt.Errorf("%q could not be emptied in %d passes: %w", itemAPI, maxDirAttempts, fsx.ErrUnsupported)
	emit.warnErr(itemAPI, err)
	res.Skipped++
	return err
}

// removeTrashChildren removes everything below one held directory descriptor. It
// returns how many entries went and the first failure it met — it carries on
// past a failure so that a user emptying their trash is told about all forty
// files that could not go, not just the first, exactly as the general delete
// does. Cancellation stops it at once.
func removeTrashChildren(ctx context.Context, dir *dirRef, dirAPI string, depth int, res *wproto.JobResult, emit Emit) (int, error) {
	removed := 0
	var firstErr error
	for {
		names, readErr := dir.names(readChunk)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return removed, err
			}
			childAPI := fsx.Join(dirAPI, name)
			// F10: the never-write component rule, applied to every entry the
			// recursion reaches and not just to the job's roots.
			if reason, hit := NeverWriteName(name); hit {
				err := neverWriteErr(childAPI, reason)
				emit.warnErr(childAPI, err)
				res.Skipped++
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			fi, err := dir.lstat(name)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				emit.warnErr(childAPI, err)
				res.Skipped++
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if err := removeTrashTree(ctx, dir, dirAPI, name, fi, depth+1, res, emit); err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return removed, cerr
				}
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			removed++
		}
		if readErr != nil || len(names) == 0 {
			break
		}
	}
	return removed, firstErr
}

// emptyProgress reports one permanently removed item. The rate limiting is the
// worker's (see Emit).
func emptyProgress(res *wproto.JobResult, emit Emit, apiPath string) {
	emit.prog(wproto.Prog{
		Files:   res.Files + res.Dirs,
		Bytes:   res.Bytes,
		Current: []byte(apiPath),
		Phase:   wproto.PhaseWorking,
	})
}
