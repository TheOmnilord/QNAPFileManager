package fsops

// The M2-C upload (contract §1): the worker creates and owns the file, and the
// root front-end only ever streams bytes into a descriptor it was handed.
//
// That division is the whole feature. An upload is the one operation where the
// front-end has the DATA — it is reading the HTTP body — and the worker has the
// AUTHORITY, and the descriptor is what carries the authority to where the data
// is. Nothing in internal/web opens, creates, names or renames anything; it
// writes into an fd the kernel already agreed this uid could create (identity
// plan §2.5: fds travel worker → front-end and never the reverse).
//
// Everything the copy engine's file path does is done here, in the same order
// and for the same reasons (copy.go's header is the long version):
//
//   - The file is created UNNAMED where the kernel allows it (O_TMPFILE), so
//     there is no window in which a half-written upload stands under its final
//     name for somebody else to open. An inode nobody can name is filled,
//     owned, flushed and verified while it is unreachable, and linked into
//     place only when it is complete.
//   - The EMPTY file is proved before a byte of the body reaches it: the right
//     kind, this worker's uid, a mode no wider than 0644, and the group the
//     kernel would have given it. A file that came out wider or in another
//     group is not the one this upload created, and the body does not go into
//     it.
//   - The owner is installed on the empty file, not afterwards. A chown that
//     fails now costs an empty inode; one that failed after the transfer cost a
//     disclosure for as long as the upload took.
//   - Publication proves the name still refers to the inode the bytes went
//     through, with the descriptor still open, and re-checks the kind of
//     whatever stands at the target. A directory or a symlink that appeared at
//     the name during the transfer is a conflict, never something to rename
//     over.
//
// Where O_TMPFILE is unavailable — an old kernel, a filesystem without it, or
// no /proc for the linkat that publishes one — the file is created under a
// hidden `.qfm-upload-<16 hex>.part` name with O_EXCL, and the window between
// that creation and the chown is the documented residual (contract §1.2). Off
// Linux there is no unnamed form at all and nothing chowns, which is the dev
// box's degradation and not the NAS's (INV-2).
//
// A handle is per worker SESSION. It holds the open inode and the held
// destination directory, so a worker that is killed, or a session that ends,
// takes every unfinished upload with it: the unnamed ones vanish with their
// descriptors and the named ones are unlinked, by identity, exactly as the copy
// engine's cleanup is.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

const (
	// uploadMode is the creation mode of every upload, from contract §1.2: the
	// kernel narrows it by the worker's umask and by the destination's default
	// ACL, and nothing here ever chmods. 0644 is what a file created by a shell
	// redirect on the NAS gets, which is the mode a user expects of something
	// they just put there.
	uploadMode = 0o644

	// uploadTmpPrefix and uploadTmpSuffix name the file the NAMED fallback is
	// written to, and the staging name an overwrite is linked under. It is a
	// dot-name so a listing hides it, and it carries sixteen random hex digits
	// so two uploads into one directory cannot collide and nobody can guess the
	// name in order to race it.
	uploadTmpPrefix = ".qfm-upload-"
	uploadTmpSuffix = ".part"
)

// UploadHandle is one upload in flight: the inode, the directory it will be
// published into, and what was promised about it.
//
// It is opaque on purpose. The wire carries an unguessable id for it
// (OpenWriteResp.Tmp) and never a path, because a path is something a caller
// could change between OpenWrite and Finalize — and the whole point of holding
// the directory open is that nothing about where this lands is ever named
// twice.
type UploadHandle struct {
	// f is the worker's OWN descriptor for the inode. The front-end streams
	// into a dup of it; this one is what proves the inode's identity at
	// publication and what the fsync and the fstat are made on.
	f *os.File
	// dir is the destination directory, held open for the life of the handle.
	dir *dirRef
	// dirAPI is the destination as the CALLER spelled it, so the reply names
	// /share/Public/x and not the dataset path underneath it (Mkdir's rule).
	dirAPI string
	// name is the name the upload was opened for. Finalize may be told a
	// different one; this is the fallback and what the audit record named.
	name string

	// named says the file was created under tmpName instead of unnamed, which
	// is the fallback path with the disclosure window contract §1.2 records.
	named   bool
	tmpName string

	// size is the declared length (0 = unknown) and mtime the declared
	// modification time, both from OpenWriteReq.
	size  int64
	mtime int64
	// conflict is the policy the request carried, used when Finalize does not
	// carry one of its own.
	conflict string

	// spent marks a handle whose inode has been published or thrown away.
	// Every path through Finalize sets it, so a second Finalize for the same id
	// — or the session's own sweep — can never publish twice or unlink
	// somebody else's file.
	spent bool
}

// Path is where this upload would land, for an audit record or a log line.
func (h *UploadHandle) Path() string {
	if h == nil {
		return ""
	}
	return fsx.Join(h.dirAPI, h.name)
}

// Named reports whether this upload took the named fallback, which is the one
// thing about a handle a caller may want to log.
func (h *UploadHandle) Named() bool { return h != nil && h.named }

// Close throws the upload away: the inode, the descriptor and — for the named
// fallback — the `.part` file, removed only while that name still refers to the
// object this upload created.
//
// It is what an expired handle and a session that ends both get, and it is
// idempotent.
func (h *UploadHandle) Close() {
	if h == nil || h.spent {
		return
	}
	h.spent = true
	if h.named && h.tmpName != "" && h.f != nil {
		// The identity check and the unlink are made while the descriptor is
		// still open: the inode cannot be freed while this process holds it, so
		// its number cannot be handed to a stranger's file at the same name and
		// the check cannot be fooled into removing one (unlinkIfOurs).
		if fi, err := h.f.Stat(); err == nil {
			removeIfOurs(h.dir, h.tmpName, fi)
		}
	}
	h.release()
}

// release closes what the handle holds without touching the filesystem.
func (h *UploadHandle) release() {
	if h.f != nil {
		_ = h.f.Close()
		h.f = nil
	}
	if h.dir != nil {
		_ = h.dir.close()
		h.dir = nil
	}
}

// OpenWrite creates the file an upload will be streamed into, AS THE USER, and
// returns a descriptor for the front-end plus the handle the worker keeps
// (contract §1.2).
//
// The two descriptors are the same inode and neither is the other's: the
// returned *os.File is a dup, meant to be passed over SCM_RIGHTS and closed;
// the handle keeps its own, which is what Finalize proves identity with. If the
// front-end's copy is closed, lost or never read, the inode is still this
// worker's to publish or throw away.
func OpenWrite(ctx context.Context, r fsx.Root, plat *platform.Platform, req wproto.OpenWriteReq) (*os.File, *UploadHandle, error) {
	_ = plat // the destination's mount is the kernel's business here, not the table's
	name := string(req.Name)
	if err := fsx.ValidName(name); err != nil {
		return nil, nil, err
	}
	if reason, hit := NeverWriteName(name); hit {
		return nil, nil, neverWriteErr(name, reason)
	}
	cleanDir, err := fsx.Clean(string(req.Dir))
	if err != nil {
		return nil, nil, err
	}
	// F10, applied to the one path this upload writes through. The guard
	// refuses these too; the worker refuses them as well because it is the
	// process that actually makes the syscall.
	if reason, hit := neverWritePath(cleanDir); hit {
		return nil, nil, neverWriteErr(cleanDir, reason)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// NOT resolve(): the route sends the spelling its own guarded resolution
	// produced, so "upload into /share/Public" arrives as the dataset path the
	// share symlink pointed at when it was authorized (round 14 adversarial).
	// Resolving again here would follow whatever the tree says NOW — and the
	// gap is the client's, because the worker opens the destination only when
	// the file part's headers arrive. An ancestor swapped for a symlink in that
	// gap would be followed into somewhere the guard never cleared, and the
	// identity check below would then prove the replacement perfectly.
	//
	// The walk follows nothing and refuses a symlink anywhere on the path,
	// including the leaf: this caller wants the directory that was authorized,
	// not what a link of that name points at. It is held as a dirfd-only handle
	// for openPathRef's reason — creating an entry needs search permission on
	// the directory and not read, so a mode-0333 drop directory is one the
	// kernel allows and this app must not refuse (INV-2).
	dir, _, err := canonicalDir(r, cleanDir)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.close()
		}
	}()
	// The destination has to be the very directory the front-end authorized,
	// and not merely a directory of that name (M2-C review round 13).
	//
	// The route clears the destination and then the worker opens it — but only
	// when the file part's headers arrive, and the client decides when that is.
	// In between, anybody who can write the parent can rename the authorized
	// directory away and leave a symlink to somewhere protected in its place;
	// the name still resolves, the guard was never asked again, and the upload
	// lands where the ladder would have refused it. Every component of the walk
	// above is already opened with openat and O_NOFOLLOW from the jail's own
	// descriptor (walkOPath), so a symlink cannot redirect it — what that does
	// not catch is a REAL directory substituted for a real directory, which is
	// what the inode answers.
	if err := dirIsStill(dir, req.DirIdentity); err != nil {
		return nil, nil, err
	}

	// The early refusal of contract §1.4. It is a COURTESY and is documented as
	// one: the atomic answer is the RENAME_NOREPLACE at Finalize, and this only
	// exists so a user who is about to upload four gigabytes over a slow link is
	// asked "skip, overwrite or keep both?" before the four gigabytes rather
	// than after them.
	if conflictOf(req.Conflict, "") == wproto.ConflictSkip {
		if _, lerr := dir.lstat(name); lerr == nil {
			return nil, nil, fmt.Errorf("%q already exists in %q: %w", name, cleanDir, fs.ErrExist)
		} else if !errors.Is(lerr, fs.ErrNotExist) {
			return nil, nil, lerr
		}
	}

	// Refused BEFORE anything is created, on the descriptor the destination is
	// already held on (§1.9, ensureSpace's rule). A filesystem that will not
	// answer is not a refusal: the kernel's own ENOSPC is still there, and
	// inventing a limit this app cannot measure is the wrong half of INV-2.
	if req.Size > 0 {
		avail, known, serr := statfsAvail(dir)
		if serr == nil && known && avail < uint64(req.Size) {
			return nil, nil, fmt.Errorf("%q has %d bytes free and this upload declares %d: %w",
				cleanDir, avail, req.Size, fsx.ErrNoSpace)
		}
	}

	h := &UploadHandle{
		dir:      dir,
		dirAPI:   cleanDir,
		name:     name,
		size:     req.Size,
		mtime:    req.MTime,
		conflict: req.Conflict,
	}
	if err := h.create(); err != nil {
		return nil, nil, err
	}
	// From here on the handle owns the inode: every failure goes through Close,
	// which unlinks the named fallback by identity and lets an unnamed one
	// simply vanish.
	if err := h.proveEmpty(req.As); err != nil {
		h.Close()
		return nil, nil, err
	}
	dup, err := dupForWire(h)
	if err != nil {
		h.Close()
		return nil, nil, err
	}
	ok = true
	return dup, h, nil
}

// create makes the inode: unnamed where the kernel and the filesystem allow it,
// and a hidden `.part` where they do not.
func (h *UploadHandle) create() error {
	if unnamedUsable(h.dir) {
		if f, err := openUnnamedFile(h.dir, uploadMode); err == nil {
			h.f = f
			return nil
		}
		// An O_TMPFILE that the probe said would work and that failed anyway is
		// still not a reason to refuse the upload: the named path is the same
		// path an older kernel takes.
	}
	tmp, err := uploadTmpName()
	if err != nil {
		return err
	}
	f, err := h.dir.openFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, uploadMode)
	if err != nil {
		return err
	}
	h.f, h.named, h.tmpName = f, true, tmp
	return nil
}

// proveEmpty is everything that happens to the file before a byte of anybody's
// data is in it (§1.2).
//
// One fstat answers all of it: the kind, the creator, the mode and the group.
// The mode may never be WIDER than what was asked for — O_CREAT narrows by the
// umask and by a default ACL and never widens, so a wider mode means this is
// not the file this upload thinks it created — and the group must be the one
// the kernel would have given a new entry here, because a file takes its group
// from a setgid destination and one that came out elsewhere is a substitution
// (createdInGroup).
func (h *UploadHandle) proveEmpty(as *wproto.CreateAs) error {
	empty, err := h.f.Stat()
	if err != nil {
		return err
	}
	if err := createdByUs(empty, kindRegular); err != nil {
		return fmt.Errorf("the upload's file was not created as this worker asked: %w", err)
	}
	if err := modeSubset(empty.Mode(), uploadMode, 0); err != nil {
		return fmt.Errorf("the upload's file was not created as this worker asked: %w", err)
	}
	if err := createdInGroup(h.dir, empty); err != nil {
		return fmt.Errorf("the upload's file was not created as this worker asked: %w", err)
	}
	if empty.Size() != 0 {
		return fmt.Errorf("the upload's file already has %d bytes in it, so it is not the one that was just created: %w",
			empty.Size(), fsx.ErrUnsupported)
	}
	if as == nil || os.Geteuid() != 0 {
		// Only the root worker chowns. The kernel refuses a non-root process
		// that chowns an inode to another uid (EPERM), so trying would produce a
		// failure whose outcome the kernel has already fixed; os.Geteuid reports
		// -1 on Windows, so the dev loop never chowns either (copier.setOwnership).
		return nil
	}
	// The name is empty for an unnamed inode and the descriptor is non-nil for
	// both, so this is fchownat(fd, "", AT_EMPTY_PATH) either way: an inode, not
	// a name (chownEntry).
	if err := setEntryOwner(h.dir, h.tmpName, h.f, as.UID, as.GID); err != nil {
		return errors.Join(fsx.ErrOwnerUnset, err)
	}
	return nil
}

// Finalize publishes the upload, or throws it away, and always CONSUMES the
// handle (contract §1.3).
//
// "Always consumes" is the rule the caller can rely on: whatever this returns,
// the descriptor is closed, the held directory is released, and nothing of this
// upload is left in the destination that was not published under a name the
// reply carries.
func Finalize(ctx context.Context, h *UploadHandle, req wproto.FinalizeReq) (wproto.FinalizeResp, error) {
	if h == nil || h.spent {
		return wproto.FinalizeResp{}, fmt.Errorf("this upload is no longer in progress: %w", fs.ErrNotExist)
	}
	if req.Discard {
		h.Close()
		return wproto.FinalizeResp{}, nil
	}
	if err := ctx.Err(); err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}
	final := string(req.Final)
	if final == "" {
		final = h.name
	}
	if err := fsx.ValidName(final); err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}
	if reason, hit := NeverWriteName(final); hit {
		h.Close()
		return wproto.FinalizeResp{}, neverWriteErr(final, reason)
	}

	// Flushed BEFORE anything is published, which is where a delayed write
	// error is supposed to appear. On a buffered filesystem the writes all
	// "succeed" and the EIO or EDQUOT surfaces at close; with the name already
	// published, discovering it then would mean unlinking a file the user
	// believes they uploaded (copyFile's rule).
	if err := uploadSync(h.f); err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}
	wrote, err := h.f.Stat()
	if err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}
	// A GATE, not a remark. The front-end streams the request body into the
	// descriptor and a body that ended early is a truncated upload, not a
	// shorter file: publishing it would put a file the user believes is theirs
	// under the name they chose, and an overwrite would do it over the intact
	// one that was already there.
	if h.size > 0 && wrote.Size() != h.size {
		h.Close()
		return wproto.FinalizeResp{}, fmt.Errorf(
			"the upload of %q declared %d bytes and %d arrived, so nothing was published: %w",
			fsx.Join(h.dirAPI, final), h.size, wrote.Size(), fsx.ErrChanged)
	}
	h.setMTime(req.MTimeUnix)

	// Re-checked HERE, immediately before the one act that cannot be undone
	// (M2-C review round 8).
	//
	// The check at the top of this function is not enough, and the gap was
	// real: the fsync above flushes gigabytes on a busy volume and can block
	// for a long time, and a cancellation that arrived while it did still went
	// on to link — or, under `overwrite`, to RENAME OVER the file that was
	// already there. The user had been told the upload was cancelled and their
	// existing file was replaced anyway, and the Discard the route sends next
	// found no handle, because this one had consumed it.
	//
	// Nothing is published, the inode is thrown away (an unnamed one simply
	// vanishes; the named fallback's `.part` is unlinked by identity), the
	// handle is consumed, and the caller gets context.Canceled — which the
	// route audits as `aborted` rather than as a failure of the upload.
	if err := ctx.Err(); err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}

	name, err := h.publish(final, conflictOf(req.Conflict, h.conflict), wrote)
	if err != nil {
		h.Close()
		return wproto.FinalizeResp{}, err
	}
	// The entry is described from the fstat of the descriptor the bytes went
	// through — the object that was published — and not from a fresh lookup of
	// the name, which by now could be anything. It is taken AFTER the
	// publication so that what the client is told (the mode the umask and the
	// destination's ACL produced, the modification time that was actually
	// stamped) is what is on the disk.
	published := fsx.Join(h.dirAPI, name)
	fi, serr := h.f.Stat()
	if serr != nil {
		fi = wrote
	}
	e := newEntry(published, []byte(name), fi, IDMap())
	h.spent = true
	h.release()
	return wproto.FinalizeResp{Entry: e, Path: []byte(published)}, nil
}

// setMTime stamps the descriptor with the client's modification time.
//
// It is futimens on the fd this upload wrote through (utimesEntry with a
// non-nil file), so the stamp lands on the inode rather than on whatever
// answers to a name. A failure is deliberately not fatal: the file is complete
// and publishing it with the wrong timestamp is a far better answer than
// throwing away an upload over one — and the entry the reply carries is read
// back from the descriptor afterwards, so what the client is told is what is
// actually on the disk.
func (h *UploadHandle) setMTime(unix int64) {
	if unix == 0 {
		unix = h.mtime
	}
	if unix == 0 {
		return
	}
	t := time.Unix(unix, 0)
	_ = setEntryTimes(h.dir, h.tmpName, h.f, false, t, t)
}

// conflictOf picks the policy: the one Finalize carried, else the one OpenWrite
// carried, else skip — which is the safe default, the one that never replaces
// anything.
func conflictOf(first, second string) string {
	for _, c := range []string{first, second} {
		switch c {
		case wproto.ConflictOverwrite, wproto.ConflictRename, wproto.ConflictSkip:
			return c
		}
	}
	return wproto.ConflictSkip
}

// publish gives the finished inode its name under the conflict policy, and
// returns the name it actually landed under.
func (h *UploadHandle) publish(final, conflict string, wrote os.FileInfo) (string, error) {
	dstPath := fsx.Join(h.dirAPI, final)
	existing, lerr := h.dir.lstat(final)
	switch {
	case errors.Is(lerr, fs.ErrNotExist):
		// The name is free. Link under it with RENAME_NOREPLACE semantics: a
		// stranger who takes it in the meantime gets an EEXIST back, which is
		// the same `exists` this would have reported a moment earlier.
		err := h.linkAs(final, wrote)
		switch {
		case err == nil:
			return final, nil
		case errors.Is(err, fs.ErrExist) && conflict == wproto.ConflictRename:
			return h.keepBoth(final, wrote)
		default:
			return "", err
		}
	case lerr != nil:
		return "", lerr
	}

	// The kind of what is standing there matters to ONE policy, and only that
	// one (M2-C review round 3 adversarial, finding 2).
	//
	// Overwrite is the policy that would destroy it, so overwrite is where the
	// refusal belongs: a file over a folder, or over a symlink, is not a
	// replacement. Keep-both destroys nothing — it leaves whatever is there
	// exactly as it is and takes the next free name — so refusing it because
	// the obstacle happened to be a directory made "Keep both" fail on the one
	// case a user would most want it for, after the whole body had been
	// transferred. Skip destroys nothing either, and its answer is the same
	// whatever is in the way: something is, and this upload was told to leave
	// it alone.
	switch conflict {
	case wproto.ConflictOverwrite:
		if kindOf(existing) != kindRegular {
			return "", fmt.Errorf("%q is a %s at the destination and an upload never replaces one kind with another: %w",
				dstPath, kindName(kindOf(existing)), syscall.EBUSY)
		}
		return final, h.overwrite(final, wrote)
	case wproto.ConflictRename:
		// Whatever is at the name — a file, a folder, a symlink — is untouched:
		// keepBoth publishes with RENAME_NOREPLACE semantics, so it steps over
		// every taken name regardless of what is behind it.
		return h.keepBoth(final, wrote)
	}
	return "", fmt.Errorf("%q already exists and this upload was told to skip it: %w", dstPath, fs.ErrExist)
}

// keepBoth finds the first free "name (2)", "name (3)" … and publishes under
// it, bounded exactly as the copy engine's search is.
func (h *UploadHandle) keepBoth(final string, wrote os.FileInfo) (string, error) {
	for n := 2; n < 2+maxKeepBothTries; n++ {
		// Bounded by NAME_MAX: " (2)" on a name that is already 255 bytes is a
		// linkat that fails with ENAMETOOLONG after the whole body has been
		// transferred (round 7 adversarial). The stem is shortened to make room;
		// where there is none, the upload is refused with a code the route can
		// turn into a 413 rather than an unexplained failure at the very end.
		cand, ok := keepBothWithin(final, false, n)
		if !ok {
			return "", fmt.Errorf(
				"%q is too long for a \"keep both\" name to be made from it: %w",
				fsx.Join(h.dirAPI, final), fsx.ErrTooLarge)
		}
		err := h.linkAs(cand, wrote)
		switch {
		case err == nil:
			return cand, nil
		case errors.Is(err, fs.ErrExist):
			continue
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("%q and the next %d names after it are all taken in %q: %w",
		final, maxKeepBothTries, h.dirAPI, syscall.EBUSY)
}

// linkAs publishes the inode under one name, atomically, refusing to replace
// anything.
//
// For an unnamed inode the linkat IS the publication: there was no name before
// it and EEXIST is the kernel's own answer to somebody having taken the name.
// The named fallback renames its `.part` with RENAME_NOREPLACE, after proving
// that the `.part` still refers to the object this upload wrote — an attacker
// with write access to the destination could otherwise have replaced it during
// the transfer and had their own file published under the user's name
// (publish's rule in copy.go).
func (h *UploadHandle) linkAs(name string, wrote os.FileInfo) error {
	if !h.named {
		return linkUnnamed(h.f, h.dir, name)
	}
	if err := h.stillOurs(wrote); err != nil {
		return err
	}
	return h.dir.renameFromDir(h.dir, h.tmpName, name, true)
}

// overwrite publishes over an existing file of the same kind.
//
// The inode is given an unguessable staging name first — the named fallback
// already has one — and the rename that replaces the target is made from that
// name, so the target is never unlinked and recreated and a reader sees either
// the old file or the new one and never a gap. The target's kind is re-checked
// immediately before the rename for the reason copy.go's publish gives: the
// placement decision was made before a transfer that can run for minutes, and
// renameat replaces whatever it finds.
func (h *UploadHandle) overwrite(final string, wrote os.FileInfo) error {
	staged := h.tmpName
	if !h.named {
		tmp, err := uploadTmpName()
		if err != nil {
			return err
		}
		if err := linkUnnamed(h.f, h.dir, tmp); err != nil {
			return err
		}
		staged = tmp
		h.named, h.tmpName = true, tmp // so a later failure cleans the staged name up
	}
	dstPath := fsx.Join(h.dirAPI, final)
	if tfi, terr := h.dir.lstat(final); terr == nil && kindOf(tfi) != kindRegular {
		removeIfOurs(h.dir, staged, wrote)
		return fmt.Errorf("%q became a %s while the upload was being written, and it was not replaced: %w",
			dstPath, kindName(kindOf(tfi)), syscall.EBUSY)
	}
	if err := h.stillOurs(wrote); err != nil {
		return err
	}
	if err := h.dir.renameFromDir(h.dir, staged, final, false); err != nil {
		removeIfOurs(h.dir, staged, wrote)
		return err
	}
	return nil
}

// stillOurs proves that the staging name still refers to the inode this upload
// wrote, with that inode's descriptor still open so its number cannot have been
// recycled underneath the comparison.
//
// Residual, stated rather than hidden: Linux has no rename-by-descriptor, so
// between this check and the renameat the name could be re-pointed once more.
// It is the §2.4-class residual the copy engine already names, and it is two
// adjacent syscalls wide with nothing in between.
func (h *UploadHandle) stillOurs(wrote os.FileInfo) error {
	if same, known := sameNamedObject(h.dir, h.tmpName, wrote); known && !same {
		return fmt.Errorf("%q was replaced while the upload was being written, so nothing was published: %w",
			fsx.Join(h.dirAPI, h.name), fsx.ErrChanged)
	}
	return nil
}

// removeIfOurs unlinks a name this worker created, and only while that name
// still refers to the object it created. A stranger's file at that name is left
// exactly where it is: it is not ours, and tidying it away would be the second
// half of the mistake (unlinkIfOurs).
func removeIfOurs(dir *dirRef, name string, ours os.FileInfo) bool {
	if dir == nil || name == "" || ours == nil {
		return false
	}
	if same, known := sameNamedObject(dir, name, ours); known && !same {
		return false
	}
	return dir.unlink(name, false) == nil
}

// unnamedUsable answers, once per upload and before a single byte is written,
// whether this destination can hold an unnamed file AND publish it by link.
//
// Two questions no errno at the wrong moment could answer: whether the
// filesystem implements O_TMPFILE, and whether /proc is mounted for the linkat
// that gives an unnamed inode a name. Finding out on the real file instead
// would mean discovering at Finalize that four gigabytes just written can never
// be given a name.
//
// It is a variable so a test can make a filesystem that has none, which is the
// only way to exercise the named fallback on a kernel that supports O_TMPFILE.
// Production never assigns to it.
var unnamedUsable = func(d *dirRef) bool {
	f, err := openUnnamedFile(d, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	name, nerr := uploadTmpName()
	if nerr != nil {
		return false
	}
	if linkUnnamed(f, d, name) != nil {
		return false
	}
	_ = d.unlink(name, false)
	return true
}

// dirIsStill refuses a destination that is not the object the caller
// authorized (M2-C review round 13).
//
// want == nil is a caller that asked for no binding — an older front-end — and
// the behaviour is then exactly what it was. It is the route's job to always
// send one; this is deliberately not the place to invent a refusal for a
// request that did not carry the question.
//
// Off Linux there is no inode behind a FileInfo, so there is nothing to compare
// and the check is not made. That is the same INV-2 degradation the copy
// engine's identity checks accept, and it costs nothing in production: the
// dev-loop pool refuses uploads outright, because they need a descriptor pass
// that only a Unix socket has. The CI Linux jobs and the NAS make the check.
//
// The descriptor is what is measured, never the name: whatever the pathname
// means by now, this is the object the file will be created in and the object
// Finalize will link into, because the handle keeps this very dirRef.
func dirIsStill(d *dirRef, want *wproto.FSIdentityResp) error {
	if want == nil || !inodeIdentity {
		return nil
	}
	got, err := heldIdentityOf(d)
	if err != nil {
		return fmt.Errorf("the upload's destination could not be identified: %w", err)
	}
	if !got.SameInode(*want) {
		return fmt.Errorf(
			"the destination of this upload is not the folder that was authorized (it is now inode %d on device %d, not %d on %d): %w",
			got.Ino, got.Dev, want.Ino, want.Dev, fsx.ErrChanged)
	}
	return nil
}

// uploadSync flushes the finished upload before anything is published, as a
// variable so a test can arrive DURING it.
//
// That is the only way to stage round 8's finding: the window it closes is a
// cancellation that lands while the fsync is blocked — which on a real volume
// is seconds of flushing gigabytes, and in a test is an instant no scheduler
// can be asked to hit. Production never assigns to it.
var uploadSync = func(f *os.File) error { return f.Sync() }

// uploadTmpName is a hidden, unguessable name inside the destination directory.
// Sixteen hex digits is eight bytes of crypto/rand: the name is created with
// O_EXCL so a collision would be an error rather than a silent share, and it is
// unguessable so that nobody can pre-create or race a name they worked out.
func uploadTmpName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return uploadTmpPrefix + hex.EncodeToString(b[:]) + uploadTmpSuffix, nil
}
