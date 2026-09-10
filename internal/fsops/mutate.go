package fsops

// The M1 mutations: Mkdir, Rename and single Delete. Each one resolves the
// *parent* directory through the same resolve()/O_PATH machinery the read side
// uses — so containment, the search-only-directory handling and the
// no-simulation rule (INV-2) all hold unchanged — and then makes one *at
// syscall relative to that parent's descriptor. Operating on the parent fd
// rather than on a freshly built pathname is what closes the window between
// resolving a path and mutating through it: nothing can swap a component for a
// symlink to /etc between the check and the create, because the create names
// only the final component and the descriptor it is relative to was walked one
// openat at a time.
//
// What is deliberately *not* here: the /share RAM-disk refusal, the protected
// -path table, the read-only toggle and the mount-point guard. Those live in
// the root front-end's guard, before the RPC (INV-1, PLAN.md decision 7). fsops
// makes the syscall and returns the kernel's own errno; it never invents a
// refusal the kernel would not have made.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"qnapfilemanager/internal/fsx"
)

// Mkdir creates <dir>/<name> and returns the new entry.
//
// The name is validated as a single component; dir is resolved (following the
// symlinks QTS builds its shares out of) to a parent descriptor, and the
// directory is created relative to that descriptor with O_EXCL semantics — an
// existing name is fs.ErrExist, never a silent success. When parents is set the
// missing intermediate directories of dir are created first, each ignoring
// EEXIST, exactly as mkdir -p does; the final component still surfaces EEXIST,
// so "the folder is already there" stays an error a caller can see.
//
// mode 0 means 0755; the worker's umask is applied by the kernel on the
// mkdirat, so the stored mode is 0755 &^ umask without this code touching it.
func Mkdir(ctx context.Context, r fsx.Root, dir, name string, mode os.FileMode, parents bool) (fsx.Entry, error) {
	if err := fsx.ValidName(name); err != nil {
		return fsx.Entry{}, err
	}
	cleanDir, err := fsx.Clean(dir)
	if err != nil {
		return fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Entry{}, err
	}
	if mode == 0 {
		mode = 0o755
	}
	// The parent is followed to its real location — /share/Public is a symlink,
	// and creating a directory "in it" means creating one in the dataset it
	// points at. The final name is never part of this resolution.
	tg, err := resolve(r, cleanDir, true)
	if err != nil {
		return fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Entry{}, err
	}
	if err := mkdirAt(tg.jail, tg.rel, name, mode, parents); err != nil {
		return fsx.Entry{}, err
	}
	// Report the requested child path, the way Stat reports the requested path
	// rather than the resolved one, so a caller that created /share/Public/x is
	// told about /share/Public/x and not the dataset path underneath it.
	childAPI := fsx.Join(cleanDir, name)
	fi, err := statAt(tg.jail, relJoin(tg.rel, name))
	if err != nil {
		return fsx.Entry{}, err
	}
	return newEntry(childAPI, []byte(name), fi, IDMap()), nil
}

// Rename moves from to to. Both may be in different directories — a move within
// the jail — so both parents are resolved. renameat is relative to the two
// resolved parent descriptors, and neither final component is followed: a
// symlink at either end is renamed as the link it is, not through to its target.
//
// os.Rename overwrites silently on Linux, which is the wrong default for a file
// manager, so an existing destination is refused with fs.ErrExist unless
// overwrite is set. On Linux this is enforced atomically by renameat2(2) with
// RENAME_NOREPLACE, closing the check-then-act window (adv 2): the kernel itself
// refuses the rename if the destination exists. Where the syscall is unavailable
// (an old kernel, a filesystem that does not implement it, or a non-Linux host)
// it falls back to a separate lstat pre-check, whose residual TOCTOU is accepted
// (PLAN.md §2.4) — far less dangerous than the containment races the O_PATH walk
// closes.
//
// A cross-filesystem rename — which on QuTS hero is any move between shares,
// since every share is its own dataset — is reported as fsx.ErrCrossDevice so
// the front-end can offer a copy+delete move instead.
func Rename(ctx context.Context, r fsx.Root, from, to string, overwrite bool) error {
	cleanFrom, err := fsx.Clean(from)
	if err != nil {
		return err
	}
	cleanTo, err := fsx.Clean(to)
	if err != nil {
		return err
	}
	fromName := fsx.Base(cleanFrom)
	toName := fsx.Base(cleanTo)
	if err := fsx.ValidName(fromName); err != nil {
		return fmt.Errorf("rename source %q: %w", from, err)
	}
	if err := fsx.ValidName(toName); err != nil {
		return fmt.Errorf("rename target %q: %w", to, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fromParent, err := resolve(r, fsx.Parent(cleanFrom), true)
	if err != nil {
		return err
	}
	toParent, err := resolve(r, fsx.Parent(cleanTo), true)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// !overwrite is enforced inside renameAt: atomically on Linux (RENAME_NOREPLACE)
	// and by an lstat pre-check where that is unavailable. An existing destination
	// surfaces as fs.ErrExist either way.
	if err := renameAt(fromParent.jail, fromParent.rel, fromName, toParent.jail, toParent.rel, toName, !overwrite); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			return fmt.Errorf("cannot rename %q to %q, which is on a different filesystem: %w", cleanFrom, cleanTo, fsx.ErrCrossDevice)
		}
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%q already exists: %w", cleanTo, fs.ErrExist)
		}
		return err
	}
	return nil
}

// Delete removes a single item: a file, an empty directory, or a symlink. This
// is the M1 delete only — a non-empty directory is refused with ENOTEMPTY
// (mapped to not_empty), never recursed into; recursive delete and trash are
// M2. The final component is never followed, so deleting a symlink removes the
// link and leaves whatever it pointed at alone.
//
// Mount-point refusal is deliberately not made here: it is the front-end
// guard's, before the RPC. fsops unlinks and returns the kernel's answer.
func Delete(ctx context.Context, r fsx.Root, path string) error {
	clean, err := fsx.Clean(path)
	if err != nil {
		return err
	}
	name := fsx.Base(clean)
	if err := fsx.ValidName(name); err != nil {
		return fmt.Errorf("delete %q: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := resolve(r, fsx.Parent(clean), true)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// lstat, so a symlink is classified as itself and unlinked as a file rather
	// than removed with AT_REMOVEDIR (which would be ENOTDIR) or followed.
	fi, err := statAt(parent.jail, relJoin(parent.rel, name))
	if err != nil {
		return err
	}
	return unlinkAt(parent.jail, parent.rel, name, fi.IsDir())
}
