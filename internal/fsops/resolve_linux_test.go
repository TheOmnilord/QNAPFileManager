package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// TestResolvePathUnsearchableIntermediateIsPermission is round-3 finding 2 as a
// unit test: resolving as the user, a component the user cannot search is the
// kernel's EACCES, not something resolved around. It runs unprivileged, because
// root's CAP_DAC_OVERRIDE would ignore the very search bit under test (INV-2).
func TestResolvePathUnsearchableIntermediateIsPermission(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "locked/sub")
	locked := filepath.Join(base, "locked")
	chmodBack(t, locked, 0o755)
	if err := os.Chmod(locked, 0o644); err != nil { // readable, not searchable
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(locked, "sub")); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("this filesystem does not enforce the directory execute bit: %v", err)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	// !followLeaf: reaching the parent /locked/sub needs search on locked.
	if got, err := ResolvePath(ctx, r, "/locked/sub/leaf", false); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ResolvePath through an unsearchable intermediate = (%q, %v), want a permission error", got, err)
	} else if code := fsx.Code(err); code != "permission" {
		t.Errorf("code = %q, want permission", code)
	}

	// followLeaf: the finding-2 shape — a final component under an unsearchable
	// directory. Naming it needs search on locked, which the user does not have.
	if got, err := ResolvePath(ctx, r, "/locked/sub", true); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ResolvePath(followLeaf) under an unsearchable directory = (%q, %v), want a permission error", got, err)
	}

	// Restoring the bit makes the same resolution succeed, so what was refused
	// was the missing permission and not the shape of the path.
	if err := os.Chmod(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolvePath(ctx, r, "/locked/sub/leaf", false); err != nil {
		t.Fatalf("ResolvePath once locked is searchable: %v", err)
	} else if got != "/locked/sub/leaf" {
		t.Errorf("got %q, want /locked/sub/leaf", got)
	}
}

// TestRenameFallbackDestExistsAtIsRelativeToTheParentFD covers round-3 finding 5:
// the no-overwrite rename fallback checks the destination with fstatat relative
// to the destination-parent descriptor it already holds, and continues only on
// ENOENT. renameat2(RENAME_NOREPLACE) is the primary atomic path and is what runs
// on a modern kernel, so the fallback's existence check is exercised directly
// here, the way it is reached when the syscall is unavailable.
func TestRenameFallbackDestExistsAtIsRelativeToTheParentFD(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "d")
	write(t, base, "d/present.txt", "here")
	if err := os.Symlink("nowhere", filepath.Join(base, "d", "dangling")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	r := newRoot(t, base)

	j, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}
	toDir, err := walkOPath(j, "d")
	if err != nil {
		t.Fatalf("walkOPath: %v", err)
	}
	defer toDir.Close()

	// An absent name: ENOENT is the one error read as "absent, proceed".
	if exists, err := destExistsAt(toDir, "absent.txt"); err != nil || exists {
		t.Errorf("destExistsAt(absent) = (%v, %v), want (false, nil)", exists, err)
	}
	// A present regular file exists.
	if exists, err := destExistsAt(toDir, "present.txt"); err != nil || !exists {
		t.Errorf("destExistsAt(present) = (%v, %v), want (true, nil)", exists, err)
	}
	// A dangling symlink still exists — O_NOFOLLOW means the link itself counts,
	// the same as renameat2 would refuse to overwrite it.
	if exists, err := destExistsAt(toDir, "dangling"); err != nil || !exists {
		t.Errorf("destExistsAt(dangling symlink) = (%v, %v), want (true, nil)", exists, err)
	}
}

// TestRenameFallbackDestExistsAtNonENOENTIsNotAbsence is the other half of the
// finding-5 fix: any error but ENOENT must fail the rename rather than be read as
// "the destination is not there, overwrite freely". An unsearchable destination
// parent makes the relative lookup EACCES, which must surface rather than pass as
// absence. Unprivileged, because root ignores the search bit (INV-2).
func TestRenameFallbackDestExistsAtNonENOENTIsNotAbsence(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "d")
	write(t, base, "d/present.txt", "here")
	dir := filepath.Join(base, "d")
	chmodBack(t, dir, 0o755)
	if err := os.Chmod(dir, 0o644); err != nil { // readable, not searchable
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "present.txt")); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("this filesystem does not enforce the directory execute bit: %v", err)
	}
	r := newRoot(t, base)

	j, err := r.Open()
	if err != nil {
		t.Fatal(err)
	}
	// walkOPath opens d itself O_PATH, which needs only search on the base; the
	// lookup *inside* d is what needs the search bit d no longer has.
	toDir, err := walkOPath(j, "d")
	if err != nil {
		t.Fatalf("walkOPath: %v", err)
	}
	defer toDir.Close()

	exists, err := destExistsAt(toDir, "present.txt")
	if err == nil {
		t.Fatalf("destExistsAt on an unsearchable parent = (%v, nil), want a non-ENOENT error", exists)
	}
	if errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a non-ENOENT failure was reported as ENOENT: %v", err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v, want a permission error", err)
	}
	if exists {
		t.Error("exists must be false when the lookup itself failed")
	}
}
