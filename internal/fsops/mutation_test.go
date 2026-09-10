package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// The mutation tests that do not turn on a kernel permission decision run on
// every platform: mkdir, rename and delete go through os.Root off Linux and the
// O_PATH walk on it, and both must produce the same observable result. The
// search-only-parent and cross-device cases, which are the kernel's alone, live
// in mutation_linux_test.go (INV-2: never simulate the kernel).

func exists(t *testing.T, base, rel string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(base, filepath.FromSlash(rel)))
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	t.Fatalf("lstat %q: %v", rel, err)
	return false
}

func TestMkdirCreatesAndReturnsEntry(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "parent")
	r := newRoot(t, base)

	e, err := Mkdir(context.Background(), r, "/parent", "child", 0, false)
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if e.Type != "dir" || e.Name != "child" || e.Path != "/parent/child" {
		t.Fatalf("entry = %+v, want a dir named child at /parent/child", e)
	}
	if !exists(t, base, "parent/child") {
		t.Fatal("the directory was not created on disk")
	}
	fi, err := os.Stat(filepath.Join(base, "parent", "child"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("stat of the new directory: %v (isDir=%v)", err, fi != nil && fi.IsDir())
	}
}

func TestMkdirRefusesAnExistingName(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "here")
	r := newRoot(t, base)

	_, err := Mkdir(context.Background(), r, "/", "here", 0, false)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Mkdir of an existing name = %v, want fs.ErrExist", err)
	}
	if code := fsx.Code(err); code != "exists" {
		t.Errorf("code = %q, want exists", code)
	}
}

func TestMkdirParentsCreatesIntermediates(t *testing.T) {
	base := tempDir(t)
	r := newRoot(t, base)

	e, err := Mkdir(context.Background(), r, "/a/b/c", "d", 0, true)
	if err != nil {
		t.Fatalf("Mkdir with parents: %v", err)
	}
	if e.Path != "/a/b/c/d" || e.Type != "dir" {
		t.Fatalf("entry = %+v, want /a/b/c/d", e)
	}
	for _, rel := range []string{"a", "a/b", "a/b/c", "a/b/c/d"} {
		if !exists(t, base, rel) {
			t.Errorf("%q was not created", rel)
		}
	}

	// Without parents the same missing chain is a not_found, not a silent
	// creation.
	_, err = Mkdir(context.Background(), r, "/x/y", "z", 0, false)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Mkdir into a missing parent without parents = %v, want fs.ErrNotExist", err)
	}
}

func TestMkdirRejectsBadName(t *testing.T) {
	r := newRoot(t, tempDir(t))
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := Mkdir(context.Background(), r, "/", name, 0, false); !errors.Is(err, fsx.ErrBadName) {
			t.Errorf("Mkdir name %q = %v, want ErrBadName", name, err)
		}
	}
}

func TestRenameWithinADirectory(t *testing.T) {
	base := tempDir(t)
	write(t, base, "old.txt", "content")
	r := newRoot(t, base)

	if err := Rename(context.Background(), r, "/old.txt", "/new.txt", false); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if exists(t, base, "old.txt") {
		t.Error("the source still exists after the rename")
	}
	if got, _ := os.ReadFile(filepath.Join(base, "new.txt")); string(got) != "content" {
		t.Errorf("new.txt = %q, want the source content", got)
	}
}

func TestRenameAcrossDirectories(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "from")
	mkdir(t, base, "to")
	write(t, base, "from/f.txt", "moved")
	r := newRoot(t, base)

	if err := Rename(context.Background(), r, "/from/f.txt", "/to/f.txt", false); err != nil {
		t.Fatalf("Rename across directories: %v", err)
	}
	if exists(t, base, "from/f.txt") {
		t.Error("the source still exists after the move")
	}
	if got, _ := os.ReadFile(filepath.Join(base, "to", "f.txt")); string(got) != "moved" {
		t.Errorf("to/f.txt = %q, want the moved content", got)
	}
}

func TestRenameRefusesAnExistingDestination(t *testing.T) {
	base := tempDir(t)
	write(t, base, "a.txt", "aaa")
	write(t, base, "b.txt", "bbb")
	r := newRoot(t, base)

	err := Rename(context.Background(), r, "/a.txt", "/b.txt", false)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Rename onto an existing name without overwrite = %v, want fs.ErrExist", err)
	}
	if code := fsx.Code(err); code != "exists" {
		t.Errorf("code = %q, want exists", code)
	}
	// The destination is untouched by the refused rename.
	if got, _ := os.ReadFile(filepath.Join(base, "b.txt")); string(got) != "bbb" {
		t.Errorf("b.txt = %q, want it unchanged", got)
	}

	// With overwrite the rename replaces it.
	if err := Rename(context.Background(), r, "/a.txt", "/b.txt", true); err != nil {
		t.Fatalf("Rename with overwrite: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(base, "b.txt")); string(got) != "aaa" {
		t.Errorf("b.txt = %q, want the source content after overwrite", got)
	}
	if exists(t, base, "a.txt") {
		t.Error("the source still exists after the overwriting rename")
	}
}

func TestDeleteAFile(t *testing.T) {
	base := tempDir(t)
	write(t, base, "gone.txt", "x")
	r := newRoot(t, base)

	if err := Delete(context.Background(), r, "/gone.txt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if exists(t, base, "gone.txt") {
		t.Error("the file still exists after Delete")
	}
}

func TestDeleteAnEmptyDirectory(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "empty")
	r := newRoot(t, base)

	if err := Delete(context.Background(), r, "/empty"); err != nil {
		t.Fatalf("Delete of an empty directory: %v", err)
	}
	if exists(t, base, "empty") {
		t.Error("the directory still exists after Delete")
	}
}

func TestDeleteRefusesANonEmptyDirectory(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "full")
	write(t, base, "full/child.txt", "still here")
	r := newRoot(t, base)

	err := Delete(context.Background(), r, "/full")
	if err == nil {
		t.Fatal("Delete of a non-empty directory must fail")
	}
	// The not_empty code is the kernel's ENOTEMPTY on the Linux NAS. Windows,
	// the dev box, reports ERROR_DIR_NOT_EMPTY, which stdlib's syscall.Errno.Is
	// bridges to fs.ErrExist rather than to ENOTEMPTY — an fsx.Code classification
	// detail, not the delete's behaviour, so the code is asserted where it is the
	// real one (INV-2: never simulate the kernel).
	if runtime.GOOS != "windows" {
		if code := fsx.Code(err); code != "not_empty" {
			t.Fatalf("code = %q (err %v), want not_empty", code, err)
		}
	}
	// M1 does not recurse: the child and the directory are both still there.
	if !exists(t, base, "full/child.txt") || !exists(t, base, "full") {
		t.Error("a refused delete must leave the tree intact")
	}
}

// TestDeleteASymlinkRemovesTheLinkNotTheTarget: the final component of a delete
// is never followed, so unlinking a symlink removes the link and leaves what it
// pointed at.
func TestDeleteASymlinkRemovesTheLinkNotTheTarget(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	write(t, base, "target.txt", "keep me")
	if err := os.Symlink(filepath.Join(base, "target.txt"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	if err := Delete(context.Background(), r, "/link"); err != nil {
		t.Fatalf("Delete of a symlink: %v", err)
	}
	if exists(t, base, "link") {
		t.Error("the symlink still exists after Delete")
	}
	if !exists(t, base, "target.txt") {
		t.Fatal("Delete followed the symlink and removed its target")
	}
	if got, _ := os.ReadFile(filepath.Join(base, "target.txt")); string(got) != "keep me" {
		t.Errorf("target.txt = %q, want it untouched", got)
	}
}

func TestDeleteMissingIsNotFound(t *testing.T) {
	r := newRoot(t, tempDir(t))
	if err := Delete(context.Background(), r, "/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete of a missing path = %v, want fs.ErrNotExist", err)
	}
}
