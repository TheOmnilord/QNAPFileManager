package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// The two tests here are about what the kernel decides, so they need a process
// whose decisions the kernel actually makes. Root is not that process:
// CAP_DAC_OVERRIDE means every mode bit below is ignored for it, so a run as
// root would observe nothing and pass either way — the simulation INV-2 exists
// to forbid. They run in the ordinary Linux CI job, which is unprivileged, and
// skip in the root job.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission bits this test is about (CAP_DAC_OVERRIDE); this runs in the unprivileged Linux job")
	}
}

// chmodBack restores a mode at the end of the test, so that t.TempDir can still
// remove a directory the test made unwritable.
func chmodBack(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
}

// TestDotDotNeedsSearchPermissionOnTheDirectoryItIsWrittenIn: "..'" is resolved
// by the kernel *inside* the directory it appears in, so "locked/../report"
// fails for a user who cannot traverse "locked" — even though the Lstat that
// classified "locked" from outside succeeded. Popping the component in this
// process instead served /report to somebody the kernel would have refused.
func TestDotDotNeedsSearchPermissionOnTheDirectoryItIsWrittenIn(t *testing.T) {
	requireSymlinks(t)
	requireUnprivileged(t)
	r, base := fixture(t)
	mkdir(t, base, "locked")
	write(t, base, "report", "not yours")
	locked := filepath.Join(base, "locked")
	chmodBack(t, locked, 0o755)
	if err := os.Chmod(locked, 0o644); err != nil { // readable, not searchable
		t.Fatal(err)
	}
	// The kernel has to be enforcing this for the test to mean anything.
	if _, err := os.Stat(filepath.Join(locked, "anything")); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("this filesystem does not enforce the directory execute bit: %v", err)
	}
	if err := os.Symlink("locked/../report", filepath.Join(base, "ptr")); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if e, err := StatFollow(ctx, r, nil, "/ptr"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("entry %+v, err = %v, want a permission error", e, err)
	} else if code := fsx.Code(err); code != "permission" {
		t.Errorf("code = %q, want permission", code)
	}
	if f, _, err := OpenRead(ctx, r, "/ptr"); err == nil {
		f.Close()
		t.Fatal("a download through a directory the user cannot traverse must be refused")
	}
}

// TestOpenReadThroughASearchOnlyDirectory: a user with search permission but no
// read permission on a directory may open a child they already know the name of
// — that is what mode 0111 means, and it is how a QNAP share with a private
// index but readable files behaves. Opening the parent O_RDONLY|O_DIRECTORY on
// the way to the final openat asked for the listing right instead and turned
// every such download into EACCES.
func TestOpenReadThroughASearchOnlyDirectory(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "search")
	write(t, base, "search/known.txt", "readable all the same")
	dir := filepath.Join(base, "search")
	chmodBack(t, dir, 0o755)
	if err := os.Chmod(dir, 0o111); err != nil {
		t.Fatal(err)
	}
	// Precondition: the kernel really does refuse the listing here.
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("this filesystem does not enforce the directory read bit")
	}
	r := newRoot(t, base)

	f, e, err := OpenRead(context.Background(), r, "/search/known.txt")
	if err != nil {
		t.Fatalf("downloading a readable file out of a search-only directory: %v", err)
	}
	defer f.Close()
	if e.Size != int64(len("readable all the same")) {
		t.Errorf("size = %d, want %d", e.Size, len("readable all the same"))
	}
	// The listing itself is still the kernel's to refuse.
	if _, err := List(context.Background(), r, nil, "/search", fsx.ListOptions{}); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("listing a directory with no read bit = %v, want a permission error", err)
	}
}

// TestListThroughASearchOnlyDirectory: a listing needs read permission on the
// directory being listed and search permission on the ones above it. os.Root's
// walk opened every intermediate component O_RDONLY, so listing /outer/child
// demanded the read bit on outer too and returned EACCES where the kernel
// returns the listing — a private index (0111) holding a readable subdirectory
// is an ordinary shape for a share. The refusal on outer itself is the other
// half: the read bit is still the kernel's to require where it does require it.
func TestListThroughASearchOnlyDirectory(t *testing.T) {
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "outer/child")
	write(t, base, "outer/child/leaf.txt", "listable")
	outer := filepath.Join(base, "outer")
	chmodBack(t, outer, 0o755)
	if err := os.Chmod(outer, 0o111); err != nil { // searchable, not readable
		t.Fatal(err)
	}
	// The kernel has to be enforcing the read bit for the test to mean anything.
	if _, err := os.ReadDir(outer); err == nil {
		t.Skip("this filesystem does not enforce the directory read bit")
	}
	r := newRoot(t, base)
	ctx := context.Background()

	l, err := List(ctx, r, nil, "/outer/child", fsx.ListOptions{})
	if err != nil {
		t.Fatalf("listing a readable directory inside a search-only one: %v", err)
	}
	if l.Total != 1 || len(l.Entries) != 1 || l.Entries[0].Name != "leaf.txt" {
		t.Fatalf("listing = %+v, want the one entry leaf.txt", l)
	}
	if l.Path != "/outer/child" || l.Parent != "/outer" {
		t.Errorf("path = %q, parent = %q, want /outer/child and /outer", l.Path, l.Parent)
	}

	// And the directory with no read bit is still the kernel's to refuse.
	if _, err := List(ctx, r, nil, "/outer", fsx.ListOptions{}); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("listing a directory with no read bit = %v, want a permission error", err)
	} else if code := fsx.Code(err); code != "permission" {
		t.Errorf("code = %q, want permission", code)
	}
}

// TestMetadataThroughNestedSearchOnlyDirectories is the same rule for every
// operation that only needs to *reach* a name rather than to enumerate one, and
// for more than one directory deep — because the walk os.Root does is the same
// walk whether the read permission is missing on the first component or the
// fourth. Stat, StatFollow, Readlink and OpenRead all take the O_PATH walk now;
// this is what says so.
func TestMetadataThroughNestedSearchOnlyDirectories(t *testing.T) {
	requireSymlinks(t)
	requireUnprivileged(t)
	base := tempDir(t)
	mkdir(t, base, "outer/inner")
	write(t, base, "outer/inner/leaf.txt", "reachable")
	if err := os.Symlink("leaf.txt", filepath.Join(base, "outer", "inner", "ptr")); err != nil {
		t.Fatal(err)
	}
	outer := filepath.Join(base, "outer")
	inner := filepath.Join(outer, "inner")
	// Restored innermost first, which is the order t.Cleanup runs them in and
	// the only order that works: chmod on the inner directory needs the search
	// bit on the outer one, which 0111 still grants.
	chmodBack(t, outer, 0o755)
	chmodBack(t, inner, 0o755)
	for _, dir := range []string{outer, inner} {
		if err := os.Chmod(dir, 0o111); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.ReadDir(outer); err == nil {
		t.Skip("this filesystem does not enforce the directory read bit")
	}
	r := newRoot(t, base)
	ctx := context.Background()

	// The directories themselves are still nameable.
	if e, err := Stat(ctx, r, nil, "/outer/inner"); err != nil {
		t.Fatalf("stat of a search-only directory two deep: %v", err)
	} else if e.Type != "dir" {
		t.Errorf("type = %q, want dir", e.Type)
	}
	if e, err := Stat(ctx, r, nil, "/outer/inner/leaf.txt"); err != nil {
		t.Fatalf("stat through two search-only directories: %v", err)
	} else if e.Size != int64(len("reachable")) {
		t.Errorf("size = %d, want %d", e.Size, len("reachable"))
	}
	if target, err := Readlink(ctx, r, "/outer/inner/ptr"); err != nil {
		t.Fatalf("readlink through two search-only directories: %v", err)
	} else if target != "leaf.txt" {
		t.Errorf("target = %q, want leaf.txt", target)
	}
	if e, err := StatFollow(ctx, r, nil, "/outer/inner/ptr"); err != nil {
		t.Fatalf("stat through the link: %v", err)
	} else if e.Size != int64(len("reachable")) {
		t.Errorf("size through the link = %d, want %d", e.Size, len("reachable"))
	}
	f, _, err := OpenRead(ctx, r, "/outer/inner/leaf.txt")
	if err != nil {
		t.Fatalf("downloading through two search-only directories: %v", err)
	}
	f.Close()

	// And a name that is not there is still ENOENT rather than EACCES: the walk
	// must not turn "you may not look" into the answer for "it is not here".
	if _, err := Stat(ctx, r, nil, "/outer/inner/missing.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat of a missing name = %v, want a not-exist error", err)
	}
}
