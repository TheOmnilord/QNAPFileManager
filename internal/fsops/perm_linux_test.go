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
