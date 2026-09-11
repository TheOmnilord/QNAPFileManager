package trashroot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/platform"
)

// storageAt declares dir as an ext4 storage mount root, which is what makes it
// a trash root: the nearest enclosing Storage, non-network mount.
//
// The directory-creating half of this package's tests lives in this file
// because the sticky bit only exists on Linux (INV-2: never simulate the
// kernel). On Windows os.Chmod ignores os.ModeSticky and os.Lstat never
// reports it, so the assertion that matters could only be faked there.
func storageAt(t *testing.T, dir string) *platform.Platform {
	t.Helper()
	return mountinfo(t, storageLine(30, dir))
}

// tempMount is a temporary directory pretending to be a volume root. The
// symlinks are evaluated because /tmp is a symlink on some distributions and
// mountinfo paths are resolved.
func tempMount(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return dir
}

// TestEnsureCreatesASticky1777DirectoryOnce is the whole contract: the
// directory is made once, with the sticky bit the kernel will enforce, and a
// second call finds it rather than making it again.
func TestEnsureCreatesASticky1777DirectoryOnce(t *testing.T) {
	root := tempMount(t)
	plat := storageAt(t, root)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public", "deep", "file.txt"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Fatal("the first Ensure must report that it created the directory — the caller audits that as a milestone")
	}
	if want := filepath.Join(root, DirName); dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory: %v", dir, fi.Mode())
	}
	if fi.Mode().Perm() != 0o777 {
		t.Fatalf("mode = %v, want 0777 regardless of the daemon's umask", fi.Mode().Perm())
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		t.Fatalf("mode = %v, want the sticky bit: without it any user could take another's trashed files", fi.Mode())
	}

	// Idempotent, and it does not touch what is already there.
	marker := filepath.Join(dir, "1001")
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	again, created, err := Ensure(plat, filepath.Join(root, "Other"))
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if created {
		t.Error("the second Ensure must not report a creation")
	}
	if again != dir {
		t.Errorf("dir = %q, want %q", again, dir)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("Ensure disturbed an existing entry: %v", err)
	}
}

// TestEnsureRefusesSomethingElseAtTheName: a symlink, a plain file or a
// directory that is not sticky is never used and never replaced. Following a
// planted symlink would let whoever made it redirect a stream of other
// people's deleted files anywhere on the NAS.
func TestEnsureRefusesSomethingElseAtTheName(t *testing.T) {
	cases := []struct {
		name  string
		place func(t *testing.T, dir string)
	}{
		{"symlink", func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), "elsewhere")
			if err := os.Mkdir(target, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		}},
		{"regular file", func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory without the sticky bit", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := tempMount(t)
			c.place(t, filepath.Join(root, DirName))
			plat := storageAt(t, root)

			dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
			if !errors.Is(err, ErrUnsafeTrash) {
				t.Fatalf("Ensure = %q,%v,%v — want ErrUnsafeTrash", dir, created, err)
			}
			if created {
				t.Error("nothing may be reported as created here")
			}
		})
	}
}

// TestEnsureOnAnUnwritableRootIsNoTrash: a read-only or permission-refusing
// filesystem has no trash, which the caller turns into a permanent delete with
// a confirmation rather than a half-made directory or an internal error.
func TestEnsureOnAnUnwritableRootIsNoTrash(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on (INV-2: the kernel decides)")
	}
	root := tempMount(t)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	plat := storageAt(t, root)

	dir, created, err := Ensure(plat, filepath.Join(root, "Public"))
	if !errors.Is(err, ErrNoTrash) {
		t.Fatalf("Ensure = %q,%v,%v — want ErrNoTrash", dir, created, err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, DirName)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("something was created on a read-only root: %v", statErr)
	}
}

// TestEnsureUsesTheNearestStorageMount is decision 10 in one assertion: on a
// hero-shaped table the trash lands on the share's own dataset, not on the pool
// root, because a rename into the pool root would cross devices.
func TestEnsureUsesTheNearestStorageMount(t *testing.T) {
	pool := tempMount(t)
	share := filepath.Join(pool, "Public")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	plat := mountinfo(t,
		line(30, "0:50", pool, "zfs", "pool0/vol"),
		line(31, "0:51", share, "zfs", "pool0/vol/Public"),
	)
	dir, created, err := Ensure(plat, filepath.Join(share, "a", "b"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Error("the directory should have been created")
	}
	if want := filepath.Join(share, DirName); dir != want {
		t.Fatalf("dir = %q, want %q (the share's own dataset, next to @Recycle)", dir, want)
	}
}
