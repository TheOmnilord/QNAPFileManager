package trashroot

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"qnapfilemanager/internal/platform"
)

// mountinfo builds a Platform from the given mountinfo lines. FromMountinfo is
// pure — it never re-reads /proc — so a crafted table is the whole world for
// the platform it produces (PLAN.md decision 15).
func mountinfo(t *testing.T, lines ...string) *platform.Platform {
	t.Helper()
	p, err := platform.FromMountinfo(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("FromMountinfo: %v", err)
	}
	return p
}

// storageLine declares mp as an ext4 storage mount.
func storageLine(id int, mp string) string {
	return line(id, "8:1", mp, "ext4", "/dev/sda1")
}

func line(id int, dev, mp, fstype, source string) string {
	return strings.Join([]string{
		itoa(id), itoa(id - 1), dev, "/", escape(mp), "rw,relatime", "-", fstype, source, "rw",
	}, " ")
}

func itoa(i int) string { return strconv.Itoa(i) }

// escape applies the octal escaping mountinfo uses for spaces, so a temporary
// directory with a space in it still produces a valid line.
func escape(p string) string {
	r := strings.NewReplacer(" ", `\040`, "\t", `\011`, "\n", `\012`, `\`, `\134`)
	return r.Replace(p)
}

// TestEnsureWithoutAMountTable: no platform means no trash, not a panic and
// certainly not a directory created somewhere unknown.
func TestEnsureWithoutAMountTable(t *testing.T) {
	dir, created, err := Ensure(nil, "/share/CACHEDEV1_DATA/x")
	if !errors.Is(err, ErrNoTrash) || dir != "" || created {
		t.Fatalf("Ensure(nil) = %q,%v,%v want ErrNoTrash", dir, created, err)
	}
}

// TestEnsureRefusesANonStorageLocation: /proc, tmpfs, a network share — none of
// them gets a trash directory, and the caller must fall back to a permanent
// delete with a confirmation (PLAN.md decision 10).
func TestEnsureRefusesANonStorageLocation(t *testing.T) {
	plat := mountinfo(t,
		storageLine(30, "/share/CACHEDEV1_DATA"),
		line(31, "0:21", "/proc", "proc", "proc"),
		line(32, "0:22", "/tmp", "tmpfs", "tmpfs"),
		line(33, "0:40", "/share/remote", "nfs4", "nas:/export"),
	)
	for _, path := range []string{"/proc/1/status", "/tmp/scratch/file", "/share/remote/deep/file", "/nowhere/at/all"} {
		dir, created, err := Ensure(plat, path)
		if !errors.Is(err, ErrNoTrash) {
			t.Errorf("Ensure(%q) = %q,%v,%v — want ErrNoTrash", path, dir, created, err)
		}
		if dir != "" || created {
			t.Errorf("Ensure(%q) must create nothing, got %q created=%v", path, dir, created)
		}
	}
}

// TestDirNameIsTheAgreedOne pins the name the worker renames into. The
// front-end creates it and the user's worker moves files into it; if the two
// ever disagree, deletes fail as permission errors on a path nobody made.
func TestDirNameIsTheAgreedOne(t *testing.T) {
	if DirName != ".@qfm_trash" {
		t.Fatalf("DirName = %q, want .@qfm_trash (PLAN.md decision 10)", DirName)
	}
	if Mode.Perm() != 0o777 {
		t.Fatalf("Mode permissions = %v, want 0777", Mode.Perm())
	}
	if Mode&os.ModeSticky == 0 {
		t.Fatalf("Mode = %v, want the sticky bit: it is the whole security model", Mode)
	}
}
