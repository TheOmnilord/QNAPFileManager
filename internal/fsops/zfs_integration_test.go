package fsops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// The QuTS hero half of fsops, against the real file-backed pool built by
// scripts/ci-zfs-setup.sh (PLAN.md decision 14). Skips everywhere else; see
// internal/platform/zfs_integration_test.go for the same gate and the reason
// there is no simulated dataset boundary.
//
//	sudo bash scripts/ci-zfs-setup.sh
//	sudo -E env "PATH=$PATH" QFM_ZFS_TEST=1 go test -run ZFS ./internal/fsops/...
const (
	zfsShare  = "/share"
	zfsVol1   = "/share/ZFS1_DATA"
	zfsPublic = zfsVol1 + "/Public"
	zfsMedia  = zfsVol1 + "/Media"
)

func zfsFixture(t *testing.T) *platform.Platform {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the ZFS fixture is Linux only")
	}
	if os.Getenv("QFM_ZFS_TEST") != "1" {
		t.Skip("set QFM_ZFS_TEST=1 after running scripts/ci-zfs-setup.sh")
	}
	p := platform.Detect()
	if c := p.For(zfsPublic); c.FSType != "zfs" {
		t.Fatalf("QFM_ZFS_TEST=1 but %s is not on zfs (fstype %q): run scripts/ci-zfs-setup.sh first", zfsPublic, c.FSType)
	}
	return p
}

// TestZFSFixtureListShareClassifiesSharesAndVolumeRoots is the §2.2 rule on the
// real layout: at /share the registered shared folders are symlinks into a
// volume root, and the volume roots themselves are the raw mounts File Station
// will not show. Both have to be labelled, because the UI decides which to
// display and it cannot decide from the name.
func TestZFSFixtureListShareClassifiesSharesAndVolumeRoots(t *testing.T) {
	plat := zfsFixture(t)

	// The unjailed Root: the fixture lives at absolute paths on this host.
	var r fsx.Root
	l, err := List(context.Background(), r, plat, zfsShare, fsx.ListOptions{Limit: fsx.MaxListLimit})
	if err != nil {
		t.Fatalf("List(/share): %v", err)
	}

	for _, name := range []string{"Public", "Media"} {
		e, ok := find(l, name)
		if !ok {
			t.Errorf("/share has no entry %q; got %v", name, names(l))
			continue
		}
		if !e.IsSymlink {
			t.Errorf("/share/%s: IsSymlink = false, want true", name)
		}
		if !e.ShareLink {
			t.Errorf("/share/%s: ShareLink = false, want true (target type %q)", name, e.TargetType)
		}
		if e.VolumeRoot {
			t.Errorf("/share/%s: VolumeRoot = true, want false; it is a share link", name)
		}
	}

	for _, name := range []string{"ZFS1_DATA", "ZFS2_DATA"} {
		e, ok := find(l, name)
		if !ok {
			t.Errorf("/share has no entry %q; got %v", name, names(l))
			continue
		}
		if !e.VolumeRoot {
			t.Errorf("/share/%s: VolumeRoot = false, want true", name)
		}
		if !e.MountPoint {
			t.Errorf("/share/%s: MountPoint = false, want true", name)
		}
		if e.ShareLink {
			t.Errorf("/share/%s: ShareLink = true, want false; it is a raw volume mount", name)
		}
	}
}

// TestZFSFixtureRenameAcrossDatasetsIsEXDEV documents the platform fact the
// whole move pre-flight exists for: on hero every shared folder is its own
// dataset, so rename(2) between two shares of the *same pool* still fails with
// EXDEV and a move has to become copy-then-delete. syscall.EXDEV is compared
// directly rather than through a helper, because the point of the test is the
// errno.
func TestZFSFixtureRenameAcrossDatasetsIsEXDEV(t *testing.T) {
	zfsFixture(t)

	src := filepath.Join(zfsPublic, ".qfm-exdev-probe")
	dst := filepath.Join(zfsMedia, ".qfm-exdev-probe")
	if err := os.WriteFile(src, []byte("exdev"), 0o644); err != nil {
		t.Fatalf("writing the probe file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(src)
		_ = os.Remove(dst)
	})

	err := os.Rename(src, dst)
	if err == nil {
		t.Fatalf("os.Rename(%s, %s) succeeded; two datasets are two filesystems and this must be EXDEV", src, dst)
	}
	if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("os.Rename across datasets: got %v, want EXDEV", err)
	}
	// Same dataset, same st_dev: the rename that must keep working.
	within := filepath.Join(zfsPublic, ".qfm-exdev-probe-moved")
	if err := os.Rename(src, within); err != nil {
		t.Fatalf("rename inside one dataset: %v", err)
	}
	_ = os.Remove(within)
}

// TestZFSFixtureStatDevDiffersBetweenDatasets is the reason PLAN.md decision 9
// replaced the one-filesystem walk rule with the storage-domain rule: st_dev
// differs per share on hero, so "stay on one device" would have skipped every
// share.
func TestZFSFixtureStatDevDiffersBetweenDatasets(t *testing.T) {
	plat := zfsFixture(t)

	pub := zfsStatDev(t, zfsPublic)
	media := zfsStatDev(t, zfsMedia)
	sub := zfsStatDev(t, filepath.Join(zfsPublic, "sub"))

	if pub == media {
		t.Errorf("st_dev of %s and %s are both %d; each dataset must be its own device", zfsPublic, zfsMedia, pub)
	}
	if pub != sub {
		t.Errorf("st_dev of %s (%d) differs from its own subdirectory (%d)", zfsPublic, pub, sub)
	}
	// And yet the crossing rule lets a walk pass between them, which is the
	// whole point.
	if !plat.MayCross(plat.For(zfsPublic), plat.For(zfsMedia)) {
		t.Errorf("MayCross between two datasets of one pool = false, want true")
	}
}
