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
	"qnapfilemanager/internal/wproto"
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
	zfsVol2   = "/share/ZFS2_DATA"
	zfsBackup = zfsVol2 + "/Backup"
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

// TestZFSFixtureFSIdentityTellsDatasetsApart is the measurement the whole move
// pre-flight rests on (M2-B contract §1.2). Two shares of one pool are two
// datasets and must answer differently; one dataset must answer the same for
// everything inside it. A pure st_dev comparison would already get this right
// on ZFS — the mount id matters on QTS, where the share layout is bind mounts —
// but this is the platform where the prediction actually has to be made.
func TestZFSFixtureFSIdentityTellsDatasetsApart(t *testing.T) {
	plat := zfsFixture(t)
	ctx := context.Background()
	var r fsx.Root // the unjailed Root: the fixture lives at absolute paths

	pub, err := FSIdentity(ctx, r, plat, zfsPublic)
	if err != nil {
		t.Fatalf("FSIdentity(%s): %v", zfsPublic, err)
	}
	if !pub.Dir {
		t.Errorf("%s: Dir = false", zfsPublic)
	}
	media, err := FSIdentity(ctx, r, plat, zfsMedia)
	if err != nil {
		t.Fatalf("FSIdentity(%s): %v", zfsMedia, err)
	}
	backup, err := FSIdentity(ctx, r, plat, zfsBackup)
	if err != nil {
		t.Fatalf("FSIdentity(%s): %v", zfsBackup, err)
	}
	sub, err := FSIdentity(ctx, r, plat, filepath.Join(zfsPublic, "sub"))
	if err != nil {
		t.Fatalf("FSIdentity(%s/sub): %v", zfsPublic, err)
	}

	if pub.Same(media) {
		t.Errorf("%s and %s report one filesystem (%+v / %+v); each dataset is its own", zfsPublic, zfsMedia, pub, media)
	}
	if pub.Same(backup) {
		t.Errorf("%s and %s report one filesystem; they are different pools", zfsPublic, zfsBackup)
	}
	if !pub.Same(sub) {
		t.Errorf("%s and its own subdirectory report two filesystems (%+v / %+v)", zfsPublic, pub, sub)
	}
}

// TestZFSFixtureMoveAcrossPoolsCopiesThenDeletes runs the real EXDEV half of a
// move against two real datasets — the case the seam in copy_test.go can only
// imitate, and the case every hero move between shares actually takes.
func TestZFSFixtureMoveAcrossPoolsCopiesThenDeletes(t *testing.T) {
	plat := zfsFixture(t)
	ctx := context.Background()
	var r fsx.Root

	src := filepath.Join(zfsPublic, ".qfm-move-probe")
	dst := filepath.Join(zfsBackup, ".qfm-move-probe")
	t.Cleanup(func() {
		_ = os.RemoveAll(src)
		_ = os.RemoveAll(dst)
	})
	_ = os.RemoveAll(src)
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatalf("building the probe tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "deep.txt"), []byte("deeper"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The rename this move cannot make, stated first, so a failure below is
	// read as the engine's and not as the fixture's.
	if err := os.Rename(src, dst); err == nil {
		t.Fatalf("rename between %s and %s succeeded; the fixture is not two filesystems", zfsPublic, zfsBackup)
	} else if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("rename between datasets: got %v, want EXDEV", err)
	}

	var log jobLog
	res, err := Copy(ctx, r, plat, copyReq(zfsBackup, wproto.CopyOptions{}, src), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean cross-pool move: %v", log.warns)
	}
	if res.Files != 2 || res.Dirs != 2 {
		t.Fatalf("result = %+v, want 2 files and 2 directories moved", res)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "sub", "deep.txt")); err != nil || string(b) != "deeper" {
		t.Fatalf("the moved file is %q (%v)", b, err)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatalf("the source survived a verified cross-pool move: %v", err)
	}
}
