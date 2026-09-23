package fsops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestZFSFixtureSearchCrossesDatasetsOnlyWhenAsked is PLAN.md decision 9 on the
// search path, against real mount boundaries. Every share of one pool is its own
// dataset, so "include mounted sub-folders" is the difference between searching
// a volume root and searching one empty directory — and a dev box has no way to
// produce the boundary at all (INV-2).
func TestZFSFixtureSearchCrossesDatasetsOnlyWhenAsked(t *testing.T) {
	plat := zfsFixture(t)
	ctx := context.Background()
	var r fsx.Root

	probe := filepath.Join(zfsPublic, ".qfm-search-probe.txt")
	t.Cleanup(func() { _ = os.Remove(probe) })
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatalf("building the probe: %v", err)
	}

	req := wproto.SearchReq{Roots: [][]byte{[]byte(zfsVol1)}, Query: "qfm-search-probe", Hidden: true}
	res, err := Search(ctx, r, plat, req, Emit{})
	if err != nil {
		t.Fatalf("Search without CrossMounts: %v", err)
	}
	for _, h := range res.Hits {
		if strings.Contains(h.Path, ".qfm-search-probe") {
			t.Fatalf("the search crossed into %s without being asked: %+v", zfsPublic, h)
		}
	}

	req.CrossMounts = true
	res, err = Search(ctx, r, plat, req, Emit{})
	if err != nil {
		t.Fatalf("Search with CrossMounts: %v", err)
	}
	found := false
	for _, h := range res.Hits {
		if h.Path == probe {
			found = true
		}
	}
	if !found {
		t.Fatalf("with CrossMounts the probe in %s must be found; hits = %d", zfsPublic, len(res.Hits))
	}

	// From the RAM disk itself (decision 9, amended — the QKVM hardware report):
	// /share is a tmpfs, so no volume under it shares its domain, and a search
	// of /share reached nothing at all. The read rule enters the volume, and the
	// same-pool rule then carries it into Public; unticked, the volumes are
	// counted as not searched rather than passed over in silence.
	shareReq := wproto.SearchReq{Roots: [][]byte{[]byte(zfsShare)}, Query: "qfm-search-probe", Hidden: true, CrossMounts: true}
	res, err = Search(ctx, r, plat, shareReq, Emit{})
	if err != nil {
		t.Fatalf("Search of %s with CrossMounts: %v", zfsShare, err)
	}
	found = false
	for _, h := range res.Hits {
		found = found || h.Path == probe
	}
	if !found {
		t.Fatalf("a search of %s with CrossMounts must reach %s; hits = %d, mounts skipped = %d",
			zfsShare, probe, len(res.Hits), res.MountsSkipped)
	}
	shareReq.CrossMounts = false
	res, err = Search(ctx, r, plat, shareReq, Emit{})
	if err != nil {
		t.Fatalf("Search of %s without CrossMounts: %v", zfsShare, err)
	}
	if len(res.Hits) != 0 || res.MountsSkipped < 2 {
		t.Fatalf("without CrossMounts: hits = %d, mounts skipped = %d; want none, and both volumes counted",
			len(res.Hits), res.MountsSkipped)
	}
}

// TestZFSFixtureArchiveOfADataset streams a real dataset and reads it back with
// archive/zip, which is what the client will do. It is here rather than in
// archive_test.go because a dataset is a mount point, and a mount point is the
// one thing the dev box cannot produce.
func TestZFSFixtureArchiveOfADataset(t *testing.T) {
	plat := zfsFixture(t)
	ctx := context.Background()
	var r fsx.Root

	dir := filepath.Join(zfsPublic, ".qfm-archive-probe")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("building the probe tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "deep.txt"), []byte("deeper"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &sink{}
	req := wproto.ArchiveReq{Paths: [][]byte{[]byte(dir)}, Format: ArchiveZip}
	if _, err := Archive(ctx, r, plat, req, mustPlan(t, r, plat, req), s); err != nil {
		t.Fatalf("Archive of a dataset: %v", err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m[".qfm-archive-probe/sub/deep.txt"] == nil {
		t.Fatalf("members = %v", memberNames(m))
	}
	if got := zipContent(t, m[".qfm-archive-probe/sub/deep.txt"]); got != "deeper" {
		t.Errorf("content = %q", got)
	}
	if m["ERROR.txt"] != nil {
		t.Errorf("a clean archive has no ERROR.txt: %s", zipContent(t, m["ERROR.txt"]))
	}
}

// TestZFSFixtureUploadIntoADataset is the whole upload shape against a real ZFS
// dataset: O_TMPFILE, the linkat that publishes it, and the ACLs a hero dataset
// hands a new file. All three are filesystem behaviour rather than this code's.
func TestZFSFixtureUploadIntoADataset(t *testing.T) {
	plat := zfsFixture(t)
	ctx := context.Background()
	var r fsx.Root

	name := ".qfm-upload-probe.txt"
	target := filepath.Join(zfsPublic, name)
	t.Cleanup(func() { _ = os.Remove(target) })
	_ = os.Remove(target)

	f, h, err := OpenWrite(ctx, r, plat, wproto.OpenWriteReq{
		Dir: []byte(zfsPublic), Name: []byte(name), Size: 5,
	})
	if err != nil {
		t.Fatalf("OpenWrite into a dataset: %v", err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		h.Close()
		t.Fatal(err)
	}
	f.Close()
	resp, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte(name)})
	if err != nil {
		t.Fatalf("Finalize into a dataset: %v", err)
	}
	if string(resp.Path) != target {
		t.Errorf("Path = %q, want %q", resp.Path, target)
	}
	b, rerr := os.ReadFile(target)
	if rerr != nil || string(b) != "hello" {
		t.Fatalf("the published file is %q (%v)", b, rerr)
	}
}
