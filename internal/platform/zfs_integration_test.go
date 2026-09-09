package platform

import (
	"os"
	"runtime"
	"testing"
)

// These tests run against the real file-backed ZFS fixture built by
// scripts/ci-zfs-setup.sh, on the CI job that has it (PLAN.md decision 14).
// Everywhere else they skip: there is no ZFS on the Windows dev box and no
// simulation of one, because a simulated dataset boundary would test the
// simulation rather than the product (INV-2).
//
//	sudo bash scripts/ci-zfs-setup.sh
//	sudo -E env "PATH=$PATH" QFM_ZFS_TEST=1 go test -run ZFS ./internal/platform/...
//
// Everything the hero delta turns on is here: the per-dataset FSCaps, the
// pool-wide crossing domain, the refusal to cross into a second pool or the
// tmpfs /share, the volume roots derived from the table, and `zfs get aclmode`
// read through the real binary.
const (
	zfsShare  = "/share"
	zfsVol1   = "/share/ZFS1_DATA"
	zfsVol2   = "/share/ZFS2_DATA"
	zfsPublic = zfsVol1 + "/Public"
	zfsMedia  = zfsVol1 + "/Media"
	zfsBackup = zfsVol2 + "/Backup"

	zfsPool1Domain = "zfs:qfmpool"
	zfsPool2Domain = "zfs:qfmpool2"
)

// zfsFixture skips unless this is a Linux box that was told it has the
// fixture. Once QFM_ZFS_TEST=1 is set the fixture must actually be there: a
// silent pass on a job whose whole purpose is the ZFS check would be worse
// than a failure.
func zfsFixture(t *testing.T) *Platform {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the ZFS fixture is Linux only")
	}
	if os.Getenv("QFM_ZFS_TEST") != "1" {
		t.Skip("set QFM_ZFS_TEST=1 after running scripts/ci-zfs-setup.sh")
	}
	p := Detect()
	if c := p.For(zfsPublic); c.FSType != "zfs" {
		t.Fatalf("QFM_ZFS_TEST=1 but %s is not on zfs (fstype %q): run scripts/ci-zfs-setup.sh first", zfsPublic, c.FSType)
	}
	return p
}

func TestZFSFixtureDetectReportsDatasetCaps(t *testing.T) {
	p := zfsFixture(t)

	for _, mp := range []string{zfsVol1, zfsPublic, zfsMedia} {
		c := p.For(mp)
		if c.FSType != "zfs" {
			t.Errorf("For(%q).FSType = %q, want zfs", mp, c.FSType)
		}
		if !c.Storage {
			t.Errorf("For(%q).Storage = false, want true", mp)
		}
		if c.Network || c.Tmpfs {
			t.Errorf("For(%q): Network=%v Tmpfs=%v, want both false", mp, c.Network, c.Tmpfs)
		}
		if c.Domain != zfsPool1Domain {
			t.Errorf("For(%q).Domain = %q, want %q", mp, c.Domain, zfsPool1Domain)
		}
		if c.Mount != mp {
			t.Errorf("For(%q).Mount = %q, want the dataset's own mount point", mp, c.Mount)
		}
	}

	if c := p.For(zfsBackup); c.Domain != zfsPool2Domain {
		t.Errorf("For(%q).Domain = %q, want %q", zfsBackup, c.Domain, zfsPool2Domain)
	}
	if c := p.For(zfsShare); !c.Tmpfs || c.Storage {
		t.Errorf("For(%q) = %+v, want the QTS RAM disk: Tmpfs true, Storage false", zfsShare, c)
	}
}

func TestZFSFixtureDatasetsOfOnePoolShareADomain(t *testing.T) {
	p := zfsFixture(t)

	// A file inside one dataset and the root of another: identity plan §4.2
	// says the whole pool is one crossing domain, so these must agree.
	file := p.For(zfsPublic + "/hello.txt")
	media := p.For(zfsMedia)
	if file.Domain != media.Domain {
		t.Fatalf("domains differ inside one pool: %q vs %q", file.Domain, media.Domain)
	}
	if file.Domain != zfsPool1Domain {
		t.Fatalf("domain = %q, want %q", file.Domain, zfsPool1Domain)
	}
}

func TestZFSFixtureMayCross(t *testing.T) {
	p := zfsFixture(t)

	pub := p.For(zfsPublic + "/hello.txt")
	media := p.For(zfsMedia)
	other := p.For(zfsBackup)
	share := p.For(zfsShare)

	if !p.MayCross(pub, media) {
		t.Errorf("MayCross(Public, Media) = false, want true: one pool is one domain")
	}
	if !p.MayCross(media, pub) {
		t.Errorf("MayCross(Media, Public) = false, want true")
	}
	if p.MayCross(pub, other) {
		t.Errorf("MayCross(Public, %s) = true, want false: a second pool is a second domain", zfsBackup)
	}
	if p.MayCross(pub, share) {
		t.Errorf("MayCross(Public, /share) = true, want false: /share is a RAM disk")
	}
}

func TestZFSFixtureIsMountPoint(t *testing.T) {
	p := zfsFixture(t)

	for _, mp := range []string{zfsVol1, zfsVol2, zfsPublic, zfsMedia, zfsBackup} {
		if !p.IsMountPoint(mp) {
			t.Errorf("IsMountPoint(%q) = false, want true", mp)
		}
	}
	// A plain directory inside a dataset is not a mount point, which is what
	// keeps the UI from putting a mount badge on every folder.
	if p.IsMountPoint(zfsPublic + "/sub") {
		t.Errorf("IsMountPoint(%q) = true, want false", zfsPublic+"/sub")
	}
}

func TestZFSFixtureVolumeRoots(t *testing.T) {
	p := zfsFixture(t)

	got := mountPoints(p.VolumeRoots())
	want := map[string]bool{zfsVol1: true, zfsVol2: true}
	for _, mp := range got {
		if !want[mp] {
			t.Errorf("VolumeRoots contains %q, which is not a volume root of the fixture", mp)
		}
		delete(want, mp)
	}
	for mp := range want {
		t.Errorf("VolumeRoots is missing %q; got %v", mp, got)
	}
	// The datasets themselves are storage mounts too, but they are not direct
	// children of /share and must not be promoted to volume roots.
	for _, mp := range got {
		if mp == zfsPublic || mp == zfsMedia {
			t.Errorf("VolumeRoots contains the dataset %q; only /share's direct children qualify", mp)
		}
	}
}

func TestZFSFixtureAclmodeFromTheRealBinary(t *testing.T) {
	p := zfsFixture(t)

	for _, tc := range []struct{ dataset, want string }{
		{"qfmpool/Public", "discard"},
		{"qfmpool/Media", "passthrough"},
	} {
		if got := p.ZFSAclmode(tc.dataset); got != tc.want {
			t.Errorf("ZFSAclmode(%q) = %q, want %q", tc.dataset, got, tc.want)
		}
	}

	// Detect() runs Probe(), so the same answers must be in the caps table
	// without the caller having to know the dataset name.
	if got := p.For(zfsPublic).ZFSAclmode; got != "discard" {
		t.Errorf("For(%q).ZFSAclmode = %q, want discard", zfsPublic, got)
	}
	if got := p.For(zfsMedia).ZFSAclmode; got != "passthrough" {
		t.Errorf("For(%q).ZFSAclmode = %q, want passthrough", zfsMedia, got)
	}
}

func TestZFSFixtureACLBackendProbe(t *testing.T) {
	p := zfsFixture(t)

	// Written tolerantly on purpose (identity plan §6): upstream OpenZFS on
	// Linux may expose no ACL xattr at all where QNAP's fork exposes an NFSv4
	// one. The contract is "report whichever is present, and none otherwise",
	// never "assert nfs4".
	for _, mp := range []string{zfsPublic, zfsMedia, zfsBackup} {
		got := p.ACLBackendFor(mp)
		switch got {
		case ACLPosix, ACLNFS4, ACLNone:
			t.Logf("ACLBackendFor(%q) = %q (xattr %q)", mp, got, p.For(mp).ACLXattr)
		default:
			t.Errorf("ACLBackendFor(%q) = %q, want one of %q, %q, %q", mp, got, ACLPosix, ACLNFS4, ACLNone)
		}
		if c := p.For(mp); c.ACLBackend != got {
			t.Errorf("For(%q).ACLBackend = %q but ACLBackendFor said %q", mp, c.ACLBackend, got)
		}
	}
}
