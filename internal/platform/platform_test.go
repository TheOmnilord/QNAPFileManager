package platform

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) *Platform {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	p, err := FromMountinfo(f)
	if err != nil {
		t.Fatalf("FromMountinfo(%s): %v", name, err)
	}
	return p
}

func TestParseMountinfoFields(t *testing.T) {
	line := `34 31 9:1 /Public /share/Public\040Files rw,relatime - ext4 /dev/md1 rw,data=ordered`
	mounts, err := ParseMountinfo(strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	m := mounts[0]
	if m.ID != 34 || m.ParentID != 31 || m.Major != 9 || m.Minor != 1 {
		t.Errorf("ids/dev wrong: %+v", m)
	}
	if m.Root != "/Public" {
		t.Errorf("Root = %q, want /Public", m.Root)
	}
	if m.MountPoint != "/share/Public Files" {
		t.Errorf("MountPoint = %q, want %q", m.MountPoint, "/share/Public Files")
	}
	if m.FSType != "ext4" || m.Source != "/dev/md1" {
		t.Errorf("fstype/source wrong: %+v", m)
	}
	if len(m.Options) != 2 || m.Options[0] != "rw" || m.Options[1] != "relatime" {
		t.Errorf("Options = %v", m.Options)
	}
	if len(m.SuperOptions) != 2 || m.SuperOptions[1] != "data=ordered" {
		t.Errorf("SuperOptions = %v", m.SuperOptions)
	}
	if m.Dev() != "9:1" {
		t.Errorf("Dev() = %q", m.Dev())
	}
}

func TestUnescapeOctal(t *testing.T) {
	cases := map[string]string{
		`/share/Public\040Files`:     "/share/Public Files",
		`/a\011b`:                    "/a\tb",
		`/a\012b`:                    "/a\nb",
		`/back\134slash`:             "/back\\slash",
		`/plain`:                     "/plain",
		`/not\09escape`:              `/not\09escape`,
		`/trailing\`:                 `/trailing\`,
		`/share/\040leading\040both`: "/share/ leading both",
	}
	for in, want := range cases {
		if got := unescapeOctal(in); got != want {
			t.Errorf("unescapeOctal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMountinfoSkipsGarbage(t *testing.T) {
	in := "not a mountinfo line\n" +
		"\n" +
		"25 1 8:2 / / rw,relatime - ext4 /dev/sda1 rw\n" +
		"12 13 nope / /x rw - ext4 /dev/sdb rw\n" +
		"14 15 8:3 / /y rw ext4 /dev/sdc rw\n" // no separator
	mounts, err := ParseMountinfo(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].MountPoint != "/" {
		t.Fatalf("got %+v, want only the root mount", mounts)
	}
}

func TestQTSTable(t *testing.T) {
	p := load(t, "qts_mountinfo.txt")

	vol := p.For("/share/CACHEDEV1_DATA/Public/report.txt")
	if vol.FSType != "ext4" || !vol.Storage || vol.Network || vol.Tmpfs {
		t.Errorf("volume caps = %+v", vol)
	}
	if vol.Mount != "/share/CACHEDEV1_DATA" {
		t.Errorf("Mount = %q", vol.Mount)
	}
	if vol.Domain != "dev:9:1" {
		t.Errorf("Domain = %q, want dev:9:1", vol.Domain)
	}

	share := p.For("/share")
	if !share.Tmpfs || share.Storage {
		t.Errorf("/share caps = %+v", share)
	}
	if proc := p.For("/proc/1/status"); proc.FSType != "proc" || proc.Storage {
		t.Errorf("/proc caps = %+v", proc)
	}
	if nfs := p.For("/share/remote/x"); !nfs.Network || nfs.Storage {
		t.Errorf("nfs caps = %+v", nfs)
	}
	if root := p.For("/etc/config/uLinux.conf"); root.Mount != "/" || !root.Storage {
		t.Errorf("root caps = %+v", root)
	}
	// Escaped mount point is reachable by its decoded name.
	if esc := p.For("/share/CACHEDEV1_DATA/Public Files/x"); esc.Mount != "/share/CACHEDEV1_DATA/Public Files" {
		t.Errorf("escaped mount caps = %+v", esc)
	}
	// A relative or empty path never matches, even though "/" matches all.
	if c := p.For("relative/path"); c.Mount != "" || c.Storage {
		t.Errorf("relative path caps = %+v", c)
	}

	usb := p.For("/share/external/DEV3301_1/x")
	if usb.Mount != "/share/external/DEV3301_1" || usb.Domain != "dev:8:33" {
		t.Errorf("usb caps = %+v", usb)
	}
	// Same volume, different device: a walk of the volume must not descend
	// into the USB disk or the NFS mount, but stays within the volume.
	if p.MayCross(vol, usb) {
		t.Error("MayCross(volume, usb) = true, want false")
	}
	if p.MayCross(vol, p.For("/share/remote/x")) {
		t.Error("MayCross(volume, nfs) = true, want false")
	}
	if p.MayCross(vol, share) {
		t.Error("MayCross(volume, tmpfs) = true, want false")
	}
	if p.MayCross(vol, p.For("/proc")) {
		t.Error("MayCross(volume, proc) = true, want false")
	}
	// The bind mount of the same device is the same domain and crossable.
	if !p.MayCross(vol, p.For("/share/CACHEDEV1_DATA/Public Files/x")) {
		t.Error("MayCross(volume, same-device bind) = false, want true")
	}

	roots := p.VolumeRoots()
	if len(roots) != 1 || roots[0].MountPoint != "/share/CACHEDEV1_DATA" {
		t.Fatalf("VolumeRoots = %v, want [/share/CACHEDEV1_DATA]", mountPoints(roots))
	}
}

func TestHeroTable(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")

	ds := p.For("/share/ZFS530_DATA/Public/file.txt")
	if ds.Mount != "/share/ZFS530_DATA/Public" {
		t.Fatalf("Mount = %q, want /share/ZFS530_DATA/Public", ds.Mount)
	}
	if ds.Domain != "zfs:zpool1" || !ds.Storage || ds.Network {
		t.Errorf("dataset caps = %+v", ds)
	}

	media := p.For("/share/ZFS530_DATA/Media")
	if !p.MayCross(ds, media) {
		t.Error("MayCross(Public, Media) = false, want true (same pool)")
	}
	volRoot := p.For("/share/ZFS530_DATA")
	if !p.MayCross(volRoot, ds) {
		t.Error("MayCross(volume root, dataset) = false, want true")
	}

	other := p.For("/share/ZFS531_DATA/Backup/x")
	if other.Domain != "zfs:zpool2" {
		t.Errorf("second pool domain = %q", other.Domain)
	}
	if p.MayCross(ds, other) {
		t.Error("MayCross(zpool1, zpool2) = true, want false")
	}
	if p.MayCross(ds, p.For("/share")) {
		t.Error("MayCross(dataset, tmpfs /share) = true, want false")
	}
	if p.MayCross(ds, p.For("/proc/self")) {
		t.Error("MayCross(dataset, proc) = true, want false")
	}
	if p.MayCross(ds, p.For("/share/remote/x")) {
		t.Error("MayCross(dataset, cifs) = true, want false")
	}

	// Path-boundary matching: Publication is its own dataset and must never
	// be served by the /share/ZFS530_DATA/Public mount.
	pub := p.For("/share/ZFS530_DATA/Publication/notes.txt")
	if pub.Mount != "/share/ZFS530_DATA/Publication" {
		t.Errorf("Publication resolved to %q", pub.Mount)
	}
	// A sibling with the same prefix but no mount of its own falls back to
	// the parent dataset, not to Public.
	if fb := p.For("/share/ZFS530_DATA/Publicity/x"); fb.Mount != "/share/ZFS530_DATA" {
		t.Errorf("Publicity resolved to %q, want /share/ZFS530_DATA", fb.Mount)
	}
	// Escapes decoded in the hero table too.
	if hv := p.For("/share/ZFS530_DATA/Home Videos/a.mkv"); hv.Mount != "/share/ZFS530_DATA/Home Videos" {
		t.Errorf("escaped dataset resolved to %q", hv.Mount)
	}

	roots := p.VolumeRoots()
	if got := mountPoints(roots); len(got) != 2 || got[0] != "/share/ZFS530_DATA" || got[1] != "/share/ZFS531_DATA" {
		t.Fatalf("VolumeRoots = %v", got)
	}
	for _, m := range roots {
		if l := VolumeLabel(path.Base(m.MountPoint)); l == "" {
			t.Errorf("VolumeLabel(%s) empty", m.MountPoint)
		}
	}
}

func TestUbuntuTable(t *testing.T) {
	p := load(t, "ubuntu_mountinfo.txt")

	if roots := p.VolumeRoots(); len(roots) != 0 {
		t.Errorf("VolumeRoots = %v, want none on a plain Linux box", mountPoints(roots))
	}
	home := p.For("/home/sv/file")
	if home.Mount != "/home" || home.FSType != "xfs" || !home.Storage {
		t.Errorf("/home caps = %+v", home)
	}
	root := p.For("/usr/bin/env")
	if root.Mount != "/" || root.Domain != "dev:8:1" {
		t.Errorf("root caps = %+v", root)
	}
	if p.MayCross(root, home) {
		t.Error("MayCross(/, /home) = true, want false (different devices)")
	}
	if fuse := p.For("/run/user/1000/gvfs/x"); !fuse.Network {
		t.Errorf("fuse caps = %+v, want Network", fuse)
	}
	if efi := p.For("/boot/efi/EFI"); efi.Storage {
		t.Errorf("vfat treated as storage: %+v", efi)
	}
	if usb := p.For("/media/usb stick/x"); usb.Mount != "/media/usb stick" || !usb.Storage {
		t.Errorf("escaped usb mount = %+v", usb)
	}
	if !p.IsMountPoint("/home") {
		t.Error("IsMountPoint(/home) = false")
	}
	if p.IsMountPoint("/home/sv/projects/qfm") {
		t.Error("IsMountPoint(/home/sv/projects/qfm) = true, want false")
	}
	if !p.IsMountPoint("/") {
		t.Error("IsMountPoint(/) = false")
	}
}

// TestIsMountPointByTableMakesNoLookup pins the difference between the two
// classifiers, because the containment of every jailed caller rests on it: the
// table-only one must never reach the path probe, whose stat follows symlinks
// and can therefore describe a filesystem the caller was refused.
func TestIsMountPointByTableMakesNoLookup(t *testing.T) {
	p := load(t, "ubuntu_mountinfo.txt")

	var probed []string
	restore := mountProbe
	mountProbe = func(path string) bool {
		probed = append(probed, path)
		return true // the probe's answer must be the only way to get "true" here
	}
	t.Cleanup(func() { mountProbe = restore })

	// Absent from the table, and the table is all IsMountPointByTable may read.
	if p.IsMountPointByTable("/nowhere/at/all") {
		t.Error("IsMountPointByTable answered true for a path the table does not mention")
	}
	if len(probed) != 0 {
		t.Fatalf("IsMountPointByTable resolved %v; it must make no filesystem lookup at all", probed)
	}

	// The same path through IsMountPoint still falls back, which is the
	// behaviour the fallback's own tests rely on.
	if !p.IsMountPoint("/nowhere/at/all") {
		t.Error("IsMountPoint did not reach the path probe")
	}
	if len(probed) != 1 || probed[0] != "/nowhere/at/all" {
		t.Fatalf("probe calls = %v, want exactly one for /nowhere/at/all", probed)
	}

	// A table hit answers before the probe, on either entry point.
	probed = nil
	if !p.IsMountPointByTable("/proc") || !p.IsMountPoint("/proc") {
		t.Error("/proc is in the fixture table and must be a mount point on both paths")
	}
	if len(probed) != 0 {
		t.Fatalf("a table hit probed %v", probed)
	}
	if p.IsMountPointByTable("") {
		t.Error("the empty path is not a mount point")
	}
}

func TestRefreshLeavesStaticTableAlone(t *testing.T) {
	// A golden table must survive Refresh even when the test runs on a Linux
	// host whose /proc/self/mountinfo is readable.
	p := load(t, "hero_mountinfo.txt")
	before := len(p.Mounts())
	if err := p.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := len(p.Mounts()); got != before {
		t.Fatalf("static table changed: %d -> %d mounts", before, got)
	}
	if c := p.For("/share/ZFS530_DATA/Media"); c.Domain != "zfs:zpool1" {
		t.Fatalf("caps after Refresh = %+v", c)
	}
}

func TestFuseZFSIsNotNetwork(t *testing.T) {
	if IsNetworkFS("fuse.zfs") {
		t.Error("fuse.zfs must not be classified as a network filesystem")
	}
	for _, fs := range []string{"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "fuse.s3fs"} {
		if !IsNetworkFS(fs) {
			t.Errorf("IsNetworkFS(%s) = false", fs)
		}
	}
	for _, fs := range []string{"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs"} {
		if !IsStorageFS(fs) {
			t.Errorf("IsStorageFS(%s) = false", fs)
		}
	}
	for _, fs := range []string{"tmpfs", "proc", "sysfs", "vfat", "nfs4", "overlay"} {
		if IsStorageFS(fs) {
			t.Errorf("IsStorageFS(%s) = true", fs)
		}
	}
}

func TestVolumeLabel(t *testing.T) {
	cases := map[string]string{
		"CACHEDEV1_DATA":  "Volume 1",
		"ZFS530_DATA":     "Pool volume 530",
		"HDA_DATA":        "Legacy volume A",
		"HDK_DATA":        "Legacy volume K",
		"MD3_DATA":        "RAID volume 3",
		"Public":          "",
		"CACHEDEV_DATA":   "",
		"ZFS530_DATAX":    "",
		"xCACHEDEV1_DATA": "",
	}
	for in, want := range cases {
		if got := VolumeLabel(in); got != want {
			t.Errorf("VolumeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGetCfgAndFamily(t *testing.T) {
	dir := t.TempDir()
	hero := filepath.Join(dir, "uLinux.conf")
	content := "# QNAP firmware config\n" +
		"[Misc]\n" +
		"Version = 1.2.3\n" +
		"\n" +
		"[System]\n" +
		"Model = TS-h973AX\n" +
		"Version = \"h5.1.0\"\n" +
		"Build Number = 20250101\n" +
		"[Network]\n" +
		"Version = 9.9.9\n"
	if err := os.WriteFile(hero, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	v, ok := GetCfg(hero, "System", "Version")
	if !ok || v != "h5.1.0" {
		t.Fatalf("GetCfg System/Version = %q, %v", v, ok)
	}
	if v, ok := GetCfg(hero, "system", "version"); !ok || v != "h5.1.0" {
		t.Errorf("case-insensitive lookup = %q, %v", v, ok)
	}
	if v, ok := GetCfg(hero, "Misc", "Version"); !ok || v != "1.2.3" {
		t.Errorf("Misc/Version = %q, %v", v, ok)
	}
	if _, ok := GetCfg(hero, "System", "Nope"); ok {
		t.Error("missing key reported present")
	}
	if _, ok := GetCfg(filepath.Join(dir, "absent.conf"), "System", "Version"); ok {
		t.Error("missing file reported present")
	}

	if got := deriveFamily(v, false, false, false, true); got != FamilyHero {
		t.Errorf("hero version -> %q", got)
	}

	qts := filepath.Join(dir, "qts.conf")
	if err := os.WriteFile(qts, []byte("[System]\nVersion = 5.1.0\nModel = TS-453D\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	qv, _ := GetCfg(qts, "System", "Version")
	if qv != "5.1.0" {
		t.Fatalf("qts version = %q", qv)
	}
	if got := deriveFamily(qv, false, false, false, true); got != FamilyQTS {
		t.Errorf("qts version -> %q", got)
	}
	// A ZFS mount on a NAS makes it hero even if the version string does not
	// start with "h" (the version prefix is unverified hardware behaviour).
	if got := deriveFamily(qv, true, true, true, true); got != FamilyHero {
		t.Errorf("zfs mount on NAS -> %q", got)
	}
	// No uLinux.conf: never a NAS family, whatever ZFS says.
	if got := deriveFamily("", true, true, true, false); got != FamilyLinux {
		t.Errorf("plain linux with zfs -> %q", got)
	}
	if got := deriveFamily("", false, false, false, false); got != FamilyLinux {
		t.Errorf("plain linux -> %q", got)
	}
}

func TestDetectOffNAS(t *testing.T) {
	p := Detect()
	if p == nil {
		t.Fatal("Detect returned nil")
	}
	if p.Family == "" {
		t.Error("Detect left Family empty")
	}
	// The call must be usable everywhere; on Windows it is an empty table.
	_ = p.For("/share/CACHEDEV1_DATA")
	_ = p.Diag()
	_ = p.VolumeRoots()
}

func TestACLBackendProbe(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")

	// Filesystem that supports POSIX ACLs but has none set on the root.
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name == XattrPosixACL {
			return 0, ErrNoData
		}
		return 0, ErrNotSupported
	})
	if got := p.ACLBackendFor("/share/ZFS530_DATA"); got != ACLPosix {
		t.Errorf("ENODATA on posix acl -> %q, want posix", got)
	}

	// Filesystem that answers with a real NFSv4 ACL.
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name == XattrNFS4ACL {
			return 88, nil
		}
		return 0, ErrNotSupported
	})
	if got := p.ACLBackendFor("/share/ZFS530_DATA"); got != ACLNFS4 {
		t.Errorf("nfs4_acl -> %q, want nfs4", got)
	}

	// RichACL build.
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name == XattrRichACL {
			return 0, ErrNoData
		}
		return 0, ErrNotSupported
	})
	if got := p.ACLBackendFor("/share/ZFS530_DATA"); got != ACLNFS4 {
		t.Errorf("richacl -> %q, want nfs4", got)
	}

	// Nothing supported.
	p.SetXattrProbe(func(path, name string) (int, error) { return 0, ErrNotSupported })
	if got := p.ACLBackendFor("/share/ZFS530_DATA"); got != ACLNone {
		t.Errorf("ENOTSUP -> %q, want none", got)
	}

	// An unrelated error is not evidence of support either.
	p.SetXattrProbe(func(path, name string) (int, error) { return 0, errors.New("boom") })
	if got := p.ACLBackendFor("/share/ZFS530_DATA"); got != ACLNone {
		t.Errorf("error -> %q, want none", got)
	}
}

func TestZFSAclmode(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")

	var gotArgs []string
	p.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		gotArgs = append([]string{name}, args...)
		if _, ok := ctx.Deadline(); !ok {
			t.Error("ZFSAclmode ran without a deadline")
		}
		return []byte("discard\n"), nil
	})
	if got := p.ZFSAclmode("zpool1/zfs530_data/Public"); got != "discard" {
		t.Errorf("aclmode = %q, want discard", got)
	}
	want := []string{"zfs", "get", "-Hp", "-o", "value", "aclmode", "zpool1/zfs530_data/Public"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", gotArgs, want)
	}

	// Unavailable binary, an empty answer or "-" must never be guessed at.
	p.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("exec: zfs not found")
	})
	if got := p.ZFSAclmode("zpool1/zfs530_data"); got != "" {
		t.Errorf("missing zfs binary -> %q, want empty", got)
	}
	p.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("-\n"), nil
	})
	if got := p.ZFSAclmode("zpool1/zfs530_data"); got != "" {
		t.Errorf("dash -> %q, want empty", got)
	}
	if got := p.ZFSAclmode(""); got != "" {
		t.Errorf("empty dataset -> %q", got)
	}
}

func TestProbeFillsCaps(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name == XattrNFS4ACL {
			return 0, ErrNoData
		}
		return 0, ErrNotSupported
	})
	p.SetCommandRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("passthrough"), nil
	})
	p.Probe()

	c := p.For("/share/ZFS530_DATA/Media")
	if c.ACLBackend != ACLNFS4 || c.ACLXattr != XattrNFS4ACL {
		t.Errorf("dataset acl fields = %+v", c)
	}
	if c.ZFSAclmode != "passthrough" {
		t.Errorf("aclmode = %q", c.ZFSAclmode)
	}
	// Non-storage mounts are never probed.
	if tmp := p.For("/share"); tmp.ACLBackend != "" || tmp.ZFSAclmode != "" {
		t.Errorf("tmpfs probed: %+v", tmp)
	}
}

func TestDiag(t *testing.T) {
	p := load(t, "qts_mountinfo.txt")
	p.Family = FamilyQTS
	p.Firmware = "5.1.0"
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name == XattrPosixACL {
			return 0, ErrNoData
		}
		return 0, ErrNotSupported
	})
	p.Probe()

	d := p.Diag()
	if d["family"] != FamilyQTS || d["firmware"] != "5.1.0" {
		t.Errorf("family/firmware = %v/%v", d["family"], d["firmware"])
	}
	if n, _ := d["mountCount"].(int); n != 10 {
		t.Errorf("mountCount = %v, want 10", d["mountCount"])
	}
	mounts, _ := d["mounts"].([]map[string]any)
	if len(mounts) != 10 {
		t.Fatalf("mounts len = %d", len(mounts))
	}
	vols, _ := d["volumeRoots"].([]map[string]any)
	if len(vols) != 1 || vols[0]["label"] != "Volume 1" {
		t.Fatalf("volumeRoots = %v", vols)
	}
	acl, _ := d["aclBackends"].(map[string]string)
	if acl["/share/CACHEDEV1_DATA"] != ACLPosix {
		t.Errorf("aclBackends = %v", acl)
	}
	if _, ok := acl["/share"]; ok {
		t.Error("tmpfs listed in aclBackends")
	}
}

func TestConcurrentUse(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				_ = p.For("/share/ZFS530_DATA/Public/x")
				_ = p.VolumeRoots()
				_ = p.IsMountPoint("/share/ZFS530_DATA")
				_ = p.Mounts()
				_ = p.Diag()
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func mountPoints(ms []Mount) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.MountPoint)
	}
	return out
}

// TestMayCrossRead is decision 9's amendment (2026-09-23), on the captured
// tables: a read-only walk may step from the tmpfs /share into a volume — the
// QKVM hardware report, a search of /share that could reach nothing — and every
// crossing that starts inside a storage mount is still MayCross's own. The
// strict column is asserted beside it so the exception cannot leak into the
// rule that delete, trash, chmod and copy use.
func TestMayCrossRead(t *testing.T) {
	hero := load(t, "hero_mountinfo.txt")
	qts := load(t, "qts_mountinfo.txt")
	tests := []struct {
		name         string
		p            *Platform
		from, to     string
		read, strict bool // MayCrossRead, MayCross
	}{
		{"hero: tmpfs /share into a pool volume", hero, "/share", "/share/ZFS530_DATA", true, false},
		{"hero: tmpfs /share into the second pool", hero, "/share", "/share/ZFS531_DATA", true, false},
		{"hero: tmpfs /share into a network share", hero, "/share", "/share/remote/x", false, false},
		{"hero: tmpfs /share into proc", hero, "/share", "/proc/self", false, false},
		{"hero: tmpfs /share into another tmpfs", hero, "/share", "/share", false, false},
		{"hero: volume into its own dataset", hero, "/share/ZFS530_DATA", "/share/ZFS530_DATA/Public", true, true},
		{"hero: pool into the other pool", hero, "/share/ZFS530_DATA/Public", "/share/ZFS531_DATA/Backup", false, false},
		{"hero: pool back into tmpfs /share", hero, "/share/ZFS530_DATA", "/share", false, false},
		{"hero: pool into a network share", hero, "/share/ZFS530_DATA", "/share/remote/x", false, false},
		{"qts: tmpfs /share into the volume", qts, "/share", "/share/CACHEDEV1_DATA", true, false},
		// An ext4 USB disk mounted straight under the RAM disk is storage too, and a
		// read-only walk of /share reaches it; only a walk from a VOLUME is kept out.
		{"qts: tmpfs /share into a USB disk", qts, "/share", "/share/external/DEV3301_1", true, false},
		{"qts: tmpfs /share into nfs", qts, "/share", "/share/remote/x", false, false},
		{"qts: tmpfs /share into /tmp tmpfs", qts, "/share", "/tmp", false, false},
		{"qts: volume into a USB disk", qts, "/share/CACHEDEV1_DATA", "/share/external/DEV3301_1", false, false},
		{"qts: volume into its bind mount", qts, "/share/CACHEDEV1_DATA", "/share/CACHEDEV1_DATA/Public Files", true, true},
		{"qts: storage / into tmpfs /share", qts, "/", "/share", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			from, to := tc.p.For(tc.from), tc.p.For(tc.to)
			if got := tc.p.MayCrossRead(from, to); got != tc.read {
				t.Errorf("MayCrossRead(%s, %s) = %v, want %v", from.Mount, to.Mount, got, tc.read)
			}
			if got := tc.p.MayCross(from, to); got != tc.strict {
				t.Errorf("MayCross(%s, %s) = %v, want %v (the strict rule must not change)", from.Mount, to.Mount, got, tc.strict)
			}
		})
	}
}
