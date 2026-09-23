package fsops

// PLAN.md decision 9, amended 2026-09-23: a walk that only READS may step from a
// non-storage parent — the tmpfs /share every volume hangs off — into a storage
// volume. The hardware report was a search of /share for "QKVM" that returned
// nothing and said nothing, for a folder at /share/ZFS530_DATA/.qpkg/QKVM.
//
// The tables are synthetic (PLAN.md decision 15): mounting anything needs root,
// and the crossing decision is a lookup by OS path on a static table, which is
// exactly what these exercise on every platform. The CI ZFS job crosses real
// datasets (zfs_integration_test.go).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// ramDiskShare builds the hero shape under a temporary directory:
//
//	share/                       tmpfs (the RAM disk)
//	share/ZFS530_DATA/           zfs zpool1  — .qpkg/QKVM lives here
//	share/ZFS530_DATA/Public/    zfs zpool1  — same pool, crossed from the volume
//	share/ZFS530_DATA/other/     zfs zpool2  — another pool, NESTED: refused
//	share/ZFS530_DATA/ram/       tmpfs       — nested RAM disk: refused
//	share/ZFS531_DATA/           zfs zpool2  — the second pool, entered from /share
//	share/remote/                cifs        — never entered, never even lstat'ed
//
// Every leaf that could match is called something with "qkvm" in it, so the
// hit list alone says which mounts were entered.
func ramDiskShare(t *testing.T) string {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "share/ZFS530_DATA/.qpkg/QKVM")
	mkdir(t, base, "share/ZFS530_DATA/Public")
	write(t, base, "share/ZFS530_DATA/Public/qkvm-notes.txt", "12345")
	mkdir(t, base, "share/ZFS530_DATA/other")
	write(t, base, "share/ZFS530_DATA/other/qkvm-other-pool.txt", "x")
	mkdir(t, base, "share/ZFS530_DATA/ram")
	write(t, base, "share/ZFS530_DATA/ram/qkvm-ram.txt", "x")
	mkdir(t, base, "share/ZFS531_DATA")
	write(t, base, "share/ZFS531_DATA/qkvm-backup.txt", "123")
	mkdir(t, base, "share/remote")
	write(t, base, "share/remote/qkvm-remote.txt", "x")
	return base
}

func ramDiskPlatform(t *testing.T, api string) *platform.Platform {
	t.Helper()
	share := api + "/share"
	return synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: share, fsType: "tmpfs", dev: "0:23", source: "tmpfs"},
		synthMount{mountPoint: share + "/ZFS530_DATA", fsType: "zfs", dev: "0:40", source: "zpool1/zfs530_data"},
		synthMount{mountPoint: share + "/ZFS530_DATA/Public", fsType: "zfs", dev: "0:41", source: "zpool1/zfs530_data/Public"},
		synthMount{mountPoint: share + "/ZFS530_DATA/other", fsType: "zfs", dev: "0:42", source: "zpool2/elsewhere"},
		synthMount{mountPoint: share + "/ZFS530_DATA/ram", fsType: "tmpfs", dev: "0:24", source: "tmpfs"},
		synthMount{mountPoint: share + "/ZFS531_DATA", fsType: "zfs", dev: "0:45", source: "zpool2/zfs531_data"},
		synthMount{mountPoint: share + "/remote", fsType: "cifs", dev: "0:47", source: "//fileserver/share"},
	)
}

func sortedHitNames(res wproto.JobResult) []string {
	out := hitNames(res)
	sort.Strings(out)
	return out
}

func TestSearchFromTheRAMDiskEntersEveryVolume(t *testing.T) {
	base := ramDiskShare(t)
	r, api := hostRoot(t, base)
	plat := ramDiskPlatform(t, api)
	share := api + "/share"

	tests := []struct {
		name    string
		cross   bool
		hits    []string
		mounts  int64
		network int64
	}{
		// The report's own search: both boxes ticked. The volumes under the RAM
		// disk are entered; inside a volume the strict rule still holds, so the
		// nested other pool and the nested tmpfs are not, and the network share
		// never is. Only the other pool is counted: a tmpfs is nowhere a search
		// could start.
		{"include mounted sub-folders", true,
			[]string{"QKVM", "qkvm-backup.txt", "qkvm-notes.txt"}, 1, 1},
		// Unticked: nothing under /share is on /share's own filesystem, so there
		// is nothing to find — and the two volumes it stopped at are counted, so
		// the answer is "not looked at" rather than "not there".
		{"mounted sub-folders off", false, []string{}, 2, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := searchReq("qkvm", share)
			req.Hidden, req.CrossMounts = true, tc.cross
			res, err := Search(context.Background(), r, plat, req, Emit{})
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if got := sortedHitNames(res); strings.Join(got, ",") != strings.Join(tc.hits, ",") {
				t.Errorf("hits = %v, want %v", got, tc.hits)
			}
			if res.MountsSkipped != tc.mounts || res.MountsNetwork != tc.network {
				t.Errorf("MountsSkipped = %d, MountsNetwork = %d, want %d and %d",
					res.MountsSkipped, res.MountsNetwork, tc.mounts, tc.network)
			}
		})
	}
}

// TestSearchCountsHiddenMountsOnlyWhenHiddenIsOn: a hidden mount point is passed
// over because it is hidden, not because it is a mount, and saying "1 mounted
// folder was not searched" about a folder the user asked not to see would be
// noise.
func TestSearchCountsHiddenMountsOnlyWhenHiddenIsOn(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "share/.hidden_vol")
	mkdir(t, base, "share/vol")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/share", fsType: "tmpfs", dev: "0:23", source: "tmpfs"},
		synthMount{mountPoint: api + "/share/.hidden_vol", fsType: "ext4", dev: "8:2", source: "/dev/sdb1"},
		synthMount{mountPoint: api + "/share/vol", fsType: "ext4", dev: "8:3", source: "/dev/sdc1"},
	)
	for _, hidden := range []bool{false, true} {
		req := searchReq("nothing-matches", api+"/share")
		req.Hidden = hidden
		res, err := Search(context.Background(), r, plat, req, Emit{})
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		want := int64(1)
		if hidden {
			want = 2
		}
		if res.MountsSkipped != want {
			t.Errorf("hidden=%v: MountsSkipped = %d, want %d", hidden, res.MountsSkipped, want)
		}
	}
}

func TestSizeFromTheRAMDiskTakesTheReadRuleOnlyWhenAsked(t *testing.T) {
	base := ramDiskShare(t)
	r, api := hostRoot(t, base)
	plat := ramDiskPlatform(t, api)
	share := api + "/share"

	tests := []struct {
		name    string
		opts    SizeOptions
		files   int64
		bytes   int64
		mounts  int64
		network int64
	}{
		// The folder-size route: into both volumes and the same-pool dataset, not
		// into the nested pool, the nested tmpfs or the network share; the tmpfs
		// is not counted as a mounted folder left out.
		{"read rule", SizeOptions{CrossMounts: true, ReadCross: true}, 2, 8, 1, 1},
		// A pre-scan that confirms a change: the strict rule, so nothing under the
		// RAM disk is a volume it may enter.
		{"strict rule", SizeOptions{CrossMounts: true}, 0, 0, 2, 1},
		{"crossing off", SizeOptions{ReadCross: true}, 0, 0, 2, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Size(context.Background(), r, plat, []string{share}, tc.opts, Emit{})
			if err != nil {
				t.Fatalf("Size: %v", err)
			}
			if res.Files != tc.files || res.Bytes != tc.bytes || res.MountsSkipped != tc.mounts || res.MountsNetwork != tc.network {
				t.Errorf("result = files %d bytes %d mounts %d network %d, want %d %d %d %d",
					res.Files, res.Bytes, res.MountsSkipped, res.MountsNetwork, tc.files, tc.bytes, tc.mounts, tc.network)
			}
		})
	}
}

// TestAChangingWalkNeverTakesTheReadRule is the other half of the amendment: a
// walk that changes the tree, and the pre-scan that gives one its denominator,
// keep MayCross whatever flag they are handed.
func TestAChangingWalkNeverTakesTheReadRule(t *testing.T) {
	base := ramDiskShare(t)
	r, api := hostRoot(t, base)
	plat := ramDiskPlatform(t, api)
	share := api + "/share"

	// The pre-scan, asked for the read rule by mistake: ProtectWrite makes it a
	// mutating walk, and it still counts only /share and the three mount points it
	// stopped at — the count the delete will walk.
	scan, err := scanTrees(context.Background(), r, plat, []string{share}, true, true, Emit{}, scanLimits{}, true, ProtectWrite)
	if err != nil {
		t.Fatalf("scanTrees: %v", err)
	}
	if scan.files != 0 || scan.bytes != 0 {
		t.Errorf("pre-scan = %+v, want nothing under the RAM disk counted", scan)
	}

	// A Walk handed both flags directly, with Mutating: nothing below a volume.
	var entered []string
	err = Walk(context.Background(), r, plat, share, WalkOptions{CrossMounts: true, ReadCrossing: true, Mutating: true},
		Visitor{Pre: func(it WalkItem) error {
			if it.Depth > 1 {
				entered = append(entered, it.Path)
			}
			return nil
		}})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entered) != 0 {
		t.Errorf("a mutating walk entered %v", entered)
	}

	// And the real thing: a recursive delete of /share with "include mounted
	// sub-folders" on removes nothing on any volume.
	var log jobLog
	if _, err := DeleteTree(context.Background(), r, plat, []string{share}, DeleteOptions{Recursive: true, CrossMounts: true}, log.emit()); err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	for _, rel := range []string{
		"share/ZFS530_DATA/.qpkg/QKVM",
		"share/ZFS530_DATA/Public/qkvm-notes.txt",
		"share/ZFS531_DATA/qkvm-backup.txt",
		"share/remote/qkvm-remote.txt",
	} {
		if _, err := os.Lstat(filepath.Join(base, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s: %v — the delete reached a volume through the read rule", rel, err)
		}
	}
}

// TestOnlyStorageMountsAreCountedAsNotSearched is Astra r2 on the QKVM fix: a
// search or size of / meets /proc, /sys, /dev and a tmpfs or two, and counting
// them as "mounted folders not searched" would point at places no search can
// start — a search rooted at a kernel filesystem is refused. Only
// an IDENTIFIED Storage, non-network mount is counted; one the table cannot name
// (the fail-closed path) is not.
func TestOnlyStorageMountsAreCountedAsNotSearched(t *testing.T) {
	base := tempDir(t)
	for _, d := range []string{"proc", "sys", "dev", "run", "cgroup", "data", "unnamed"} {
		mkdir(t, base, d)
		write(t, base, d+"/probe-"+d+".txt", "x")
	}
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/proc", fsType: "proc", dev: "0:16", source: "proc"},
		synthMount{mountPoint: api + "/sys", fsType: "sysfs", dev: "0:17", source: "sysfs"},
		synthMount{mountPoint: api + "/dev", fsType: "devtmpfs", dev: "0:6", source: "devtmpfs"},
		synthMount{mountPoint: api + "/run", fsType: "tmpfs", dev: "0:19", source: "tmpfs"},
		synthMount{mountPoint: api + "/cgroup", fsType: "cgroup2", dev: "0:26", source: "cgroup2"},
		// A second disk: storage, another domain, so a boundary either way.
		synthMount{mountPoint: api + "/data", fsType: "ext4", dev: "8:17", source: "/dev/sdb1"},
	)
	// "unnamed" is on another mount by its descriptor and absent from the table.
	fakeIdentities(t, map[string]uint64{"unnamed": 7})

	for _, cross := range []bool{false, true} {
		req := searchReq("probe", api)
		req.Hidden, req.CrossMounts = true, cross
		res, err := Search(context.Background(), r, plat, req, Emit{})
		if err != nil {
			t.Fatalf("Search(cross=%v): %v", cross, err)
		}
		if len(res.Hits) != 0 || res.MountsSkipped != 1 || res.MountsNetwork != 0 {
			t.Errorf("search cross=%v: hits %v, MountsSkipped %d, MountsNetwork %d; want no hits and only /data counted",
				cross, hitNames(res), res.MountsSkipped, res.MountsNetwork)
		}

		size, err := Size(context.Background(), r, plat, []string{api}, SizeOptions{CrossMounts: cross, ReadCross: true}, Emit{})
		if err != nil {
			t.Fatalf("Size(cross=%v): %v", cross, err)
		}
		if size.Files != 0 || size.MountsSkipped != 1 {
			t.Errorf("size cross=%v: files %d, MountsSkipped %d; want nothing counted and only /data reported",
				cross, size.Files, size.MountsSkipped)
		}
	}
}

// qtsGoldenUnder is the captured QTS mount table (internal/platform/testdata,
// PLAN.md decision 15) re-rooted under a temporary directory, so the walk can
// be run against it on real directories. Every mount point gets api in front and
// every mount ID and parent ID is moved past synthMountIDBase, for the reason
// that constant exists: the walk names a mount by its descriptor first, and the
// captured IDs (17, 25, 30…) are small enough to collide with the CI kernel's.
// extra lines, in the same format and already un-prefixed, are appended after
// the captured ones and are rewritten the same way.
func qtsGoldenUnder(t *testing.T, api string, extra ...string) *platform.Platform {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "platform", "testdata", "qts_mountinfo.txt"))
	if err != nil {
		t.Fatalf("reading the golden QTS table: %v", err)
	}
	lines := append(strings.Split(strings.TrimSpace(string(raw)), "\n"), extra...)
	var b strings.Builder
	for _, line := range lines {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 5 {
			continue
		}
		for _, i := range []int{0, 1} {
			var id int
			if _, err := fmt.Sscan(f[i], &id); err != nil {
				t.Fatalf("mount id %q: %v", f[i], err)
			}
			f[i] = fmt.Sprint(synthMountIDBase + id)
		}
		mp := strings.TrimSuffix(api+f[4], "/")
		f[4] = strings.ReplaceAll(mp, " ", `\040`)
		b.WriteString(strings.Join(f, " ") + "\n")
	}
	p, err := platform.FromMountinfo(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("re-rooted golden table: %v", err)
	}
	return p
}

// TestSearchOfShareOnTheQTSTable is the search dialog's "Include mounted
// sub-folders" box on QTS (owner, 2026-09-23: offered there too, not only on
// hero), against the captured QTS table plus three lines it does not have: a
// second volume, a USB disk mounted INSIDE a volume and a tmpfs inside a volume.
//
// Ticked, a search of /share enters every volume under the RAM disk and, inside
// a volume, only its own domain — which on QTS includes the bind mount "Public
// Files", one device with its volume, so what is under it is found a second time
// by that path. The USB disk the table mounts under /share/external hangs off the
// RAM disk too, and is entered by the same rule; the one inside a volume is
// another domain and is not. Network and tmpfs mounts are never entered.
func TestSearchOfShareOnTheQTSTable(t *testing.T) {
	base := tempDir(t)
	for _, d := range []string{
		"share",
		"share/CACHEDEV1_DATA",
		"share/CACHEDEV1_DATA/Public",
		"share/CACHEDEV1_DATA/Public Files",
		"share/CACHEDEV1_DATA/usbstick",
		"share/CACHEDEV1_DATA/ram",
		"share/CACHEDEV2_DATA",
		"share/external/DEV3301_1",
		"share/remote",
	} {
		mkdir(t, base, d)
		write(t, base, d+"/probe-"+strings.ReplaceAll(filepath.Base(d), " ", "_")+".txt", "x")
	}
	r, api := hostRoot(t, base)
	plat := qtsGoldenUnder(t, api,
		"35 30 9:2 / /share/CACHEDEV2_DATA rw,relatime - ext4 /dev/md2 rw,data=ordered",
		"36 31 8:49 / /share/CACHEDEV1_DATA/usbstick rw,relatime - ext4 /dev/sdd1 rw",
		"37 31 0:50 / /share/CACHEDEV1_DATA/ram rw,relatime - tmpfs tmpfs rw",
	)

	tests := []struct {
		name    string
		cross   bool
		hits    []string
		mounts  int64
		network int64
	}{
		{"box ticked", true, []string{
			"probe-CACHEDEV1_DATA.txt", "probe-CACHEDEV2_DATA.txt", "probe-DEV3301_1.txt",
			"probe-Public.txt", "probe-Public_Files.txt", "probe-share.txt",
		}, 1, 1}, // usbstick is counted; the tmpfs is not; the NFS mount is network
		{"box unticked", false, []string{"probe-share.txt"}, 3, 1}, // both volumes and the USB disk
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := searchReq("probe", api+"/share")
			req.Hidden, req.CrossMounts = true, tc.cross
			res, err := Search(context.Background(), r, plat, req, Emit{})
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if got := sortedHitNames(res); strings.Join(got, ",") != strings.Join(tc.hits, ",") {
				t.Errorf("hits = %v, want %v", got, tc.hits)
			}
			if res.MountsSkipped != tc.mounts || res.MountsNetwork != tc.network {
				t.Errorf("MountsSkipped = %d, MountsNetwork = %d, want %d and %d",
					res.MountsSkipped, res.MountsNetwork, tc.mounts, tc.network)
			}
		})
	}
}
