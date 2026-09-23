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
		// never is. Both the nested pool and the nested tmpfs are counted; the
		// network share is counted apart.
		{"include mounted sub-folders", true,
			[]string{"QKVM", "qkvm-backup.txt", "qkvm-notes.txt"}, 2, 1},
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
		// into the nested pool, the nested tmpfs or the network share, and the
		// first two are counted as left out.
		{"read rule", SizeOptions{CrossMounts: true, ReadCross: true}, 2, 8, 2, 1},
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

// TestPseudoFilesystemsAreNeverCountedAsNotSearched is Astra r2 on the QKVM fix,
// as amended by the "search of /" hardware report: a walk meets /proc, /sys,
// /dev and cgroup, and counting them as "mounted folders not searched" would
// point at places no search can start — a search rooted at a kernel filesystem
// is refused. Only an IDENTIFIED Storage or RAM (tmpfs, ramfs) mount is
// counted: a RAM filesystem is where QTS mounts its volumes (/share), so one not
// entered may hide all of them. A mount the table cannot name fails closed and
// is not counted. The parent here is a storage mount that is not "/", so the
// tmpfs is a boundary with crossing on as well as off.
func TestPseudoFilesystemsAreNeverCountedAsNotSearched(t *testing.T) {
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
		if len(res.Hits) != 0 || res.MountsSkipped != 2 || res.MountsNetwork != 0 {
			t.Errorf("search cross=%v: hits %v, MountsSkipped %d, MountsNetwork %d; want no hits and only /data and /run counted",
				cross, hitNames(res), res.MountsSkipped, res.MountsNetwork)
		}

		size, err := Size(context.Background(), r, plat, []string{api}, SizeOptions{CrossMounts: cross, ReadCross: true}, Emit{})
		if err != nil {
			t.Fatalf("Size(cross=%v): %v", cross, err)
		}
		if size.Files != 0 || size.MountsSkipped != 2 {
			t.Errorf("size cross=%v: files %d, MountsSkipped %d; want nothing counted and only /data and /run reported",
				cross, size.Files, size.MountsSkipped)
		}
	}
}

// goldenUnder is a captured mount table (internal/platform/testdata, PLAN.md
// decision 15) re-rooted under a temporary directory, so the walk can be run
// against it on real directories. Every mount point but "/" gets api in front;
// "/" stays the root filesystem, the one the temporary directory really is on,
// so a search rooted at api is a search of "/" as far as the table can tell —
// FSCaps.Root comes from the row, not from the walk's path. Every mount ID and
// parent ID is moved past synthMountIDBase, for the reason that constant
// exists: the walk names a mount by its descriptor first, and the captured IDs
// (17, 25, 30…) are small enough to collide with the CI kernel's. extra lines,
// in the same format and un-prefixed, are appended and rewritten the same way.
func goldenUnder(t *testing.T, file, api string, extra ...string) *platform.Platform {
	t.Helper()
	return goldenUnderFile(t, filepath.Join("..", "platform", "testdata", file), api, extra...)
}

// goldenUnderFile is goldenUnder for a table at any path.
func goldenUnderFile(t *testing.T, file, api string, extra ...string) *platform.Platform {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading the golden table %s: %v", file, err)
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
		mp := f[4]
		if mp != "/" {
			mp = api + mp
		}
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
	plat := goldenUnder(t, "qts_mountinfo.txt", api,
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
		}, 2, 1}, // usbstick and the tmpfs inside the volume; the NFS mount is network
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

// TestSearchOfRootOnTheGoldenTables is the "search of /" hardware report (hero,
// QKVM): / is the root filesystem, /share a tmpfs under it and every pool a
// mount under that, so no crossing rule reached a pool from /. The read rule
// now lets a system parent — the mount at "/" or a RAM filesystem — enter a RAM
// filesystem or a Storage one, and nothing else; inside a pool or volume only
// the strict rule applies.
//
// Both captured tables, with the lines they lack appended: /tmp on hero, and on
// each a tmpfs and a USB disk mounted INSIDE a pool or volume. Every directory
// holds one probe file, so the hit list says exactly which mounts were entered.
func TestSearchOfRootOnTheGoldenTables(t *testing.T) {
	type table struct {
		name  string
		file  string
		dirs  []string
		extra []string
		// ticked: the hits (by directory) and the counts; unticked likewise.
		tickedHits      []string
		tickedMounts    int64
		tickedNetwork   int64
		untickedMounts  int64
		untickedNetwork int64
	}
	tables := []table{
		{
			name: "hero", file: "hero_mountinfo.txt",
			dirs: []string{"proc", "sys", "dev", "tmp", "share", "share/remote",
				"share/ZFS530_DATA", "share/ZFS530_DATA/Public", "share/ZFS530_DATA/Media",
				"share/ZFS530_DATA/Publication", "share/ZFS530_DATA/Home Videos",
				"share/ZFS530_DATA/ram", "share/ZFS530_DATA/usb",
				"share/ZFS531_DATA", "share/ZFS531_DATA/Backup"},
			extra: []string{
				"26 25 0:19 / /tmp rw,relatime - tmpfs tmpfs rw",
				"50 40 0:50 / /share/ZFS530_DATA/ram rw,relatime - tmpfs tmpfs rw",
				"51 40 8:49 / /share/ZFS530_DATA/usb rw,relatime - ext4 /dev/sdd1 rw",
			},
			tickedHits: []string{"root", "tmp", "share", "ZFS530_DATA", "Public", "Media", "Publication",
				"Home_Videos", "ZFS531_DATA", "Backup"},
			tickedMounts: 2, tickedNetwork: 1, // ram and usb inside the pool; the CIFS share
			untickedMounts: 2, untickedNetwork: 0, // /share and /tmp; /proc, /sys, /dev are not counted
		},
		{
			name: "qts", file: "qts_mountinfo.txt",
			dirs: []string{"proc", "sys", "dev", "tmp", "share", "share/remote",
				"share/CACHEDEV1_DATA", "share/CACHEDEV1_DATA/Public Files",
				"share/CACHEDEV1_DATA/ram", "share/CACHEDEV1_DATA/usbstick", "share/external/DEV3301_1"},
			extra: []string{
				"36 31 8:49 / /share/CACHEDEV1_DATA/usbstick rw,relatime - ext4 /dev/sdd1 rw",
				"37 31 0:50 / /share/CACHEDEV1_DATA/ram rw,relatime - tmpfs tmpfs rw",
			},
			tickedHits:   []string{"root", "tmp", "share", "CACHEDEV1_DATA", "Public_Files", "DEV3301_1"},
			tickedMounts: 2, tickedNetwork: 1, // usbstick and ram inside the volume; the NFS mount
			untickedMounts: 2, untickedNetwork: 0,
		},
	}
	probe := func(dir string) string {
		return "probe-" + strings.ReplaceAll(filepath.Base(dir), " ", "_") + ".txt"
	}
	for _, tb := range tables {
		t.Run(tb.name, func(t *testing.T) {
			base := tempDir(t)
			write(t, base, "probe-root.txt", "x")
			for _, d := range tb.dirs {
				mkdir(t, base, d)
				write(t, base, d+"/"+probe(d), "x")
			}
			r, api := hostRoot(t, base)
			plat := goldenUnder(t, tb.file, api, tb.extra...)
			if !plat.For(api).Root {
				t.Fatalf("the search root must be on the table's \"/\": %+v", plat.For(api))
			}

			want := make([]string, 0, len(tb.tickedHits))
			for _, h := range tb.tickedHits {
				want = append(want, "probe-"+h+".txt")
			}
			sort.Strings(want)
			for _, tc := range []struct {
				name             string
				cross            bool
				hits             []string
				mounts, networks int64
			}{
				{"ticked", true, want, tb.tickedMounts, tb.tickedNetwork},
				{"unticked", false, []string{"probe-root.txt"}, tb.untickedMounts, tb.untickedNetwork},
			} {
				req := searchReq("probe", api)
				req.Hidden, req.CrossMounts = true, tc.cross
				res, err := Search(context.Background(), r, plat, req, Emit{})
				if err != nil {
					t.Fatalf("%s: Search: %v", tc.name, err)
				}
				if got := sortedHitNames(res); strings.Join(got, ",") != strings.Join(tc.hits, ",") {
					t.Errorf("%s: hits = %v, want %v", tc.name, got, tc.hits)
				}
				if res.MountsSkipped != tc.mounts || res.MountsNetwork != tc.networks {
					t.Errorf("%s: MountsSkipped = %d, MountsNetwork = %d, want %d and %d",
						tc.name, res.MountsSkipped, res.MountsNetwork, tc.mounts, tc.networks)
				}
			}

			// The size probe with the read rule reaches the same files …
			read, err := Size(context.Background(), r, plat, []string{api}, SizeOptions{CrossMounts: true, ReadCross: true}, Emit{})
			if err != nil {
				t.Fatalf("Size: %v", err)
			}
			if read.Files != int64(len(want)) {
				t.Errorf("read-rule size counted %d files, want %d", read.Files, len(want))
			}
			// … and without it — every pre-scan that confirms a change — / enters
			// neither /share nor /tmp, exactly as before.
			strict, err := Size(context.Background(), r, plat, []string{api}, SizeOptions{CrossMounts: true}, Emit{})
			if err != nil {
				t.Fatalf("Size: %v", err)
			}
			if strict.Files != 1 {
				t.Errorf("strict size of / counted %d files, want only the one on / itself", strict.Files)
			}

			// And a recursive delete of / with crossing on removes what is on /
			// and nothing under any mount.
			var log jobLog
			if _, err := DeleteTree(context.Background(), r, plat, []string{api}, DeleteOptions{Recursive: true, CrossMounts: true}, log.emit()); err != nil {
				t.Fatalf("DeleteTree: %v", err)
			}
			if exists(t, base, "probe-root.txt") {
				t.Error("the delete did not even remove the file on / itself")
			}
			for _, d := range tb.dirs {
				if !exists(t, base, d+"/"+probe(d)) {
					t.Errorf("the delete of / reached %s", d)
				}
			}
		})
	}
}

// TestSearchOfRootOnTheTVSh1688x is the "search of /" hardware report against
// the table the owner captured on the TVS-h1688X (QuTS hero,
// internal/platform/testdata/hero_tvsh1688x_mountinfo.txt, verbatim): "/" is a
// tmpfs, /share a tmpfs under it and every share a ZFS dataset under that.
//
// With the box ticked a search of "/" enters every RAM filesystem hung off "/"
// (and /tmp/wfm inside /tmp), every storage mount straight under it (pool roots,
// /mnt/*), /share, every share, and the same-pool docker dataset. It enters no
// pseudo-filesystem — so nothing under /proc, /sys or /dev, including the
// cgroup_root tmpfs, /dev/shm and /dev/pts — no zvol, no tmpfs inside a pool or
// under /mnt/ext (FileStation6 included, where an ext3 loop is stacked on the
// tmpfs and is what the path shows), and never .zfs. The expectations are the
// table below; every directory holds one probe, so the hit list is the proof.
func TestSearchOfRootOnTheTVSh1688x(t *testing.T) {
	type dir struct {
		path    string
		entered bool
	}
	dirs := []dir{
		// Pseudo-filesystems and everything mounted beneath them.
		{"proc", false}, {"sys", false}, {"sys/fs/cgroup", false}, {"sys/fs/cgroup/cpu", false},
		{"sys/kernel/security", false}, {"sys/kernel/debug", false},
		{"dev", false}, {"dev/pts", false}, {"dev/shm", false},
		// RAM filesystems from "/", and one RAM filesystem inside another.
		{"tmp", true}, {"tmp/wfm", true}, {"var/log", true}, {"share", true},
		{"mnt/snapshot/export", true}, {"samba_third_party", true}, {"python_party", true},
		// Storage straight under "/".
		{"mnt/boot_config", true}, {"mnt/HDA_ROOT", true}, {"mnt/ext", true},
		{"mnt/ext2", true}, {"mnt/sync", true},
		{"zpoolExt2", true}, {"zpool1", true}, {"zpool2", true}, {"zpool256", true},
		// Every share, both pools.
		{"share/ZFS1_DATA", true}, {"share/ZFS2_DATA", true}, {"share/ZFS18_DATA", true},
		{"share/ZFS19_DATA", true}, {"share/ZFS530_DATA", true},
		{"share/ZFS20_DATA", true}, {"share/ZFS21_DATA", true}, {"share/ZFS531_DATA", true},
		// Inside /mnt/ext, a storage mount that is not "/": only the strict rule.
		{"mnt/ext/opt/mtpBinary", false}, {"mnt/ext/opt/SnapshotManager", false},
		{"mnt/ext/opt/samba/private/msg.sock", false}, {"mnt/ext/opt/FileStation6", false},
		// Inside a pool: the same-pool dataset only.
		{"share/ZFS530_DATA/.qpkg/container-station/docker", true},
		{"share/ZFS530_DATA/.qpkg/container-station/system-docker", false},
		{"share/ZFS530_DATA/.zfs1_data.sync/.samba/lock/msg.lock", false},
		{"share/ZFS19_DATA/Container/container-station-data/lib/lxd/shmounts", false},
		{"share/ZFS19_DATA/Container/container-station-data/lib/lxd/devlxd", false},
		// The snapshot directory: refused by name (ProtectSnapshots) before it is a
		// mount at all. The ":init:" mount below it cannot be a directory name on
		// every OS this test runs on, and does not need to be.
		{"share/ZFS530_DATA/.zfs/snapshot", false},
	}
	base := tempDir(t)
	write(t, base, "probe-root.txt", "x")
	want := []string{"probe-root.txt"}
	for _, d := range dirs {
		mkdir(t, base, d.path)
		name := "probe-" + strings.ReplaceAll(d.path, "/", "_") + ".txt"
		write(t, base, d.path+"/"+name, "x")
		if d.entered {
			want = append(want, name)
		}
	}
	sort.Strings(want)
	r, api := hostRoot(t, base)
	plat := goldenUnder(t, "hero_tvsh1688x_mountinfo.txt", api)
	if c := plat.For(api); !c.Root || !c.RAM {
		t.Fatalf("the root of this table is a tmpfs at \"/\": %+v", c)
	}

	req := searchReq("probe", api)
	req.Hidden, req.CrossMounts = true, true
	res, err := Search(context.Background(), r, plat, req, Emit{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := sortedHitNames(res); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("hits:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The eight storage or RAM mounts reached and not entered: four under
	// /mnt/ext/opt, msg.lock, system-docker and the two lxd tmpfs mounts. The
	// pseudo-filesystems are not counted, and .zfs is refused before it is one.
	if res.MountsSkipped != 8 || res.MountsNetwork != 0 {
		t.Errorf("MountsSkipped = %d, MountsNetwork = %d, want 8 and 0", res.MountsSkipped, res.MountsNetwork)
	}

	// Unticked: only "/" itself, and every RAM or storage mount directly under
	// it is counted as not searched — six RAM filesystems and nine storage ones.
	req.CrossMounts = false
	res, err = Search(context.Background(), r, plat, req, Emit{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := sortedHitNames(res); strings.Join(got, ",") != "probe-root.txt" {
		t.Errorf("unticked hits = %v, want only the one on /", got)
	}
	if res.MountsSkipped != 15 {
		t.Errorf("unticked MountsSkipped = %d, want 15", res.MountsSkipped)
	}
}
