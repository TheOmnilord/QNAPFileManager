package platform

import "testing"

// TestTrashRootFor pins PLAN.md decision 10 on the two real golden mount
// tables: the trash root is the nearest enclosing Storage, non-network mount.
// On QuTS hero that is the share's own dataset; on QTS the volume root. A path
// with no enclosing Storage mount (/proc) yields no root, so the caller falls
// back to a permanent delete.
func TestTrashRootFor(t *testing.T) {
	hero := load(t, "hero_mountinfo.txt")
	heroCases := []struct {
		path, want string
		ok         bool
	}{
		{"/share/ZFS530_DATA/Public/x/y", "/share/ZFS530_DATA/Public", true}, // the share's own dataset, next to @Recycle
		{"/share/ZFS530_DATA/x", "/share/ZFS530_DATA", true},                 // directly under the pool root
		{"/share/ZFS531_DATA/Backup/z", "/share/ZFS531_DATA/Backup", true},   // a second pool's dataset
		{"/proc/1/x", "", false}, // never a trash root
	}
	for _, c := range heroCases {
		got, caps, ok := hero.TrashRootFor(c.path)
		if ok != c.ok || got != c.want {
			t.Errorf("hero TrashRootFor(%q) = %q,%v want %q,%v", c.path, got, ok, c.want, c.ok)
		}
		if ok && (!caps.Storage || caps.Network) {
			t.Errorf("hero %q caps = %+v, want Storage and not Network", c.path, caps)
		}
	}

	qts := load(t, "qts_mountinfo.txt")
	got, caps, ok := qts.TrashRootFor("/share/CACHEDEV1_DATA/somewhere/deep")
	if !ok || got != "/share/CACHEDEV1_DATA" {
		t.Fatalf("qts TrashRootFor = %q,%v want /share/CACHEDEV1_DATA,true", got, ok)
	}
	if !caps.Storage || caps.Network {
		t.Fatalf("qts caps = %+v, want Storage and not Network", caps)
	}
	if _, _, ok := qts.TrashRootFor("/proc/self"); ok {
		t.Fatal("/proc must never yield a trash root")
	}
	// The pure lookup never needs a real path on disk, and an empty or
	// relative path is simply "no root".
	if _, _, ok := qts.TrashRootFor(""); ok {
		t.Fatal("an empty path must not yield a trash root")
	}
}
