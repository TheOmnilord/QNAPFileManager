package fsops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSizeCountsFilesDirectoriesAndBytes(t *testing.T) {
	base := deleteFixture(t) // /a/one.txt (3), /a/sub/two.txt (6), /a/sub/deep/
	r := newRoot(t, base)
	var log jobLog

	res, err := Size(context.Background(), r, nil, []string{"/a"}, false, 0, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	// The named directory is counted itself, so these are exactly the numbers a
	// delete of the same selection would move.
	if res.Files != 2 || res.Dirs != 3 || res.Bytes != 9 {
		t.Fatalf("result = %+v, want 2 files, 3 dirs, 9 bytes", res)
	}
	if len(log.warns) != 0 {
		t.Errorf("warnings on a healthy tree: %v", log.warns)
	}
	if len(log.progs) == 0 || log.progs[0].Phase != "scanning" {
		t.Errorf("a measurement reports the scanning phase throughout: %+v", log.progs)
	}
}

// TestSizeNeverFollowsASymlink: a link counts as one item the size of its link
// text, which is what lstat reports and what ls -l prints. Following it would
// count the target — here a kilobyte that is not inside the tree at all.
func TestSizeNeverFollowsASymlink(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "a")
	write(t, base, "big.txt", strings.Repeat("x", 4096))
	if err := os.Symlink(filepath.Join(base, "big.txt"), filepath.Join(base, "a", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	var log jobLog

	res, err := Size(context.Background(), r, nil, []string{"/a"}, false, 0, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if res.Files != 1 || res.Dirs != 1 {
		t.Fatalf("result = %+v, want the link counted as one item", res)
	}
	if res.Bytes >= 4096 {
		t.Fatalf("bytes = %d: the size followed the link to its target", res.Bytes)
	}
}

func TestSizeAppliesTheCrossingRule(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/inside.txt", "six666")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:1"},
	)

	var off jobLog
	res, err := Size(context.Background(), r, plat, []string{api + "/a"}, false, 0, off.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if res.Files != 1 || res.Bytes != 3 || res.Dirs != 2 {
		t.Fatalf("result = %+v, want the mounted sub-folder counted but not entered", res)
	}

	var on jobLog
	res, err = Size(context.Background(), r, plat, []string{api + "/a"}, true, 0, on.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if res.Files != 2 || res.Bytes != 9 {
		t.Fatalf("result = %+v, want the mounted sub-folder included", res)
	}
}

func TestSizeWarnsForAPathThatIsNotThere(t *testing.T) {
	base := deleteFixture(t)
	r := newRoot(t, base)
	var log jobLog

	res, err := Size(context.Background(), r, nil, []string{"/nope", "/a/one.txt"}, false, 0, log.emit())
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if res.Files != 1 {
		t.Fatalf("result = %+v, want the reachable path still measured", res)
	}
	if w, ok := log.warnFor("/nope"); !ok || w.Code != "not_found" {
		t.Fatalf("warns = %v, want not_found for /nope", log.warns)
	}
}
