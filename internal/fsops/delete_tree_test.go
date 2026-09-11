package fsops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// jobLog collects what a job reported, so a test can assert on the warnings and
// the progress rather than only on the filesystem.
type jobLog struct {
	progs []wproto.Prog
	warns []wproto.Warn
}

func (l *jobLog) emit() Emit {
	return Emit{
		Prog: func(p wproto.Prog) { l.progs = append(l.progs, p) },
		Warn: func(w wproto.Warn) { l.warns = append(l.warns, w) },
	}
}

func (l *jobLog) codes() []string {
	out := make([]string, 0, len(l.warns))
	for _, w := range l.warns {
		out = append(out, w.Code)
	}
	return out
}

func (l *jobLog) warnFor(apiPath string) (wproto.Warn, bool) {
	for _, w := range l.warns {
		if string(w.Path) == apiPath {
			return w, true
		}
	}
	return wproto.Warn{}, false
}

// deleteFixture builds
//
//	/a/one.txt        3 bytes
//	/a/sub/two.txt    6 bytes
//	/a/sub/deep/      empty
func deleteFixture(t *testing.T) string {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "a/sub/deep")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/two.txt", "twotwo")
	return base
}

func TestDeleteTreeRemovesTheWholeTreeAndCounts(t *testing.T) {
	base := deleteFixture(t)
	r := newRoot(t, base)
	var log jobLog

	res, err := DeleteTree(context.Background(), r, nil, []string{"/a"}, DeleteOptions{Recursive: true}, log.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Files != 2 || res.Dirs != 3 || res.Bytes != 9 || res.Skipped != 0 {
		t.Fatalf("result = %+v, want 2 files, 3 dirs, 9 bytes, nothing skipped", res)
	}
	if len(log.warns) != 0 {
		t.Errorf("warnings on a healthy delete: %v", log.warns)
	}
	if exists(t, base, "a") {
		t.Error("the tree is still there")
	}
}

// TestDeleteTreeScansFirst pins the two-phase shape of backend plan §3: the
// scan runs before anything is removed and gives the progress a denominator.
func TestDeleteTreeScansFirst(t *testing.T) {
	base := deleteFixture(t)
	r := newRoot(t, base)
	var log jobLog

	if _, err := DeleteTree(context.Background(), r, nil, []string{"/a"}, DeleteOptions{Recursive: true}, log.emit()); err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	var scanned, worked bool
	for _, p := range log.progs {
		switch p.Phase {
		case wproto.PhaseScanning:
			scanned = true
			if worked {
				t.Fatal("a scanning update arrived after the delete had started")
			}
		case wproto.PhaseWorking:
			worked = true
			// 2 files + 3 directories is what the scan counted, and it is what
			// the delete will remove: the same walk, the same rule.
			if p.FilesTotal != 5 {
				t.Fatalf("FilesTotal = %d, want 5", p.FilesTotal)
			}
			if p.BytesTotal != 9 {
				t.Fatalf("BytesTotal = %d, want 9", p.BytesTotal)
			}
		}
	}
	if !scanned || !worked {
		t.Fatalf("phases seen: scanning=%v working=%v", scanned, worked)
	}
}

// TestDeleteTreeNonRecursiveRefusesANonEmptyDirectory: without Recursive the
// job behaves like the M1 single delete — it reports not_empty and leaves
// everything where it is.
func TestDeleteTreeNonRecursiveRefusesANonEmptyDirectory(t *testing.T) {
	base := deleteFixture(t)
	r := newRoot(t, base)
	var log jobLog

	res, err := DeleteTree(context.Background(), r, nil, []string{"/a"}, DeleteOptions{}, log.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Skipped != 1 || res.Dirs != 0 || res.Files != 0 {
		t.Fatalf("result = %+v, want one skip and nothing removed", res)
	}
	w, ok := log.warnFor("/a")
	if !ok || w.Code != "not_empty" {
		t.Fatalf("warns = %v, want not_empty for /a", log.warns)
	}
	if !exists(t, base, "a/one.txt") {
		t.Error("a refused delete must leave the tree intact")
	}

	// An empty directory is removed by the same non-recursive call.
	res, err = DeleteTree(context.Background(), r, nil, []string{"/a/sub/deep"}, DeleteOptions{}, log.emit())
	if err != nil || res.Dirs != 1 {
		t.Fatalf("result = %+v err = %v, want the empty directory removed", res, err)
	}
}

// TestDeleteTreeRemovesTheLinkNotTheTarget: the walk never follows a symlink,
// so a delete of a tree containing one removes the link and leaves what it
// pointed at alone. This is the property that keeps "delete this folder" from
// reaching into /etc.
func TestDeleteTreeRemovesTheLinkNotTheTarget(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "a")
	mkdir(t, base, "keep")
	write(t, base, "keep/precious.txt", "still here")
	if err := os.Symlink(filepath.Join(base, "keep"), filepath.Join(base, "a", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	var log jobLog

	res, err := DeleteTree(context.Background(), r, nil, []string{"/a"}, DeleteOptions{Recursive: true}, log.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Skipped != 0 {
		t.Fatalf("result = %+v (%v), want a clean delete", res, log.warns)
	}
	if exists(t, base, "a") {
		t.Error("the tree is still there")
	}
	if !exists(t, base, "keep/precious.txt") {
		t.Fatal("the delete followed a symlink and destroyed the target")
	}
}

// TestDeleteTreeRefusesAMountPoint is the refusal that is deliberately made on
// both sides of the socket: emptying a mount point unmounts a volume by
// removing everything on it, which is the worst thing this app could do.
func TestDeleteTreeRefusesAMountPoint(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/sub")
	write(t, base, "a/sub/inside.txt", "on the other filesystem")
	write(t, base, "a/one.txt", "one")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/a/sub", fsType: "ext4", dev: "8:2", source: "/dev/sdb1"},
	)

	var direct jobLog
	res, err := DeleteTree(context.Background(), r, plat, []string{api + "/a/sub"}, DeleteOptions{Recursive: true}, direct.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Skipped != 1 || res.Files != 0 || res.Dirs != 0 {
		t.Fatalf("result = %+v, want the mount point refused", res)
	}
	w, ok := direct.warnFor(api + "/a/sub")
	if !ok || w.Code != "protected" {
		t.Fatalf("warns = %v, want protected", direct.warns)
	}
	if !exists(t, base, "a/sub/inside.txt") {
		t.Fatal("the contents of the mount point were removed")
	}

	// And from above: the tree around it is deleted, the mount point is left,
	// and the directory holding it is reported as not empty rather than
	// silently half-removed.
	var above jobLog
	res, err = DeleteTree(context.Background(), r, plat, []string{api + "/a"}, DeleteOptions{Recursive: true}, above.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Files != 1 {
		t.Errorf("result = %+v, want the ordinary file removed", res)
	}
	if !exists(t, base, "a/sub/inside.txt") || !exists(t, base, "a") {
		t.Fatal("the mount point or its parent was removed")
	}
	codes := above.codes()
	if indexOf(codes, "protected") < 0 || indexOf(codes, "not_empty") < 0 {
		t.Fatalf("warn codes = %v, want protected and not_empty", codes)
	}
}

// TestDeleteTreeWarnsForAPathThatIsNotThere: one bad path in a selection is a
// warning against that path, not the end of the job.
func TestDeleteTreeWarnsForAPathThatIsNotThere(t *testing.T) {
	base := deleteFixture(t)
	r := newRoot(t, base)
	var log jobLog

	res, err := DeleteTree(context.Background(), r, nil, []string{"/nope", "/a/one.txt"}, DeleteOptions{Recursive: true}, log.emit())
	if err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	if res.Files != 1 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want one removed and one skipped", res)
	}
	if w, ok := log.warnFor("/nope"); !ok || w.Code != "not_found" {
		t.Fatalf("warns = %v, want not_found for /nope", log.warns)
	}
	if exists(t, base, "a/one.txt") {
		t.Error("the good path in the selection was not deleted")
	}
}

// TestDeleteTreeCancelledReportsPartialWork: the counts that come back with a
// cancellation are real, and nothing is rolled back.
func TestDeleteTreeCancelledReportsPartialWork(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a")
	for i := 0; i < 40; i++ {
		write(t, base, fmt.Sprintf("a/f%02d.txt", i), "x")
	}
	r := newRoot(t, base)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &jobLog{}
	emit := log.emit()
	seen := 0
	wrapped := Emit{
		Prog: func(p wproto.Prog) {
			emit.Prog(p)
			if p.Phase == wproto.PhaseWorking {
				seen++
				if seen == 5 {
					cancel()
				}
			}
		},
		Warn: emit.Warn,
	}
	res, err := DeleteTree(ctx, r, nil, []string{"/a"}, DeleteOptions{Recursive: true}, wrapped)
	if err == nil {
		t.Fatal("DeleteTree must report the cancellation")
	}
	if res.Files == 0 || res.Files >= 40 {
		t.Fatalf("result = %+v, want a partial count", res)
	}
	left, err := os.ReadDir(filepath.Join(base, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) == 0 {
		t.Fatal("a cancelled delete removed everything anyway")
	}
}
