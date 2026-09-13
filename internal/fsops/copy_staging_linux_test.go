package fsops

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// Round 15's first finding: everything this job builds is built inside a
// private directory of its own, because an unguessable name in a LISTABLE
// directory is still a name — a readdir loop or one inotify watch sees it
// appear — and what can be substituted there passes every stat check this
// engine makes, ACL and all.

// stagedNames collects the directory each created object was built in, so a
// test can assert that it was never the destination itself.
func stagedNames(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	prevDir := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		seen = append(seen, d.rel)
		return prevDir(d, name, mode)
	}
	t.Cleanup(func() { mkdirForCopy = prevDir })
	prevLink := symlinkAtSeam
	symlinkAtSeam = func(d *dirRef, name, target string) error {
		seen = append(seen, d.rel)
		return prevLink(d, name, target)
	}
	t.Cleanup(func() { symlinkAtSeam = prevLink })
	return &seen
}

// TestEverythingIsBuiltInsideAPrivateStagingDirectory is the finding itself: a
// directory and a symlink are created inside a staging directory that is this
// worker's, 0700 and empty of anybody else's reach, and it is gone when the job
// is.
func TestEverythingIsBuiltInsideAPrivateStagingDirectory(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/sub/one.txt", "one")
	if err := os.Symlink("one.txt", filepath.Join(base, "src", "a", "sub", "link")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	seen := stagedNames(t)

	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean copy: %v", log.warns)
	}
	if res.Dirs != 2 || res.Files != 2 {
		t.Fatalf("result = %+v, want two folders and two entries copied", res)
	}
	if len(*seen) == 0 {
		t.Fatal("nothing was created, so nothing was staged")
	}
	for _, where := range *seen {
		if !strings.Contains(where, stageSuffix) {
			t.Errorf("an object was built in %q, which is not a private staging directory", where)
		}
	}
	// Nothing of the staging is left anywhere at the destination.
	for _, rel := range []string{"dst", "dst/a", "dst/a/sub"} {
		des, rerr := os.ReadDir(filepath.Join(base, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, de := range des {
			if strings.HasPrefix(de.Name(), copyTmpPrefix) {
				t.Errorf("%s/%s was left behind after the job", rel, de.Name())
			}
		}
	}
	if got := readFile(t, base, "dst/a/sub/one.txt"); got != "one" {
		t.Fatalf("dst/a/sub/one.txt = %q", got)
	}
	if got, rerr := os.Readlink(filepath.Join(base, "dst", "a", "sub", "link")); rerr != nil || got != "one.txt" {
		t.Fatalf("dst/a/sub/link -> %q (%v)", got, rerr)
	}
}

// TestTheStagingDirectoryIsPrivateWhileItExists checks the directory itself
// rather than what is built in it: mode exactly 0700 and owned by this worker,
// observed while the copy is running.
func TestTheStagingDirectoryIsPrivateWhileItExists(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	r := newRoot(t, base)

	looked := 0
	prev := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if !strings.Contains(d.rel, stageSuffix) {
			return nil
		}
		looked++
		fi, serr := os.Lstat(filepath.Join(base, filepath.FromSlash(d.rel)))
		if serr != nil {
			t.Error(serr)
			return nil
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("the staging directory is mode %o, want 0700", fi.Mode().Perm())
		}
		if uid, _, _, ok := statDetail(fi); ok && uid != os.Geteuid() {
			t.Errorf("the staging directory is owned by uid %d and not by this worker", uid)
		}
		return nil
	}
	t.Cleanup(func() { mkdirForCopy = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if looked == 0 {
		t.Fatal("nothing was built in a staging directory, so nothing was inspected")
	}
}

// TestASharedDestinationCopiesAndSaysSoOnce is the product decision: a NAS
// share is group-writable — that is what a share IS — so a destination other
// users can write cannot be a refusal, or copy and move would be unusable
// exactly where people use them.
//
// What happens instead: everything is built at its final name under every proof
// this engine has, and the job says once that the swap protection is reduced.
// The warning names no entry and does not stop a move deleting its source,
// because nothing failed — the place is simply shared.
func TestASharedDestinationCopiesAndSaysSoOnce(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	write(t, base, "src/a/sub/two.txt", "twotwo")
	// Anybody may create in the destination, as on a share.
	if err := os.Chmod(filepath.Join(base, "dst"), 0o777); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	prev := aclFactsOf
	// No private staging directory can be proved here.
	aclFactsOf = func(d *dirRef) (aclFacts, error) {
		return aclFacts{otherWriter: strings.Contains(d.rel, stageSuffix)}, nil
	}
	t.Cleanup(func() { aclFactsOf = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Fatalf("dst/a/sub/two.txt = %q — a shared destination must still be copied into", got)
	}
	if res.Skipped != 0 {
		t.Errorf("result = %+v, want nothing skipped", res)
	}
	shared := 0
	for _, w := range log.warns {
		if w.Code != warnSharedDest {
			t.Errorf("unexpected warning %v", w)
			continue
		}
		shared++
		if len(w.Path) != 0 {
			t.Errorf("the %q warning names %q; it is about the destination, not an entry", warnSharedDest, w.Path)
		}
	}
	if shared != 1 {
		t.Fatalf("%d %q warnings, want exactly one for the job", shared, warnSharedDest)
	}
	// And it did not veto the delete: the move finished.
	if exists(t, base, "src/a") {
		t.Fatal("the move kept its source over a remark about the destination")
	}
}

// TestAStagingDirectoryWithAPlantedInheritableEntryRefuses is round 17's
// finding at the engine: what the staging directory will pass DOWN has to have
// come from the destination it was made in. A planted directory that is empty,
// this worker's, 0700 and in the expected group, but carrying a default ACL of
// somebody else's, would have handed every object built inside it the
// attacker's entries — and the rename that publishes them recomputes nothing.
func TestAStagingDirectoryWithAPlantedInheritableEntryRefuses(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	r := newRoot(t, base)

	prev := aclFactsOf
	aclFactsOf = func(d *dirRef) (aclFacts, error) {
		if strings.HasSuffix(d.rel, stageSuffix) {
			// A default ACL the destination does not have.
			return aclFacts{defaultACL: []byte{2, 0, 0, 0, 2, 0, 5, 0, 42, 0, 0, 0}}, nil
		}
		return aclFacts{}, nil
	}
	t.Cleanup(func() { aclFactsOf = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if exists(t, base, "dst/a") {
		t.Fatal("a folder was built inside a staging directory that would have passed on somebody else's entries")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the root reported as not copied", res)
	}
	if indexOf(log.codes(), warnUnverified) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnUnverified)
	}
	if indexOf(log.codes(), warnSharedDest) >= 0 {
		t.Errorf("warn codes = %v: a planted ACL is not an ordinary shared destination", log.codes())
	}
	// Abandoned where it was found, like every object this job cannot prove it
	// created.
	left := false
	des, rerr := os.ReadDir(filepath.Join(base, "dst"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, de := range des {
		if strings.HasSuffix(de.Name(), stageSuffix) {
			left = true
		}
	}
	if !left {
		t.Error("the unproved staging directory was removed; nothing this job cannot prove it made is its to remove")
	}
}

// TestAStagingDirectoryOnAnotherFilesystemRefuses is the staging directory's
// own half of the crossing check, and its answer is the other one: a directory
// this job created that turns out to be on another filesystem when it is opened
// has had something mounted over it, which is not an ordinary shared share.
// Nothing is built there.
//
// The created LEVEL's crossing check is a different question with a different
// answer — `protected`, because that level is what the user asked to copy; see
// TestCreatedDestinationLevelIsAlsoCheckedForCrossing.
func TestAStagingDirectoryOnAnotherFilesystemRefuses(t *testing.T) {
	r, base := copyFixture(t)
	prev := identityFor
	identityFor = func(d *dirRef) mountIdentity {
		if strings.HasSuffix(d.rel, stageSuffix) {
			return mountIdentity{mnt: 9, hasMnt: true}
		}
		return mountIdentity{mnt: 1, hasMnt: true}
	}
	t.Cleanup(func() { identityFor = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if exists(t, base, "dst/a") {
		t.Fatal("a folder was built although the private place this job made was on another filesystem")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the root reported as not copied", res)
	}
	if indexOf(log.codes(), warnUnverified) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnUnverified)
	}
}

// TestAStagingDirectoryTakenAwayAfterItWasMadeRefuses is round 16's second
// finding, and it is the one that stops an attacker CHOOSING the weaker path.
// The destination is writable by others, so a staging directory that simply
// could not be made would fall back to building at final names — and an
// attacker who renames our fresh staging directory away between the mkdirat and
// the openat would have forced exactly that. A mkdir of ours that succeeded and
// then could not be opened is interference, not an environment, and it refuses.
func TestAStagingDirectoryTakenAwayAfterItWasMadeRefuses(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	// Writable by anybody and not sticky: the shared fallback would apply here
	// if this were an ordinary environment.
	if err := os.Chmod(filepath.Join(base, "dst"), 0o777); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	taken := false
	prev := mkdirForStaging
	mkdirForStaging = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if taken {
			return nil
		}
		taken = true
		p := filepath.Join(base, filepath.FromSlash(d.rel), name)
		return os.Rename(p, p+"-taken")
	}
	t.Cleanup(func() { mkdirForStaging = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !taken {
		t.Fatal("the staging directory was never taken away, so nothing was staged")
	}
	if exists(t, base, "dst/a") {
		t.Fatal("a folder was built at its final name after somebody took the private place this job made")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the root reported as not copied", res)
	}
	if indexOf(log.codes(), warnUnverified) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnUnverified)
	}
	if indexOf(log.codes(), warnSharedDest) >= 0 {
		t.Fatalf("warn codes = %v: an attacker must not be able to choose the weaker path", log.codes())
	}
}

// TestADestinationThatStopsInheritanceIsNotStagedIn is round 16's third
// finding. An ACE flagged NO_PROPAGATE_INHERIT reaches the staging directory
// and stops there, so a directory built inside it and renamed out would carry a
// different ACL from one created at the destination directly — and a rename
// recomputes nothing. Where the destination says that, this job does not stage
// in it at all: it builds at final names under the stat proofs, which is what
// the destination's own inheritance describes.
func TestADestinationThatStopsInheritanceIsNotStagedIn(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	r := newRoot(t, base)
	seen := stagedNames(t)

	prev := aclFactsOf
	aclFactsOf = func(d *dirRef) (aclFacts, error) {
		if d.rel == "dst" {
			return aclFacts{noPropagate: true}, nil
		}
		return aclFacts{}, nil
	}
	t.Cleanup(func() { aclFactsOf = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings: %v — the destination is private, so there is nothing to remark on", log.warns)
	}
	if res.Files != 1 || res.Dirs != 1 {
		t.Fatalf("result = %+v, want the tree copied", res)
	}
	for _, where := range *seen {
		if strings.Contains(where, stageSuffix) {
			t.Errorf("an object was built in %q, inside a destination whose ACL stops one level down", where)
		}
	}
	// Nor was a staging directory made there at all.
	des, rerr := os.ReadDir(filepath.Join(base, "dst"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, de := range des {
		if strings.HasSuffix(de.Name(), stageSuffix) {
			t.Errorf("%q was created in a destination that must not be staged in", de.Name())
		}
	}
	if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
		t.Fatalf("dst/a/one.txt = %q", got)
	}
}

// TestAStagingDirectoryThatIsNotOursRefuses is the case that still refuses:
// this job made a private directory and what it opened was not it. Nothing
// about that is an ordinary shared share, and nothing is built there.
// The two sub-cases are the two ways an impostor gives itself away, and the
// second is round 16's fourth finding: what is left of it afterwards. A
// directory this job could not prove it created is not this job's to remove —
// the old cleanup compared the opened inode with the name and found them the
// same, which they are, because the opened inode IS the stranger's.
func TestAStagingDirectoryThatIsNotOursRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(p string) error
	}{
		{name: "not empty", plant: func(p string) error {
			if err := os.Mkdir(p, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(p, "theirs.txt"), []byte("already here"), 0o600)
		}},
		{name: "empty but wider", plant: func(p string) error {
			if err := os.Mkdir(p, 0o755); err != nil {
				return err
			}
			return os.Chmod(p, 0o755)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tempDir(t)
			mkdir(t, base, "src/a")
			mkdir(t, base, "dst")
			write(t, base, "src/a/one.txt", "one")
			r := newRoot(t, base)

			planted := ""
			prev := mkdirForStaging
			mkdirForStaging = func(d *dirRef, name string, mode os.FileMode) error {
				if err := prev(d, name, mode); err != nil {
					return err
				}
				if planted != "" {
					return nil
				}
				// Somebody else's directory under the name this job just made.
				p := filepath.Join(base, filepath.FromSlash(d.rel), name)
				planted = p
				if err := os.Remove(p); err != nil {
					return err
				}
				return tc.plant(p)
			}
			t.Cleanup(func() { mkdirForStaging = prev })
			var log jobLog

			res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
			if err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if planted == "" {
				t.Fatal("the impostor was never put in place, so nothing was staged")
			}
			if exists(t, base, "dst/a") {
				t.Fatal("a folder was built although the private place this job made was not the one it opened")
			}
			if res.Skipped == 0 {
				t.Errorf("result = %+v, want the root reported as not copied", res)
			}
			if indexOf(log.codes(), warnUnverified) < 0 {
				t.Fatalf("warn codes = %v, want %q", log.codes(), warnUnverified)
			}
			if indexOf(log.codes(), warnSharedDest) >= 0 {
				t.Errorf("warn codes = %v: a substituted staging directory is not an ordinary shared destination", log.codes())
			}
			// And it is still there: nothing this job cannot prove it created
			// is ever removed by it, empty or not.
			if _, serr := os.Lstat(planted); serr != nil {
				t.Errorf("the impostor was removed (%v); it was never this job's", serr)
			}
		})
	}
}

// TestNoPrivatePlaceToBuildStillCopiesWhereNobodyElseCan is the other half: a
// destination only this worker can write has nobody to race, so the object is
// built at its final name exactly as it was before staging existed.
func TestNoPrivatePlaceToBuildStillCopiesWhereNobodyElseCan(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a")
	mkdir(t, base, "dst")
	write(t, base, "src/a/one.txt", "one")
	if err := os.Chmod(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	prev := aclFactsOf
	// The staging directory cannot be proved private; the destination itself
	// grants nobody anything.
	aclFactsOf = func(d *dirRef) (aclFacts, error) {
		return aclFacts{otherWriter: strings.Contains(d.rel, stageSuffix)}, nil
	}
	t.Cleanup(func() { aclFactsOf = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings: %v", log.warns)
	}
	if res.Files != 1 || res.Dirs != 1 {
		t.Fatalf("result = %+v, want the tree copied", res)
	}
	if got := readFile(t, base, "dst/a/one.txt"); got != "one" {
		t.Fatalf("dst/a/one.txt = %q", got)
	}
}

// TestASourceGrandparentTightenedDuringTheDeleteKeepsTheRest is round 15's
// second finding: the delete validated only the directory it was emptying, so
// tightening /src/a while the comparison of a file inside /src/a/sub was
// running stopped nothing — the recursion carried no record of anything above
// itself, and the rest of sub, then sub, went.
func TestASourceGrandparentTightenedDuringTheDeleteKeepsTheRest(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/sub")
	mkdir(t, base, "dst")
	for i := 0; i < 6; i++ {
		write(t, base, fmt.Sprintf("src/a/sub/f%d.txt", i), "contents")
	}
	r := newRoot(t, base)
	forceEXDEV(t)

	tightened := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "compare" || tightened {
			return
		}
		tightened = true
		// The GRANDPARENT of the entries being removed.
		if err := os.Chmod(filepath.Join(base, "src", "a"), 0o700); err != nil {
			t.Errorf("chmod: %v", err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit()); err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !tightened {
		t.Fatal("no comparison was announced, so nothing was staged")
	}
	left := 0
	for i := 0; i < 6; i++ {
		if exists(t, base, fmt.Sprintf("src/a/sub/f%d.txt", i)) {
			left++
		}
	}
	if left != 5 {
		t.Fatalf("%d source files are left, want 5: only the entry judged before the grandparent changed may be removed", left)
	}
	if !exists(t, base, "src/a/sub") || !exists(t, base, "src/a") {
		t.Fatal("a folder was removed although a folder above it was no longer the one that was copied")
	}
	w, ok := log.warnFor("/src/a")
	if !ok || w.Code != warnKept {
		t.Fatalf("warnings = %v, want a %q naming the folder that changed", log.warns, warnKept)
	}
}

// posixEntry is one system.posix_acl_access entry: tag, permissions, id.
type posixEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// nfs4Entry is one system.nfs4_acl ACE: type, flags, access mask, who.
type nfs4Entry struct {
	aceType uint32
	flag    uint32
	mask    uint32
	who     string
}

// TestACLsAreJudgedOnWriteNotOnPresence covers both formats the staging proof
// parses. The line it draws is the whole staging decision: an ACE that lets
// somebody else READ a directory this job builds in gives them nothing they
// would not have been given anyway, while an ACE that lets them CREATE, RENAME
// or REMOVE in it is the substitution the staging exists to make impossible.
//
// A filesystem that produces both on demand is not something a unit test has,
// so the bytes are built here.
func TestACLsAreJudgedOnWriteNotOnPresence(t *testing.T) {
	const (
		posixRead  = 0x04
		posixWrite = 0x02
		posixExec  = 0x01
	)
	posix := func(entries ...posixEntry) []byte {
		b := make([]byte, 4, 4+len(entries)*8)
		binary.LittleEndian.PutUint32(b, posixACLVersion)
		for _, e := range entries {
			raw := make([]byte, 8)
			binary.LittleEndian.PutUint16(raw[0:], e.tag)
			binary.LittleEndian.PutUint16(raw[2:], e.perm)
			binary.LittleEndian.PutUint32(raw[4:], e.id)
			b = append(b, raw...)
		}
		return b
	}
	nfs4 := func(entries ...nfs4Entry) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(entries)))
		for _, e := range entries {
			ace := make([]byte, 16)
			binary.BigEndian.PutUint32(ace[0:], e.aceType)
			binary.BigEndian.PutUint32(ace[4:], e.flag)
			binary.BigEndian.PutUint32(ace[8:], e.mask)
			binary.BigEndian.PutUint32(ace[12:], uint32(len(e.who)))
			b = append(b, ace...)
			b = append(b, e.who...)
			if pad := len(e.who) % 4; pad != 0 {
				b = append(b, make([]byte, 4-pad)...)
			}
		}
		return b
	}
	const nfs4Read = 0x00000001 | 0x00000020 | 0x00000080 // READ_DATA, EXECUTE, READ_ATTRIBUTES
	owner := posixEntry{tag: posixACLUserObj, perm: posixRead | posixWrite | posixExec}

	for _, tc := range []struct {
		name  string
		xattr string
		b     []byte
		want  bool
	}{
		{"posix mode only", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLGroupObj}, posixEntry{tag: posixACLOther}), true},
		{"posix inherited read for a group", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLGroup, perm: posixRead | posixExec, id: 4000},
				posixEntry{tag: posixACLMask, perm: posixRead | posixExec}, posixEntry{tag: posixACLOther}), true},
		{"posix group may add", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLGroup, perm: posixRead | posixWrite | posixExec, id: 4000},
				posixEntry{tag: posixACLMask, perm: posixRead | posixExec}, posixEntry{tag: posixACLOther}), false},
		{"posix named user may write", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLUser, perm: posixWrite, id: 4242}, posixEntry{tag: posixACLOther}), false},
		{"posix other may write", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLGroupObj}, posixEntry{tag: posixACLOther, perm: posixWrite}), false},
		{"posix this worker may write", platform.XattrPosixACL,
			posix(owner, posixEntry{tag: posixACLUser, perm: posixWrite, id: uint32(os.Geteuid())},
				posixEntry{tag: posixACLOther}), true},
		{"posix truncated", platform.XattrPosixACL, []byte{2, 0, 0, 0, 1}, false},

		{"nfs4 mode only", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4WriteMask | nfs4Read, who: "OWNER@"},
				nfs4Entry{mask: nfs4Read, who: "GROUP@"}, nfs4Entry{who: "EVERYONE@"}), true},
		{"nfs4 inherited read for a group", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4WriteMask, who: "OWNER@"},
				nfs4Entry{mask: nfs4Read, who: "2000"}), true},
		{"nfs4 group may add a file", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4WriteMask, who: "OWNER@"},
				nfs4Entry{mask: nfs4Read | nfs4AddFile, who: "GROUP@"}), false},
		{"nfs4 named user may delete a child", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4WriteMask, who: "OWNER@"},
				nfs4Entry{mask: nfs4DeleteChild, who: "mallory@localhost"}), false},
		{"nfs4 everyone may read", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4Read, who: "EVERYONE@"}), true},
		{"nfs4 everyone may write", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4AddSubdir, who: "EVERYONE@"}), false},
		{"nfs4 a deny grants nothing", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{aceType: 1, mask: nfs4WriteMask, who: "EVERYONE@"}), true},
		{"nfs4 this worker may write", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{mask: nfs4WriteMask, who: fdString(os.Geteuid())}), true},
		// The same number with the GROUP flag names a group, not this worker:
		// gid 0 is every member of the root group, and a root worker calling
		// that "itself" would have called a directory half the system can write
		// into private.
		{"nfs4 a group with our number may add", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{flag: nfs4IdentifierGroup, mask: nfs4AddFile, who: fdString(os.Geteuid())}), false},
		{"nfs4 group zero may add", platform.XattrNFS4ACL,
			nfs4(nfs4Entry{flag: nfs4IdentifierGroup, mask: nfs4AddFile, who: "0"}), false},
		{"nfs4 truncated", platform.XattrNFS4ACL, []byte{0, 0, 0, 2}, false},

		{"richacl is never read", platform.XattrRichACL, []byte{0, 0, 0, 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := !aclFactsOfXattr(tc.xattr, tc.b).otherWriter; got != tc.want {
				t.Fatalf("no other writer in %q = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestAnACLThatStopsOneLevelDownDisqualifiesStaging is round 16's third
// finding, read at the parser: an ACE flagged NO_PROPAGATE_INHERIT reaches the
// staging directory and then stops, so what is built inside it and renamed out
// carries a different ACL from what would have been created at the destination
// directly — an inherit-only DENY of read for one user, say, simply disappears.
// A rename recomputes nothing, so a directory carrying such an entry is no
// place to stage anything.
func TestAnACLThatStopsOneLevelDownDisqualifiesStaging(t *testing.T) {
	nfs4 := func(entries ...nfs4Entry) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(entries)))
		for _, e := range entries {
			ace := make([]byte, 16)
			binary.BigEndian.PutUint32(ace[0:], e.aceType)
			binary.BigEndian.PutUint32(ace[4:], e.flag)
			binary.BigEndian.PutUint32(ace[8:], e.mask)
			binary.BigEndian.PutUint32(ace[12:], uint32(len(e.who)))
			b = append(b, ace...)
			b = append(b, e.who...)
			if pad := len(e.who) % 4; pad != 0 {
				b = append(b, make([]byte, 4-pad)...)
			}
		}
		return b
	}
	const (
		dirInherit  = 0x02
		inheritOnly = 0x08
		nfs4Read    = 0x00000001 | 0x00000020 | 0x00000080
	)
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"plain entries propagate", nfs4(nfs4Entry{mask: nfs4WriteMask, who: "OWNER@"}), false},
		{"an inheritable entry propagates", nfs4(
			nfs4Entry{flag: dirInherit, mask: nfs4Read, who: "GROUP@"}), false},
		{"no-propagate stops one level down", nfs4(
			nfs4Entry{flag: dirInherit | nfs4NoPropagateInherit, mask: nfs4Read, who: "GROUP@"}), true},
		{"inherit-only and no-propagate", nfs4(
			nfs4Entry{aceType: 1, flag: dirInherit | inheritOnly | nfs4NoPropagateInherit, mask: nfs4Read, who: "mallory@localhost"}), true},
		{"truncated says stop", []byte{0, 0, 0, 3}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := aclFactsOfXattr(platform.XattrNFS4ACL, tc.b).noPropagate; got != tc.want {
				t.Fatalf("noPropagate = %v, want %v", got, tc.want)
			}
		})
	}
	// A POSIX default ACL reaches every generation, so it never disqualifies.
	posixTrivial := []byte{2, 0, 0, 0}
	if aclFactsOfXattr(platform.XattrPosixACL, posixTrivial).noPropagate {
		t.Error("a POSIX ACL was treated as stopping one level down; default ACLs propagate all the way")
	}
	// And what an NFSv4 ACL passes down is picked out by its inherit flags,
	// with the "this came from inheritance" flag cleared so that a parent's
	// entry and a child's copy of it compare equal (round 17).
	const inheritedACE = 0x80
	facts := aclFactsOfXattr(platform.XattrNFS4ACL, nfs4(
		nfs4Entry{mask: nfs4WriteMask, who: "OWNER@"},
		nfs4Entry{flag: dirInherit | inheritedACE, mask: nfs4Read, who: "4000"},
		nfs4Entry{flag: 0x01, mask: nfs4Read, who: "mallory@localhost"}))
	if len(facts.inheritable) != 2 {
		t.Fatalf("inheritable = %+v, want the two entries that carry an inherit flag", facts.inheritable)
	}
	if facts.inheritable[0].flag != dirInherit {
		t.Errorf("inheritable[0].flag = %#x, want the INHERITED_ACE bit cleared", facts.inheritable[0].flag)
	}
	if facts.inheritable[0].who != "4000" || facts.inheritable[1].who != "mallory@localhost" {
		t.Errorf("inheritable = %+v, want the two inheritable whos", facts.inheritable)
	}
	// A POSIX default attribute is kept as the kernel wrote it and says nothing
	// about who may write the directory it sits on.
	def := aclFactsOfXattr(xattrPosixDefaultACL, []byte{2, 0, 0, 0, 2, 0, 5, 0, 42, 0, 0, 0})
	if def.otherWriter || def.noPropagate || len(def.defaultACL) != 12 {
		t.Errorf("default ACL facts = %+v, want only the raw bytes", def)
	}
}
