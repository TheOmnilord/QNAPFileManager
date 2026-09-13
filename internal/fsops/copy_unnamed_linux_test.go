package fsops

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// Round 14 adversarial: the three findings that changed how this engine creates
// things. A file has no name until it is finished, a directory and a symlink are
// made under an unguessable one and renamed into place, and a directory created
// under a setgid parent has to carry the bit the kernel would have given it.

// TestACopiedFileHasNoNameUntilItIsPublished is the first finding. Installing
// the owner on the empty file closed the window for anybody who had not opened
// it YET — but a file created under its final name is openable the instant it
// exists, and a descriptor somebody already holds survives every chown that
// follows. Root moving alice's 0640 into a setgid `public` directory created it
// root:public 0640 under its real name; a member of `public` opening it in that
// instant read everything written into it afterwards.
//
// The assertion is the property itself: while the bytes are going in, the
// destination directory does not list the file at all.
func TestACopiedFileHasNoNameUntilItIsPublished(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src")
	mkdir(t, base, "dst")
	write(t, base, "src/one.txt", "one")
	r := newRoot(t, base)

	looked := false
	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		n, err := io.CopyBuffer(dst, src, buf)
		if err != nil {
			return n, err
		}
		looked = true
		des, rerr := os.ReadDir(filepath.Join(base, "dst"))
		if rerr != nil {
			t.Error(rerr)
			return n, nil
		}
		for _, de := range des {
			t.Errorf("%q is at the destination while its bytes are still being written; nobody may be able to open it", de.Name())
		}
		return n, nil
	}
	t.Cleanup(func() { copyStream = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/one.txt"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !looked {
		t.Fatal("the transfer never ran, so nothing was staged")
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean copy: %v", log.warns)
	}
	if res.Files != 1 {
		t.Fatalf("result = %+v, want the file copied", res)
	}
	// And it is there, complete, once the job has published it.
	if got := readFile(t, base, "dst/one.txt"); got != "one" {
		t.Fatalf("dst/one.txt = %q", got)
	}
}

// TestTheNamedFallbackStillCopies is the other half: where the kernel or the
// filesystem has no O_TMPFILE the file is created under a name as this engine
// always did — the path the header records a disclosure window for — and it has
// to go on working.
func TestTheNamedFallbackStillCopies(t *testing.T) {
	forceNamedCreate(t)
	r, base := copyFixture(t)
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if len(log.warns) != 0 {
		t.Fatalf("warnings on a clean copy: %v", log.warns)
	}
	if res.Files != 2 {
		t.Fatalf("result = %+v, want both files copied", res)
	}
	if got := readFile(t, base, "dst/a/sub/two.txt"); got != "twotwo" {
		t.Fatalf("dst/a/sub/two.txt = %q", got)
	}
	assertNoTempLeft(t, base, "dst")
}

// TestADirectoryWithoutTheInheritedSetgidIsAbandoned is the second finding. A
// non-root worker whose primary group is `public`, copying into a setgid
// `private` destination: a writer swaps in an empty directory with the worker's
// own uid, gid `private` and mode 0755 but NO setgid bit, and every file created
// inside it afterwards comes out `public`. The mode check only ever rejected
// EXTRA bits, so a missing one went unnoticed.
//
// Root-gated only because the fixture has to make a setgid directory in a group
// this process is a member of, and root is the process that always is.
func TestADirectoryWithoutTheInheritedSetgidIsAbandoned(t *testing.T) {
	requireRoot(t)
	base := tempDir(t)
	mkdir(t, base, "src/a/private")
	mkdir(t, base, "dst")
	write(t, base, "src/a/private/secret.txt", "not for everybody")
	dst := filepath.Join(base, "dst")
	if err := os.Chown(dst, os.Geteuid(), 4000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, os.ModeSetgid|0o775); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	swapped := false
	prev := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if swapped || !buildingIn(d.rel, "dst/a") {
			return nil
		}
		swapped = true
		p := filepath.Join(base, filepath.FromSlash(d.rel), name)
		if err := os.Remove(p); err != nil {
			return err
		}
		// Everything the kernel would have made, except the bit it would have
		// passed down: right uid, right gid, a mode that is no wider.
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		if err := os.Chown(p, os.Geteuid(), 4000); err != nil {
			return err
		}
		return os.Chmod(p, 0o755)
	}
	t.Cleanup(func() { mkdirForCopy = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !swapped {
		t.Fatal("the impostor was never put in place, so nothing was staged")
	}
	if exists(t, base, "dst/a/private/secret.txt") {
		t.Fatal("the secret was copied into a directory that does not carry the group its parent passes down")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the subtree reported as skipped", res)
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
}

// TestAPrePlantedFinalNameIsNeverAdopted is the third finding's point, tested
// as the thing that changed: the attacker can still take the FINAL name — that
// is a name they can guess — but the directory this job creates is not the one
// at that name, so there is nothing of theirs to adopt. RENAME_NOREPLACE
// refuses, the staged directory is removed again, and the subtree is reported
// rather than copied into a stranger's folder.
func TestAPrePlantedFinalNameIsNeverAdopted(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/private")
	mkdir(t, base, "dst")
	write(t, base, "src/a/private/secret.txt", "not for everybody")
	r := newRoot(t, base)

	planted := false
	prev := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if planted || !buildingIn(d.rel, "dst/a") {
			return nil
		}
		planted = true
		// The name the copy is going to ask for, taken while the real one is
		// still being made under a name nobody can guess.
		p := filepath.Join(base, "dst", "a", "private")
		if err := os.Mkdir(p, 0o777); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(p, "theirs.txt"), []byte("already here"), 0o644)
	}
	t.Cleanup(func() { mkdirForCopy = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit())
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !planted {
		t.Fatal("the name was never taken, so nothing was staged")
	}
	if exists(t, base, "dst/a/private/secret.txt") {
		t.Fatal("the secret was copied into a directory this job did not create")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the subtree reported as not copied", res)
	}
	if len(log.warns) == 0 {
		t.Fatal("nothing was reported about a subtree that was not copied")
	}
	// The stranger's directory is exactly as they left it.
	if got, rerr := os.ReadFile(filepath.Join(base, "dst", "a", "private", "theirs.txt")); rerr != nil || string(got) != "already here" {
		t.Errorf("the planted file is %q (%v); nothing of somebody else's may be disturbed", got, rerr)
	}
	// And this job's own staged directory did not survive its refusal.
	des, rerr := os.ReadDir(filepath.Join(base, "dst", "a"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), copyTmpPrefix) {
			t.Errorf("a staged directory was left behind: %q", de.Name())
		}
	}
}
