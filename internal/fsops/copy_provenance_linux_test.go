package fsops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// TestASwappedDestinationDirectoryIsAbandoned is round 11's first finding, and
// it had no privileges in it at all: the provenance check hung off the chown, so
// on the ordinary NON-ROOT path — which never chowns — nothing was checked.
//
// The shape that matters: a 0700 source directory holding 0644 files, copied
// into a shared non-sticky destination. Another user replaces the freshly
// created directory with their own 0777 one before it is opened, and the
// contents went straight into it. Nothing may be written into a directory this
// job cannot prove it made, and the whole subtree is abandoned.
func TestASwappedDestinationDirectoryIsAbandoned(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/private")
	mkdir(t, base, "dst")
	write(t, base, "src/a/private/secret.txt", "not for everybody")
	if err := os.Chmod(filepath.Join(base, "src", "a", "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// The impostor takes the name between the mkdir and the openat that follows
	// it. childPath is what the engine opens with, so the swap happens the
	// instant before.
	//
	// The name is whatever the engine asked for and never a name this test
	// writes down: since round 14 that is an unguessable staged one, and the
	// swap an attacker could actually make — at the FINAL name — has nothing to
	// do with the object being proved here. This stages the impossible one, so
	// the proof itself is still tested.
	swapped := ""
	prev := mkdirForCopy
	mkdirForCopy = func(d *dirRef, name string, mode os.FileMode) error {
		if err := prev(d, name, mode); err != nil {
			return err
		}
		if swapped != "" || !buildingIn(d.rel, "dst/a") {
			return nil
		}
		p := filepath.Join(base, filepath.FromSlash(d.rel), name)
		swapped = p
		if err := os.Remove(p); err != nil {
			return err
		}
		// Somebody else's directory, world-writable, under our name.
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
	if swapped == "" {
		t.Fatal("the impostor was never put in place, so nothing was staged")
	}
	if exists(t, base, "dst/a/private/secret.txt") {
		t.Fatal("the secret was copied into a directory this job did not create")
	}
	if res.Skipped == 0 {
		t.Errorf("result = %+v, want the subtree reported as skipped", res)
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
	// The impostor's own file is untouched: it was never this job's.
	if got, rerr := os.ReadFile(filepath.Join(swapped, "theirs.txt")); rerr != nil || string(got) != "already here" {
		t.Errorf("the impostor's file is %q (%v); nothing of somebody else's may be disturbed", got, rerr)
	}
}

// TestAWiderSubstitutedDirectoryIsAbandoned is round 12's first adversarial
// finding: kind, creator-uid and emptiness all pass for an existing EMPTY
// root-owned 0755 directory slid over the name of a 0700 one, the chown leaves
// it 0755, and private files land somewhere anybody can search. Creation only
// ever narrows a mode, so a wider one is proof of a substitution.
func TestAWiderSubstitutedDirectoryIsAbandoned(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "src/a/private")
	mkdir(t, base, "dst")
	write(t, base, "src/a/private/secret.txt", "not for everybody")
	if err := os.Chmod(filepath.Join(base, "src", "a", "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)

	// The impostor is EMPTY and owned by this same worker — everything the
	// older provenance check asked about — and only its mode gives it away. It
	// is staged at the name the engine asked for, which since round 14 is an
	// unguessable staged one; see TestASwappedDestinationDirectoryIsAbandoned.
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
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		return os.Chmod(p, 0o755)
	}
	t.Cleanup(func() { mkdirForCopy = prev })
	var log jobLog

	if _, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), false, log.emit()); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !swapped {
		t.Fatal("the impostor was never put in place, so nothing was staged")
	}
	if exists(t, base, "dst/a/private/secret.txt") {
		t.Fatal("the secret was copied into a directory with wider permissions than were asked for")
	}
	if indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
	}
}

// TestTheSourceRootMustNotChangeBetweenCreationAndRecord is round 12's fourth:
// the destination root was created from one fstat and the record taken from a
// later one, so a source root tightened 0755 -> 0700 in between left the
// destination 0755 while the record said 0700 — and the delete approved.
func TestTheSourceRootMustNotChangeBetweenCreationAndRecord(t *testing.T) {
	r, base := copyFixture(t)
	forceEXDEV(t)

	// The window is announced by the engine: the destination root and the
	// record have both been made from one fstat, and the walk has not yet taken
	// its own. identityFor was the wrong seam for it — the walk asks about the
	// root's descriptor from children(), which runs AFTER the verifying fstat,
	// so the change landed too late to be seen.
	tightened := false
	prev := verifyTrace
	verifyTrace = func(step string) {
		if step != "root-recorded" || tightened {
			return
		}
		tightened = true
		if err := os.Chmod(filepath.Join(base, "src", "a"), 0o700); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { verifyTrace = prev })
	var log jobLog

	res, err := Copy(context.Background(), r, nil, copyReq("/dst", wproto.CopyOptions{}, "/src/a"), true, log.emit())
	if err != nil {
		t.Fatalf("Copy(move): %v", err)
	}
	if !tightened {
		t.Skip("the seam was never reached, so the window could not be staged")
	}
	if !exists(t, base, "src/a/one.txt") {
		t.Fatal("the source was deleted although its root changed between being copied and being recorded")
	}
	if res.Skipped == 0 || indexOf(log.codes(), warnChanged) < 0 {
		t.Fatalf("result = %+v, warn codes = %v, want the root abandoned with %q", res, log.codes(), warnChanged)
	}
}
