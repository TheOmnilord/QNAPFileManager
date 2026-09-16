package fsops

// The POSIX half of the ACL badge against a REAL ACL on a real filesystem.
//
// acl_test.go and aclstate's own tests exercise the classification over bytes
// this package supplies; nothing in M3 had ever pointed the probe at an object
// the kernel had actually given an ACL to (Astra M3 round 1, finding 16). This
// does: setfacl puts a named user on a file, and the badge has to report
// "posix" both before and after a chmod.
//
// What is asserted is only what the APP said about the object. What the chmod
// did to the ACL's mask entry is the kernel's business and is deliberately not
// asserted — it is logged, so a reader of a CI log can see it, and nothing more
// (PLAN.md INV-2).

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
)

// TestPosixACLBadgeSurvivesAChmod is the ext4 half of contract §6: a file with
// a named-user entry badges as fsx.ACLPosix in a listing and in the properties
// dialog, and it still does after its mode has been changed through this
// package.
func TestPosixACLBadgeSurvivesAChmod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACLs and setfacl are Linux's")
	}
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		// The CI job installs the acl package for exactly this reason; a dev box
		// without it loses the test rather than failing it.
		t.Skipf("setfacl is not installed: %v", err)
	}

	dir := t.TempDir()
	if real, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = real
	}
	plat := platform.Detect()
	if b := plat.For(dir).ACLBackend; b != platform.ACLPosix {
		t.Skipf("the filesystem holding %s reports ACL backend %q, not %q; there is no POSIX ACL to set here",
			dir, b, platform.ACLPosix)
	}

	osPath := filepath.Join(dir, "acl.txt")
	if werr := os.WriteFile(osPath, []byte("x"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	// A NAMED user is what makes the access ACL non-empty — it is exactly the
	// "+" ls -l shows. 65534 is used because it is never the caller and needs
	// no fixture of its own.
	if out, ferr := exec.Command(setfacl, "-m", "u:65534:r--", osPath).CombinedOutput(); ferr != nil {
		t.Skipf("setfacl on %s: %v\n%s", osPath, ferr, out)
	}

	var r fsx.Root // unjailed: the fixture lives at absolute paths on this host
	ctx := context.Background()

	// The badge is read through both routes that publish it, at both points in
	// time. A table rather than two copies, because the assertion is the same
	// sentence twice and the only variable is when it is made.
	badge := func(t *testing.T, when string) {
		t.Helper()
		l, lerr := List(ctx, r, plat, dir, fsx.ListOptions{ACLProbe: true, Limit: fsx.MaxListLimit})
		if lerr != nil {
			t.Fatalf("List %s: %v", when, lerr)
		}
		e, ok := find(l, "acl.txt")
		if !ok {
			t.Fatalf("%s: the listing has no acl.txt; got %v", when, names(l))
		}
		if e.ACL != fsx.ACLPosix {
			t.Errorf("%s: listing badge = %q, want %q", when, e.ACL, fsx.ACLPosix)
		}
		if !e.HasACL {
			t.Errorf("%s: HasACL = false on an entry badged %q", when, e.ACL)
		}
		pr, perr := Props(ctx, r, plat, osPath, "")
		if perr != nil {
			t.Fatalf("Props %s: %v", when, perr)
		}
		if pr.ACL.Backend != platform.ACLPosix {
			t.Errorf("%s: Props backend = %q, want %q", when, pr.ACL.Backend, platform.ACLPosix)
		}
		if pr.ACL.State != fsx.ACLPosix {
			t.Errorf("%s: Props state = %q, want %q", when, pr.ACL.State, fsx.ACLPosix)
		}
		if pr.ACL.Xattr != platform.XattrPosixACL {
			t.Errorf("%s: Props xattr = %q, want %q", when, pr.ACL.Xattr, platform.XattrPosixACL)
		}
	}

	badge(t, "before the chmod")

	resp, err := Chmod(ctx, r, plat, osPath, perm.ModeSpec{Mask: 0o7777, Value: 0o0600}, nil)
	if err != nil {
		t.Fatalf("Chmod of an ACL-bearing file: %v", err)
	}
	if resp.Before.Name != "acl.txt" || resp.Entry.Name != "acl.txt" {
		t.Fatalf("before/after = %q/%q", resp.Before.Name, resp.Entry.Name)
	}
	// Whether the kernel rewrote the mask entry, and what it made of the group
	// bits, is not this test's to assert (INV-2). It is worth reading in a log.
	t.Logf("chmod 0600 over a POSIX ACL: %s -> %s, diffs %+v",
		resp.Before.Mode, resp.Entry.Mode, resp.Diffs)

	// The ACL survived the mode change, which is the property the permissions
	// dialog's warning rests on.
	badge(t, "after the chmod")
}
