package fsops

// The NFSv4 half of the ACL badge on the real file-backed ZFS fixture, and the
// aclmode the properties dialog reads off the dataset (Astra M3 round 1,
// finding 16). The gate and the reason there is no simulated dataset are
// zfs_integration_test.go's; these run in the same QFM_ZFS_TEST job.
//
// The ACE is written with setxattr(2) directly and never with nfs4_setfacl: the
// tool is not present on the fixture and depending on it would make the test a
// test of the tool. Upstream OpenZFS on Linux may not implement the attribute
// at all — QNAP's fork does — so a fixture that refuses the write says so in
// its skip, with the errno, rather than passing silently.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// nfs4Unavailable reports that this fixture's ZFS cannot stage an NFSv4 ACL.
//
// It is a SKIP on an ordinary runner and a FAILURE under QFM_NFS4_TEST=1 (Astra
// M3 round-2 finding 11). A skip is the honest outcome where the attribute does
// not exist — CI's upstream OpenZFS on Linux does not implement
// system.nfs4_acl, and nothing this app does can stage one — but on a runner
// that HAS it, a detection regression would then skip rather than fail, which
// is the one thing a test must never do quietly. The environment variable is
// how such a runner says so; on the NAS itself this is the hardware check the
// contract already lists (§6.1).
func nfs4Unavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	msg += fmt.Sprintf("; %s is QNAP's fork, and CI's upstream OpenZFS on Linux cannot stage it"+
		" — set QFM_NFS4_TEST=1 on a runner that has the attribute to make this a failure"+
		" (contract §6.1: the hardware check)", platform.XattrNFS4ACL)
	if os.Getenv("QFM_NFS4_TEST") == "1" {
		t.Fatalf("QFM_NFS4_TEST=1: %s", msg)
	}
	t.Skip(msg)
}

// nfs4Fixture is zfsFixture with the NFSv4 opt-in's own prerequisites checked
// FIRST (Astra r3 #6).
//
// QFM_NFS4_TEST=1 is a runner saying "the attribute exists here, so a detection
// regression must fail rather than skip" — but zfsFixture skips before any of
// that is reached unless QFM_ZFS_TEST=1 is set as well, so the opt-in alone
// bought nothing and did so silently, which is exactly the outcome it exists to
// prevent. Asking for the NFSv4 tests therefore now asks for the fixture they
// run on, and a missing prerequisite is named rather than skipped past. Without
// the opt-in nothing changes: an ordinary runner still skips.
func nfs4Fixture(t *testing.T) *platform.Platform {
	t.Helper()
	if os.Getenv("QFM_NFS4_TEST") == "1" && os.Getenv("QFM_ZFS_TEST") != "1" {
		t.Fatal("QFM_NFS4_TEST=1 asks for the NFSv4 ACL tests, and those need the ZFS fixture:" +
			" set QFM_ZFS_TEST=1 after running scripts/ci-zfs-setup.sh, or unset QFM_NFS4_TEST to skip")
	}
	return zfsFixture(t)
}

// nfs4ACLWithNamedACE builds a system.nfs4_acl attribute holding exactly one
// ALLOW ACE for a named principal: a big-endian ACE count, then type, flag,
// access mask and who-length, then the who string padded up to four bytes
// (perm.NFS4State parses the same shape). A named who is what makes the ACL say
// something the mode cannot, which is what the badge reports.
func nfs4ACLWithNamedACE(who string) []byte {
	const (
		aceAllow    = 0x00000000
		aceNoFlags  = 0x00000000
		aceReadMask = 0x00120089 // READ_DATA|READ_ATTRIBUTES|READ_ACL|SYNCHRONIZE
	)
	pad := (4 - len(who)%4) % 4
	buf := make([]byte, 0, 4+16+len(who)+pad)
	var word [4]byte
	put := func(v uint32) {
		binary.BigEndian.PutUint32(word[:], v)
		buf = append(buf, word[:]...)
	}
	put(1) // one ACE
	put(aceAllow)
	put(aceNoFlags)
	put(aceReadMask)
	put(uint32(len(who)))
	buf = append(buf, who...)
	buf = append(buf, make([]byte, pad)...)
	return buf
}

// TestZFSFixtureNamedNFS4ACEBadgesAsNFS4 puts a named ACE on a real file of a
// real dataset and asserts the badge the listing and the properties dialog
// publish for it. Every object on a hero dataset carries a trivial NFSv4 ACL,
// so "nfs4" rather than "nfs4-trivial" is the whole distinction the badge
// exists to draw (contract §6.1).
func TestZFSFixtureNamedNFS4ACEBadgesAsNFS4(t *testing.T) {
	plat := nfs4Fixture(t)
	if b := plat.For(zfsPublic).ACLBackend; b != platform.ACLNFS4 {
		nfs4Unavailable(t, "this OpenZFS build reports ACL backend %q on %s, not %q",
			b, zfsPublic, platform.ACLNFS4)
	}

	name := ".qfm-nfs4-acl-probe.txt"
	osPath := filepath.Join(zfsPublic, name)
	t.Cleanup(func() { _ = os.Remove(osPath) })
	_ = os.Remove(osPath)
	if err := os.WriteFile(osPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("writing the probe file: %v", err)
	}

	xattr := plat.For(zfsPublic).ACLXattr
	if xattr == "" {
		xattr = platform.XattrNFS4ACL
	}
	if err := syscall.Setxattr(osPath, xattr, nfs4ACLWithNamedACE("qfmacl@qfm.test"), 0); err != nil {
		nfs4Unavailable(t, "this fixture refuses setxattr of %s: %v (errno %d)", xattr, err, errnoOf(err))
	}

	ctx := context.Background()
	var r fsx.Root // unjailed: the fixture lives at absolute paths on this host

	l, err := List(ctx, r, plat, zfsPublic, fsx.ListOptions{ShowHidden: true, ACLProbe: true, Limit: fsx.MaxListLimit})
	if err != nil {
		t.Fatalf("List(%s): %v", zfsPublic, err)
	}
	e, ok := find(l, name)
	if !ok {
		t.Fatalf("the listing has no %s; got %v", name, names(l))
	}
	if e.ACL != fsx.ACLNFS4 {
		t.Errorf("listing badge = %q, want %q: the ACE names somebody the mode cannot", e.ACL, fsx.ACLNFS4)
	}
	if !e.HasACL {
		t.Errorf("HasACL = false on an entry badged %q", e.ACL)
	}

	pr, err := Props(ctx, r, plat, osPath, "")
	if err != nil {
		t.Fatalf("Props(%s): %v", osPath, err)
	}
	if pr.ACL.State != fsx.ACLNFS4 {
		t.Errorf("Props state = %q, want %q", pr.ACL.State, fsx.ACLNFS4)
	}
	if pr.ACL.Backend != platform.ACLNFS4 {
		t.Errorf("Props backend = %q, want %q", pr.ACL.Backend, platform.ACLNFS4)
	}
}

// TestZFSFixturePropsReportsTheDatasetAclmode is the other input to the chmod
// warning (contract §6.3): the aclmode of the dataset an object sits on,
// carried to the properties dialog through Props rather than re-read anywhere
// else. scripts/ci-zfs-setup.sh sets Public to discard and Media to
// passthrough, and the warning ladder is built on the difference.
func TestZFSFixturePropsReportsTheDatasetAclmode(t *testing.T) {
	plat := nfs4Fixture(t)
	ctx := context.Background()
	var r fsx.Root

	for _, tc := range []struct{ mount, dataset, aclmode string }{
		{zfsPublic, "qfmpool/Public", "discard"},
		{zfsMedia, "qfmpool/Media", "passthrough"},
	} {
		pr, err := Props(ctx, r, plat, tc.mount, "")
		if err != nil {
			t.Fatalf("Props(%s): %v", tc.mount, err)
		}
		if pr.ACL.Aclmode != tc.aclmode {
			t.Errorf("Props(%s).ACL.Aclmode = %q, want %q", tc.mount, pr.ACL.Aclmode, tc.aclmode)
		}
		if pr.ACL.Dataset != tc.dataset {
			t.Errorf("Props(%s).ACL.Dataset = %q, want %q", tc.mount, pr.ACL.Dataset, tc.dataset)
		}
		// The backend Props publishes is the one the platform detected, never a
		// second opinion of its own. Asserting "nfs4" outright would fail on an
		// upstream OpenZFS that exposes no such attribute, which is a fact about
		// the fixture and not a defect in this code (identity plan §6).
		if want := plat.For(tc.mount).ACLBackend; pr.ACL.Backend != want {
			t.Errorf("Props(%s).ACL.Backend = %q, but the platform detected %q", tc.mount, pr.ACL.Backend, want)
		} else {
			t.Logf("Props(%s): backend %q, aclmode %q", tc.mount, pr.ACL.Backend, pr.ACL.Aclmode)
		}
	}
}

// errnoOf spells the errno behind a syscall error for a skip message, so a job
// log says WHY the fixture refused rather than only that it did.
func errnoOf(err error) int {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}
