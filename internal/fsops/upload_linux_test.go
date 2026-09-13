package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The upload's Linux half: the things the kernel decides. Mode bits, uids,
// inode identity and the unnamed file itself — none of which can be simulated
// anywhere else (INV-2).

// TestUploadIsUnnamedUntilItIsPublished is contract §1.2 by construction: while
// the body is in flight there is no name in the destination for anybody to open,
// and the name appears complete.
func TestUploadIsUnnamedUntilItIsPublished(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()

	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Named() {
		t.Skip("this filesystem has no O_TMPFILE, so the fallback is the only path here")
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("an upload in flight must have no name at all; dst holds %v", got)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("still nothing should be named; dst holds %v", got)
	}
	if _, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
}

// TestUploadDiscardedUnnamedInodeVanishes: there is nothing to clean up and
// nothing to be left behind, which is the whole point of the unnamed path.
func TestUploadDiscardedUnnamedInodeVanishes(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()
	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Named() {
		t.Skip("no O_TMPFILE here")
	}
	f.Write([]byte("half"))
	f.Close()
	h.Close()
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("dst holds %v", got)
	}
}

// TestUploadPublishedModeIsTheUmaskedCreationMode: 0644 narrowed by the
// worker's umask, and never chmod'ed afterwards (§1.2).
func TestUploadPublishedModeIsTheUmaskedCreationMode(t *testing.T) {
	requireUnixModes(t)
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })

	r, base := uploadFixture(t)
	if _, err := upload(t, r, openWriteReq("/dst", "a.txt"), "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatal(err)
	}
	if got := lstat(t, base, "dst/a.txt").Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %o, want 0640 (0644 &^ 027)", got)
	}
}

// TestUploadRefusesAFileTheKernelMadeWider is the empty-file proof: a mode
// WIDER than the one asked for means this is not the file this upload created,
// and nothing is written into it.
func TestUploadRefusesAFileTheKernelMadeWider(t *testing.T) {
	requireUnixModes(t)
	r, base := uploadFixture(t)

	prev := openUnnamedFile
	openUnnamedFile = func(d *dirRef, mode os.FileMode) (*os.File, error) {
		// What a filesystem with a default ACL that WIDENS would produce, which
		// no ordinary kernel does — which is exactly why it needs a seam.
		return prev(d, 0o666)
	}
	t.Cleanup(func() { openUnnamedFile = prev })

	f, _, err := OpenWrite(context.Background(), r, nil, openWriteReq("/dst", "a.txt"))
	if err == nil {
		f.Close()
		t.Skip("the umask narrowed 0666 to no wider than 0644 here, so there is nothing to refuse")
	}
	if !strings.Contains(err.Error(), "not created as this worker asked") {
		t.Fatalf("err = %v", err)
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("a refused upload must leave nothing: %v", got)
	}
}

// TestUploadRefusesAPartSomebodySwapped is the publication proof on the named
// fallback: an attacker with write access to the destination replaces the
// `.part` during the transfer, and the rename must not publish their file under
// the user's name.
func TestUploadRefusesAPartSomebodySwapped(t *testing.T) {
	forceNamedUpload(t)
	r, base := uploadFixture(t)
	ctx := context.Background()

	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("mine"))
	f.Close()

	part := dirNames(t, base, "dst")
	if len(part) != 1 {
		t.Fatalf("dst holds %v", part)
	}
	stolen := filepath.Join(base, "dst", part[0])
	if err := os.Remove(stolen); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stolen, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")})
	if !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("err = %v, want the substitution to be refused", err)
	}
	if _, serr := os.Lstat(filepath.Join(base, "dst", "a.txt")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatal("somebody else's file was published under the user's name")
	}
	// Their file is left exactly where it is: it is not ours to tidy away.
	if got, rerr := os.ReadFile(stolen); rerr != nil || string(got) != "theirs" {
		t.Errorf("the stranger's file was removed by our cleanup: %q %v", got, rerr)
	}
}

// TestUploadInstallsTheOwnerOnTheEmptyFile is §1.2's ordering, which is the
// whole of the disclosure fix: the chown happens while the file is still empty,
// so a descriptor somebody managed to get carries nothing.
func TestUploadInstallsTheOwnerOnTheEmptyFile(t *testing.T) {
	requireRoot(t)
	r, base := uploadFixture(t)

	sizeAtChown := int64(-1)
	prev := setEntryOwner
	setEntryOwner = func(dir *dirRef, name string, f *os.File, uid, gid int) error {
		if f != nil {
			if fi, err := f.Stat(); err == nil {
				sizeAtChown = fi.Size()
			}
		}
		return prev(dir, name, f, uid, gid)
	}
	t.Cleanup(func() { setEntryOwner = prev })

	const wantUID = 12345
	req := openWriteReq("/dst", "a.txt")
	req.As = &wproto.CreateAs{UID: wantUID, GID: -1}
	if _, err := upload(t, r, req, "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatal(err)
	}
	if sizeAtChown != 0 {
		t.Fatalf("the owner was installed on a file of %d bytes; it must be installed while it is empty", sizeAtChown)
	}
	fi := lstat(t, base, "dst/a.txt")
	uid, _, _, ok := statDetail(fi)
	if !ok || uid != wantUID {
		t.Fatalf("uid = %d (read %v), want %d", uid, ok, wantUID)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Errorf("content = %q", got)
	}
}

// TestUploadDoesNotChownAsANonRootWorker: the kernel refuses a non-root process
// that chowns to another uid, so trying would produce a failure whose outcome
// the kernel has already fixed. Refusing to try is the same answer, without the
// noise.
func TestUploadDoesNotChownAsANonRootWorker(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this asserts what a NON-root worker does")
	}
	r, _ := uploadFixture(t)

	called := false
	prev := setEntryOwner
	setEntryOwner = func(dir *dirRef, name string, f *os.File, uid, gid int) error {
		called = true
		return prev(dir, name, f, uid, gid)
	}
	t.Cleanup(func() { setEntryOwner = prev })

	req := openWriteReq("/dst", "a.txt")
	req.As = &wproto.CreateAs{UID: 12345, GID: -1}
	if _, err := upload(t, r, req, "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("a non-root worker must not attempt a chown")
	}
}

// TestUploadFailedOwnershipPublishesNothing: a chown that fails costs an empty
// inode and a refusal, never a file standing under its name owned by the wrong
// user.
func TestUploadFailedOwnershipPublishesNothing(t *testing.T) {
	requireRoot(t)
	r, base := uploadFixture(t)

	prev := setEntryOwner
	setEntryOwner = func(dir *dirRef, name string, f *os.File, uid, gid int) error {
		return syscall.EPERM
	}
	t.Cleanup(func() { setEntryOwner = prev })

	req := openWriteReq("/dst", "a.txt")
	req.As = &wproto.CreateAs{UID: 12345, GID: -1}
	_, _, err := OpenWrite(context.Background(), r, nil, req)
	if fsx.Code(err) != "owner_unset" {
		t.Fatalf("err = %v (code %q), want owner_unset", err, fsx.Code(err))
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("dst holds %v", got)
	}
}

// TestUploadPolicyAgainstASymlinkAtTheName is the other half of round 3
// adversarial finding 2, and it is Linux's because a symlink here is the
// kernel's rather than a privileged Windows feature.
//
// The link is never followed and never replaced: overwrite refuses it, skip
// reports exists, and keep-both publishes beside it and leaves it — including
// its target, which is somebody else's file entirely.
func TestUploadPolicyAgainstASymlinkAtTheName(t *testing.T) {
	cases := []struct {
		policy   string
		wantCode string
		wantPath string
	}{
		{wproto.ConflictSkip, "exists", ""},
		{wproto.ConflictOverwrite, "conflict", ""},
		{wproto.ConflictRename, "", "/dst/report (2).txt"},
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			r, base := uploadFixture(t)
			write(t, base, "dst/target.txt", "the link's target")
			if err := os.Symlink("target.txt", filepath.Join(base, "dst", "report.txt")); err != nil {
				t.Skipf("symlinks are not available here: %v", err)
			}

			req := openWriteReq("/dst", "report.txt")
			req.Conflict = c.policy
			resp, err := upload(t, r, req, "uploaded", wproto.FinalizeReq{Conflict: c.policy})
			if c.wantCode != "" {
				if fsx.Code(err) != c.wantCode {
					t.Fatalf("err = %v (code %q), want %q", err, fsx.Code(err), c.wantCode)
				}
			} else if err != nil {
				t.Fatalf("keep-both over a symlink must publish beside it: %v", err)
			} else if string(resp.Path) != c.wantPath {
				t.Fatalf("Path = %q, want %q", resp.Path, c.wantPath)
			}
			// The link is still a link, and its target still holds what it did:
			// an upload that had followed it would have rewritten target.txt.
			if fi := lstat(t, base, "dst/report.txt"); fi.Mode()&fs.ModeSymlink == 0 {
				t.Fatalf("the symlink became a %v", fi.Mode())
			}
			if got := readFile(t, base, "dst/target.txt"); got != "the link's target" {
				t.Fatalf("the link's target was written through: %q", got)
			}
		})
	}
}

// TestUploadIntoADropDirectory is the openPathRef rule (INV-2): creating an
// entry needs SEARCH permission on the directory and not read, and a mode-0333
// drop folder is an ordinary shape for an upload target.
func TestUploadIntoADropDirectory(t *testing.T) {
	requireOwnPermissions(t)
	r, base := uploadFixture(t)
	drop := filepath.Join(base, "dst", "drop")
	if err := os.Mkdir(drop, 0o333); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(drop, 0o755) })

	if _, err := upload(t, r, openWriteReq("/dst/drop", "a.txt"), "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatalf("uploading into a write-only directory the kernel allows: %v", err)
	}
	if err := os.Chmod(drop, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, base, "dst/drop/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
}

// TestUploadKeepBothAtTheNameLimit is round 7 adversarial, end to end: a
// 255-byte name is legal, and the "(2)" made from it must be too. Before the
// bound, linkat answered ENAMETOOLONG after the whole body had been streamed.
func TestUploadKeepBothAtTheNameLimit(t *testing.T) {
	r, base := uploadFixture(t)
	long := strings.Repeat("a", maxNameBytes-4) + ".txt"
	if len(long) != maxNameBytes {
		t.Fatalf("the fixture name is %d bytes, not %d", len(long), maxNameBytes)
	}
	write(t, base, "dst/"+long, "original")

	req := openWriteReq("/dst", long)
	req.Conflict = wproto.ConflictRename
	resp, err := upload(t, r, req, "uploaded", wproto.FinalizeReq{Conflict: wproto.ConflictRename})
	if err != nil {
		t.Fatalf("keep-both at the name limit: %v", err)
	}
	published := fsx.Base(string(resp.Path))
	if len(published) > maxNameBytes {
		t.Fatalf("the published name is %d bytes: %q", len(published), published)
	}
	if published == long {
		t.Fatal("the original was replaced")
	}
	if !strings.HasSuffix(published, ".txt") {
		t.Errorf("the extension was lost: %q", published)
	}
	if got := readFile(t, base, "dst/"+published); got != "uploaded" {
		t.Errorf("content = %q", got)
	}
	if got := readFile(t, base, "dst/"+long); got != "original" {
		t.Errorf("the original changed: %q", got)
	}
}

// TestUploadKeepBothWithNoRoomIsRefused: an extension so long that no suffix
// fits beside it is a refusal with a code the route can turn into a 413, not a
// name this engine invented.
func TestUploadKeepBothWithNoRoomIsRefused(t *testing.T) {
	r, base := uploadFixture(t)
	// One byte of stem and an extension filling the rest: " (2)" cannot fit.
	long := "x." + strings.Repeat("e", maxNameBytes-2)
	if len(long) != maxNameBytes {
		t.Fatalf("the fixture name is %d bytes, not %d", len(long), maxNameBytes)
	}
	write(t, base, "dst/"+long, "original")

	req := openWriteReq("/dst", long)
	req.Conflict = wproto.ConflictRename
	_, err := upload(t, r, req, "uploaded", wproto.FinalizeReq{Conflict: wproto.ConflictRename})
	if fsx.Code(err) != "too_large" {
		t.Fatalf("err = %v (code %q), want too_large", err, fsx.Code(err))
	}
	if got := readFile(t, base, "dst/"+long); got != "original" {
		t.Errorf("the original changed: %q", got)
	}
	noLeftovers(t, base, "dst")
}

// TestOpenWriteRefusesAStaleDirIdentity is M2-C review round 13's second
// finding: the front-end authorizes a directory and the worker opens it only
// when the file part's headers arrive, which the client decides. An identity
// that does not match the directory actually opened is refused before a byte
// of the body can reach it.
func TestOpenWriteRefusesAStaleDirIdentity(t *testing.T) {
	r, base := uploadFixture(t)
	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &wproto.FSIdentityResp{Dev: 1, Ino: 999999, Dir: true}

	f, _, err := OpenWrite(context.Background(), r, nil, req)
	if err == nil {
		f.Close()
		t.Fatal("an upload bound to another directory must be refused")
	}
	if fsx.Code(err) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("a refused upload created something: %v", got)
	}
}

// TestOpenWriteAcceptsTheAuthorizedDirIdentity keeps the binding from being a
// blanket refusal: the identity the route really took has to match.
func TestOpenWriteAcceptsTheAuthorizedDirIdentity(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()

	id, err := FSIdentity(ctx, r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	if id.Ino == 0 || !id.Dir {
		t.Fatalf("FSIdentity did not identify the directory: %+v", id)
	}
	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &id
	if _, err := upload(t, r, req, "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatalf("an upload into the authorized directory: %v", err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
}

// TestOpenWriteRefusesADirectorySwappedForASymlink is the attack itself: the
// route clears /dst, and before the body's headers arrive the directory is
// renamed away and a symlink to somewhere else is left at the name. The
// pathname still resolves; the inode does not match.
func TestOpenWriteRefusesADirectorySwappedForASymlink(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()
	mkdir(t, base, "elsewhere")

	id, err := FSIdentity(ctx, r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	// The window: between the identity the route took and the worker's open.
	if err := os.Rename(filepath.Join(base, "dst"), filepath.Join(base, "dst-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(base, "dst")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &id
	f, _, oerr := OpenWrite(ctx, r, nil, req)
	if oerr == nil {
		f.Close()
		t.Fatal("an upload into a substituted directory must be refused")
	}
	if fsx.Code(oerr) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", oerr, fsx.Code(oerr))
	}
	if got := dirNames(t, base, "elsewhere"); len(got) != 0 {
		t.Fatalf("the symlink's target was written into: %v", got)
	}
}

// TestOpenWriteRefusesADirectorySwappedForAnotherDirectory is the half a
// no-follow walk cannot catch: the replacement is a real directory, so every
// component resolves perfectly and only the inode tells them apart.
func TestOpenWriteRefusesADirectorySwappedForAnotherDirectory(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()

	id, err := FSIdentity(ctx, r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "dst"), filepath.Join(base, "dst-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}

	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &id
	f, _, oerr := OpenWrite(ctx, r, nil, req)
	if oerr == nil {
		f.Close()
		t.Fatal("an upload into a substituted directory must be refused")
	}
	if fsx.Code(oerr) != "changed" {
		t.Fatalf("err = %v (code %q), want changed", oerr, fsx.Code(oerr))
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("the replacement was written into: %v", got)
	}
}

// TestFinalizePublishesIntoTheHeldDirectory is the other end of the binding: a
// directory replaced AFTER OpenWrite must not change where the upload lands.
// The handle keeps the descriptor it was opened with, so the file is published
// into the original directory — wherever that has been renamed to — and never
// into whatever now answers to the path.
func TestFinalizePublishesIntoTheHeldDirectory(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()

	id, err := FSIdentity(ctx, r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	req := openWriteReq("/dst", "a.txt")
	req.DirIdentity = &id
	f, h, err := OpenWrite(ctx, r, nil, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, werr := f.Write([]byte("hello")); werr != nil {
		t.Fatal(werr)
	}
	f.Close()

	// The destination is renamed away and a different directory takes its name
	// while the body is in flight.
	if err := os.Rename(filepath.Join(base, "dst"), filepath.Join(base, "dst-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "dst"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, ferr := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")}); ferr != nil {
		t.Fatalf("Finalize: %v", ferr)
	}
	if got := readFile(t, base, "dst-moved/a.txt"); got != "hello" {
		t.Fatalf("the upload did not land in the directory it was opened in: %q", got)
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("the upload landed in the replacement: %v", got)
	}
}
