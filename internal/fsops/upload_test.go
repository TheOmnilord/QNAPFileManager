package fsops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The M2-C upload's tests. The conflict policies, the declared-size gate, the
// discard and the two creation paths are this package's own logic and run
// everywhere; the mode and ownership proofs are the kernel's and live in
// upload_linux_test.go (INV-2).

func uploadFixture(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "dst")
	return newRoot(t, base), base
}

func openWriteReq(dir, name string) wproto.OpenWriteReq {
	return wproto.OpenWriteReq{Dir: []byte(dir), Name: []byte(name)}
}

// upload runs the whole shape of one upload: open, stream, finalize.
func upload(t *testing.T, r fsx.Root, req wproto.OpenWriteReq, body string, fin wproto.FinalizeReq) (wproto.FinalizeResp, error) {
	t.Helper()
	ctx := context.Background()
	f, h, err := OpenWrite(ctx, r, nil, req)
	if err != nil {
		return wproto.FinalizeResp{}, err
	}
	if _, werr := f.Write([]byte(body)); werr != nil {
		f.Close()
		h.Close()
		t.Fatalf("streaming the body: %v", werr)
	}
	if cerr := f.Close(); cerr != nil {
		h.Close()
		t.Fatalf("closing the front-end's descriptor: %v", cerr)
	}
	if len(fin.Final) == 0 {
		fin.Final = req.Name
	}
	return Finalize(ctx, h, fin)
}

// dirNames lists one directory of the fixture, dot-files included, so a test can
// prove that nothing was left behind.
func dirNames(t *testing.T, base, rel string) []string {
	t.Helper()
	des, err := os.ReadDir(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(des))
	for _, de := range des {
		out = append(out, de.Name())
	}
	sort.Strings(out)
	return out
}

func noLeftovers(t *testing.T, base, rel string) {
	t.Helper()
	for _, n := range dirNames(t, base, rel) {
		if strings.HasPrefix(n, uploadTmpPrefix) {
			t.Errorf("%s/%s was left behind", rel, n)
		}
	}
}

// forceNamedUpload makes every upload take the `.qfm-upload-*.part` fallback,
// as it does on a filesystem with no O_TMPFILE or on a host with no /proc for
// the linkat that publishes an unnamed inode. It is the only way to exercise
// that whole path on a kernel that supports O_TMPFILE perfectly well.
func forceNamedUpload(t *testing.T) {
	t.Helper()
	prev := unnamedUsable
	unnamedUsable = func(*dirRef) bool { return false }
	t.Cleanup(func() { unnamedUsable = prev })
}

// TestUploadCreatesAndPublishes is the ordinary case: the bytes the front-end
// streamed into the descriptor are what lands under the name, and the reply
// describes what is actually there.
func TestUploadCreatesAndPublishes(t *testing.T) {
	r, base := uploadFixture(t)
	resp, err := upload(t, r, openWriteReq("/dst", "a.txt"), "hello", wproto.FinalizeReq{})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
	if string(resp.Path) != "/dst/a.txt" {
		t.Errorf("Path = %q", resp.Path)
	}
	if resp.Entry.Name != "a.txt" || resp.Entry.Size != 5 || resp.Entry.Type != "file" {
		t.Errorf("entry = %+v", resp.Entry)
	}
	noLeftovers(t, base, "dst")
}

// TestUploadNamedFallbackPublishesTheSameWay: the `.part` exists only while the
// upload is in flight, it is hidden, and it is gone once the name is published.
func TestUploadNamedFallbackPublishesTheSameWay(t *testing.T) {
	forceNamedUpload(t)
	r, base := uploadFixture(t)
	ctx := context.Background()

	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.Named() {
		t.Fatal("the fallback was not taken")
	}
	during := dirNames(t, base, "dst")
	if len(during) != 1 || !strings.HasPrefix(during[0], uploadTmpPrefix) || !strings.HasSuffix(during[0], uploadTmpSuffix) {
		t.Fatalf("in flight, dst holds %v; want one hidden .part", during)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
	if got := dirNames(t, base, "dst"); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("after, dst holds %v", got)
	}
}

// TestUploadSkipRefusesBeforeTheBytes is contract §1.4's early refusal: a user
// about to send four gigabytes over a slow link is asked first.
func TestUploadSkipRefusesBeforeTheBytes(t *testing.T) {
	r, base := uploadFixture(t)
	write(t, base, "dst/a.txt", "original")

	req := openWriteReq("/dst", "a.txt")
	req.Conflict = wproto.ConflictSkip
	_, _, err := OpenWrite(context.Background(), r, nil, req)
	if fsx.Code(err) != "exists" {
		t.Fatalf("err = %v (code %q), want exists", err, fsx.Code(err))
	}
	if got := readFile(t, base, "dst/a.txt"); got != "original" {
		t.Errorf("the original must be untouched, got %q", got)
	}
	noLeftovers(t, base, "dst")
}

// TestUploadSkipRefusesAtFinalizeToo: the early refusal is a courtesy and the
// atomic one is at publication. A name taken DURING the transfer must not be
// replaced.
func TestUploadSkipRefusesAtFinalizeToo(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			ctx := context.Background()
			f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("mine")); err != nil {
				t.Fatal(err)
			}
			f.Close()
			// Somebody else got there while the body was in flight.
			write(t, base, "dst/a.txt", "theirs")

			_, err = Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt"), Conflict: wproto.ConflictSkip})
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("err = %v, want exists", err)
			}
			if got := readFile(t, base, "dst/a.txt"); got != "theirs" {
				t.Fatalf("somebody else's file was replaced: %q", got)
			}
			noLeftovers(t, base, "dst")
		})
	}
}

// TestUploadOverwriteReplaces.
func TestUploadOverwriteReplaces(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			write(t, base, "dst/a.txt", "original")

			req := openWriteReq("/dst", "a.txt")
			req.Conflict = wproto.ConflictOverwrite
			resp, err := upload(t, r, req, "replaced", wproto.FinalizeReq{Conflict: wproto.ConflictOverwrite})
			if err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, base, "dst/a.txt"); got != "replaced" {
				t.Fatalf("content = %q", got)
			}
			if string(resp.Path) != "/dst/a.txt" {
				t.Errorf("Path = %q", resp.Path)
			}
			if got := dirNames(t, base, "dst"); len(got) != 1 || got[0] != "a.txt" {
				t.Fatalf("dst holds %v", got)
			}
		})
	}
}

// TestUploadKeepBothPicksTheNextFreeName.
func TestUploadKeepBothPicksTheNextFreeName(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			write(t, base, "dst/a.txt", "original")
			write(t, base, "dst/a (2).txt", "second")

			req := openWriteReq("/dst", "a.txt")
			req.Conflict = wproto.ConflictRename
			resp, err := upload(t, r, req, "third", wproto.FinalizeReq{Conflict: wproto.ConflictRename})
			if err != nil {
				t.Fatal(err)
			}
			if string(resp.Path) != "/dst/a (3).txt" {
				t.Fatalf("Path = %q, want the next free keep-both name", resp.Path)
			}
			if resp.Entry.Name != "a (3).txt" {
				t.Errorf("entry name = %q", resp.Entry.Name)
			}
			if got := readFile(t, base, "dst/a (3).txt"); got != "third" {
				t.Errorf("content = %q", got)
			}
			if got := readFile(t, base, "dst/a.txt"); got != "original" {
				t.Errorf("the original must be untouched, got %q", got)
			}
			noLeftovers(t, base, "dst")
		})
	}
}

// TestUploadNeverReplacesAnotherKind: a file over a folder is not a
// replacement, it is a destruction, and no policy here asks for one.
func TestUploadNeverReplacesAnotherKind(t *testing.T) {
	r, base := uploadFixture(t)
	mkdir(t, base, "dst/a.txt")

	req := openWriteReq("/dst", "a.txt")
	req.Conflict = wproto.ConflictOverwrite
	_, err := upload(t, r, req, "x", wproto.FinalizeReq{Conflict: wproto.ConflictOverwrite})
	if fsx.Code(err) != "conflict" {
		t.Fatalf("err = %v (code %q), want conflict", err, fsx.Code(err))
	}
	if fi := lstat(t, base, "dst/a.txt"); !fi.IsDir() {
		t.Fatal("the directory was replaced")
	}
	noLeftovers(t, base, "dst")
}

// TestUploadPolicyAgainstADirectoryAtTheName is round 3 adversarial finding 2.
//
// The kind of what is standing in the way matters to ONE policy. Overwrite
// would destroy it, so overwrite refuses. Keep-both destroys nothing — it
// leaves the directory exactly where it is and takes the next free name — and
// refusing it was the bug: "Keep both" over a folder called report.txt
// transferred the whole body and then failed with `conflict`, which is the one
// case a user would most want that button for. Skip's answer is `exists`
// whatever is in the way, because something is.
func TestUploadPolicyAgainstADirectoryAtTheName(t *testing.T) {
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
			mkdir(t, base, "dst/report.txt")
			write(t, base, "dst/report.txt/inside.txt", "the folder's own file")

			req := openWriteReq("/dst", "report.txt")
			req.Conflict = c.policy
			resp, err := upload(t, r, req, "uploaded", wproto.FinalizeReq{Conflict: c.policy})
			if c.wantCode != "" {
				if fsx.Code(err) != c.wantCode {
					t.Fatalf("err = %v (code %q), want %q", err, fsx.Code(err), c.wantCode)
				}
			} else if err != nil {
				t.Fatalf("keep-both over a folder must publish beside it: %v", err)
			} else if string(resp.Path) != c.wantPath {
				t.Fatalf("Path = %q, want %q", resp.Path, c.wantPath)
			}
			// Whatever happened, the directory and its contents are untouched.
			if fi := lstat(t, base, "dst/report.txt"); !fi.IsDir() {
				t.Fatal("the directory was replaced")
			}
			if got := readFile(t, base, "dst/report.txt/inside.txt"); got != "the folder's own file" {
				t.Fatalf("the directory's contents changed: %q", got)
			}
			noLeftovers(t, base, "dst")
		})
	}
}

// TestUploadKeepBothOverAFileStillWorks keeps the fix from being a blanket
// permission: the ordinary keep-both is unchanged.
func TestUploadKeepBothOverAFileStillWorks(t *testing.T) {
	r, base := uploadFixture(t)
	write(t, base, "dst/report.txt", "original")

	req := openWriteReq("/dst", "report.txt")
	req.Conflict = wproto.ConflictRename
	resp, err := upload(t, r, req, "uploaded", wproto.FinalizeReq{Conflict: wproto.ConflictRename})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Path) != "/dst/report (2).txt" {
		t.Fatalf("Path = %q", resp.Path)
	}
	if got := readFile(t, base, "dst/report.txt"); got != "original" {
		t.Errorf("the original changed: %q", got)
	}
}

// TestUploadDeclaredSizeMismatchPublishesNothing is the gate: a body that ended
// short is a truncated upload, not a shorter file.
func TestUploadDeclaredSizeMismatchPublishesNothing(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			write(t, base, "dst/a.txt", "original")

			req := openWriteReq("/dst", "a.txt")
			req.Size = 100
			req.Conflict = wproto.ConflictOverwrite
			_, err := upload(t, r, req, "short", wproto.FinalizeReq{Conflict: wproto.ConflictOverwrite})
			if fsx.Code(err) != "changed" {
				t.Fatalf("err = %v (code %q), want changed", err, fsx.Code(err))
			}
			if got := readFile(t, base, "dst/a.txt"); got != "original" {
				t.Fatalf("a truncated upload was published over the original: %q", got)
			}
			if got := dirNames(t, base, "dst"); len(got) != 1 || got[0] != "a.txt" {
				t.Fatalf("dst holds %v", got)
			}
		})
	}
}

// TestUploadDeclaredSizeThatMatchesIsPublished keeps the gate honest: it must
// refuse a mismatch and nothing else.
func TestUploadDeclaredSizeThatMatchesIsPublished(t *testing.T) {
	r, base := uploadFixture(t)
	req := openWriteReq("/dst", "a.txt")
	req.Size = 5
	if _, err := upload(t, r, req, "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "hello" {
		t.Fatalf("content = %q", got)
	}
}

// TestUploadDiscardLeavesNothing is what a client disconnect turns into
// (§1.4): the handle is thrown away and the destination is as it was.
func TestUploadDiscardLeavesNothing(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			ctx := context.Background()
			f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("half")); err != nil {
				t.Fatal(err)
			}
			f.Close()
			if _, err := Finalize(ctx, h, wproto.FinalizeReq{Discard: true}); err != nil {
				t.Fatal(err)
			}
			if got := dirNames(t, base, "dst"); len(got) != 0 {
				t.Fatalf("dst holds %v after a discard", got)
			}
		})
	}
}

// TestUploadCancelledDuringTheFlushPublishesNothing is round 8. The check at
// the top of Finalize is not enough: the fsync between it and the publication
// flushes gigabytes on a busy volume, and a cancellation that arrived while it
// did still went on to link — or, under `overwrite`, to rename over the file
// that was already there, after the user had been told the upload was
// cancelled.
//
// Both creation paths, because the discard differs: an unnamed inode vanishes
// with its descriptor and the named fallback's `.part` has to be unlinked.
func TestUploadCancelledDuringTheFlushPublishesNothing(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "unnamed", true: "named"}[named], func(t *testing.T) {
			if named {
				forceNamedUpload(t)
			}
			r, base := uploadFixture(t)
			write(t, base, "dst/a.txt", "original")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// The cancellation arrives INSIDE the flush, which is the window.
			prev := uploadSync
			uploadSync = func(f *os.File) error {
				cancel()
				return prev(f)
			}
			t.Cleanup(func() { uploadSync = prev })

			req := openWriteReq("/dst", "a.txt")
			req.Conflict = wproto.ConflictOverwrite
			f, h, err := OpenWrite(ctx, r, nil, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, werr := f.Write([]byte("replacement")); werr != nil {
				t.Fatal(werr)
			}
			f.Close()

			_, err = Finalize(ctx, h, wproto.FinalizeReq{
				Final: []byte("a.txt"), Conflict: wproto.ConflictOverwrite,
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
			// The file that was already there is untouched — the whole point.
			if got := readFile(t, base, "dst/a.txt"); got != "original" {
				t.Fatalf("a cancelled upload replaced the existing file: %q", got)
			}
			if got := dirNames(t, base, "dst"); len(got) != 1 || got[0] != "a.txt" {
				t.Fatalf("dst holds %v; the cancelled inode must leave nothing", got)
			}
			// The handle is consumed, so the route's follow-up Discard is
			// answered honestly rather than acting on an inode that is gone.
			if _, aerr := Finalize(context.Background(), h, wproto.FinalizeReq{Discard: true}); !errors.Is(aerr, fs.ErrNotExist) {
				t.Fatalf("a second Finalize = %v, want not found", aerr)
			}
		})
	}
}

// TestUploadCancelledBeforeFinalizePublishesNothing is the same rule at the
// other end of the function, which is where it already was: a caller whose
// context is done before Finalize starts publishes nothing either.
func TestUploadCancelledBeforeFinalizePublishesNothing(t *testing.T) {
	r, base := uploadFixture(t)
	write(t, base, "dst/a.txt", "original")

	req := openWriteReq("/dst", "a.txt")
	req.Conflict = wproto.ConflictOverwrite
	f, h, err := OpenWrite(context.Background(), r, nil, req)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("replacement"))
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ferr := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt"), Conflict: wproto.ConflictOverwrite}); !errors.Is(ferr, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", ferr)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "original" {
		t.Fatalf("content = %q", got)
	}
	noLeftovers(t, base, "dst")
}

// TestUploadHandleCloseCleansUp is what an expired handle and a session that
// ends both do.
func TestUploadHandleCloseCleansUp(t *testing.T) {
	forceNamedUpload(t)
	r, base := uploadFixture(t)
	f, h, err := OpenWrite(context.Background(), r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := dirNames(t, base, "dst"); len(got) != 1 {
		t.Fatalf("dst holds %v", got)
	}
	h.Close()
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("dst holds %v after the handle was closed", got)
	}
	// Idempotent: the session's sweep and its shutdown may both reach a handle.
	h.Close()
}

// TestUploadFinalizeConsumesTheHandle: a second Finalize can never publish the
// same inode twice.
func TestUploadFinalizeConsumesTheHandle(t *testing.T) {
	r, _ := uploadFixture(t)
	ctx := context.Background()
	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("x"))
	f.Close()
	if _, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")}); err != nil {
		t.Fatal(err)
	}
	_, err = Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("b.txt")})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a second Finalize = %v, want not found", err)
	}
}

// TestUploadRefusesNoRoom is §1.9 on the upload path, through the seam that
// stands in for filling a real filesystem.
func TestUploadRefusesNoRoom(t *testing.T) {
	r, base := uploadFixture(t)
	prev := statfsAvail
	statfsAvail = func(d *dirRef) (uint64, bool, error) { return 10, true, nil }
	t.Cleanup(func() { statfsAvail = prev })

	req := openWriteReq("/dst", "big.bin")
	req.Size = 1 << 20
	_, _, err := OpenWrite(context.Background(), r, nil, req)
	if fsx.Code(err) != "no_space" {
		t.Fatalf("err = %v (code %q), want no_space", err, fsx.Code(err))
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("the refusal must happen before anything is created; dst holds %v", got)
	}
}

// TestUploadAcceptsWhatFits keeps the refusal from being a blanket one.
func TestUploadAcceptsWhatFits(t *testing.T) {
	r, _ := uploadFixture(t)
	prev := statfsAvail
	statfsAvail = func(d *dirRef) (uint64, bool, error) { return 1 << 30, true, nil }
	t.Cleanup(func() { statfsAvail = prev })

	req := openWriteReq("/dst", "a.txt")
	req.Size = 5
	if _, err := upload(t, r, req, "hello", wproto.FinalizeReq{}); err != nil {
		t.Fatal(err)
	}
}

// TestUploadRefusesBadNames: the name is one component and never a path, and
// the never-write component rule (F10) applies to the worker's own syscall as
// well as to the guard.
func TestUploadRefusesBadNames(t *testing.T) {
	r, _ := uploadFixture(t)
	ctx := context.Background()
	for _, name := range []string{"", ".", "..", "a/b", "sub/../a.txt"} {
		if _, _, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", name)); fsx.Code(err) != "bad_request" {
			t.Errorf("name %q = %v, want bad_request", name, err)
		}
	}
	for _, name := range []string{".zfs", "@Recycle"} {
		if _, _, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", name)); fsx.Code(err) != "protected" {
			t.Errorf("name %q = %v, want protected", name, err)
		}
	}
	if _, _, err := OpenWrite(ctx, r, nil, openWriteReq("/dst/@Recycle", "a.txt")); fsx.Code(err) != "protected" {
		t.Errorf("a never-write destination = %v, want protected", err)
	}
	if _, _, err := OpenWrite(ctx, r, nil, openWriteReq("/nope", "a.txt")); fsx.Code(err) != "not_found" {
		t.Errorf("a missing destination = %v, want not_found", err)
	}
}

// TestUploadFinalizeRefusesABadFinalName: Finalize may rename the upload, and
// the same rule applies to what it may be renamed to.
func TestUploadFinalizeRefusesABadFinalName(t *testing.T) {
	r, base := uploadFixture(t)
	ctx := context.Background()
	f, h, err := OpenWrite(ctx, r, nil, openWriteReq("/dst", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("../escape")}); fsx.Code(err) != "bad_request" {
		t.Fatalf("err = %v, want bad_request", err)
	}
	if got := dirNames(t, base, "dst"); len(got) != 0 {
		t.Fatalf("a refused Finalize must leave nothing: %v", got)
	}
}

// TestUploadStampsTheDeclaredMTime: the client's own modification time, set on
// the descriptor rather than on a name.
func TestUploadStampsTheDeclaredMTime(t *testing.T) {
	r, base := uploadFixture(t)
	want := time.Date(2020, 3, 4, 5, 6, 7, 0, time.UTC)
	req := openWriteReq("/dst", "a.txt")
	req.MTime = want.Unix()
	resp, err := upload(t, r, req, "hello", wproto.FinalizeReq{})
	if err != nil {
		t.Fatal(err)
	}
	if got := lstat(t, base, "dst/a.txt").ModTime(); !got.Equal(want) {
		t.Fatalf("mtime = %v, want %v", got, want)
	}
	if !resp.Entry.MTime.Equal(want) {
		t.Errorf("the reply must describe what is on the disk: %v", resp.Entry.MTime)
	}
}

// TestUploadDefaultsToSkip: an absent policy is the one that replaces nothing.
func TestUploadDefaultsToSkip(t *testing.T) {
	r, base := uploadFixture(t)
	write(t, base, "dst/a.txt", "original")
	ctx := context.Background()
	// OpenWrite carries no policy at all, so its early refusal does not fire;
	// the publication still refuses.
	f, h, err := OpenWrite(ctx, r, nil, wproto.OpenWriteReq{Dir: []byte("/dst"), Name: []byte("b.txt")})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Finalize(ctx, h, wproto.FinalizeReq{Final: []byte("a.txt")}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want exists", err)
	}
	if got := readFile(t, base, "dst/a.txt"); got != "original" {
		t.Errorf("content = %q", got)
	}
}
