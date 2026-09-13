package fsops

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The M2-C archive's tests. The formats, the names, the notes and the
// truncation rule are this package's own logic and run everywhere; symlinks,
// non-UTF-8 names and special files are the kernel's and live in
// archive_linux_test.go.

// archiveFixture builds
//
//	/tree/one.txt        "one"
//	/tree/sub/two.jpg    "already compressed"
//	/tree/sub/deep/      empty
//	/other/one.txt       "other one"
func archiveFixture(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "tree/sub/deep")
	mkdir(t, base, "other")
	write(t, base, "tree/one.txt", "one")
	write(t, base, "tree/sub/two.jpg", "already compressed")
	write(t, base, "other/one.txt", "other one")
	return newRoot(t, base), base
}

func archiveReq(format string, paths ...string) wproto.ArchiveReq {
	req := wproto.ArchiveReq{Format: format}
	for _, p := range paths {
		req.Paths = append(req.Paths, []byte(p))
	}
	return req
}

// sink is a writer over a buffer that can be told to fail. It is the
// front-end's end of the pipe, with the one behaviour a real pipe has that a
// buffer does not: a reader that went away.
type sink struct {
	buf    bytes.Buffer
	after  int // bytes to accept before failing; 0 = never fail
	err    error
	closed bool
}

func (s *sink) Write(p []byte) (int, error) {
	if s.err != nil && s.after >= 0 && s.buf.Len() >= s.after {
		return 0, s.err
	}
	return s.buf.Write(p)
}

func (s *sink) Close() error {
	s.closed = true
	return nil
}

// runArchive is the whole production shape: check first — which is what records
// every root's identity — then stream. A test that called Archive without a
// plan would be exercising a path the worker does not have (round 13).
func runArchive(t *testing.T, r fsx.Root, req wproto.ArchiveReq) (*sink, error) {
	t.Helper()
	s, _, err := runArchivePlanned(t, r, nil, req)
	return s, err
}

// runArchivePlanned is runArchive with the platform and the plan in hand, for
// the tests that need to reach between the two halves.
func runArchivePlanned(t *testing.T, r fsx.Root, plat *platform.Platform, req wproto.ArchiveReq) (*sink, *ArchivePlan, error) {
	t.Helper()
	ctx := context.Background()
	plan, err := ArchiveCheck(ctx, r, plat, req)
	if err != nil {
		return &sink{}, nil, err
	}
	s := &sink{}
	_, err = Archive(ctx, r, plat, req, plan, s)
	if s.closed {
		t.Error("Archive must NOT close the write end: the caller records the outcome first and closes afterwards (round 2)")
	}
	return s, plan, err
}

// zipMembers reads an archive back with archive/zip, which is what the client's
// unzip will do.
func zipMembers(t *testing.T, b []byte) map[string]*zip.File {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("reading the zip back: %v", err)
	}
	out := map[string]*zip.File{}
	for _, f := range zr.File {
		out[f.Name] = f
	}
	return out
}

func zipContent(t *testing.T, f *zip.File) string {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("opening %s: %v", f.Name, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading %s: %v", f.Name, err)
	}
	return string(b)
}

// tarMembers reads a tar.gz back with archive/tar.
func tarMembers(t *testing.T, b []byte) (map[string]*tar.Header, map[string]string) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("reading the gzip back: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	heads := map[string]*tar.Header{}
	bodies := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return heads, bodies
		}
		if err != nil {
			t.Fatalf("reading the tar back: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s: %v", h.Name, err)
		}
		heads[h.Name] = h
		bodies[h.Name] = string(body)
	}
}

// TestArchiveZipRoundTrips is the whole of §2.2 for the zip half: names
// relative to the selected root's PARENT, directories as their own members,
// content intact, modification times carried, and Store chosen for something
// already compressed.
func TestArchiveZipRoundTrips(t *testing.T) {
	r, base := archiveFixture(t)
	want := lstat(t, base, "tree/one.txt").ModTime()

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	for _, name := range []string{"tree/", "tree/one.txt", "tree/sub/", "tree/sub/two.jpg", "tree/sub/deep/"} {
		if m[name] == nil {
			t.Fatalf("%q is missing; members are %v", name, memberNames(m))
		}
	}
	if got := zipContent(t, m["tree/one.txt"]); got != "one" {
		t.Errorf("content = %q", got)
	}
	if !m["tree/"].FileInfo().IsDir() {
		t.Error("a directory member must read back as a directory")
	}
	if m["tree/one.txt"].Method != zip.Deflate {
		t.Errorf("a .txt must be deflated, got method %d", m["tree/one.txt"].Method)
	}
	if m["tree/sub/two.jpg"].Method != zip.Store {
		t.Errorf("a .jpg is already compressed and must be stored, got method %d", m["tree/sub/two.jpg"].Method)
	}
	// Zip times have a two-second granularity, which is the format's and not
	// this code's.
	if diff := m["tree/one.txt"].Modified.Sub(want); diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("mtime = %v, want %v", m["tree/one.txt"].Modified, want)
	}
	if m["ERROR.txt"] != nil {
		t.Errorf("a clean archive has no ERROR.txt: %s", zipContent(t, m["ERROR.txt"]))
	}
}

func memberNames(m map[string]*zip.File) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestArchiveTgzRoundTrips is the same for tar.gz, where the member's declared
// size is a promise the stream has to keep.
func TestArchiveTgzRoundTrips(t *testing.T) {
	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveTGZ, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	heads, bodies := tarMembers(t, s.buf.Bytes())
	for _, name := range []string{"tree/", "tree/one.txt", "tree/sub/", "tree/sub/two.jpg", "tree/sub/deep/"} {
		if heads[name] == nil {
			t.Fatalf("%q is missing; members are %v", name, headerNames(heads))
		}
	}
	if bodies["tree/one.txt"] != "one" {
		t.Errorf("content = %q", bodies["tree/one.txt"])
	}
	if heads["tree/"].Typeflag != tar.TypeDir {
		t.Errorf("a directory member must be TypeDir, got %q", heads["tree/"].Typeflag)
	}
	if heads["tree/one.txt"].Size != 3 {
		t.Errorf("size = %d", heads["tree/one.txt"].Size)
	}
}

func headerNames(m map[string]*tar.Header) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestArchiveOfASingleFile: a selected file is one member named after itself,
// with no directory above it.
func TestArchiveOfASingleFile(t *testing.T) {
	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if len(m) != 1 || m["one.txt"] == nil {
		t.Fatalf("members = %v", memberNames(m))
	}
	if got := zipContent(t, m["one.txt"]); got != "one" {
		t.Errorf("content = %q", got)
	}
}

// TestArchiveDisambiguatesTwoRootsWithOneName: two selected items called
// "one.txt" must both be extractable, or the archive has silently lost one.
func TestArchiveDisambiguatesTwoRootsWithOneName(t *testing.T) {
	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/other/one.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["one.txt"] == nil || m["one (2).txt"] == nil {
		t.Fatalf("members = %v", memberNames(m))
	}
	if zipContent(t, m["one.txt"]) == zipContent(t, m["one (2).txt"]) {
		t.Error("the two members must hold the two different files")
	}
}

// TestArchiveNotesARootThatVanishedAndKeepsTheTrailer: a per-item refusal is a
// line in ERROR.txt and the archive is still complete.
//
// The root is removed BETWEEN roots rather than being missing from the start,
// because a root that was never there is refused by ArchiveCheck before the
// reply and never reaches the producer at all (round 13). What the producer
// meets is a selection that was whole when it was authorized and is not any
// more, which is exactly this.
func TestArchiveNotesARootThatVanishedAndKeepsTheTrailer(t *testing.T) {
	r, base := archiveFixture(t)
	write(t, base, "tree/gone.txt", "here when it was checked")
	betweenRoots(t, 1, func() { _ = os.Remove(baseJoin(base, "tree/gone.txt")) })

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/tree/gone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["one.txt"] == nil {
		t.Fatalf("the readable half was lost: %v", memberNames(m))
	}
	if m["ERROR.txt"] == nil {
		t.Fatalf("a per-item failure must be recorded: %v", memberNames(m))
	}
	if body := zipContent(t, m["ERROR.txt"]); !strings.Contains(body, "gone.txt") {
		t.Errorf("ERROR.txt does not name what failed: %q", body)
	}
}

// TestArchiveCancellationTruncatesWithoutATrailer is design §2.11: what stops
// mid-stream must not produce a well-formed archive, because a well-formed
// archive that quietly lacks half the files is the one failure this feature
// must not have. ERROR.txt is written best-effort first, and the central
// directory is not.
func TestArchiveCancellationTruncatesWithoutATrailer(t *testing.T) {
	r, _ := archiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := &sink{}
	res, err := Archive(ctx, r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !res.Truncated || res.Reason == "" {
		t.Fatalf("a cancelled archive must report itself truncated: %+v", res)
	}
	if s.closed {
		t.Error("Archive must not close the write end; its caller does, after recording the outcome")
	}
	b := s.buf.Bytes()
	if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
		t.Fatal("a cancelled archive must not read back as a complete zip")
	}
	if !bytes.Contains(b, []byte(archiveNotesName)) {
		t.Errorf("the truncated stream must still carry an %s member", archiveNotesName)
	}
}

// TestArchiveWriteFailureIsFatalAndUntrailered: a stream that breaks for a
// reason that is not the reader leaving ends the same way.
func TestArchiveWriteFailureIsFatalAndUntrailered(t *testing.T) {
	r, _ := archiveFixture(t)
	s := &sink{after: 0, err: fmt.Errorf("the disk holding the socket buffer: %w", syscall.EIO)}
	res, err := Archive(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s)
	if err == nil {
		t.Fatal("a broken stream must be reported to the worker's log")
	}
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want the write failure", err)
	}
	if !res.Truncated || res.Reason == "" {
		t.Fatalf("a failed archive must report itself truncated: %+v", res)
	}
	b := s.buf.Bytes()
	if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
		t.Fatal("a failed archive must not read back as a complete zip")
	}
}

// TestArchiveEPIPEEndsQuietly: the browser cancelled the download. There is
// nobody to report to and nothing was lost.
func TestArchiveEPIPEEndsQuietly(t *testing.T) {
	r, _ := archiveFixture(t)
	for _, e := range []error{syscall.EPIPE, io.ErrClosedPipe, os.ErrClosed, syscall.ECONNRESET} {
		s := &sink{after: 0, err: fmt.Errorf("writing: %w", e)}
		if res, err := Archive(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s); err != nil || !res.Truncated {
			t.Errorf("a reader that went away (%v) must end the walk quietly, got %v", e, err)
		}
	}
}

// TestArchiveDoesNotCrossAMountWithoutTheFlag. The descriptor identity is
// faked, because mounting anything needs root; the CI root and ZFS jobs archive
// a real dataset.
func TestArchiveDoesNotCrossAMountWithoutTheFlag(t *testing.T) {
	r, base := archiveFixture(t)
	mkdir(t, base, "tree/mounted")
	write(t, base, "tree/mounted/inside.txt", "x")
	fakeIdentities(t, map[string]uint64{"mounted": 7})

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/mounted/"] == nil {
		t.Fatalf("decision 9 visits a mount point as an item: %v", memberNames(m))
	}
	if m["tree/mounted/inside.txt"] != nil {
		t.Fatalf("the walk crossed a mount it was not told to: %v", memberNames(m))
	}
}

// TestArchiveNameNamesTheDownload is §2.1's helper, clock and all.
func TestArchiveNameNamesTheDownload(t *testing.T) {
	prev := archiveClock
	archiveClock = func() time.Time { return time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { archiveClock = prev })

	cases := []struct {
		paths  []string
		format string
		want   string
	}{
		{[]string{"/share/Public/Photos"}, ArchiveZip, "Photos.zip"},
		{[]string{"/share/Public/Photos"}, ArchiveTGZ, "Photos.tar.gz"},
		{[]string{"/a/x", "/b/y"}, ArchiveZip, "archive-2026-09-13.zip"},
		{[]string{"/a/x", "/b/y"}, ArchiveTGZ, "archive-2026-09-13.tar.gz"},
		// A name a Content-Disposition header could not carry is not used.
		{[]string{"/a/we\"ird"}, ArchiveZip, "archive-2026-09-13.zip"},
		{[]string{"/a/new\nline"}, ArchiveZip, "archive-2026-09-13.zip"},
		{[]string{"/"}, ArchiveZip, "archive-2026-09-13.zip"},
	}
	for _, c := range cases {
		if got := ArchiveName(c.paths, c.format); got != c.want {
			t.Errorf("ArchiveName(%v, %q) = %q, want %q", c.paths, c.format, got, c.want)
		}
	}
}

// TestArchiveCheckRefusesBeforeThePipe is the ordering §2.2 fixes: everything
// that could be an honest error frame is decided before the reply, because
// after it the only way left to say "that failed" is to truncate.
func TestArchiveCheckRefusesBeforeThePipe(t *testing.T) {
	r, _ := archiveFixture(t)
	ctx := context.Background()

	if _, err := ArchiveCheck(ctx, r, nil, archiveReq("rar", "/tree")); fsx.Code(err) != "bad_request" {
		t.Errorf("an unknown format = %v", err)
	}
	if _, err := ArchiveCheck(ctx, r, nil, archiveReq(ArchiveZip)); fsx.Code(err) != "bad_request" {
		t.Errorf("no paths = %v", err)
	}
	if _, err := ArchiveCheck(ctx, r, nil, archiveReq(ArchiveZip, "/tree/gone")); fsx.Code(err) != "not_found" {
		t.Errorf("a missing root = %v, want not_found", err)
	}
	many := archiveReq(ArchiveZip)
	for i := 0; i <= maxArchiveRoots; i++ {
		many.Paths = append(many.Paths, []byte("/tree"))
	}
	if _, err := ArchiveCheck(ctx, r, nil, many); fsx.Code(err) != "bad_request" {
		t.Errorf("too many roots = %v", err)
	}
	plan, err := ArchiveCheck(ctx, r, nil, archiveReq(ArchiveZip, "/tree"))
	if err != nil || string(plan.Name) != "tree.zip" {
		t.Fatalf("ArchiveCheck = %+v, %v", plan, err)
	}
	// And it records what it proved, which is what the producer compares
	// against later (round 13).
	if len(plan.roots) != 1 {
		t.Fatalf("the plan holds %d roots, want 1", len(plan.roots))
	}
	root := plan.roots[0]
	if root.api != "/tree" || root.rel == "" {
		t.Errorf("root = %+v", root)
	}
	if inodeIdentity && (!root.id.have || !root.parentID.have) {
		t.Errorf("the identities the producer compares against were not recorded: %+v", root)
	}
}

// TestArchiveShortFileIsPaddedAndNoted: a tar member's header promises a
// length, and a file that turned out shorter must not break the stream for
// everything after it. The truth goes into ERROR.txt.
func TestArchiveShortFileIsPaddedAndNoted(t *testing.T) {
	r, base := archiveFixture(t)
	// A file whose stat says eight bytes and whose reader stops at three is
	// what a file being truncated underneath the walk looks like. It is staged
	// by making the file sparse-large and then truncating it between the walk's
	// stat and the read — which no test can time — so the same shape is reached
	// through the member writer instead: the padding is asserted directly.
	if err := os.WriteFile(baseJoin(base, "tree/short.bin"), []byte("12345678"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := runArchive(t, r, archiveReq(ArchiveTGZ, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	heads, bodies := tarMembers(t, s.buf.Bytes())
	if heads["tree/short.bin"].Size != 8 || bodies["tree/short.bin"] != "12345678" {
		t.Fatalf("header/body = %d/%q", heads["tree/short.bin"].Size, bodies["tree/short.bin"])
	}

	// The padding itself, which only a sink can observe: a member declared
	// longer than its content still leaves a readable tar.
	var out bytes.Buffer
	sink, err := newArchiveSink(ArchiveTGZ, &out)
	if err != nil {
		t.Fatal(err)
	}
	fi := lstat(t, base, "tree/short.bin")
	w, err := sink.addFile("p.bin", fi, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("123")); err != nil {
		t.Fatal(err)
	}
	if err := sink.padFile(5); err != nil {
		t.Fatal(err)
	}
	if err := sink.finish(); err != nil {
		t.Fatal(err)
	}
	_, padded := tarMembers(t, out.Bytes())
	if got := padded["p.bin"]; got != "123\x00\x00\x00\x00\x00" {
		t.Fatalf("the short member was not padded to its declared length: %q", got)
	}
}

// baseJoin is filepath.Join for a slash-spelled relative path, so a test can
// write a file the fixture helpers do not cover.
func baseJoin(base, rel string) string {
	return base + string(os.PathSeparator) + strings.ReplaceAll(rel, "/", string(os.PathSeparator))
}

// TestArchiveNotesNeverOverwriteAMemberOfTheirOwnName is M2-C review round 1,
// finding 3. A user may perfectly well select a file called ERROR.txt, and two
// members of one name is an archive whose extraction replaces one with the
// other. The diagnostic is allocated LAST through the same collision-free
// allocator the roots use, so the USER's file keeps its name.
func TestArchiveNotesNeverOverwriteAMemberOfTheirOwnName(t *testing.T) {
	r, base := archiveFixture(t)
	write(t, base, "ERROR.txt", "the user's own file")
	write(t, base, "tree/gone.txt", "here when it was checked")

	// The second root vanishes between roots, which is what produces notes at
	// all — and it has to vanish AFTER the check, because a root that was never
	// there never reaches the producer (round 13).
	betweenRoots(t, 1, func() { _ = os.Remove(baseJoin(base, "tree/gone.txt")) })
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/ERROR.txt", "/tree/gone.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["ERROR.txt"] == nil || m["ERROR (2).txt"] == nil {
		t.Fatalf("members = %v; want the user's file and a renamed diagnostic", memberNames(m))
	}
	if got := zipContent(t, m["ERROR.txt"]); got != "the user's own file" {
		t.Fatalf("the user's file was replaced by the diagnostic: %q", got)
	}
	if got := zipContent(t, m["ERROR (2).txt"]); !strings.Contains(got, "gone.txt") {
		t.Errorf("the diagnostic did not land: %q", got)
	}
	// One member per name, which is what makes the archive extractable.
	zr, zerr := zip.NewReader(bytes.NewReader(s.buf.Bytes()), int64(s.buf.Len()))
	if zerr != nil {
		t.Fatal(zerr)
	}
	seen := map[string]int{}
	for _, f := range zr.File {
		seen[f.Name]++
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("%q appears %d times", name, n)
		}
	}
}

// TestArchiveRefusesAnUnknownFormatWithoutWriting keeps the sink honest: a
// format nothing can write must not produce a closed, empty, "valid" download.
func TestArchiveRefusesAnUnknownFormat(t *testing.T) {
	r, _ := archiveFixture(t)
	s := &sink{}
	_, err := Archive(context.Background(), r, nil, archiveReq("rar", "/tree"), nil, s)
	if fsx.Code(err) != "bad_request" {
		t.Fatalf("err = %v", err)
	}
	if s.buf.Len() != 0 {
		t.Errorf("%d bytes were written for a format nothing can write", s.buf.Len())
	}
	if s.closed {
		t.Error("Archive must not close the write end even for a format it cannot write")
	}
}

// TestArchiveSkipsNothingItCanRead is a guard against a silent regression in
// the walk options: ".zfs" is the only thing an archive refuses to enter, and
// "@Recycle" — which a WRITING walk refuses — is ordinary content here.
func TestArchiveEntersRecycleButNotSnapshots(t *testing.T) {
	r, base := archiveFixture(t)
	mkdir(t, base, "tree/@Recycle")
	mkdir(t, base, "tree/.zfs/snapshot")
	write(t, base, "tree/@Recycle/bin.txt", "r")
	write(t, base, "tree/.zfs/snapshot/old.txt", "s")

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/@Recycle/bin.txt"] == nil {
		t.Errorf("@Recycle is ordinary content for a read-only walk: %v", memberNames(m))
	}
	if m["tree/.zfs/"] != nil || m["tree/.zfs/snapshot/old.txt"] != nil {
		t.Errorf("a snapshot directory must never be archived: %v", memberNames(m))
	}
}

var _ = fs.ErrNotExist // the fs import is used by the linux half of these tests

// mustPlan is ArchiveCheck for the tests that call Archive directly, so the
// identities every root is proved against are recorded the way production
// records them (round 13).
func mustPlan(t *testing.T, r fsx.Root, plat *platform.Platform, req wproto.ArchiveReq) *ArchivePlan {
	t.Helper()
	plan, err := ArchiveCheck(context.Background(), r, plat, req)
	if err != nil {
		t.Fatalf("ArchiveCheck: %v", err)
	}
	return plan
}

// betweenRoots runs f in the window the producer really has: after it has
// finished one root and before it opens the next. Nothing else can stage the
// round-13 race, because that window is between two syscall sequences inside
// another goroutine.
func betweenRoots(t *testing.T, at int, f func()) {
	t.Helper()
	prev := archiveBetweenRoots
	archiveBetweenRoots = func(i int) {
		if i == at {
			f()
		}
	}
	t.Cleanup(func() { archiveBetweenRoots = prev })
}
