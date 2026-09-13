package fsops

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The findings of M2-C review round 1's adversarial pass that live in this
// package: the archive's item bound, the root exclusions, the search deadline
// and the name allocator.

// TestArchiveStopsAtItsItemBoundAndSaysSo is adversarial finding 1. The zip
// central directory keeps one header per member in memory until Close, so an
// archive of a four-million-file share would take a 1 GB NAS with it. Past the
// bound the archive ends TRUNCATED — no trailer — which is what makes the
// client's unzip report a damaged file instead of a complete one that quietly
// holds a fraction of the tree.
func TestArchiveStopsAtItsItemBoundAndSaysSo(t *testing.T) {
	prev := archiveMemberCap
	archiveMemberCap = 3
	t.Cleanup(func() { archiveMemberCap = prev })

	r, _ := archiveFixture(t)
	s := &sink{}
	res, err := Archive(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s)
	if err == nil {
		t.Fatal("reaching the item bound must be reported to the worker's log")
	}
	if !res.Truncated {
		t.Fatalf("res = %+v, want a truncated archive", res)
	}
	b := s.buf.Bytes()
	if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
		t.Fatal("an archive that hit its bound must not read back as a complete zip")
	}
	if !bytes.Contains(b, []byte(archiveNotesName)) {
		t.Fatalf("the truncated stream must carry an %s member", archiveNotesName)
	}
	if !bytes.Contains(b, []byte("stopped after")) {
		t.Error("the notes must say why the archive stopped")
	}
}

// TestArchiveWithinItsBoundKeepsTheTrailer keeps the bound from being a bound
// on everything: an ordinary archive is still complete.
func TestArchiveWithinItsBoundKeepsTheTrailer(t *testing.T) {
	prev := archiveMemberCap
	archiveMemberCap = 1000
	t.Cleanup(func() { archiveMemberCap = prev })

	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/one.txt"] == nil || m["ERROR.txt"] != nil {
		t.Fatalf("members = %v", memberNames(m))
	}
}

// TestArchiveBoundAppliesToTarToo: one rule for both formats. Tar has no
// in-memory table and needs none, but "an archive stops at N items" is a
// sentence a user can be told, and a limit that depended on the format they
// picked is one they would meet by accident.
func TestArchiveBoundAppliesToTarToo(t *testing.T) {
	prev := archiveMemberCap
	archiveMemberCap = 2
	t.Cleanup(func() { archiveMemberCap = prev })

	r, _ := archiveFixture(t)
	s := &sink{}
	res, _ := Archive(context.Background(), r, nil, archiveReq(ArchiveTGZ, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveTGZ, "/tree")), s)
	if !res.Truncated {
		t.Fatalf("res = %+v, want a truncated archive", res)
	}
}

// TestArchiveStopsAtItsMetadataBudget is round 2 adversarial finding 1: the
// item count alone does not bound the memory archive/zip retains, because what
// it keeps per member is a header plus the member's NAME — and a Linux path may
// be four kilobytes. Names long enough, few enough to pass the item bound, and
// the budget is what stops it.
func TestArchiveStopsAtItsMetadataBudget(t *testing.T) {
	prevMembers, prevMeta := archiveMemberCap, archiveMetadataCap
	archiveMemberCap = 1_000_000 // out of the way: the BYTES must be what stops it
	archiveMetadataCap = 2 * (archiveHeaderOverhead + 64)
	t.Cleanup(func() { archiveMemberCap, archiveMetadataCap = prevMembers, prevMeta })

	r, _ := archiveFixture(t)
	s := &sink{}
	res, err := Archive(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s)
	if err == nil {
		t.Fatal("reaching the metadata budget must be reported to the worker's log")
	}
	if !res.Truncated {
		t.Fatalf("res = %+v, want a truncated archive", res)
	}
	if !strings.Contains(res.Reason, "names alone") {
		t.Errorf("the reason must name the bound that was hit: %q", res.Reason)
	}
	b := s.buf.Bytes()
	if _, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b))); zerr == nil {
		t.Fatal("an archive that hit its budget must not read back as a complete zip")
	}
	if !bytes.Contains(b, []byte(archiveNotesName)) {
		t.Errorf("the truncated stream must carry an %s member", archiveNotesName)
	}
}

// TestArchiveMetadataBudgetCountsTheNameLength keeps the budget honest about
// what it is measuring: the same number of members costs more when their names
// are longer, which is the whole point.
func TestArchiveMetadataBudgetCountsTheNameLength(t *testing.T) {
	a := &archiver{used: map[string]bool{}}
	if !a.room("x") {
		t.Fatal("the first member must fit")
	}
	short := a.metaBytes
	if !a.room(strings.Repeat("y", 4000)) {
		t.Fatal("the second member must fit")
	}
	if a.metaBytes-short <= short {
		t.Fatalf("a 4000-byte name cost %d and a one-byte name cost %d", a.metaBytes-short, short)
	}
}

// TestReserveNeverHandsOutATakenName is adversarial finding 7. The copy
// engine's keep-both search is bounded and can refuse the entry; an archive
// that gave up and returned a name already in use would write a SECOND member
// at that path, and extracting it would replace one of the two files with the
// other, silently.
func TestReserveNeverHandsOutATakenName(t *testing.T) {
	a := &archiver{used: map[string]bool{}}
	seen := map[string]bool{}
	for i := 0; i < maxKeepBothTries+50; i++ {
		name := a.reserve("photos.zip", false)
		if seen[name] {
			t.Fatalf("reserve handed out %q twice (iteration %d)", name, i)
		}
		seen[name] = true
	}
	if len(seen) != maxKeepBothTries+50 {
		t.Fatalf("%d distinct names for %d roots", len(seen), maxKeepBothTries+50)
	}
}

// TestKeepBothNamesStayWithinTheComponentLimit is round 7 adversarial. " (2)"
// is four bytes, a component may already be all 255 of them, and appending
// regardless produced a name no Linux filesystem will take — discovered by the
// upload's linkat after the whole body had gone, and by the user's unzip for an
// archive, which creates nothing and so is told nothing.
func TestKeepBothNamesStayWithinTheComponentLimit(t *testing.T) {
	long := strings.Repeat("a", maxNameBytes)
	longStem := strings.Repeat("b", maxNameBytes-4) + ".txt" // 255 with an extension

	cases := []struct {
		name    string
		isDir   bool
		n       int
		wantOK  bool
		wantExt string
	}{
		{"report.txt", false, 2, true, ".txt"},
		{long, false, 2, true, ""},
		{long, true, 2, true, ""},
		{longStem, false, 2, true, ".txt"},
		{longStem, false, 100, true, ".txt"},
		// An extension that leaves no room for even the shortest suffix plus
		// one byte of stem.
		{"x." + strings.Repeat("e", maxNameBytes-2), false, 2, false, ""},
	}
	for _, c := range cases {
		got, ok := keepBothWithin(c.name, c.isDir, c.n)
		if ok != c.wantOK {
			t.Errorf("keepBothWithin(%d bytes, n=%d) ok = %v, want %v", len(c.name), c.n, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if len(got) > maxNameBytes {
			t.Errorf("keepBothWithin produced %d bytes: %q", len(got), got)
		}
		if c.wantExt != "" && !strings.HasSuffix(got, c.wantExt) {
			t.Errorf("the extension was lost: %q", got)
		}
		if !strings.Contains(got, fmt.Sprintf("(%d)", c.n)) {
			t.Errorf("the candidate does not carry its number: %q", got)
		}
		if !utf8.ValidString(c.name) || utf8.ValidString(got) {
			continue
		}
		t.Errorf("a valid name was truncated into an invalid one: %q", got)
	}

	// Every attempt produces a DIFFERENT name, shortened or not — otherwise the
	// keep-both loop would try the same candidate a hundred times.
	seen := map[string]bool{}
	for n := 2; n < 2+maxKeepBothTries; n++ {
		got, ok := keepBothWithin(long, false, n)
		if !ok {
			t.Fatalf("n=%d produced no candidate", n)
		}
		if seen[got] {
			t.Fatalf("n=%d repeated a candidate: %q", n, got)
		}
		seen[got] = true
	}
}

// TestKeepBothShorteningKeepsRunesWhole: a name is shortened on a rune
// boundary, because half a rune renders as U+FFFD and turns a shortened name
// into an unreadable one.
func TestKeepBothShorteningKeepsRunesWhole(t *testing.T) {
	// Three-byte runes, so a byte-wise cut at 251 would land inside one.
	name := strings.Repeat("あ", 85) // 255 bytes
	if len(name) != maxNameBytes {
		t.Fatalf("the fixture is %d bytes, not %d", len(name), maxNameBytes)
	}
	got, ok := keepBothWithin(name, false, 2)
	if !ok {
		t.Fatal("a 255-byte name of whole runes must still take a suffix")
	}
	if len(got) > maxNameBytes {
		t.Fatalf("%d bytes: %q", len(got), got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("the shortened name is not valid UTF-8: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("the shortening split a rune: %q", got)
	}
}

// TestSearchRefusesAProtectedRoot is adversarial finding 4: the walker checks
// the never-read components of CHILDREN, so a job rooted at the component
// itself was never shown it.
func TestSearchRefusesAProtectedRoot(t *testing.T) {
	r, base := searchFixture(t)
	mkdir(t, base, "tree/.zfs/snapshot")
	write(t, base, "tree/.zfs/snapshot/old.txt", "report")

	ctx := context.Background()
	for _, root := range []string{"/tree/.zfs", "/tree/.zfs/snapshot"} {
		_, err := Search(ctx, r, nil, searchReq("report", root), Emit{})
		if fsx.Code(err) != "protected" {
			t.Errorf("Search(%q) = %v (code %q), want protected", root, err, fsx.Code(err))
		}
	}
	// And the ordinary root still works, with the snapshot tree skipped.
	res, err := Search(ctx, r, nil, searchReq("report", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if hasName(res, "old.txt") {
		t.Errorf("a snapshot entry was searched: %v", hitNames(res))
	}
}

// TestArchiveRefusesAProtectedRoot is the same rule for the archive, and it is
// refused BEFORE the reply: ArchiveCheck runs on this side of the pipe, so a
// selection holding a snapshot directory is an honest error frame rather than a
// download that turns out to be missing something (round 2, sharpened by round
// 13's plan — the producer never resolves a root the check did not clear).
func TestArchiveRefusesAProtectedRoot(t *testing.T) {
	r, base := archiveFixture(t)
	mkdir(t, base, "tree/.zfs/snapshot")
	write(t, base, "tree/.zfs/snapshot/old.txt", "x")
	ctx := context.Background()

	for _, sel := range [][]string{
		{"/tree/.zfs"},
		{"/tree/.zfs", "/tree/one.txt"},
		{"/tree/one.txt", "/tree/.zfs/snapshot"},
	} {
		_, err := ArchiveCheck(ctx, r, nil, archiveReq(ArchiveZip, sel...))
		if fsx.Code(err) != "protected" {
			t.Errorf("ArchiveCheck(%v) = %v (code %q), want protected", sel, err, fsx.Code(err))
		}
	}
	// And the ordinary selection still archives, with the snapshot tree skipped
	// by the walk rather than by the root check.
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/.zfs/"] != nil || m["tree/.zfs/snapshot/old.txt"] != nil {
		t.Fatalf("a snapshot directory was archived: %v", memberNames(m))
	}
	if m["tree/one.txt"] == nil {
		t.Fatalf("the rest of the tree was lost: %v", memberNames(m))
	}
}

// TestRootOnAKernelFilesystemIsRefused is the other half of finding 4: the
// walker refuses to CROSS into /proc, and a job rooted directly at it was
// crossing nothing.
//
// The table is synthetic because the test cannot mount a procfs, and the
// classification is the only thing under test: /share is a tmpfs on the golden
// QTS table and must NOT be refused, or the rule would refuse the folder every
// share hangs off.
func TestRootOnAKernelFilesystemIsRefused(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/proc")
	mkdir(t, base, "tree/remote")
	mkdir(t, base, "tree/ram")
	write(t, base, "tree/ram/report.txt", "x")
	// An UNJAILED root, because the mount table describes the host and the
	// classification under test is a lookup by OS path.
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/tree/proc", fsType: "proc", dev: "0:16", source: "proc"},
		synthMount{mountPoint: api + "/tree/remote", fsType: "nfs4", dev: "0:45", source: "server:/export"},
		synthMount{mountPoint: api + "/tree/ram", fsType: "tmpfs", dev: "0:23", source: "tmpfs"},
	)

	ctx := context.Background()
	for _, root := range []string{api + "/tree/proc", api + "/tree/remote"} {
		_, err := Search(ctx, r, plat, searchReq("report", root), Emit{})
		if fsx.Code(err) != "protected" {
			t.Errorf("Search(%q) = %v (code %q), want protected", root, err, fsx.Code(err))
		}
	}
	// A tmpfs is NOT refused: /share is one on the golden QTS table, and it is
	// the folder every share hangs off.
	res, err := Search(ctx, r, plat, searchReq("report", api+"/tree/ram"), Emit{})
	if err != nil {
		t.Fatalf("a tmpfs root must be searchable: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Errorf("hits = %v", hitNames(res))
	}

	// The archive makes the same refusals, and ArchiveCheck makes them on THIS
	// side of the reply so they are honest error frames.
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, api+"/tree/remote")); fsx.Code(aerr) != "protected" {
		t.Errorf("ArchiveCheck of a network root = %v, want protected", aerr)
	}
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, api+"/tree/ram")); aerr != nil {
		t.Errorf("ArchiveCheck of a tmpfs root = %v, want it allowed", aerr)
	}
}

// TestANetworkRootIsRefusedBeforeAnythingIsResolved is round 2 adversarial
// finding 2, and the property is WHERE the refusal happens rather than that it
// happens at all: a hard NFS mount whose server has gone parks the caller inside
// the first lstat, in uninterruptible sleep, and the request slot it holds is
// never given back.
//
// The mount table is asked about the requested spelling, which costs no syscall
// — so the seam is the resolver itself: if anything reached it, the refusal came
// too late.
func TestANetworkRootIsRefusedBeforeAnythingIsResolved(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + "/tree/dead", fsType: "nfs4", dev: "0:45", source: "gone:/export"},
	)
	// The directory is deliberately NOT created: a refusal that got as far as
	// the filesystem would report not_found, and a refusal made from the table
	// alone reports protected. That is the difference this test is for.
	ctx := context.Background()

	_, err := Search(ctx, r, plat, searchReq("report", api+"/tree/dead/sub"), Emit{})
	if fsx.Code(err) != "protected" {
		t.Fatalf("Search inside a network mount = %v (code %q), want protected from the table alone",
			err, fsx.Code(err))
	}
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, api+"/tree/dead/sub")); fsx.Code(aerr) != "protected" {
		t.Fatalf("ArchiveCheck inside a network mount = %v (code %q), want protected", aerr, fsx.Code(aerr))
	}
}

// TestANetworkRootWithABackslashIsStillRefused is round 3 adversarial finding
// 1, and it is the same shape as the walker's own
// TestWalkRefusesAMountWhoseNameHasABackslash.
//
// A backslash is an ORDINARY CHARACTER in a Linux filename, and Platform.For
// normalises it into a separator and then Cleans the result — so a real NFS
// mount at `remote\backup` never matches its own row, and everything inside it
// walks straight past the refusal into the lstat that hangs. ForLiteral
// compares the bytes.
func TestANetworkRootWithABackslashIsStillRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a backslash is a separator here, so there is no such filename to refuse")
	}
	base := tempDir(t)
	mkdir(t, base, "tree")
	r, api := hostRoot(t, base)
	plat := synthPlatform(t,
		synthMount{mountPoint: api, fsType: "ext4", dev: "8:1"},
		synthMount{mountPoint: api + `/tree/remote\backup`, fsType: "nfs4", dev: "0:45", source: "gone:/export"},
	)
	ctx := context.Background()

	inside := api + `/tree/remote\backup/sub`
	_, err := Search(ctx, r, plat, searchReq("report", inside), Emit{})
	if fsx.Code(err) != "protected" {
		t.Fatalf("Search(%q) = %v (code %q), want protected", inside, err, fsx.Code(err))
	}
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, inside)); fsx.Code(aerr) != "protected" {
		t.Fatalf("ArchiveCheck(%q) = %v (code %q), want protected", inside, aerr, fsx.Code(aerr))
	}
	// And the mount point itself, not only what is under it.
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, api+`/tree/remote\backup`)); fsx.Code(aerr) != "protected" {
		t.Errorf("the mount point itself = %v, want protected", aerr)
	}
	// A neighbour that merely shares a prefix is NOT on that mount: the lookup
	// is boundary-aware, so `remote\backupX` is a different name.
	mkdir(t, base, `tree/remote\backupX`)
	if _, aerr := ArchiveCheck(ctx, r, plat, archiveReq(ArchiveZip, api+`/tree/remote\backupX`)); aerr != nil {
		t.Errorf("a name that only shares a prefix must not be refused: %v", aerr)
	}
}

// TestSearchStopsAtItsResultByteBudget is round 6 adversarial. A thousand is a
// bound on ROWS, and a row carries a path — up to four kilobytes of it, doubled
// by pathB64 for a non-UTF-8 name and again by JSON escaping. A thousand such
// rows do not fit in wproto.MaxFrame, and a terminal frame that cannot be
// encoded used to take the whole worker down with it.
func TestSearchStopsAtItsResultByteBudget(t *testing.T) {
	r, base := searchFixture(t)
	// Enough matching names that the budget, not the hit count, is what stops
	// it: the cap below is a couple of entries' worth.
	for i := 0; i < 12; i++ {
		write(t, base, fmt.Sprintf("tree/report-big-%02d.txt", i), "x")
	}
	prev := searchResultBytesCap
	searchResultBytesCap = 3 * (searchHitOverhead / 2) // a handful of small hits
	t.Cleanup(func() { searchResultBytesCap = prev })

	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) == 0 {
		t.Fatal("the budget must truncate, not empty, the results")
	}
	if len(res.Hits) >= 12 {
		t.Fatalf("%d hits came back; the byte budget did not bound them", len(res.Hits))
	}
	if !strings.Contains(res.Detail, "results too large") {
		t.Fatalf("Detail = %q, want the byte bound named", res.Detail)
	}
	if !strings.HasPrefix(res.Detail, fmt.Sprintf("first %d of many", len(res.Hits))) {
		t.Errorf("Detail = %q, want it to agree with the %d hits it carries", res.Detail, len(res.Hits))
	}
	// The truncated result must be what it says it is: small enough to send.
	encoded, merr := json.Marshal(res)
	if merr != nil {
		t.Fatal(merr)
	}
	if int64(len(encoded)) > searchResultBytesCap*4 {
		t.Errorf("the truncated result still encodes to %d bytes against a %d budget", len(encoded), searchResultBytesCap)
	}
}

// TestSearchHitCostIsTheEncodedLength is the accounting itself: what is charged
// has to be what the frame will actually carry, or the budget bounds the wrong
// number.
func TestSearchHitCostIsTheEncodedLength(t *testing.T) {
	small := fsx.Entry{Name: "a.txt", Path: "/a.txt", Type: "file", Mode: "0644"}
	big := small
	big.Path = "/" + strings.Repeat("x", 4000) + "/a.txt"

	sc, bc := hitCost(small), hitCost(big)
	if sc <= 0 || bc <= sc {
		t.Fatalf("costs = %d and %d; a longer path must cost more", sc, bc)
	}
	b, err := json.Marshal(small)
	if err != nil {
		t.Fatal(err)
	}
	if sc < int64(len(b)) {
		t.Fatalf("cost %d is less than the %d bytes it encodes to", sc, len(b))
	}
	if bc < int64(len(big.Path)) {
		t.Fatalf("cost %d does not even cover the path it carries", bc)
	}
}

// TestSearchResultFitsInAFrame is the property the budget exists for, stated
// against the real constant rather than against the seam: a full result at the
// maxima must encode to less than wproto.MaxFrame with room to spare for the
// warnings and the envelope that share the frame.
func TestSearchResultFitsInAFrame(t *testing.T) {
	// The worst legal shape: every hit at the byte budget's own limit.
	if maxSearchResultBytes >= wproto.MaxFrame {
		t.Fatalf("the result budget (%d) must be well under the frame cap (%d)", maxSearchResultBytes, wproto.MaxFrame)
	}
	// Warnings share the frame: a hundred of them, each with a path and a
	// message, plus the envelope. A tenth of the frame is ample room.
	if maxSearchResultBytes > wproto.MaxFrame/2 {
		t.Fatalf("the result budget (%d) leaves too little of the %d byte frame for the warnings beside it",
			maxSearchResultBytes, wproto.MaxFrame)
	}
}

// TestSearchDeadlineBoundsTheWalkItself is adversarial finding 5. The visited
// counter is only read when an entry is VISITED, and a directory whose children
// all fail their lstat visits none: every failure goes through Warn. A context
// bounds every syscall path the walk takes, including that one.
func TestSearchDeadlineBoundsTheWalkItself(t *testing.T) {
	r, _ := searchFixture(t)

	prev := searchTimeout
	searchTimeout = func(ctx context.Context, seconds int64) (context.Context, context.CancelFunc) {
		// A deadline that has already passed: the walk's very first context
		// check ends it, which is the shape of a walk that spent sixty seconds
		// producing nothing but warnings.
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c, cancel
	}
	t.Cleanup(func() { searchTimeout = prev })

	req := searchReq("report", "/tree")
	req.MaxDuration = 60
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatalf("the walk's own deadline is a truncation, not a failure: %v", err)
	}
	if res.Detail != "stopped after 60 s" {
		t.Fatalf("Detail = %q, want the duration bound", res.Detail)
	}
}

// TestSearchCallerCancellationIsStillCancellation keeps the previous test
// honest: the caller giving up must not be reported as a bound being reached.
func TestSearchCallerCancellationIsStillCancellation(t *testing.T) {
	r, _ := searchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := searchReq("report", "/tree")
	req.MaxDuration = 60
	_, err := Search(ctx, r, nil, req, Emit{})
	if err == nil {
		t.Fatal("a cancelled caller must not be reported as a truncation")
	}
	if fsx.Code(err) != "cancelled" {
		t.Fatalf("err = %v (code %q), want cancelled", err, fsx.Code(err))
	}
}

// TestSearchReportsTheBoundItWasGiven: the reason names the cap that was
// applied rather than the maximum, so a route that sends thirty seconds does
// not produce a message about sixty.
func TestSearchReportsTheBoundItWasGiven(t *testing.T) {
	r, _ := searchFixture(t)
	prev := searchTimeout
	searchTimeout = func(ctx context.Context, seconds int64) (context.Context, context.CancelFunc) {
		if seconds != 30 {
			t.Errorf("the walk was bounded by %d s, want 30", seconds)
		}
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c, cancel
	}
	t.Cleanup(func() { searchTimeout = prev })

	req := searchReq("report", "/tree")
	req.MaxDuration = 30
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "stopped after 30 s" {
		t.Fatalf("Detail = %q", res.Detail)
	}
}

// TestArchiveResultReportsACleanRun keeps the outcome record honest in the
// direction that matters most: a complete archive must never be reported as
// truncated, or every audit line would say so.
func TestArchiveResultReportsACleanRun(t *testing.T) {
	r, _ := archiveFixture(t)
	s := &sink{}
	res, err := Archive(context.Background(), r, nil, archiveReq(ArchiveZip, "/tree"), mustPlan(t, r, nil, archiveReq(ArchiveZip, "/tree")), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || res.Reason != "" {
		t.Fatalf("res = %+v, want a complete archive", res)
	}
	if res.Bytes != int64(s.buf.Len()) {
		t.Errorf("Bytes = %d, want %d", res.Bytes, s.buf.Len())
	}
}

// TestSameInodeComparesBirthTime is round 14 adversarial's third finding at the
// wire's own level: an inode number is freed with its object and may be handed
// straight back, so a client that controls the gap can loop until the number
// repeats. Birth time is set once at creation and nothing changes it.
func TestSameInodeComparesBirthTime(t *testing.T) {
	base := wproto.FSIdentityResp{Dev: 7, Ino: 42, Btime: 1000, HasBtime: true}

	same := base
	if !base.SameInode(same) {
		t.Fatal("one object must equal itself")
	}
	recycled := base
	recycled.Btime = 2000
	if base.SameInode(recycled) {
		t.Fatal("a recycled inode number with a later birth time is a different object")
	}
	// A filesystem that records no birth time degrades to device and inode,
	// which is what the comparison was before this existed.
	noBtime := wproto.FSIdentityResp{Dev: 7, Ino: 42}
	if !noBtime.SameInode(wproto.FSIdentityResp{Dev: 7, Ino: 42}) {
		t.Fatal("without birth times the comparison must still work")
	}
	if !base.SameInode(noBtime) || !noBtime.SameInode(base) {
		t.Fatal("one side without a birth time must not turn into a refusal")
	}
	// And the old rules still hold.
	if base.SameInode(wproto.FSIdentityResp{Dev: 8, Ino: 42, Btime: 1000, HasBtime: true}) {
		t.Error("a different device is a different object")
	}
	if base.SameInode(wproto.FSIdentityResp{Dev: 7, Ino: 0}) {
		t.Error("an inode nobody could read identifies nothing")
	}
}
