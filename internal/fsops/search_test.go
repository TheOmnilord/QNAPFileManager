package fsops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// The M2-C search's tests. The matching, the caps and the filters are the same
// on every platform — they are this package's own logic over a walk that already
// has its own tests — so they run everywhere; the one Linux-only test is the
// unreadable directory, which is the kernel's refusal and not a simulation of
// one (INV-2).

// searchFixture builds
//
//	/tree/Report.txt
//	/tree/report-2.md
//	/tree/.hidden/secret-report.txt
//	/tree/notes/REPORT.pdf
//	/tree/notes/other.txt
//	/tree/Reports/          (a directory whose name matches)
func searchFixture(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "tree/.hidden")
	mkdir(t, base, "tree/notes")
	mkdir(t, base, "tree/Reports")
	write(t, base, "tree/Report.txt", "a")
	write(t, base, "tree/report-2.md", "b")
	write(t, base, "tree/.hidden/secret-report.txt", "c")
	write(t, base, "tree/notes/REPORT.pdf", "d")
	write(t, base, "tree/notes/other.txt", "e")
	return newRoot(t, base), base
}

func searchReq(query string, roots ...string) wproto.SearchReq {
	req := wproto.SearchReq{Query: query}
	for _, r := range roots {
		req.Roots = append(req.Roots, []byte(r))
	}
	return req
}

func hitNames(res wproto.JobResult) []string {
	out := make([]string, 0, len(res.Hits))
	for _, h := range res.Hits {
		out = append(out, h.Name)
	}
	return out
}

func hasName(res wproto.JobResult, name string) bool {
	for _, h := range res.Hits {
		if h.Name == name {
			return true
		}
	}
	return false
}

// TestSearchMatchesTheNameCaseInsensitively is §3.1's default: a substring of
// the entry's NAME, folded. The directory whose name matches is a hit like any
// other, and the root itself never is — searching a folder means searching what
// is in it.
func TestSearchMatchesTheNameCaseInsensitively(t *testing.T) {
	r, _ := searchFixture(t)
	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Report.txt", "report-2.md", "REPORT.pdf", "Reports"} {
		if !hasName(res, want) {
			t.Errorf("%q is missing from %v", want, hitNames(res))
		}
	}
	if hasName(res, "other.txt") {
		t.Errorf("a non-matching name was returned: %v", hitNames(res))
	}
	if hasName(res, "secret-report.txt") {
		t.Errorf("a hidden entry was returned without Hidden: %v", hitNames(res))
	}
	if hasName(res, "tree") {
		t.Errorf("the root of the search is not a hit in its own search: %v", hitNames(res))
	}
	if res.Files == 0 {
		t.Error("Files must report how many entries were visited")
	}
	if res.Detail != "" {
		t.Errorf("nothing was capped, so Detail must be empty: %q", res.Detail)
	}
}

// TestSearchPathIsNotMatched pins that the query is tested against the name and
// never against the path: otherwise the answer would depend on where the search
// started rather than on what is in the tree.
func TestSearchPathIsNotMatched(t *testing.T) {
	r, _ := searchFixture(t)
	res, err := Search(context.Background(), r, nil, searchReq("notes", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hitNames(res); len(got) != 1 || got[0] != "notes" {
		t.Fatalf("hits = %v, want the directory itself and nothing under it", got)
	}
}

// TestSearchFoldingIsSimpleAndSaysSo is the documented rule, asserted rather
// than assumed: simple folding relates single runes to single runes, so "ß"
// matches "ẞ" and "Σ" matches "ς" — but "straße" does NOT match a query of
// "strasse", which is FULL folding and which Go's standard library does not
// implement. The behaviour is in the comment on foldContains; this is what
// holds it there.
func TestSearchFoldingIsSimpleAndSaysSo(t *testing.T) {
	cases := []struct {
		name, query string
		want        bool
	}{
		{"Report.txt", "report", true},
		{"report.txt", "REPORT", true},
		{"Straße.txt", "STRAßE", true},
		{"STRAẞE.txt", "straße", true},
		{"Straße.txt", "strasse", false},
		{"Strasse.txt", "STRASSE", true},
		{"ΣΊΣΥΦΟΣ", "σίσυφος", true},
		{"Σίσυφος", "ΣΊΣΥΦΟΣ", true},
		{"Kelvin.txt", "kelvin", true}, // ordinary case folding
		{"report", "reportage", false},
		{"anything", "", true},
	}
	for _, c := range cases {
		if got := foldContains(c.name, c.query); got != c.want {
			t.Errorf("foldContains(%q, %q) = %v, want %v", c.name, c.query, got, c.want)
		}
	}
}

// TestSearchFoldingSurvivesInvalidUTF8 is the other half of "a Linux filename
// is an arbitrary byte string": the scan must advance through bytes that are
// not a rune rather than looping or panicking on them.
func TestSearchFoldingSurvivesInvalidUTF8(t *testing.T) {
	name := "pre\xff\xfe-report"
	if !foldContains(name, "REPORT") {
		t.Errorf("foldContains over an invalid-UTF-8 name did not find the tail")
	}
	if foldContains("\xff\xfe", "report") {
		t.Errorf("foldContains matched something that is not there")
	}
}

// TestSearchGlobMatchesPatterns is §3.1's other mode.
func TestSearchGlobMatchesPatterns(t *testing.T) {
	r, _ := searchFixture(t)
	req := searchReq("*.txt", "/tree")
	req.Glob = true
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasName(res, "Report.txt") || !hasName(res, "other.txt") {
		t.Errorf("hits = %v", hitNames(res))
	}
	if hasName(res, "report-2.md") {
		t.Errorf("*.txt matched a .md file: %v", hitNames(res))
	}
	// A glob is case SENSITIVE, which is what path.Match does and what anybody
	// typing a pattern means by it.
	if hasName(res, "REPORT.pdf") {
		t.Errorf("*.txt matched a .pdf file: %v", hitNames(res))
	}
}

// TestSearchRefusesABadPatternBeforeWalking: an unclosed character class is a
// bad request, not four million entries that quietly match nothing.
func TestSearchRefusesABadPatternBeforeWalking(t *testing.T) {
	r, _ := searchFixture(t)
	req := searchReq("[unclosed", "/tree")
	req.Glob = true
	_, err := Search(context.Background(), r, nil, req, Emit{})
	if err == nil || fsx.Code(err) != "bad_request" {
		t.Fatalf("err = %v (code %q), want bad_request", err, fsx.Code(err))
	}
}

func TestSearchRefusesAnEmptyQueryAndANonDirectoryRoot(t *testing.T) {
	r, _ := searchFixture(t)
	ctx := context.Background()
	if _, err := Search(ctx, r, nil, searchReq("", "/tree"), Emit{}); fsx.Code(err) != "bad_request" {
		t.Errorf("an empty query = %v, want bad_request", err)
	}
	if _, err := Search(ctx, r, nil, searchReq("x", "/tree/Report.txt"), Emit{}); fsx.Code(err) != "bad_request" {
		t.Errorf("a file as a root = %v, want bad_request", err)
	}
	if _, err := Search(ctx, r, nil, searchReq("x", "/nope"), Emit{}); fsx.Code(err) != "not_found" {
		t.Errorf("a missing root = %v, want not_found", err)
	}
	bad := searchReq("x", "/tree")
	bad.Kind = "banana"
	if _, err := Search(ctx, r, nil, bad, Emit{}); fsx.Code(err) != "bad_request" {
		t.Errorf("an unknown kind = %v, want bad_request", err)
	}
}

// TestSearchHiddenIsOneSwitch: without it, neither a hidden entry nor anything
// inside a hidden directory is searched.
func TestSearchHiddenIsOneSwitch(t *testing.T) {
	r, _ := searchFixture(t)
	req := searchReq("report", "/tree")
	req.Hidden = true
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasName(res, "secret-report.txt") {
		t.Errorf("with Hidden, an entry inside a dot-directory must be found: %v", hitNames(res))
	}
}

func TestSearchKindFilters(t *testing.T) {
	r, _ := searchFixture(t)
	ctx := context.Background()

	dirs := searchReq("report", "/tree")
	dirs.Kind = "dir"
	res, err := Search(ctx, r, nil, dirs, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hitNames(res); len(got) != 1 || got[0] != "Reports" {
		t.Fatalf("kind=dir hits = %v", got)
	}

	files := searchReq("report", "/tree")
	files.Kind = "file"
	res, err = Search(ctx, r, nil, files, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if hasName(res, "Reports") {
		t.Fatalf("kind=file returned a directory: %v", hitNames(res))
	}
	if !hasName(res, "Report.txt") {
		t.Fatalf("kind=file lost the files: %v", hitNames(res))
	}
}

// TestSearchCountsHiddenEntriesAgainstTheCaps is M2-C review round 1, finding
// 4. An excluded dot-entry used to return before the count and before the
// clock was read, so a directory of a million hidden files was enumerated and
// lstat'ed in full for a search bounded at five hundred thousand entries. Every
// entry the walk touches costs the same syscalls whether or not it can become a
// hit, so every entry counts.
func TestSearchCountsHiddenEntriesAgainstTheCaps(t *testing.T) {
	r, base := searchFixture(t)
	for i := 0; i < 20; i++ {
		write(t, base, fmt.Sprintf("tree/.junk-%02d", i), "x")
	}

	req := searchReq("nothing-matches-this", "/tree")
	req.MaxVisited = 5
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 5 {
		t.Fatalf("Files = %d, want the cap of 5: a hidden entry must be counted like any other", res.Files)
	}
	if !strings.Contains(res.Detail, "stopped after 5 entries") {
		t.Errorf("Detail = %q", res.Detail)
	}
}

// TestSearchStillDoesNotDescendIntoAHiddenDirectory is the other half of the
// same fix: counting a hidden entry must not turn into searching inside it.
func TestSearchStillDoesNotDescendIntoAHiddenDirectory(t *testing.T) {
	r, _ := searchFixture(t)
	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if hasName(res, "secret-report.txt") {
		t.Fatalf("the walk went into a dot-directory: %v", hitNames(res))
	}
	// The directory itself was still touched, so it is counted — and its
	// contents were not.
	if res.Files < 5 {
		t.Fatalf("Files = %d; every entry the walk touched must be counted", res.Files)
	}
}

// TestSearchHiddenEntriesAreCountedButNotMatched pins the third property: a
// hidden name that WOULD match is still not a hit.
func TestSearchHiddenEntriesAreCountedButNotMatched(t *testing.T) {
	r, base := searchFixture(t)
	write(t, base, "tree/.report-hidden.txt", "x")

	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if hasName(res, ".report-hidden.txt") {
		t.Fatalf("a hidden entry was matched without Hidden: %v", hitNames(res))
	}
	withHidden := searchReq("report", "/tree")
	withHidden.Hidden = true
	res2, err := Search(context.Background(), r, nil, withHidden, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasName(res2, ".report-hidden.txt") {
		t.Fatalf("with Hidden it must be found: %v", hitNames(res2))
	}
	if res2.Files <= res.Files {
		t.Errorf("including hidden entries must visit more, not fewer: %d then %d", res.Files, res2.Files)
	}
}

// TestSearchHitCapTruncatesAndSaysSo: the cap is the request's, clamped by the
// worker, and the Detail is what the results header shows (§3.2).
func TestSearchHitCapTruncatesAndSaysSo(t *testing.T) {
	r, _ := searchFixture(t)
	req := searchReq("report", "/tree")
	req.MaxHits = 2
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 2 {
		t.Fatalf("%d hits, want 2: %v", len(res.Hits), hitNames(res))
	}
	if res.Detail != "first 2 of many" {
		t.Errorf("Detail = %q", res.Detail)
	}
}

// TestSearchVisitedCapStopsTheWalk. The count is entries LOOKED AT, so a cap of
// one stops after the first.
func TestSearchVisitedCapStopsTheWalk(t *testing.T) {
	r, _ := searchFixture(t)
	req := searchReq("nothing-matches-this", "/tree")
	req.MaxVisited = 1
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 {
		t.Fatalf("Files = %d, want 1", res.Files)
	}
	if !strings.Contains(res.Detail, "stopped after 1 entries") {
		t.Errorf("Detail = %q", res.Detail)
	}
}

// TestSearchDurationCapStopsTheWalk drives the clock rather than waiting a
// minute for it, and makes every entry a clock check so a small fixture can
// reach the bound at all.
func TestSearchDurationCapStopsTheWalk(t *testing.T) {
	r, _ := searchFixture(t)

	now := time.Now()
	prevClock, prevCheck := searchClock, searchTimeCheck
	searchClock = func() time.Time { return now }
	searchTimeCheck = 1
	t.Cleanup(func() { searchClock, searchTimeCheck = prevClock, prevCheck })

	req := searchReq("nothing-matches-this", "/tree")
	req.MaxDuration = 60
	// The deadline is taken when the search starts; the walk then finds the
	// clock already past it.
	first := true
	searchClock = func() time.Time {
		if first {
			first = false
			return now
		}
		return now.Add(2 * time.Minute)
	}
	res, err := Search(context.Background(), r, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Detail, "stopped after 60 s") {
		t.Fatalf("Detail = %q, want the duration bound", res.Detail)
	}
}

// TestSearchCapsAreClampedToTheMaxima: the worker does not trust the request to
// carry its own limits (§3.2).
func TestSearchCapsAreClampedToTheMaxima(t *testing.T) {
	req := wproto.SearchReq{Query: "x", MaxHits: 1 << 20, MaxVisited: 1 << 40, MaxDuration: 3600}
	s, err := newSearch(fsx.Root{}, nil, req, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if s.maxHits != searchMaxHits || s.maxVisited != searchMaxVisited {
		t.Fatalf("caps = %d/%d, want %d/%d", s.maxHits, s.maxVisited, searchMaxHits, searchMaxVisited)
	}
	zero := wproto.SearchReq{Query: "x"}
	s, err = newSearch(fsx.Root{}, nil, zero, Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if s.maxHits != searchMaxHits || s.maxVisited != searchMaxVisited {
		t.Fatalf("an absent cap must become the maximum, got %d/%d", s.maxHits, s.maxVisited)
	}
}

// TestSearchCancelKeepsWhatItFound is F7 for a search: the partial hits come
// back with the cancellation, because an err frame has nowhere to carry them.
func TestSearchCancelKeepsWhatItFound(t *testing.T) {
	r, _ := searchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	var seen int
	emit := Emit{Prog: func(p wproto.Prog) {
		seen++
		if seen == 2 {
			cancel()
		}
	}}
	res, err := Search(ctx, r, nil, searchReq("report", "/tree"), emit)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res.Files == 0 {
		t.Error("a cancelled search must still report what it visited")
	}
}

// TestSearchSkipsAnUnreadableDirectoryAndCountsIt. The kernel's refusal, not a
// simulation of one: Windows has no mode bits of this shape and root is refused
// nothing.
func TestSearchSkipsAnUnreadableDirectoryAndCountsIt(t *testing.T) {
	requireOwnPermissions(t)
	r, base := searchFixture(t)
	locked := filepath.Join(base, "tree", "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, base, "tree/locked/report-inside.txt", "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	var warns []wproto.Warn
	emit := Emit{Warn: func(w wproto.Warn) { warns = append(warns, w) }}
	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), emit)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
	if len(warns) != 1 || warns[0].Code != "permission" {
		t.Fatalf("warnings = %+v, want one permission warning", warns)
	}
	if hasName(res, "report-inside.txt") {
		t.Error("an entry inside an unreadable directory was reported")
	}
	// The rest of the tree is still searched: one unreadable directory is a
	// warning, never the end of the job.
	if !hasName(res, "Report.txt") {
		t.Errorf("the readable half was lost: %v", hitNames(res))
	}
}

// TestSearchProgressReportsVisitedWithNoDenominator: FilesTotal is -1, because
// a search has no total and a UI that saw a zero would draw a full bar.
func TestSearchProgressReportsVisitedWithNoDenominator(t *testing.T) {
	r, _ := searchFixture(t)
	var last wproto.Prog
	emit := Emit{Prog: func(p wproto.Prog) { last = p }}
	if _, err := Search(context.Background(), r, nil, searchReq("report", "/tree"), emit); err != nil {
		t.Fatal(err)
	}
	if last.FilesTotal != -1 {
		t.Errorf("FilesTotal = %d, want -1", last.FilesTotal)
	}
	if last.Files == 0 || last.Phase != wproto.PhaseScanning {
		t.Errorf("prog = %+v", last)
	}
	if !strings.HasPrefix(string(last.Current), "/tree") {
		t.Errorf("Current = %q, want the directory being scanned", last.Current)
	}
}

// TestSearchHitsAreFullEntries: a result row has to carry what a listing row
// carries, because the UI renders them in the same table.
func TestSearchHitsAreFullEntries(t *testing.T) {
	r, _ := searchFixture(t)
	res, err := Search(context.Background(), r, nil, searchReq("report-2", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %v", hitNames(res))
	}
	e := res.Hits[0]
	if e.Path != "/tree/report-2.md" || e.Type != "file" || e.Size != 1 || e.Mode == "" || e.MTime.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
}

// TestSearchSpansEveryRootInWalkOrder.
func TestSearchSpansEveryRootInWalkOrder(t *testing.T) {
	r, _ := searchFixture(t)
	res, err := Search(context.Background(), r, nil, searchReq("report", "/tree/notes", "/tree/Reports"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hitNames(res); len(got) != 1 || got[0] != "REPORT.pdf" {
		t.Fatalf("hits = %v", got)
	}
}

// TestSearchCountsTheHiddenFoldersItPassedOver: with hidden items off, every
// hidden DIRECTORY the walk reaches is counted once, at the level it was
// skipped — never what is beneath it, which is not visited — and a hidden FILE
// is not a folder the search failed to look in. With hidden items on there is
// nothing to count.
func TestSearchCountsTheHiddenFoldersItPassedOver(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "tree/.qpkg/QKVM/.deeper")
	mkdir(t, base, "tree/sub/.cache")
	write(t, base, "tree/.hidden-file", "x")
	write(t, base, "tree/sub/.cache/QKVM.txt", "x")
	r := newRoot(t, base)

	for _, tc := range []struct {
		hidden bool
		want   int64
		hits   int
	}{
		{false, 2, 0}, // .qpkg and sub/.cache; not QKVM/.deeper, not the file
		{true, 0, 2},  // QKVM and QKVM.txt are found instead
	} {
		req := searchReq("qkvm", "/tree")
		req.Hidden = tc.hidden
		res, err := Search(context.Background(), r, nil, req, Emit{})
		if err != nil {
			t.Fatalf("hidden=%v: %v", tc.hidden, err)
		}
		if res.HiddenSkipped != tc.want || len(res.Hits) != tc.hits {
			t.Errorf("hidden=%v: HiddenSkipped = %d, hits %v; want %d and %d hits",
				tc.hidden, res.HiddenSkipped, hitNames(res), tc.want, tc.hits)
		}
	}
}

// TestAnUnreadableHiddenFolderIsNotCountedAsHidden is Astra r9: a hidden
// directory the kernel will not let the walk open is a directory it could not
// read (Skipped, with a warning) whatever the hidden-items option says, so it
// is not reported as a hidden folder that ticking the box would reach.
func TestAnUnreadableHiddenFolderIsNotCountedAsHidden(t *testing.T) {
	requireOwnPermissions(t)
	base := tempDir(t)
	mkdir(t, base, "tree/.locked/inside")
	mkdir(t, base, "tree/.open")
	locked := filepath.Join(base, "tree", ".locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	r := newRoot(t, base)

	res, err := Search(context.Background(), r, nil, searchReq("nothing-matches", "/tree"), Emit{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.HiddenSkipped != 1 || res.Skipped != 1 {
		t.Errorf("HiddenSkipped = %d, Skipped = %d; want 1 (.open) and 1 (.locked)", res.HiddenSkipped, res.Skipped)
	}
}

// TestAHiddenFolderAtTheDepthBoundIsNotCountedAsHidden is Astra r10: a
// readable hidden directory AT the depth bound is one the walk will not descend
// into whatever the hidden-items option says, so it is not reported as a hidden
// folder that ticking the box would reach. The bound is lowered for the test;
// a 256-level tree does not fit in a Windows path.
func TestAHiddenFolderAtTheDepthBoundIsNotCountedAsHidden(t *testing.T) {
	prev := maxWalkDepth
	maxWalkDepth = 3
	t.Cleanup(func() { maxWalkDepth = prev })

	base := tempDir(t)
	mkdir(t, base, "tree/a/b/.deep/inside") // .deep is at depth 3, the bound
	mkdir(t, base, "tree/.shallow")         // depth 1: an ordinary hidden folder
	r := newRoot(t, base)

	res, err := Search(context.Background(), r, nil, searchReq("nothing-matches", "/tree"), Emit{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.HiddenSkipped != 1 {
		t.Errorf("HiddenSkipped = %d, want 1 (.shallow only, not .deep at the depth bound)", res.HiddenSkipped)
	}
}
