package fsops

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// TestCompareNames pins the name order every listing falls through to
// (stabilization contract §1.1). Most pairs are chosen so that byte order —
// what sortEntries used before — gives the opposite answer, so a comparator
// that quietly fell back to it fails here rather than passing by coincidence.
func TestCompareNames(t *testing.T) {
	cases := []struct {
		why  string
		a, b string
		want int
	}{
		// ASCII case pairs: byte order put every capital above every lower case.
		{"a lower-case initial before a later capital", "apple", "Banana", -1},
		{"a capital Z after a lower-case a", "Zebra", "apple", 1},
		{"case inside the name is folded too", "IMG_0002.JPG", "img_0001.jpg", 1},
		{"a capital sorts among the lower-case names", "Report.pdf", "readme", 1},
		{"…and before the ones after it", "Report.pdf", "zebra", -1},

		// Accented letters fold to their own lower case and, as code points, come
		// after ASCII: no collation.
		{"an accented letter is not its base letter", "École", "ecole", 1},
		{"an accented letter comes after z", "élan", "Zebra", 1},
		{"an accented capital folds to its lower case", "Örtlich", "ölberg", 1},
		{"a non-Latin capital folds too", "Σ", "α", 1},

		// A byte that does not begin valid UTF-8 keys as 0x110000 + byte.
		{"two invalid bytes keep their own order", "a\xffb", "a\xfeb", 1},
		{"an invalid byte comes after the last code point", "\x80", "\U0010FFFF", 1},
		{"an invalid byte comes after an accented letter", "\x80x", "éx", 1},

		// U+FFFD the character is not an invalid byte, although decoding the byte
		// alone yields it.
		{"U+FFFD before a raw 0xFF", "\uFFFD", "\xff", -1},
		{"U+FFFD before a raw 0x80", "\x80", "\uFFFD", 1},
		{"a raw 0xFF is decided where it stands, not by what follows", "a\xffb", "a\uFFFDz", 1},

		// A name that runs out first is the smaller.
		{"a folded prefix is first", "abc", "ABCD", -1},
		{"a bare name before its extension", "Notes", "notes.txt", -1},

		// Folded-equal names fall to their bytes, which keeps the order total.
		{"capitals first among case twins", "README", "readme", -1},
		{"mixed case between the two", "Readme", "README", 1},
		{"identical names are equal", "readme", "readme", 0},
		{"the Kelvin sign folds to k and is longer", "k", "\u212A", -1},
		{"…and still after the plain capital", "\u212A", "K", 1},
	}
	for _, c := range cases {
		if got := compareNames(c.a, c.b); got != c.want {
			t.Errorf("%s: compareNames(%q, %q) = %d, want %d", c.why, c.a, c.b, got, c.want)
		}
		if got := compareNames(c.b, c.a); got != -c.want {
			t.Errorf("%s: compareNames(%q, %q) = %d, want %d (antisymmetry)", c.why, c.b, c.a, got, -c.want)
		}
	}

	// Totality: sorted with the comparator itself, every pair of different
	// names must stand in strict order and only a name compares equal to
	// itself. A comparator that tied two different names, or was not
	// transitive, cannot pass this over a set this mixed.
	set := map[string]bool{}
	for _, c := range cases {
		set[c.a], set[c.b] = true, true
	}
	for _, extra := range []string{"", "a", "A", "\xff", "\xfe", "ä", "Ä", "\u212A", "K", "k", "file10", "file2", "File1"} {
		set[extra] = true
	}
	all := make([]string, 0, len(set))
	for n := range set {
		all = append(all, n)
	}
	slices.SortFunc(all, compareNames)
	for i := range all {
		if got := compareNames(all[i], all[i]); got != 0 {
			t.Errorf("compareNames(%q, itself) = %d", all[i], got)
		}
		for j := i + 1; j < len(all); j++ {
			if got := compareNames(all[i], all[j]); got != -1 {
				t.Errorf("sorted %q (at %d) and %q (at %d) compare %d, want -1", all[i], i, all[j], j, got)
			}
		}
	}
}

// TestNameKeyFoldsLikeUnicode keeps the ASCII shortcut honest: it is only a
// shortcut if it answers what unicode.ToLower answers, for every ASCII byte.
// The two keys that are not a lower case are pinned beside it.
func TestNameKeyFoldsLikeUnicode(t *testing.T) {
	for c := 0; c < 0x80; c++ {
		k, w := nameKey(string(rune(c)), 0)
		if k != unicode.ToLower(rune(c)) || w != 1 {
			t.Errorf("nameKey(%q) = %U/%d, want %U/1", rune(c), k, w, unicode.ToLower(rune(c)))
		}
	}
	for _, c := range []struct {
		s    string
		key  rune
		size int
	}{
		{"\xff", 0x1100FF, 1},
		{"\x80", 0x110080, 1},
		{"\uFFFD", 0xFFFD, 3},
		{"É", 'é', 2},
		{"\u212A", 'k', 3},
	} {
		if k, w := nameKey(c.s, 0); k != c.key || w != c.size {
			t.Errorf("nameKey(%q) = %#x/%d, want %#x/%d", c.s, k, w, c.key, c.size)
		}
	}
}

// TestEverySortKeyFallsThroughToTheFoldedName: size, mtime and type all tie
// here, so the order each of them leaves is the name order — case-insensitive,
// case twins by their bytes — with DirsFirst and Desc applied around it exactly
// as before (§1.1, §1.2).
func TestEverySortKeyFallsThroughToTheFoldedName(t *testing.T) {
	stamp := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	entry := func(name, typ string) fsx.Entry {
		return fsx.Entry{Name: name, Type: typ, Size: 1, MTime: stamp}
	}
	base := []fsx.Entry{
		entry("readme", "file"), entry("Gamma", "dir"), entry("beta", "file"),
		entry("README", "file"), entry("delta", "dir"), entry("Alpha", "file"),
	}
	order := func(o fsx.ListOptions) string {
		es := slices.Clone(base)
		sortEntries(es, o)
		out := make([]string, 0, len(es))
		for _, e := range es {
			out = append(out, e.Name)
		}
		return strings.Join(out, " ")
	}
	const plain = "Alpha beta delta Gamma README readme"
	for _, key := range []string{"", fsx.SortName, fsx.SortSize, fsx.SortMTime} {
		if got := order(fsx.ListOptions{Sort: key}); got != plain {
			t.Errorf("sort %q: %s, want %s", key, got, plain)
		}
	}
	// The type sort ranks folders first on its own; inside each rank, the name.
	if got, want := order(fsx.ListOptions{Sort: fsx.SortType}), "delta Gamma Alpha beta README readme"; got != want {
		t.Errorf("sort type: %s, want %s", got, want)
	}
	for _, c := range []struct {
		o    fsx.ListOptions
		want string
	}{
		{fsx.ListOptions{DirsFirst: true}, "delta Gamma Alpha beta README readme"},
		{fsx.ListOptions{Desc: true}, "readme README Gamma delta beta Alpha"},
		// Folders stay first when the order is reversed; only the order inside
		// each group turns round.
		{fsx.ListOptions{DirsFirst: true, Desc: true}, "Gamma delta readme README beta Alpha"},
		{fsx.ListOptions{DirsFirst: true, Desc: true, Sort: fsx.SortSize}, "Gamma delta readme README beta Alpha"},
	} {
		if got := order(c.o); got != c.want {
			t.Errorf("%+v: %s, want %s", c.o, got, c.want)
		}
	}
}

// TestSortEntriesIgnoresTheReadOrder: the order is total, so the entries come
// out the same whatever order the filesystem read them in — which is what lets
// sortEntries use a sort that is not stable, and what keeps a page boundary in
// one place across two reads of a folder. Every sort key ties here on purpose
// (sizes, instants and types repeat), along with case twins and names that fold
// alike from different bytes.
func TestSortEntriesIgnoresTheReadOrder(t *testing.T) {
	stamp := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var base []fsx.Entry
	for i, n := range []string{"readme", "README", "Readme", "k", "K", "K", "\xff", "�", "\x80x",
		"éclair", "Éclair", "eclair", "Zeta", "zeta", "alpha", "Alpha", "b", "B", "file10", "file2", "File1"} {
		typ := "file"
		if i%4 == 0 {
			typ = "dir"
		}
		base = append(base, fsx.Entry{Name: n, Type: typ, Size: int64(i % 3), MTime: stamp.Add(time.Duration(i%2) * time.Second)})
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for _, key := range []string{fsx.SortName, fsx.SortSize, fsx.SortMTime, fsx.SortType} {
		for _, dirsFirst := range []bool{false, true} {
			for _, desc := range []bool{false, true} {
				o := fsx.ListOptions{Sort: key, DirsFirst: dirsFirst, Desc: desc}
				want := slices.Clone(base)
				sortEntries(want, o)
				for range 20 {
					got := slices.Clone(base)
					rng.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
					sortEntries(got, o)
					for i := range got {
						if got[i].Name != want[i].Name {
							t.Fatalf("%+v: a different read order sorted differently at %d: %q vs %q", o, i, got[i].Name, want[i].Name)
						}
					}
				}
			}
		}
	}
}

// foldedDir is a fixed folder whose names differ by more than case, so it can
// be built on a case-insensitive filesystem too, and whose byte order is far
// from its folded order: five folders and ten files, mixed case. Every mtime is
// the same instant and sizes repeat, so the size and mtime sorts tie and fall
// through to the name as well.
func foldedDir(t *testing.T) (fsx.Root, []string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "fixed")
	dirs := []string{"alpha", "Bravo", "charlie", "Delta", "echo"}
	files := []string{"apple.txt", "Banana.txt", "cherry.txt", "Damson.txt", "elder.txt",
		"Fig.txt", "grape.txt", "Hazel.txt", "ice.txt", "Juniper.txt"}
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, d := range dirs {
		mkdir(t, base, "fixed/"+d)
	}
	for i, f := range files {
		write(t, base, "fixed/"+f, strings.Repeat("x", i%3))
	}
	for _, n := range append(slices.Clone(dirs), files...) {
		if err := os.Chtimes(filepath.Join(base, "fixed", n), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	return newRoot(t, base), append(dirs, files...)
}

// TestListPagesOfAFixedFolderNeitherOverlapNorSkip is §1.4's paging case: the
// same fixed folder read in three pages, folders first and not, ascending and
// descending, must hand back every entry exactly once and in the order of the
// unpaged listing. A comparator that tied two different names would let the
// sort put them either way round on different requests, and a page boundary
// between them would then show one twice and the other never.
func TestListPagesOfAFixedFolderNeitherOverlapNorSkip(t *testing.T) {
	r, all := foldedDir(t)
	ctx := context.Background()
	const pageSize = 5 // fifteen entries: exactly three pages

	want := map[fsx.ListOptions]string{
		{Sort: fsx.SortName}: "alpha apple.txt Banana.txt Bravo charlie cherry.txt Damson.txt Delta echo elder.txt " +
			"Fig.txt grape.txt Hazel.txt ice.txt Juniper.txt",
		{Sort: fsx.SortName, DirsFirst: true}: "alpha Bravo charlie Delta echo apple.txt Banana.txt cherry.txt " +
			"Damson.txt elder.txt Fig.txt grape.txt Hazel.txt ice.txt Juniper.txt",
		{Sort: fsx.SortName, DirsFirst: true, Desc: true}: "echo Delta charlie Bravo alpha Juniper.txt ice.txt Hazel.txt " +
			"grape.txt Fig.txt elder.txt Damson.txt cherry.txt Banana.txt apple.txt",
		{Sort: fsx.SortName, Desc: true}: "Juniper.txt ice.txt Hazel.txt grape.txt Fig.txt elder.txt echo Delta Damson.txt " +
			"cherry.txt charlie Bravo Banana.txt apple.txt alpha",
	}

	for _, key := range []string{"", fsx.SortName, fsx.SortSize, fsx.SortMTime, fsx.SortType} {
		for _, dirsFirst := range []bool{false, true} {
			for _, desc := range []bool{false, true} {
				o := fsx.ListOptions{Sort: key, DirsFirst: dirsFirst, Desc: desc}
				full, err := List(ctx, r, nil, "/fixed", o)
				if err != nil {
					t.Fatal(err)
				}
				if full.Total != len(all) || len(full.Entries) != len(all) || full.Truncated || len(full.Notes) != 0 {
					t.Fatalf("%+v: total=%d entries=%d truncated=%v notes=%q, want the whole folder and nothing else",
						o, full.Total, len(full.Entries), full.Truncated, full.Notes)
				}
				if w, ok := want[o]; ok {
					if got := strings.Join(names(full), " "); got != w {
						t.Errorf("%+v:\n got %s\nwant %s", o, got, w)
					}
				}

				var paged []string
				for p := 0; p < 3; p++ {
					po := o
					po.Offset, po.Limit = p*pageSize, pageSize
					page, err := List(ctx, r, nil, "/fixed", po)
					if err != nil {
						t.Fatal(err)
					}
					if len(page.Entries) != pageSize || page.Total != len(all) {
						t.Fatalf("%+v page %d: %d entries of %d, want %d of %d", o, p, len(page.Entries), page.Total, pageSize, len(all))
					}
					if wantMore := p < 2; page.Truncated != wantMore {
						t.Errorf("%+v page %d: truncated = %v, want %v", o, p, page.Truncated, wantMore)
					}
					paged = append(paged, names(page)...)
				}
				seen := map[string]int{}
				for _, n := range paged {
					seen[n]++
				}
				for _, n := range all {
					if seen[n] != 1 {
						t.Errorf("%+v: %q appears %d times across the pages, want once", o, n, seen[n])
					}
				}
				if got, w := strings.Join(paged, " "), strings.Join(names(full), " "); got != w {
					t.Errorf("%+v: the pages differ from the unpaged listing:\n got %s\nwant %s", o, got, w)
				}
			}
		}
	}
}

// TestListOrdersCaseTwinsByTheirBytes needs a filesystem that keeps "readme"
// and "README" apart — every Linux one the NAS uses, none of Windows'. Folded
// they are equal, so the bytes order them, and a page of one entry each still
// walks the folder without repeating or losing one.
func TestListOrdersCaseTwinsByTheirBytes(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "twins")
	for _, n := range []string{"readme", "README", "Readme", "readme.txt"} {
		write(t, base, "twins/"+n, n)
	}
	if des, err := os.ReadDir(filepath.Join(base, "twins")); err != nil {
		t.Fatal(err)
	} else if len(des) != 4 {
		t.Skipf("this filesystem folds case (%d names kept of 4); the tie-break cannot be observed here", len(des))
	}
	r := newRoot(t, base)
	ctx := context.Background()
	const want = "README Readme readme readme.txt"

	l, err := List(ctx, r, nil, "/twins", fsx.ListOptions{Sort: fsx.SortName})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(l), " "); got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	var paged []string
	for off := 0; off < 4; off++ {
		p, err := List(ctx, r, nil, "/twins", fsx.ListOptions{Sort: fsx.SortName, Offset: off, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		paged = append(paged, names(p)...)
	}
	if got := strings.Join(paged, " "); got != want {
		t.Fatalf("one-entry pages = %s, want %s", got, want)
	}
}

// TestListPutsInvalidBytesAfterEveryLetter: a raw byte that is not UTF-8 keys
// past every code point, so it lands after "é" — where byte order put it before,
// since 0x80 is less than é's lead byte. Linux keeps such a name as written;
// Windows rewrites it, and there is then nothing to observe.
func TestListPutsInvalidBytesAfterEveryLetter(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "bytes")
	raw := "\x80x"
	for _, n := range []string{"Zeta", "éclair", raw} {
		if err := os.WriteFile(filepath.Join(base, "bytes", n), nil, 0o644); err != nil {
			t.Skipf("this filesystem refuses the name %q: %v", n, err)
		}
	}
	des, err := os.ReadDir(filepath.Join(base, "bytes"))
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, de := range des {
		kept = kept || de.Name() == raw
	}
	if !kept {
		t.Skip("the OS rewrote the non-UTF-8 name; nothing to test")
	}
	l, err := List(context.Background(), newRoot(t, base), nil, "/bytes", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(l); !slices.Equal(got, []string{"Zeta", "éclair", raw}) {
		t.Fatalf("order = %q, want [Zeta éclair %q]", got, raw)
	}
}

// TestDirsFirstDoesNotCountALinkToAFolder: §1.2 says a folder is Type "dir",
// as it always was, so a symlink to a folder is sorted with the files even when
// the listing has resolved it and knows where it lands.
func TestDirsFirstDoesNotCountALinkToAFolder(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "mix/zdir")
	write(t, base, "mix/Bfile", "b")
	if err := os.Symlink(filepath.Join(base, "mix", "zdir"), filepath.Join(base, "mix", "alink")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	l, err := List(context.Background(), r, nil, "/mix", fsx.ListOptions{DirsFirst: true, ResolveLinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(l), " "); got != "zdir alink Bfile" {
		t.Fatalf("order = %s, want zdir alink Bfile", got)
	}
	if link, _ := find(l, "alink"); link.Type != "symlink" || link.TargetType != "dir" {
		t.Fatalf("alink = %+v, want a resolved link to a folder", link)
	}
}

// withListReadCap narrows the read cap for one test.
func withListReadCap(t *testing.T, n int) {
	t.Helper()
	prev := listReadCap
	listReadCap = n
	t.Cleanup(func() { listReadCap = prev })
}

// TestListCapIsHonest is §1.3: the read stops at the cap, and only an entry
// past it — one the listing would have shown — makes the listing "capped". A
// folder of exactly the cap is complete. The cap is narrowed to four through
// the seam; the logic is the one fifty thousand would take.
func TestListCapIsHonest(t *testing.T) {
	const capN = 4
	withListReadCap(t, capN)
	base := tempDir(t)
	mkdir(t, base, "exact")
	mkdir(t, base, "over")
	// Hidden entries are not listed by default, so they are not "more": with
	// them hidden the folder holds exactly the cap. The test only means
	// something if a hidden entry is read AFTER the last visible one, so the
	// fixture makes sure of it in every read order a filesystem here uses: one
	// is created first and the rest last (creation order and its reverse), and
	// the visible names start with "-", which sorts before "." (name order, as
	// NTFS hands them out). A hashed order is left to the number of them.
	write(t, base, "exact/.h0", "h")
	for i, n := range []string{"-a1", "-b2", "-C3", "-d4"} {
		write(t, base, "exact/"+n, strings.Repeat("x", i))
	}
	for i := 1; i <= 8; i++ {
		write(t, base, "exact/.h"+strconv.Itoa(i), "h")
	}
	over := []string{"a1", "b2", "C3", "d4", "e5"}
	for _, n := range over {
		write(t, base, "over/"+n, n)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	t.Run("exactly the cap is not capped", func(t *testing.T) {
		l, err := List(ctx, r, nil, "/exact", fsx.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if l.Total != capN || len(l.Entries) != capN || l.Truncated || len(l.Notes) != 0 {
			t.Fatalf("total=%d entries=%d truncated=%v notes=%q, want %d complete entries and no note",
				l.Total, len(l.Entries), l.Truncated, l.Notes, capN)
		}
		// Paging still says "more pages" where there are some, but that is the
		// page's truncation, not the cap's, and it carries no note.
		first, err := List(ctx, r, nil, "/exact", fsx.ListOptions{Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		if !first.Truncated || len(first.Notes) != 0 {
			t.Fatalf("first page: truncated=%v notes=%q, want truncated (one more page) and no note", first.Truncated, first.Notes)
		}
		last, err := List(ctx, r, nil, "/exact", fsx.ListOptions{Offset: 3, Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		if len(last.Entries) != 1 || last.Truncated || len(last.Notes) != 0 {
			t.Fatalf("last page: %d entries truncated=%v notes=%q, want 1, false, none", len(last.Entries), last.Truncated, last.Notes)
		}
	})

	t.Run("hidden entries count once they are shown", func(t *testing.T) {
		l, err := List(ctx, r, nil, "/exact", fsx.ListOptions{ShowHidden: true})
		if err != nil {
			t.Fatal(err)
		}
		if l.Total != capN || len(l.Entries) != capN || !l.Truncated {
			t.Fatalf("total=%d entries=%d truncated=%v, want %d and truncated", l.Total, len(l.Entries), l.Truncated, capN)
		}
		if len(l.Notes) != 1 || l.Notes[0] != cappedNote(capN) {
			t.Fatalf("notes = %q, want [%q]", l.Notes, cappedNote(capN))
		}
	})

	t.Run("one past the cap is capped and the peek is not listed", func(t *testing.T) {
		l, err := List(ctx, r, nil, "/over", fsx.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if l.Total != capN || len(l.Entries) != capN || !l.Truncated {
			t.Fatalf("total=%d entries=%d truncated=%v, want %d and truncated", l.Total, len(l.Entries), l.Truncated, capN)
		}
		if len(l.Notes) == 0 || l.Notes[0] != cappedNote(capN) {
			t.Fatalf("notes = %q, want the cap's note first", l.Notes)
		}
		// Which four were read is the filesystem's order, not ours; what is
		// pinned is that they are four different names of the folder, sorted,
		// and that nothing beyond them was added.
		got := names(l)
		if !slices.IsSortedFunc(got, compareNames) {
			t.Errorf("entries %q are not in name order", got)
		}
		seen := map[string]bool{}
		for _, n := range got {
			if seen[n] || !slices.Contains(over, n) {
				t.Errorf("entries %q: %q is repeated or not in the folder", got, n)
			}
			seen[n] = true
		}
		// A page inside a capped listing says so as well: it is the folder that
		// is incomplete, whichever page is looked at.
		p, err := List(ctx, r, nil, "/over", fsx.ListOptions{Offset: 2, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Entries) != 2 || !p.Truncated || len(p.Notes) == 0 || p.Notes[0] != cappedNote(capN) {
			t.Fatalf("last page of a capped listing: %d entries truncated=%v notes=%q", len(p.Entries), p.Truncated, p.Notes)
		}
	})
}

// TestTheCapNoteIsTheContractsSentence pins the production wording verbatim
// (§1.3), with the number taken from fsx.MaxListLimit, and its place at the
// head of Notes, before what is said about the mount.
func TestTheCapNoteIsTheContractsSentence(t *testing.T) {
	const want = "Only the first 50,000 entries read are listed, so others are missing, and sorting applies only to the entries listed."
	if listReadCap != fsx.MaxListLimit {
		t.Fatalf("listReadCap = %d, want fsx.MaxListLimit (%d) outside a test that narrows it", listReadCap, fsx.MaxListLimit)
	}
	if got := cappedNote(fsx.MaxListLimit); got != want {
		t.Fatalf("cappedNote = %q, want %q", got, want)
	}
	if got := dirNotes(nil, "/big", "", false, true); !slices.Equal(got, []string{want}) {
		t.Fatalf("dirNotes = %q, want [%q]", got, want)
	}
	if got := dirNotes(nil, "/big", "", false, false); len(got) != 0 {
		t.Fatalf("an uncapped listing carries no note: %q", got)
	}
	plat, err := platform.FromMountinfo(strings.NewReader(shareMountinfo))
	if err != nil {
		t.Fatal(err)
	}
	notes := dirNotes(plat, "/share", "/share", true, true)
	if len(notes) != 3 || notes[0] != want || notes[1] != "mount point" || !strings.Contains(notes[2], "RAM disk") {
		t.Fatalf("notes = %q, want the cap's note, then the mount point, then the RAM disk", notes)
	}
}

func TestGroupDigits(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{
		{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"}, {50000, "50,000"},
		{123456, "123,456"}, {1234567, "1,234,567"}, {-100, "-100"}, {-1000, "-1,000"},
	} {
		if got := groupDigits(c.n); got != c.want {
			t.Errorf("groupDigits(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
