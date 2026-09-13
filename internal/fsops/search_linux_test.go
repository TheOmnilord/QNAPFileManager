package fsops

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The search's Linux half: symlinks, which are the kernel's here and a
// privileged feature on the dev box.

// TestSearchHitCarriesASymlinkTarget is M2-C review round 10. A hit built from
// the lstat alone left LinkTarget empty, and the UI renders a link with no
// target as "→ ? (broken)" — so every matching symlink in a search looked
// broken, whatever it pointed at.
//
// The resolved fields stay empty on purpose: filling them means following the
// link, and a search follows nothing.
func TestSearchHitCarriesASymlinkTarget(t *testing.T) {
	r, base := searchFixture(t)
	write(t, base, "tree/real-report.dat", "content")
	if err := os.Symlink("real-report.dat", filepath.Join(base, "tree", "report-link.txt")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	// A dangling one too: it must be described exactly the same way, because a
	// search cannot tell them apart without following — and must not pretend to.
	if err := os.Symlink("nowhere-at-all", filepath.Join(base, "tree", "report-dangling.txt")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	res, err := Search(context.Background(), r, nil, searchReq("report-", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"report-link.txt":     "real-report.dat",
		"report-dangling.txt": "nowhere-at-all",
	}
	seen := 0
	for _, h := range res.Hits {
		target, ok := want[h.Name]
		if !ok {
			continue
		}
		seen++
		if !h.IsSymlink || h.Type != "symlink" {
			t.Errorf("%s: type = %q, isSymlink = %v", h.Name, h.Type, h.IsSymlink)
		}
		if h.LinkTarget != target {
			t.Errorf("%s: LinkTarget = %q, want %q", h.Name, h.LinkTarget, target)
		}
		if h.LinkResolved != "" || h.TargetType != "" {
			t.Errorf("%s: a search must not follow the link (resolved %q, targetType %q)",
				h.Name, h.LinkResolved, h.TargetType)
		}
	}
	if seen != len(want) {
		t.Fatalf("%d of the %d symlinks came back: %v", seen, len(want), hitNames(res))
	}
}

// TestSearchReadsATargetInAReadOnlyDirectory: reading a link's target costs no
// more permission than the walk already spent getting there — readlinkat needs
// search on the parent and nothing else — so a hit inside a directory nobody
// may write to still carries its target.
//
// It is the guard against "fill it in with something that needs more access
// than the walk had", which would turn a perfectly good hit into one the UI
// renders as broken for a reason that has nothing to do with the link.
func TestSearchReadsATargetInAReadOnlyDirectory(t *testing.T) {
	r, base := searchFixture(t)
	deep := filepath.Join(base, "tree", "search-only")
	if err := os.Mkdir(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(deep, "report-inside.txt")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Chmod(deep, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(deep, 0o755) })

	res, err := Search(context.Background(), r, nil, searchReq("report-inside", "/tree"), Emit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %v", hitNames(res))
	}
	if got := res.Hits[0].LinkTarget; got != "elsewhere" {
		t.Fatalf("LinkTarget = %q, want %q", got, "elsewhere")
	}
}
