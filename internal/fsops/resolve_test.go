package fsops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// TestResolvePathPlainNestedResolvesToItself is the cross-platform floor: a path
// with no symlinks on it resolves to its own spelling, with the leaf kept literal
// under !followLeaf even when it does not exist yet (a mkdir target) and the
// whole path returned under followLeaf for an existing directory.
func TestResolvePathPlainNestedResolvesToItself(t *testing.T) {
	base := tempDir(t)
	mkdir(t, base, "a/b")
	r := newRoot(t, base)
	ctx := context.Background()

	// !followLeaf: /a/b is the parent, "c" a not-yet-existing leaf kept literal.
	if got, err := ResolvePath(ctx, r, "/a/b/c", false); err != nil {
		t.Fatalf("ResolvePath(/a/b/c, followLeaf=false): %v", err)
	} else if got != "/a/b/c" {
		t.Errorf("got %q, want /a/b/c", got)
	}

	// followLeaf: /a/b exists and is returned as itself.
	if got, err := ResolvePath(ctx, r, "/a/b", true); err != nil {
		t.Fatalf("ResolvePath(/a/b, followLeaf=true): %v", err)
	} else if got != "/a/b" {
		t.Errorf("got %q, want /a/b", got)
	}
}

// TestResolvePathResolvesASymlinkedParent: a parent reached through a symlink is
// returned under its canonical spelling, and — under !followLeaf — a symlink at
// the leaf is left as the link rather than followed. This is exactly the shape
// QTS builds its shares out of (/share/Public is a symlink into the dataset), and
// the reason delete and rename resolve the parent but keep the named entry.
func TestResolvePathResolvesASymlinkedParent(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "target")
	write(t, base, "target/file.txt", "keep me")
	// A symlink parent, and a symlink leaf inside the real directory.
	if err := os.Symlink(filepath.Join(base, "target"), filepath.Join(base, "plink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "target", "file.txt"), filepath.Join(base, "target", "leaflink")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	// The parent symlink is resolved to /target; the leaf symlink is kept literal.
	if got, err := ResolvePath(ctx, r, "/plink/leaflink", false); err != nil {
		t.Fatalf("ResolvePath(/plink/leaflink, followLeaf=false): %v", err)
	} else if got != "/target/leaflink" {
		t.Errorf("got %q, want /target/leaflink (parent resolved, leaf kept as the link)", got)
	}

	// A missing leaf under the symlinked parent is fine (a mkdir target).
	if got, err := ResolvePath(ctx, r, "/plink/newname", false); err != nil {
		t.Fatalf("ResolvePath(/plink/newname, followLeaf=false): %v", err)
	} else if got != "/target/newname" {
		t.Errorf("got %q, want /target/newname", got)
	}

	// followLeaf on the leaf symlink follows it to the canonical target.
	if got, err := ResolvePath(ctx, r, "/plink/leaflink", true); err != nil {
		t.Fatalf("ResolvePath(/plink/leaflink, followLeaf=true): %v", err)
	} else if got != "/target/file.txt" {
		t.Errorf("got %q, want /target/file.txt", got)
	}
}

// TestResolvePathRefusesEscapingTheJail: an absolute symlink target that leaves
// the jail base is refused with ErrOutsideRoot rather than resolved to the host
// path it names. Never escape the jail.
func TestResolvePathRefusesEscapingTheJail(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	outside := tempDir(t) // a sibling directory, outside the jail base
	write(t, outside, "secret", "not yours")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(base, "escape")); err != nil {
		t.Fatal(err)
	}
	r := newRoot(t, base)
	ctx := context.Background()

	if got, err := ResolvePath(ctx, r, "/escape", true); !errors.Is(err, fsx.ErrOutsideRoot) {
		t.Fatalf("ResolvePath of a jail-escaping symlink = (%q, %v), want ErrOutsideRoot", got, err)
	}
}
