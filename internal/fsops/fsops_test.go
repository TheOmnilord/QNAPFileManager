package fsops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
)

// requireSymlinks skips the caller when this box cannot create a symlink.
// Windows only allows it for an administrator or in developer mode, and a test
// that silently passed by not testing anything would be worse than a skip.
func requireSymlinks(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
}

// fixture builds a small tree and returns its Root.
//
//	/a/                 dir
//	/a/one.txt          "one"
//	/a/sub/             dir
//	/a/sub/two.txt      "twotwo"
//	/a/.hidden          "h"
//	/b.txt              "bb"
func fixture(t *testing.T) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	mkdir(t, base, "a")
	mkdir(t, base, "a/sub")
	write(t, base, "a/one.txt", "one")
	write(t, base, "a/sub/two.txt", "twotwo")
	write(t, base, "a/.hidden", "h")
	write(t, base, "b.txt", "bb")
	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	return r, base
}

// tempDir is t.TempDir with the symlinks and the Windows 8.3 short names
// resolved out of it, so that a LinkResolved computed with EvalSymlinks lands
// back inside the jail rather than one directory-name spelling beside it.
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return dir
}

func mkdir(t *testing.T, base, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(base, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, base, rel, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(rel)), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func names(l fsx.Listing) []string {
	out := make([]string, 0, len(l.Entries))
	for _, e := range l.Entries {
		out = append(out, e.Name)
	}
	return out
}

func find(l fsx.Listing, name string) (fsx.Entry, bool) {
	for _, e := range l.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return fsx.Entry{}, false
}

func TestListBasics(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()

	l, err := List(ctx, r, nil, "/a", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if l.Path != "/a" || l.Parent != "/" {
		t.Errorf("path/parent = %q/%q", l.Path, l.Parent)
	}
	if got := names(l); len(got) != 2 || got[0] != "one.txt" || got[1] != "sub" {
		t.Fatalf("entries = %v, want [one.txt sub] (the dotfile is hidden by default)", got)
	}
	if l.Total != 2 || l.Truncated {
		t.Errorf("total = %d, truncated = %v", l.Total, l.Truncated)
	}
	one, _ := find(l, "one.txt")
	if one.Type != "file" || one.Size != 3 || one.Path != "/a/one.txt" {
		t.Errorf("one.txt = %+v", one)
	}
	if one.Mode == "" || len(one.ModeStr) != 10 {
		t.Errorf("mode = %q, modeStr = %q", one.Mode, one.ModeStr)
	}
	sub, _ := find(l, "sub")
	if sub.Type != "dir" {
		t.Errorf("sub is a %q", sub.Type)
	}

	// ShowHidden reveals the dotfile and flags it.
	l, err = List(ctx, r, nil, "/a", fsx.ListOptions{ShowHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	if l.Total != 3 {
		t.Fatalf("total with hidden = %d, want 3", l.Total)
	}
	h, ok := find(l, ".hidden")
	if !ok || !h.Hidden {
		t.Errorf(".hidden = %+v, ok=%v", h, ok)
	}
	if one, _ := find(l, "one.txt"); one.Hidden {
		t.Error("a plain name must not be flagged hidden")
	}
}

func TestListErrors(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()

	if _, err := List(ctx, r, nil, "relative", fsx.ListOptions{}); !errors.Is(err, fsx.ErrNotAbsolute) {
		t.Errorf("relative path error = %v", err)
	}
	if _, err := List(ctx, r, nil, "/nope", fsx.ListOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing directory error = %v", err)
	}
	_, err := List(ctx, r, nil, "/b.txt", fsx.ListOptions{})
	if !errors.Is(err, fsx.ErrBadName) {
		t.Errorf("listing a file error = %v", err)
	}
	if code := fsx.Code(err); code != "bad_request" {
		t.Errorf("code = %q, want bad_request", code)
	}
}

func TestListCancelled(t *testing.T) {
	r, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := List(ctx, r, nil, "/a", fsx.ListOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := Stat(ctx, r, nil, "/a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("stat err = %v", err)
	}
	if _, _, err := OpenRead(ctx, r, "/b.txt"); !errors.Is(err, context.Canceled) {
		t.Fatalf("openread err = %v", err)
	}
}

// bigDir builds a directory with n entries: every tenth is a directory, sizes
// and mtimes repeat so that every sort key has ties to break.
func bigDir(t *testing.T, n int) (fsx.Root, string) {
	t.Helper()
	base := tempDir(t)
	dir := filepath.Join(base, "big")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("e%05d", i)
		p := filepath.Join(dir, name)
		if i%10 == 0 {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.WriteFile(p, make([]byte, i%13), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		when := stamp.Add(time.Duration(i%97) * time.Minute)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

// TestListPagingInvariants is the property the UI depends on: for every sort
// order, the concatenation of the pages is exactly the unpaged listing, no
// entry is seen twice or lost, and offset+len(page) never exceeds Total.
func TestListPagingInvariants(t *testing.T) {
	const n = 3000
	r, _ := bigDir(t, n)
	ctx := context.Background()

	for _, sortKey := range []string{"", fsx.SortName, fsx.SortSize, fsx.SortMTime, fsx.SortType} {
		for _, desc := range []bool{false, true} {
			for _, dirsFirst := range []bool{false, true} {
				o := fsx.ListOptions{Sort: sortKey, Desc: desc, DirsFirst: dirsFirst, Limit: fsx.MaxListLimit}
				full, err := List(ctx, r, nil, "/big", o)
				if err != nil {
					t.Fatal(err)
				}
				if full.Total != n || len(full.Entries) != n {
					t.Fatalf("%s desc=%v: total=%d entries=%d", sortKey, desc, full.Total, len(full.Entries))
				}
				if full.Truncated {
					t.Errorf("%s desc=%v: a complete listing must not be truncated", sortKey, desc)
				}

				// The same options twice must give the same order.
				again, err := List(ctx, r, nil, "/big", o)
				if err != nil {
					t.Fatal(err)
				}
				for i := range full.Entries {
					if full.Entries[i].Name != again.Entries[i].Name {
						t.Fatalf("%s desc=%v: the order is not stable at %d: %q vs %q",
							sortKey, desc, i, full.Entries[i].Name, again.Entries[i].Name)
					}
				}

				var got []string
				const pageSize = 137
				for off := 0; ; off += pageSize {
					po := o
					po.Offset, po.Limit = off, pageSize
					p, err := List(ctx, r, nil, "/big", po)
					if err != nil {
						t.Fatal(err)
					}
					if p.Total != n {
						t.Fatalf("page at %d: total = %d, want %d", off, p.Total, n)
					}
					if min(off, p.Total)+len(p.Entries) > p.Total {
						t.Fatalf("page at %d: offset+len = %d exceeds total %d", off, off+len(p.Entries), p.Total)
					}
					if want := off+pageSize < n; p.Truncated != want {
						t.Errorf("page at %d: truncated = %v, want %v", off, p.Truncated, want)
					}
					got = append(got, names(p)...)
					if len(p.Entries) == 0 {
						break
					}
				}
				if len(got) != n {
					t.Fatalf("%s desc=%v: pages held %d entries, want %d", sortKey, desc, len(got), n)
				}
				for i := range got {
					if got[i] != full.Entries[i].Name {
						t.Fatalf("%s desc=%v dirsFirst=%v: page concat differs at %d: %q vs %q",
							sortKey, desc, dirsFirst, i, got[i], full.Entries[i].Name)
					}
				}
			}
		}
	}

	// An offset past the end is an empty page, not an error.
	p, err := List(ctx, r, nil, "/big", fsx.ListOptions{Offset: n + 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 || p.Entries == nil || p.Total != n {
		t.Fatalf("past-the-end page = %+v", p)
	}
}

func TestListSortOrders(t *testing.T) {
	r, _ := bigDir(t, 40)
	ctx := context.Background()

	byName, err := List(ctx, r, nil, "/big", fsx.ListOptions{Sort: fsx.SortName})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(byName.Entries); i++ {
		if byName.Entries[i-1].Name > byName.Entries[i].Name {
			t.Fatalf("name sort is not ascending at %d", i)
		}
	}
	desc, err := List(ctx, r, nil, "/big", fsx.ListOptions{Sort: fsx.SortName, Desc: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := range desc.Entries {
		if desc.Entries[i].Name != byName.Entries[len(byName.Entries)-1-i].Name {
			t.Fatalf("desc is not the reverse of asc at %d", i)
		}
	}

	bySize, err := List(ctx, r, nil, "/big", fsx.ListOptions{Sort: fsx.SortSize})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(bySize.Entries); i++ {
		a, b := bySize.Entries[i-1], bySize.Entries[i]
		if a.Size > b.Size || (a.Size == b.Size && a.Name > b.Name) {
			t.Fatalf("size sort broken at %d: %+v then %+v", i, a, b)
		}
	}

	byTime, err := List(ctx, r, nil, "/big", fsx.ListOptions{Sort: fsx.SortMTime})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(byTime.Entries); i++ {
		if byTime.Entries[i-1].MTime.After(byTime.Entries[i].MTime) {
			t.Fatalf("mtime sort broken at %d", i)
		}
	}

	dirs, err := List(ctx, r, nil, "/big", fsx.ListOptions{DirsFirst: true, Sort: fsx.SortName, Desc: true})
	if err != nil {
		t.Fatal(err)
	}
	seenFile := false
	for _, e := range dirs.Entries {
		if e.Type == "dir" && seenFile {
			t.Fatalf("a directory appeared after a file with DirsFirst: %q", e.Name)
		}
		if e.Type != "dir" {
			seenFile = true
		}
	}
}

func TestListHardCapIsNotExceeded(t *testing.T) {
	// The cap itself needs 50 001 files to observe, which is too slow for a
	// unit test; what is checked here is that the limit is clamped to the cap
	// rather than honoured verbatim.
	r, _ := bigDir(t, 20)
	l, err := List(context.Background(), r, nil, "/big", fsx.ListOptions{Limit: fsx.MaxListLimit * 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 20 {
		t.Fatalf("entries = %d", len(l.Entries))
	}
	off, limit := page(fsx.ListOptions{Limit: fsx.MaxListLimit * 10}, 100)
	if limit != fsx.MaxListLimit || off != 0 {
		t.Fatalf("page() = %d, %d, want 0, %d", off, limit, fsx.MaxListLimit)
	}
	if _, limit := page(fsx.ListOptions{}, 100); limit != fsx.DefaultListLimit {
		t.Fatalf("default limit = %d", limit)
	}
}

func TestListSymlinks(t *testing.T) {
	requireSymlinks(t)
	r, base := fixture(t)
	ctx := context.Background()

	if err := os.Symlink(filepath.Join(base, "a", "sub"), filepath.Join(base, "todir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "a", "one.txt"), filepath.Join(base, "tofile")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "nowhere"), filepath.Join(base, "dangling")); err != nil {
		t.Fatal(err)
	}

	// Without ResolveLinks the target is not stat'ed at all.
	l, err := List(ctx, r, nil, "/", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e, ok := find(l, "todir")
	if !ok {
		t.Fatal("todir is missing")
	}
	if !e.IsSymlink || e.Type != "symlink" {
		t.Errorf("todir = %+v, want a symlink (its own metadata, never the target's)", e)
	}
	if e.LinkTarget == "" {
		t.Error("LinkTarget must carry the raw readlink text")
	}
	if e.TargetType != "" || e.LinkResolved != "" {
		t.Errorf("without ResolveLinks nothing may be resolved: %+v", e)
	}

	l, err = List(ctx, r, nil, "/", fsx.ListOptions{ResolveLinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := find(l, "todir"); e.TargetType != "dir" || e.LinkResolved != "/a/sub" {
		t.Errorf("todir resolved = %q, targetType = %q", e.LinkResolved, e.TargetType)
	}
	if e, _ := find(l, "tofile"); e.TargetType != "file" {
		t.Errorf("tofile targetType = %q", e.TargetType)
	}
	if e, _ := find(l, "dangling"); e.TargetType != "" || e.LinkResolved != "" {
		t.Errorf("a dangling link must resolve to nothing: %+v", e)
	}

	// Stat never follows the final component.
	st, err := Stat(ctx, r, nil, "/todir")
	if err != nil {
		t.Fatal(err)
	}
	if st.Type != "symlink" || !st.IsSymlink || st.TargetType != "dir" {
		t.Errorf("stat todir = %+v", st)
	}
	if st.LinkResolved != "/a/sub" {
		t.Errorf("stat resolved = %q", st.LinkResolved)
	}
	// StatFollow does.
	ft, err := StatFollow(ctx, r, nil, "/todir")
	if err != nil {
		t.Fatal(err)
	}
	if ft.Type != "dir" {
		t.Errorf("statfollow todir type = %q", ft.Type)
	}

	tgt, err := Readlink(ctx, r, "/tofile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(tgt), "a/one.txt") {
		t.Errorf("readlink = %q", tgt)
	}
	if _, err := Readlink(ctx, r, "/b.txt"); err == nil {
		t.Error("readlink of a regular file must fail")
	}
}

// shareMountinfo is a synthetic QTS mount table: / on ext4, /share on tmpfs
// (the QTS RAM disk), and one storage volume mounted under it.
const shareMountinfo = `21 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
30 21 0:19 / /share rw,relatime - tmpfs tmpfs rw
31 30 9:1 / /share/CACHEDEV1_DATA rw,relatime - ext4 /dev/md1 rw
32 30 9:2 / /share/HDA_DATA rw,relatime - ext4 /dev/md2 rw
`

func TestListShareClassification(t *testing.T) {
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "share/CACHEDEV1_DATA/Public")
	mkdir(t, base, "share/HDA_DATA")
	write(t, base, "share/CACHEDEV1_DATA/Public/hello.txt", "hi")
	if err := os.Symlink(filepath.Join(base, "share", "CACHEDEV1_DATA", "Public"),
		filepath.Join(base, "share", "Public")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "share", "CACHEDEV1_DATA", "Public", "hello.txt"),
		filepath.Join(base, "share", "notashare")); err != nil {
		t.Fatal(err)
	}
	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	plat, err := platform.FromMountinfo(strings.NewReader(shareMountinfo))
	if err != nil {
		t.Fatal(err)
	}

	l, err := List(context.Background(), r, plat, "/share", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Everything is returned; nothing is hidden (§2.2).
	if l.Total != 4 {
		t.Fatalf("total = %d, want 4 (two volume roots, two links): %v", l.Total, names(l))
	}
	pub, ok := find(l, "Public")
	if !ok || !pub.ShareLink || pub.VolumeRoot {
		t.Errorf("Public = %+v, want shareLink", pub)
	}
	if na, _ := find(l, "notashare"); na.ShareLink {
		t.Error("a symlink to a file is not a shared folder")
	}
	for _, name := range []string{"CACHEDEV1_DATA", "HDA_DATA"} {
		v, ok := find(l, name)
		if !ok || !v.VolumeRoot || !v.MountPoint || v.ShareLink {
			t.Errorf("%s = %+v, want a volume root and a mount point", name, v)
		}
	}

	// The same classification through Stat.
	st, err := Stat(context.Background(), r, plat, "/share/CACHEDEV1_DATA")
	if err != nil {
		t.Fatal(err)
	}
	if !st.VolumeRoot {
		t.Errorf("stat of a volume root = %+v", st)
	}
	st, err = Stat(context.Background(), r, plat, "/share/Public")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ShareLink {
		t.Errorf("stat of a share link = %+v", st)
	}

	// A nil platform simply means no classification, never a crash.
	if l, err := List(context.Background(), r, nil, "/share", fsx.ListOptions{}); err != nil {
		t.Fatal(err)
	} else if v, _ := find(l, "CACHEDEV1_DATA"); v.VolumeRoot {
		t.Error("without a mount table nothing can be a volume root")
	}
}

func TestListNonUTF8Name(t *testing.T) {
	base := tempDir(t)
	raw := "we\xffird"
	p := filepath.Join(base, raw)
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Skipf("this filesystem refuses a non-UTF-8 name: %v", err)
	}
	// Windows stores names as UTF-16 and silently substitutes U+FFFD, so the
	// byte string never comes back; there is nothing to assert there.
	des, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || des[0].Name() != raw {
		t.Skipf("the OS rewrote the name to %q; nothing to test", des[0].Name())
	}

	r, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	l, err := List(context.Background(), r, nil, "/", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 1 {
		t.Fatalf("entries = %v", names(l))
	}
	e := l.Entries[0]
	if e.Name != raw {
		t.Errorf("name = %q, want the raw bytes %q", e.Name, raw)
	}
	if e.NameB64 == "" || e.PathB64 == "" {
		t.Errorf("a non-UTF-8 name must carry nameB64 and pathB64: %+v", e)
	}
	if e.Path != "/"+raw {
		t.Errorf("path = %q", e.Path)
	}
}

func TestStat(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()

	e, err := Stat(ctx, r, nil, "/a/one.txt")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "one.txt" || e.Path != "/a/one.txt" || e.Type != "file" || e.Size != 3 {
		t.Errorf("entry = %+v", e)
	}
	if runtime.GOOS == "linux" && e.Nlink != 1 {
		t.Errorf("nlink = %d, want 1", e.Nlink)
	}
	if _, err := Stat(ctx, r, nil, "/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v", err)
	}
	if _, err := Stat(ctx, r, nil, ""); !errors.Is(err, fsx.ErrNotAbsolute) {
		t.Errorf("err = %v", err)
	}
	root, err := Stat(ctx, r, nil, "/")
	if err != nil {
		t.Fatal(err)
	}
	if root.Type != "dir" {
		t.Errorf("the root is a %q", root.Type)
	}
}

func TestOpenRead(t *testing.T) {
	r, _ := fixture(t)
	ctx := context.Background()

	f, e, err := OpenRead(ctx, r, "/a/one.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if e.Size != 3 || e.Name != "one.txt" || e.Type != "file" {
		t.Errorf("entry = %+v", e)
	}
	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != "one" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}

	// A directory is refused, and with the code the API needs.
	_, _, err = OpenRead(ctx, r, "/a")
	if !errors.Is(err, fsx.ErrUnsupported) {
		t.Fatalf("opening a directory = %v, want ErrUnsupported", err)
	}
	if code := fsx.Code(err); code != "unsupported" {
		t.Errorf("code = %q", code)
	}
	if _, _, err := OpenRead(ctx, r, "/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v", err)
	}
}

func TestOpenReadRefusesASymlinkOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("O_NOFOLLOW exists only on Linux")
	}
	requireSymlinks(t)
	r, base := fixture(t)
	if err := os.Symlink(filepath.Join(base, "a", "one.txt"), filepath.Join(base, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if f, _, err := OpenRead(context.Background(), r, "/link.txt"); err == nil {
		f.Close()
		t.Fatal("O_NOFOLLOW must refuse a symlink as the final component")
	}
}

// TestSymlinkEscapesFromTheJailAreRefused: with -jail, a directory symlink
// inside the jail pointing out of it was followed by os.Open — so List
// enumerated the host's directory and OpenRead downloaded its children, since
// O_NOFOLLOW only ever protected the final component.
func TestSymlinkEscapesFromTheJailAreRefused(t *testing.T) {
	requireSymlinks(t)
	r, base := fixture(t)
	outside := tempDir(t)
	mkdir(t, outside, "secret")
	write(t, outside, "secret/passwd", "root:x:0:0:")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(base, "escape")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if l, err := List(ctx, r, nil, "/escape", fsx.ListOptions{}); !errors.Is(err, fsx.ErrOutsideRoot) {
		t.Fatalf("listing through an escaping symlink = %v (entries %v), want ErrOutsideRoot", err, names(l))
	}
	if _, _, err := OpenRead(ctx, r, "/escape/passwd"); !errors.Is(err, fsx.ErrOutsideRoot) {
		t.Fatalf("downloading through an escaping symlink = %v, want ErrOutsideRoot", err)
	}
	// A path that does not exist out there is refused on the ancestor that
	// does, rather than leaking the difference between a missing file and a
	// present one.
	if _, _, err := OpenRead(ctx, r, "/escape/nothing-here"); !errors.Is(err, fsx.ErrOutsideRoot) {
		t.Fatalf("a missing file behind an escaping symlink = %v, want ErrOutsideRoot", err)
	}
	if _, err := StatFollow(ctx, r, nil, "/escape"); !errors.Is(err, fsx.ErrOutsideRoot) {
		t.Fatalf("statting through an escaping symlink = %v, want ErrOutsideRoot", err)
	}

	// The link itself is inside the jail and stays fully visible: hiding it
	// would be lying about the directory. What it must not do is leak where it
	// points on the host.
	e, err := Stat(ctx, r, nil, "/escape")
	if err != nil {
		t.Fatalf("stat of the link itself: %v", err)
	}
	if !e.IsSymlink || e.LinkResolved != "" {
		t.Errorf("link entry = %+v, want a symlink with no resolved path", e)
	}
	if _, err := Readlink(ctx, r, "/escape"); err != nil {
		t.Errorf("readlink of the link itself: %v", err)
	}
	l, err := List(ctx, r, nil, "/", fsx.ListOptions{ResolveLinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if le, ok := find(l, "escape"); !ok || !le.IsSymlink || le.LinkResolved != "" {
		t.Errorf("the escaping link in the parent listing = %+v (present: %v)", le, ok)
	}

	// A symlink that stays inside is untouched by any of this.
	if err := os.Symlink(filepath.Join(base, "a", "sub"), filepath.Join(base, "inside")); err != nil {
		t.Fatal(err)
	}
	if _, err := List(ctx, r, nil, "/inside", fsx.ListOptions{}); err != nil {
		t.Fatalf("listing through a symlink that stays inside the jail: %v", err)
	}
	inside, _, err := OpenRead(ctx, r, "/inside/two.txt")
	if err != nil {
		t.Fatalf("reading through a symlink that stays inside the jail: %v", err)
	}
	inside.Close()
}

// Without a jail there is nothing to contain, so the containment check must
// not start refusing paths on the NAS, where Root is the identity.
func TestUnjailedRootFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		// An API path is POSIX-absolute, so the identity mapping cannot
		// address a drive-lettered temporary directory at all.
		t.Skip("the unjailed mapping is only addressable where paths start at /")
	}
	requireSymlinks(t)
	base := tempDir(t)
	mkdir(t, base, "real")
	write(t, base, "real/file.txt", "hi")
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	var r fsx.Root // the identity mapping production runs with
	if r.Jailed() {
		t.Fatal("the zero Root must be the identity")
	}
	l, err := List(context.Background(), r, nil, filepath.ToSlash(filepath.Join(base, "link")), fsx.ListOptions{})
	if err != nil {
		t.Fatalf("listing through a symlink without a jail: %v", err)
	}
	if _, ok := find(l, "file.txt"); !ok {
		t.Fatalf("entries = %v", names(l))
	}
}

func TestNotesForARAMDisk(t *testing.T) {
	plat, err := platform.FromMountinfo(strings.NewReader(shareMountinfo))
	if err != nil {
		t.Fatal(err)
	}
	// dirNotes reads the mount table by OS path, which under -jail does not
	// describe the fake tree; call it directly with the path the NAS would
	// have so the wording itself is covered.
	notes := dirNotes(plat, "/share", "/share", false)
	joined := strings.Join(notes, "; ")
	if !strings.Contains(joined, "mount point") || !strings.Contains(joined, "RAM disk") {
		t.Fatalf("notes = %v", notes)
	}
	if notes := dirNotes(plat, "/big", "/", true); len(notes) == 0 || !strings.Contains(notes[0], "capped") {
		t.Fatalf("a capped listing must say so: %v", notes)
	}
}

func TestIDMapIsOptional(t *testing.T) {
	if IDMap() != nil {
		t.Fatal("no map is installed by default")
	}
	r, _ := fixture(t)
	l, err := List(context.Background(), r, nil, "/a", fsx.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if e.User != "" || e.Group != "" {
			t.Errorf("without a map, ownership must stay numeric: %+v", e)
		}
	}
}
