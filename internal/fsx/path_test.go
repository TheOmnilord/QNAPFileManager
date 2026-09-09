package fsx

import (
	"errors"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{"root", "/", "/", nil},
		{"plain", "/etc/passwd", "/etc/passwd", nil},
		{"trailing slash", "/share/Public/", "/share/Public", nil},
		{"double slash inside", "/share//Public", "/share/Public", nil},
		{"repeated slashes", "/share///a//b/", "/share/a/b", nil},
		{"backslash is a real character", "/share/a\\b", "/share/a\\b", nil},
		// A "." or a ".." is refused, never resolved: the kernel walks
		// "/dangling/../report" into ENOENT and "/locked/../report" into EACCES,
		// where a lexical clean would answer about "/report" — a file the request
		// never named.
		{"dot element", "/share/./Public", "", ErrBadName},
		{"dotdot inside", "/share/Public/../Multimedia", "", ErrBadName},
		{"dotdot past root", "/../../etc", "", ErrBadName},
		{"trailing dotdot", "/share/Public/..", "", ErrBadName},
		{"trailing dot", "/share/Public/.", "", ErrBadName},
		{"dot-only path", "/.", "", ErrBadName},
		// Only a whole component counts; these are ordinary filenames.
		{"leading dots in a name", "/share/...", "/share/...", nil},
		{"dotfile", "/share/.hidden", "/share/.hidden", nil},
		{"name ending in dots", "/share/a..b", "/share/a..b", nil},
		{"space and hash", "/share/a #b.txt", "/share/a #b.txt", nil},
		{"empty", "", "", ErrNotAbsolute},
		{"relative", "etc/passwd", "", ErrNotAbsolute},
		{"dot relative", "./etc", "", ErrNotAbsolute},
		{"windows drive", `C:\Windows`, "", ErrNotAbsolute},
		{"nul byte", "/etc/pass\x00wd", "", ErrBadName},
		{"unc", "//server/share", "", ErrBadName},
		{"unc root only", "//", "", ErrBadName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Clean(c.in)
			if !errors.Is(err, c.err) {
				t.Fatalf("Clean(%q) error = %v, want %v", c.in, err, c.err)
			}
			if c.err == nil && got != c.want {
				t.Fatalf("Clean(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestValidName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"plain", "notes.txt", true},
		{"dotfile", ".hidden", true},
		{"space and hash", "a #b.txt", true},
		{"unicode", "Bilder – 2024 ✓", true},
		// A backslash is an ordinary byte in a Linux filename and QNAP shares
		// written from Windows clients do contain them.
		{"backslash", `a\b`, true},
		{"invalid utf8", string([]byte{0x66, 0xff, 0x6f}), true},
		{"empty", "", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"slash", "a/b", false},
		{"leading slash", "/a", false},
		{"nul", "a\x00b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidName(c.in)
			if c.ok && err != nil {
				t.Fatalf("ValidName(%q) = %v, want nil", c.in, err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("ValidName(%q) = nil, want an error", c.in)
				}
				if !errors.Is(err, ErrBadName) {
					t.Fatalf("ValidName(%q) = %v, want ErrBadName", c.in, err)
				}
			}
		})
	}
}

func TestIsWithin(t *testing.T) {
	cases := []struct {
		name   string
		p      string
		prefix string
		want   bool
	}{
		{"self", "/etc/config", "/etc/config", true},
		{"child", "/etc/config/uLinux.conf", "/etc/config", true},
		{"grandchild", "/etc/config/a/b/c", "/etc/config", true},
		// The whole reason this helper exists: a plain string prefix test
		// says yes here, and the guard's protected-path table would then
		// refuse an unrelated directory (or, reversed, allow one it must not).
		{"sibling with a longer name", "/etc/configuration", "/etc/config", false},
		{"sibling prefix reversed", "/etc/config", "/etc/configuration", false},
		{"parent is not within child", "/etc", "/etc/config", false},
		{"unrelated", "/share/Public", "/etc/config", false},
		{"everything is within root", "/etc/config", "/", true},
		{"root within root", "/", "/", true},
		{"uncleaned path", "/etc//config/./uLinux.conf", "/etc/config", true},
		{"uncleaned prefix", "/etc/config/", "/etc/config", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsWithin(c.p, c.prefix); got != c.want {
				t.Fatalf("IsWithin(%q, %q) = %v, want %v", c.p, c.prefix, got, c.want)
			}
		})
	}
}

func TestJoinParentBase(t *testing.T) {
	cases := []struct {
		dir, elem                   string
		wantJoin, wantDir, wantBase string
	}{
		{"/share", "Public", "/share/Public", "/share", "Public"},
		{"/", "etc", "/etc", "/", "etc"},
		{"/share/", "a #b.txt", "/share/a #b.txt", "/share", "a #b.txt"},
	}
	for _, c := range cases {
		got := Join(c.dir, c.elem)
		if got != c.wantJoin {
			t.Fatalf("Join(%q, %q) = %q, want %q", c.dir, c.elem, got, c.wantJoin)
		}
		if p := Parent(got); p != c.wantDir {
			t.Fatalf("Parent(%q) = %q, want %q", got, p, c.wantDir)
		}
		if b := Base(got); b != c.wantBase {
			t.Fatalf("Base(%q) = %q, want %q", got, b, c.wantBase)
		}
	}
	if p := Parent("/"); p != "/" {
		t.Fatalf(`Parent("/") = %q, want "/"`, p)
	}
}
