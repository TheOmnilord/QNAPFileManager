package fsx

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRootIdentity(t *testing.T) {
	r, err := NewRoot("")
	if err != nil {
		t.Fatal(err)
	}
	if r.Jailed() {
		t.Fatal("an empty base must be the identity")
	}
	// "/" is what an operator writes for "no jail"; it must not turn into a
	// Windows drive root by way of filepath.Abs.
	r2, err := NewRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Jailed() {
		t.Fatal(`NewRoot("/") must be the identity`)
	}
	want := filepath.FromSlash("/etc/passwd")
	if got := r.OS("/etc/passwd"); got != want {
		t.Fatalf("OS = %q, want %q", got, want)
	}
	api, err := r.API(want)
	if err != nil {
		t.Fatal(err)
	}
	if api != "/etc/passwd" {
		t.Fatalf("API = %q, want /etc/passwd", api)
	}
}

// A jail base with a drive letter and a space in it is the everyday case on
// the Windows dev box: C:\Dev\QNAPFileManager\testdata\fakeroot, and the
// operator's own directories are worse.
func TestRootWindowsStyleBase(t *testing.T) {
	base := `C:\Dev\QNAP File Manager\testdata\fakeroot`
	if runtime.GOOS != "windows" {
		t.Skip("a drive-letter base is only meaningful on Windows")
	}
	r, err := NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Jailed() {
		t.Fatal("want a jailed root")
	}
	cases := []struct {
		api string
		os  string
	}{
		{"/", base},
		{"/etc/passwd", base + `\etc\passwd`},
		{"/share/Public/a #b.txt", base + `\share\Public\a #b.txt`},
		// Whatever the caller passes, OS may not climb out of the jail.
		{"/../../etc/shadow", base + `\etc\shadow`},
		{"/share/../etc", base + `\etc`},
	}
	for _, c := range cases {
		if got := r.OS(c.api); got != c.os {
			t.Errorf("OS(%q) = %q, want %q", c.api, got, c.os)
		}
	}
	for _, c := range cases[:3] {
		got, err := r.API(c.os)
		if err != nil {
			t.Fatalf("API(%q): %v", c.os, err)
		}
		if got != c.api {
			t.Errorf("API(%q) = %q, want %q", c.os, got, c.api)
		}
	}
	// Windows paths are case-insensitive, so a resolved path that came back
	// in a different case is still inside.
	if got, err := r.API(strings.ToLower(base) + `\etc`); err != nil || got != "/etc" {
		t.Errorf("API(lowercased base) = %q, %v; want /etc, nil", got, err)
	}
	for _, out := range []string{`C:\Dev\Other`, `C:\Dev\QNAP File Manager\testdata\fakeroot-2\x`, `D:\`} {
		if _, err := r.API(out); !errors.Is(err, ErrOutsideRoot) {
			t.Errorf("API(%q) = %v, want ErrOutsideRoot", out, err)
		}
	}
}

// The same round trip against a real temporary directory, which is what every
// other test in the tree will use.
func TestRootTempDirRoundTrip(t *testing.T) {
	base := t.TempDir()
	r, err := NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"/", "/etc", "/etc/passwd", "/share/Public/a #b.txt", "/share/Bilder – 2024"} {
		osPath := r.OS(api)
		if !strings.HasPrefix(osPath, base) {
			t.Fatalf("OS(%q) = %q, which is not under %q", api, osPath, base)
		}
		back, err := r.API(osPath)
		if err != nil {
			t.Fatalf("API(%q): %v", osPath, err)
		}
		if back != api {
			t.Fatalf("round trip: %q -> %q -> %q", api, osPath, back)
		}
	}
	// A trailing separator on the base must not change the mapping.
	r2, err := NewRoot(base + string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	if r2.OS("/etc") != r.OS("/etc") {
		t.Fatalf("trailing separator changed the mapping: %q vs %q", r2.OS("/etc"), r.OS("/etc"))
	}
	if _, err := r.API(filepath.Join(filepath.Dir(base), "elsewhere")); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("a sibling directory must be outside the root, got %v", err)
	}
	if _, err := r.API(""); !errors.Is(err, ErrNotAbsolute) {
		t.Fatalf("an empty OS path must be rejected, got %v", err)
	}
}
