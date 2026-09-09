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
	if got, err := r.OS("/etc/passwd"); err != nil || got != want {
		t.Fatalf("OS = %q, %v, want %q", got, err, want)
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
		got, err := r.OS(c.api)
		if err != nil || got != c.os {
			t.Errorf("OS(%q) = %q, %v, want %q", c.api, got, err, c.os)
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

// TestRootBackslashTraversal is the Windows escape the round-one review found:
// fsx.Clean treats "\" as a filename character, filepath.Join treats it as a
// separator, and "/..\..\PLAN.md" therefore used to land above the jail. The
// table branches on runtime.GOOS rather than living behind a build tag, so
// both halves are compiled — and vetted — on every platform.
func TestRootBackslashTraversal(t *testing.T) {
	base := t.TempDir()
	r, err := NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`/..\..\PLAN.md`,             // the escape itself
		`/share\..\..\..\etc\shadow`, // and a deeper one
		`/a\b`,                       // an ordinary Linux filename with a backslash in it
		`/share/Public/back\slash`,   // as written from a Windows SMB client
		"/etc/passwd",
	}
	for _, api := range cases {
		got, err := r.OS(api)
		// On Windows every backslash is refused, escaping or not: the
		// character cannot appear in a filename there, so nothing legitimate
		// is lost and no join can be talked into climbing out. On Linux they
		// are all ordinary names and none of them may leave the jail.
		if runtime.GOOS == "windows" && strings.ContainsRune(api, '\\') {
			if !errors.Is(err, ErrOutsideRoot) {
				t.Errorf("OS(%q) = %q, %v; want ErrOutsideRoot on Windows", api, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("OS(%q): %v", api, err)
			continue
		}
		if !r.Contains(got) {
			t.Errorf("OS(%q) = %q, which is outside %q", api, got, base)
		}
		if _, err := r.API(got); err != nil {
			t.Errorf("API(%q): %v", got, err)
		}
	}
	// Contains is the boundary check the mapping leans on, so it must compare
	// whole elements rather than string prefixes.
	if r.Contains(base + "-sibling") {
		t.Error("a sibling directory sharing the base's prefix must not be contained")
	}
	if !r.Contains(base) {
		t.Error("the base itself is contained")
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
		osPath, err := r.OS(api)
		if err != nil {
			t.Fatalf("OS(%q): %v", api, err)
		}
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
	with, err1 := r2.OS("/etc")
	without, err2 := r.OS("/etc")
	if err1 != nil || err2 != nil || with != without {
		t.Fatalf("trailing separator changed the mapping: %q (%v) vs %q (%v)", with, err1, without, err2)
	}
	if _, err := r.API(filepath.Join(filepath.Dir(base), "elsewhere")); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("a sibling directory must be outside the root, got %v", err)
	}
	if _, err := r.API(""); !errors.Is(err, ErrNotAbsolute) {
		t.Fatalf("an empty OS path must be rejected, got %v", err)
	}
}

// TestRootDriveRootBase is the round-four finding: on Windows a jail of "C:\"
// was trimmed to "C:", which names the drive's current directory, so the jail
// silently pointed at the working directory. The mapping must keep the volume
// root intact in both directions.
func TestRootDriveRootBase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive roots exist only on Windows")
	}
	r, err := NewRoot(`C:\`)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.base; got != `C:\` {
		t.Fatalf("base = %q, want C:\\", got)
	}
	osPath, err := r.OS("/Windows/notepad.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(osPath, `C:\Windows\notepad.exe`) {
		t.Fatalf("OS() = %q", osPath)
	}
	api, err := r.API(`C:\Windows\notepad.exe`)
	if err != nil || api != "/Windows/notepad.exe" {
		t.Fatalf("API() = %q, %v", api, err)
	}
	if !r.Contains(`C:\Windows`) || r.Contains(`D:\Windows`) {
		t.Fatal("Contains misjudged a drive-root jail")
	}
	if root, err := r.OS("/"); err != nil || root != `C:\` {
		t.Fatalf("OS(\"/\") = %q, %v", root, err)
	}
}
