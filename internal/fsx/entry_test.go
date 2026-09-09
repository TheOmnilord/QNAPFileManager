package fsx

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf8"
)

func TestSetNameAndPath(t *testing.T) {
	// The legacy-share case: a name that is not valid UTF-8. encoding/json
	// would silently replace the bytes with U+FFFD, so the raw form has to
	// travel in NameB64 or the file becomes unreachable from the UI.
	bad := []byte{0x66, 0x6f, 0x6f, 0xff, 0xfe, 0x2e, 0x74, 0x78, 0x74} // "foo\xff\xfe.txt"
	cases := []struct {
		name    string
		raw     []byte
		wantB64 bool
	}{
		{"ascii", []byte("notes.txt"), false},
		{"unicode", []byte("Bilder – 2024 ✓"), false},
		{"space and hash", []byte("a #b.txt"), false},
		{"invalid utf8", bad, true},
		{"lone continuation byte", []byte{0x80}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var e Entry
			e.SetName(c.raw)
			e.SetPath(append([]byte("/share/Public/"), c.raw...))
			if e.Name != string(c.raw) {
				t.Fatalf("Name = %q, want %q", e.Name, string(c.raw))
			}
			if c.wantB64 {
				if e.NameB64 == "" || e.PathB64 == "" {
					t.Fatal("want NameB64 and PathB64 set for a non-UTF-8 name")
				}
				got, err := base64.RawURLEncoding.DecodeString(e.NameB64)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(c.raw) {
					t.Fatalf("NameB64 decoded to %q, want %q", got, c.raw)
				}
				// The point of the exercise: Name itself does not survive JSON.
				b, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				var back Entry
				if err := json.Unmarshal(b, &back); err != nil {
					t.Fatal(err)
				}
				if back.Name == e.Name {
					t.Skip("this Go release round-trips invalid UTF-8 through JSON; NameB64 is still the contract")
				}
				if back.NameB64 != e.NameB64 {
					t.Fatalf("NameB64 did not survive JSON: %q vs %q", back.NameB64, e.NameB64)
				}
				raw, err := base64.RawURLEncoding.DecodeString(back.NameB64)
				if err != nil || string(raw) != string(c.raw) {
					t.Fatalf("could not recover the raw name from JSON: %q, %v", raw, err)
				}
			} else {
				if !utf8.Valid(c.raw) {
					t.Fatal("test case is wrong")
				}
				if e.NameB64 != "" || e.PathB64 != "" {
					t.Fatalf("want no base64 form for a valid UTF-8 name, got %q/%q", e.NameB64, e.PathB64)
				}
			}
		})
	}
}

// SetName must clear a stale base64 form when the entry is reused.
func TestSetNameClearsStaleB64(t *testing.T) {
	var e Entry
	e.SetName([]byte{0xff})
	if e.NameB64 == "" {
		t.Fatal("want NameB64 set")
	}
	e.SetName([]byte("clean.txt"))
	if e.NameB64 != "" {
		t.Fatalf("NameB64 = %q, want it cleared", e.NameB64)
	}
}

func TestModeString(t *testing.T) {
	cases := []struct {
		name string
		mode fs.FileMode
		want string
	}{
		{"regular 644", 0o644, "-rw-r--r--"},
		{"dir 755", fs.ModeDir | 0o755, "drwxr-xr-x"},
		// The setgid share directory QTS creates, and the string in the spec.
		{"dir setgid", fs.ModeDir | fs.ModeSetgid | 0o755, "drwxr-sr-x"},
		{"setgid without group execute", fs.ModeDir | fs.ModeSetgid | 0o745, "drwxr-Sr-x"},
		{"setuid binary", fs.ModeSetuid | 0o4755, "-rwsr-xr-x"},
		{"setuid without owner execute", fs.ModeSetuid | 0o644, "-rwSr--r--"},
		{"sticky tmp", fs.ModeDir | fs.ModeSticky | 0o777, "drwxrwxrwt"},
		{"sticky without other execute", fs.ModeDir | fs.ModeSticky | 0o776, "drwxrwxrwT"},
		{"symlink", fs.ModeSymlink | 0o777, "lrwxrwxrwx"},
		{"fifo", fs.ModeNamedPipe | 0o600, "prw-------"},
		{"socket", fs.ModeSocket | 0o755, "srwxr-xr-x"},
		{"char device", fs.ModeDevice | fs.ModeCharDevice | 0o666, "crw-rw-rw-"},
		{"block device", fs.ModeDevice | 0o660, "brw-rw----"},
		{"no permissions", 0, "----------"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ModeString(c.mode); got != c.want {
				t.Fatalf("ModeString(%v) = %q, want %q", c.mode, got, c.want)
			}
		})
	}
}

func TestModeOctalAndType(t *testing.T) {
	cases := []struct {
		mode      fs.FileMode
		octal     string
		typeLabel string
	}{
		{0o644, "0644", "file"},
		{fs.ModeDir | 0o755, "0755", "dir"},
		{fs.ModeDir | fs.ModeSetgid | 0o2775, "2775", "dir"},
		{fs.ModeDir | fs.ModeSticky | 0o1777, "1777", "dir"},
		{fs.ModeSetuid | 0o4755, "4755", "file"},
		{fs.ModeSymlink | 0o777, "0777", "symlink"},
		{fs.ModeNamedPipe | 0o600, "0600", "fifo"},
		{fs.ModeSocket | 0o600, "0600", "socket"},
		{fs.ModeDevice | 0o660, "0660", "device"},
		{fs.ModeIrregular, "0000", "other"},
	}
	for _, c := range cases {
		if got := ModeOctal(c.mode); got != c.octal {
			t.Errorf("ModeOctal(%v) = %q, want %q", c.mode, got, c.octal)
		}
		if got := TypeString(c.mode); got != c.typeLabel {
			t.Errorf("TypeString(%v) = %q, want %q", c.mode, got, c.typeLabel)
		}
	}
}

func TestValidSortKey(t *testing.T) {
	for _, s := range []string{"", SortName, SortSize, SortMTime, SortType} {
		if !ValidSortKey(s) {
			t.Errorf("ValidSortKey(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"nope", "Name", "size ", "path"} {
		if ValidSortKey(s) {
			t.Errorf("ValidSortKey(%q) = true, want false", s)
		}
	}
}

// statDetail is the only place the platform split shows through to Entry, so
// exercise it against a real file on both builds: Linux fills the fields in,
// everything else returns zeros and callers must read that as "unknown".
func TestStatDetail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, dev, ino, nlink := statDetail(fi)
	if runtime.GOOS == "linux" {
		if nlink != 1 {
			t.Errorf("nlink = %d, want 1", nlink)
		}
		if ino == 0 || dev == 0 {
			t.Errorf("dev/ino = %d/%d, want both non-zero", dev, ino)
		}
		if uid < 0 || gid < 0 {
			t.Errorf("uid/gid = %d/%d, want non-negative", uid, gid)
		}
	} else if uid|gid != 0 || dev|ino|nlink != 0 {
		t.Errorf("off Linux every field must be zero, got %d %d %d %d %d", uid, gid, dev, ino, nlink)
	}
}
