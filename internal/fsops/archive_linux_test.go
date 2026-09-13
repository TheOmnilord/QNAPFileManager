package fsops

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The archive's Linux half: the things only this kernel has — symlinks that are
// entries rather than doorways, filenames that are not text in any encoding,
// special files with no bytes to store, and a file the user may not read.
// Simulating any of them would be testing the simulation (INV-2).

// TestArchiveRecordsASymlinkAsASymlink is the rule that keeps an archive from
// quietly reaching outside the selection: a link is reproduced as a link, never
// followed and copied.
func TestArchiveRecordsASymlinkAsASymlink(t *testing.T) {
	r, base := archiveFixture(t)
	if err := os.Symlink("/etc/shadow", filepath.Join(base, "tree", "escape")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	link := m["tree/escape"]
	if link == nil {
		t.Fatalf("the symlink is missing: %v", memberNames(m))
	}
	if link.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("mode = %v, want a symlink (0120000)", link.Mode())
	}
	if got := zipContent(t, link); got != "/etc/shadow" {
		t.Fatalf("a symlink member's content is its target text, got %q", got)
	}

	tgz, err := runArchive(t, r, archiveReq(ArchiveTGZ, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	heads, bodies := tarMembers(t, tgz.buf.Bytes())
	h := heads["tree/escape"]
	if h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != "/etc/shadow" {
		t.Fatalf("tar symlink header = %+v", h)
	}
	if bodies["tree/escape"] != "" {
		t.Errorf("a tar symlink has no content, got %q", bodies["tree/escape"])
	}
}

// TestArchiveKeepsANonUTF8Name: a Linux filename is an arbitrary byte string,
// and the one thing an archive must not do is rewrite it into U+FFFD on the way
// through. The UTF-8 flag stays unset so no extractor is told to decode bytes
// that are not text.
func TestArchiveKeepsANonUTF8Name(t *testing.T) {
	r, base := archiveFixture(t)
	raw := "tree/bad\xff\xfename.txt"
	if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(raw)), []byte("x"), 0o644); err != nil {
		t.Skipf("this filesystem will not take the name: %v", err)
	}

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	want := "tree/bad\xff\xfename.txt"
	m := zipMembers(t, s.buf.Bytes())
	f := m[want]
	if f == nil {
		t.Fatalf("the raw name did not survive: %v", memberNames(m))
	}
	if !f.NonUTF8 {
		t.Error("a name that is not UTF-8 must not carry the UTF-8 flag")
	}
	if zipContent(t, f) != "x" {
		t.Error("content lost")
	}

	tgz, err := runArchive(t, r, archiveReq(ArchiveTGZ, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	heads, _ := tarMembers(t, tgz.buf.Bytes())
	if heads[want] == nil {
		t.Fatalf("the raw name did not survive the tar: %v", headerNames(heads))
	}
}

// TestArchiveSkipsASpecialFileAndKeepsTheTrailer: a fifo has no bytes in the
// filesystem to archive, so it is noted and skipped — and the archive is still
// a complete, extractable one.
func TestArchiveSkipsASpecialFileAndKeepsTheTrailer(t *testing.T) {
	r, base := archiveFixture(t)
	fifo := filepath.Join(base, "tree", "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/pipe"] != nil {
		t.Errorf("a fifo has no contents and must not be a member: %v", memberNames(m))
	}
	if m["tree/one.txt"] == nil {
		t.Errorf("the rest of the tree was lost: %v", memberNames(m))
	}
	notes := m["ERROR.txt"]
	if notes == nil {
		t.Fatalf("the skip must be recorded: %v", memberNames(m))
	}
	if body := zipContent(t, notes); !strings.Contains(body, "pipe") {
		t.Errorf("ERROR.txt = %q", body)
	}
}

// TestArchiveNotesAnUnreadableFileAndCarriesOn is the per-item rule: EACCES on
// one file of a tree is a line in ERROR.txt, not the end of the download.
func TestArchiveNotesAnUnreadableFileAndCarriesOn(t *testing.T) {
	requireOwnPermissions(t)
	r, base := archiveFixture(t)
	locked := filepath.Join(base, "tree", "locked.txt")
	if err := os.WriteFile(locked, []byte("secret"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/locked.txt"] != nil {
		t.Error("a file that could not be opened must not appear as a member")
	}
	if m["tree/one.txt"] == nil {
		t.Errorf("the readable half was lost: %v", memberNames(m))
	}
	notes := m["ERROR.txt"]
	if notes == nil {
		t.Fatalf("the failure must be recorded: %v", memberNames(m))
	}
	if body := zipContent(t, notes); !strings.Contains(body, "locked.txt") {
		t.Errorf("ERROR.txt = %q", body)
	}
}

// TestArchiveRecordsUnixModes: the mode a member carries is the file's own, so
// an extracted tree keeps its executables executable.
func TestArchiveRecordsUnixModes(t *testing.T) {
	r, base := archiveFixture(t)
	script := filepath.Join(base, "tree", "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if got := m["tree/run.sh"].Mode().Perm(); got != 0o755 {
		t.Errorf("zip mode = %o, want 0755", got)
	}
	if got := m["tree/one.txt"].Mode().Perm(); got != 0o644 {
		t.Errorf("zip mode = %o, want 0644", got)
	}

	tgz, err := runArchive(t, r, archiveReq(ArchiveTGZ, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	heads, _ := tarMembers(t, tgz.buf.Bytes())
	if got := heads["tree/run.sh"].FileInfo().Mode().Perm(); got != 0o755 {
		t.Errorf("tar mode = %o, want 0755", got)
	}
}

// TestArchiveDoesNotFollowASymlinkedDirectory: a link to a directory is one
// member, and its target's contents are not in the archive at all.
func TestArchiveDoesNotFollowASymlinkedDirectory(t *testing.T) {
	r, base := archiveFixture(t)
	if err := os.Symlink(filepath.Join(base, "other"), filepath.Join(base, "tree", "elsewhere")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/elsewhere"] == nil {
		t.Fatalf("the link itself is missing: %v", memberNames(m))
	}
	if m["tree/elsewhere/one.txt"] != nil {
		t.Fatalf("the walk went through a symlink: %v", memberNames(m))
	}
	if m["tree/elsewhere"].Mode()&fs.ModeSymlink == 0 {
		t.Errorf("mode = %v", m["tree/elsewhere"].Mode())
	}
}

// TestArchiveDisambiguatesTwoLongBasenames is round 7 adversarial for the
// archive: two files from different directories with identical 255-byte
// basenames. The member the allocator invents for the second must still be a
// name a filesystem will take, or the archive completes silently and the user's
// unzip fails with ENAMETOOLONG on a download they waited for.
func TestArchiveDisambiguatesTwoLongBasenames(t *testing.T) {
	r, base := archiveFixture(t)
	long := strings.Repeat("a", maxNameBytes-4) + ".txt"
	if len(long) != maxNameBytes {
		t.Fatalf("the fixture name is %d bytes, not %d", len(long), maxNameBytes)
	}
	write(t, base, "tree/"+long, "from tree")
	write(t, base, "other/"+long, "from other")

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/"+long, "/other/"+long))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if len(m) != 2 {
		t.Fatalf("members = %v", memberNames(m))
	}
	bodies := map[string]bool{}
	for name, f := range m {
		if len(name) > maxNameBytes {
			t.Errorf("the member name is %d bytes and cannot be extracted: %q", len(name), name)
		}
		if !strings.HasSuffix(name, ".txt") {
			t.Errorf("the extension was lost: %q", name)
		}
		bodies[zipContent(t, f)] = true
	}
	if !bodies["from tree"] || !bodies["from other"] {
		t.Fatalf("both files must be in the archive, got %v", bodies)
	}
}

// TestArchiveRefusesARootWhoseParentWasSwapped is M2-C review round 13's first
// finding, and it is the whole reason the archive carries a plan.
//
// Authorization, the guard and ArchiveCheck all finish before the first byte
// leaves. The roots after the first are reached minutes later, while earlier
// members are still streaming, and an administrator archiving a large file
// followed by /safe/config.json could use that window: rename /safe away and
// leave something else in its place. A producer that resolved the path again
// would archive whatever answered to it — refuseRoot is a mount and snapshot
// rule, not the web guard, so nothing else would have objected.
//
// Both substitutions are tested, because they fail at different gates: a
// SYMLINK is refused by the O_NOFOLLOW walk itself, and a real DIRECTORY gets
// past that and is caught by the recorded identity. Neither may contribute a
// byte to the archive.
func TestArchiveRefusesARootWhoseParentWasSwapped(t *testing.T) {
	const secret = "the daemon's own configuration"

	for _, c := range []struct {
		name    string
		replace func(t *testing.T, base string)
	}{
		{"symlink", func(t *testing.T, base string) {
			if err := os.Symlink(filepath.Join(base, "secrets"), filepath.Join(base, "safe")); err != nil {
				t.Skipf("symlinks are not available here: %v", err)
			}
		}},
		{"directory", func(t *testing.T, base string) {
			if err := os.Mkdir(filepath.Join(base, "safe"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "safe", "config.json"), []byte(secret), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, base := archiveFixture(t)
			mkdir(t, base, "safe")
			write(t, base, "safe/config.json", "the authorized file")
			mkdir(t, base, "secrets")
			write(t, base, "secrets/config.json", secret)

			// Between the first root and the second: exactly the window the
			// producer has.
			betweenRoots(t, 1, func() {
				if err := os.Rename(filepath.Join(base, "safe"), filepath.Join(base, "safe-moved")); err != nil {
					t.Fatal(err)
				}
				c.replace(t, base)
			})

			s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/safe/config.json"))
			if err != nil {
				t.Fatal(err)
			}
			m := zipMembers(t, s.buf.Bytes())
			if m["one.txt"] == nil {
				t.Fatalf("the rest of the selection was lost: %v", memberNames(m))
			}
			if m["config.json"] != nil {
				t.Fatalf("the substituted root was archived: %q", zipContent(t, m["config.json"]))
			}
			notes := m["ERROR.txt"]
			if notes == nil {
				t.Fatalf("the refusal must be recorded: %v", memberNames(m))
			}
			if body := zipContent(t, notes); !strings.Contains(body, "config.json") {
				t.Errorf("ERROR.txt does not name what was skipped: %q", body)
			}
			// The strongest assertion: the replacement's bytes are nowhere in
			// the stream, compressed or not.
			if bytes.Contains(s.buf.Bytes(), []byte(secret)) {
				t.Fatal("the archive carries bytes from the substituted directory")
			}
		})
	}
}

// TestArchiveRefusesARootThatWasItselfReplaced is the other half of the
// comparison: the directory holding it never changed, and the ENTRY did.
func TestArchiveRefusesARootThatWasItselfReplaced(t *testing.T) {
	const secret = "somebody else's file"
	r, base := archiveFixture(t)
	write(t, base, "tree/target.txt", "the authorized file")

	// The replacement is created FIRST and renamed over the target, so its
	// inode is certainly a different one: removing and recreating could be
	// handed the inode number that was just freed, and this test would then be
	// asserting the allocator's mood rather than the identity check.
	if err := os.WriteFile(filepath.Join(base, "tree", "replacement.txt"), []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	betweenRoots(t, 1, func() {
		if err := os.Rename(
			filepath.Join(base, "tree", "replacement.txt"),
			filepath.Join(base, "tree", "target.txt")); err != nil {
			t.Fatal(err)
		}
	})

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/tree/target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["target.txt"] != nil {
		t.Fatalf("the replaced entry was archived: %q", zipContent(t, m["target.txt"]))
	}
	if m["one.txt"] == nil {
		t.Fatalf("the rest of the selection was lost: %v", memberNames(m))
	}
	if m["ERROR.txt"] == nil {
		t.Fatalf("the refusal must be recorded: %v", memberNames(m))
	}
	if body := zipContent(t, m["ERROR.txt"]); !strings.Contains(body, "changed") {
		t.Errorf("ERROR.txt = %q, want it to say the item changed", body)
	}
	if bytes.Contains(s.buf.Bytes(), []byte(secret)) {
		t.Fatal("the archive carries the replacement's bytes")
	}
}

// TestArchiveOfAnUnchangedSelectionIsNotRefused keeps the identity check from
// being a blanket refusal: the ordinary case must still archive everything.
func TestArchiveOfAnUnchangedSelectionIsNotRefused(t *testing.T) {
	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/other/one.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["one.txt"] == nil || m["one (2).txt"] == nil || m["ERROR.txt"] != nil {
		t.Fatalf("members = %v", memberNames(m))
	}
}

// TestArchiveRefusesARootReplacedBetweenTheStatAndTheOpen is M2-C review round
// 14: the identity was proved on the lstat that classified the root, and the
// directory that was then ENUMERATED came from a separate openat. O_NOFOLLOW
// refuses a symlink at that name and has nothing to say about a different real
// directory, and neither a.tree nor walkFrom compared the descriptor to
// anything — so the whole of the replacement was archived under the selected
// root's name, with no warning anywhere.
//
// The window is two adjacent syscalls wide, so it is staged through the seam
// the open goes through.
func TestArchiveRefusesARootReplacedBetweenTheStatAndTheOpen(t *testing.T) {
	const secret = "the replacement's contents"
	r, base := archiveFixture(t)
	mkdir(t, base, "safe")
	write(t, base, "safe/config.json", "the authorized file")
	mkdir(t, base, "replacement")
	write(t, base, "replacement/config.json", secret)

	swapped := false
	prev := archiveOpenRoot
	archiveOpenRoot = func(d *dirRef, name string) (*dirRef, error) {
		if name == "safe" && !swapped {
			swapped = true
			if err := os.Rename(filepath.Join(base, "safe"), filepath.Join(base, "safe-moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(base, "replacement"), filepath.Join(base, "safe")); err != nil {
				t.Fatal(err)
			}
		}
		return prev(d, name)
	}
	t.Cleanup(func() { archiveOpenRoot = prev })

	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree/one.txt", "/safe"))
	if err != nil {
		t.Fatal(err)
	}
	if !swapped {
		t.Fatal("the seam never fired; this test proves nothing")
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["one.txt"] == nil {
		t.Fatalf("the rest of the selection was lost: %v", memberNames(m))
	}
	for _, name := range []string{"safe/", "safe/config.json"} {
		if m[name] != nil {
			t.Fatalf("the replacement was archived as %q: %q", name, zipContent(t, m[name]))
		}
	}
	notes := m["ERROR.txt"]
	if notes == nil {
		t.Fatalf("the refusal must be recorded: %v", memberNames(m))
	}
	body := zipContent(t, notes)
	if !strings.Contains(body, "/safe") || !strings.Contains(body, "changed") {
		t.Errorf("ERROR.txt = %q, want it to name /safe and say it changed", body)
	}
	if bytes.Contains(s.buf.Bytes(), []byte(secret)) {
		t.Fatal("the archive carries the replacement's bytes")
	}
}

// TestArchiveOfADirectoryRootOpensWhatItChecked keeps the new comparison from
// being a blanket refusal: an untouched directory root is still archived whole.
func TestArchiveOfADirectoryRootOpensWhatItChecked(t *testing.T) {
	r, _ := archiveFixture(t)
	s, err := runArchive(t, r, archiveReq(ArchiveZip, "/tree"))
	if err != nil {
		t.Fatal(err)
	}
	m := zipMembers(t, s.buf.Bytes())
	if m["tree/"] == nil || m["tree/one.txt"] == nil || m["ERROR.txt"] != nil {
		t.Fatalf("members = %v", memberNames(m))
	}
}
