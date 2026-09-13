package fsops

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"qnapfilemanager/internal/wproto"
)

// rewriteMidRead makes the transfer read part of the source, rewrite it
// underneath itself with the same number of bytes, and then read the rest — so
// what arrives is exactly the right length and is neither version.
//
// The modification time is moved on as well, and that is about the TEST rather
// than about the engine. On Linux the change time carries the detection: it
// moves on any write and nothing a writer can call moves it back, which is
// exactly why the engine compares it. Windows has no change time for the engine
// to compare, and NTFS updates the last-write time lazily — often not until the
// handle closes — so an equal-length rewrite through another handle can leave
// the modification time unchanged at the moment of the stat that follows the
// read. That is the dev box's timestamp latency, not the property under test:
// what is asserted here is that a source which CHANGED is not published, so the
// change is made unambiguous. On Linux the stamp changes nothing, since the
// change time has already moved.
func rewriteMidRead(t *testing.T, path, with string, prefix int) {
	t.Helper()
	prev := copyStream
	copyStream = func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
		head := make([]byte, prefix)
		n1, err := io.ReadFull(src, head)
		if err != nil && n1 == 0 {
			return 0, err
		}
		if _, werr := dst.Write(head[:n1]); werr != nil {
			return int64(n1), werr
		}
		before, serr := os.Lstat(path)
		if serr != nil {
			return int64(n1), serr
		}
		if werr := os.WriteFile(path, []byte(with), 0o644); werr != nil {
			return int64(n1), werr
		}
		when := before.ModTime().Add(time.Second)
		if cerr := os.Chtimes(path, when, when); cerr != nil {
			return int64(n1), cerr
		}
		n2, cerr := io.Copy(dst, src)
		return int64(n1) + n2, cerr
	}
	t.Cleanup(func() { copyStream = prev })
}

// TestAnEqualLengthRewriteDuringTheReadIsNotPublished is the round-8
// adversarial probe, and it is a COPY bug before it is a move one: "AABB" is
// four bytes, so the length check passed, and under overwrite it was published
// over an intact destination — which then held neither the old file nor the new
// one.
func TestAnEqualLengthRewriteDuringTheReadIsNotPublished(t *testing.T) {
	for _, tc := range []struct {
		name     string
		conflict string
		move     bool
	}{
		{name: "overwrite", conflict: wproto.ConflictOverwrite},
		{name: "create", conflict: wproto.ConflictSkip},
		{name: "move", conflict: wproto.ConflictSkip, move: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tempDir(t)
			mkdir(t, base, "src")
			mkdir(t, base, "dst")
			write(t, base, "src/probe.txt", "AAAA")
			if tc.conflict == wproto.ConflictOverwrite {
				write(t, base, "dst/probe.txt", "the original bytes")
			}
			r := newRoot(t, base)
			if tc.move {
				forceEXDEV(t)
			}
			rewriteMidRead(t, filepath.Join(base, "src", "probe.txt"), "BBBB", 2)
			var log jobLog

			res, err := Copy(context.Background(), r, nil,
				copyReq("/dst", wproto.CopyOptions{Conflict: tc.conflict}, "/src/probe.txt"), tc.move, log.emit())
			if err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if res.Files != 0 || res.Skipped != 1 {
				t.Fatalf("result = %+v, want the entry counted as not copied", res)
			}
			if indexOf(log.codes(), warnChanged) < 0 {
				t.Fatalf("warn codes = %v, want %q", log.codes(), warnChanged)
			}
			switch tc.conflict {
			case wproto.ConflictOverwrite:
				if got := readFile(t, base, "dst/probe.txt"); got != "the original bytes" {
					t.Fatalf("dst/probe.txt = %q — a mixed copy was published over an intact file", got)
				}
			default:
				if exists(t, base, "dst/probe.txt") {
					got := readFile(t, base, "dst/probe.txt")
					t.Fatalf("dst/probe.txt = %q — a mixed copy was published", got)
				}
			}
			if tc.move && !exists(t, base, "src/probe.txt") {
				t.Fatal("the source was deleted for an entry that was never published")
			}
			assertNoTempLeft(t, base, "dst")
		})
	}
}
