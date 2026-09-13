package workerpool

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// ownerOf reads the uid behind a FileInfo, so a test can assert that what a
// worker created belongs to the user the worker is.
func ownerOf(t *testing.T, fi os.FileInfo) int {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat behind %s", fi.Name())
	}
	return int(st.Uid)
}

// M2-C through a REAL spawned worker with real credentials: the upload's
// descriptor, the archive's pipe and the search job, each making the whole trip
// the NAS makes. They live beside the other root tests for the reason
// requireLinuxRoot gives — spawning a worker as another user needs root, and
// simulating it would be testing the simulation (PLAN.md INV-2).

// TestUploadThroughARealWorker is contract §1 end to end: the worker creates
// the file as the user, the pool streams the body into the descriptor it was
// handed over SCM_RIGHTS, and the published file belongs to that user.
func TestUploadThroughARealWorker(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")

	dir := filepath.Join(base, "drop")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, alice.UID, alice.GID); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	ctx := context.Background()
	who := principalOf(alice)

	body := []byte("uploaded by alice")
	f, resp, err := p.OpenWrite(ctx, who, wproto.OpenWriteReq{
		Dir:  []byte("/drop"),
		Name: []byte("note.txt"),
		Size: int64(len(body)),
	})
	if err != nil {
		t.Fatalf("OpenWrite: %v", err)
	}
	if len(resp.Tmp) == 0 {
		t.Fatal("the reply carried no handle")
	}
	// Nothing is named in the destination while the body is in flight.
	if _, serr := os.Stat(filepath.Join(dir, "note.txt")); !os.IsNotExist(serr) {
		t.Errorf("the name exists before Finalize: %v", serr)
	}
	if _, werr := f.Write(body); werr != nil {
		f.Close()
		t.Fatalf("streaming into the passed descriptor: %v", werr)
	}
	f.Close()

	fin, err := p.Finalize(ctx, who, wproto.FinalizeReq{Tmp: resp.Tmp, Final: []byte("note.txt")})
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if string(fin.Path) != "/drop/note.txt" || fin.Entry.Size != int64(len(body)) {
		t.Fatalf("resp = %+v", fin)
	}
	got, rerr := os.ReadFile(filepath.Join(dir, "note.txt"))
	if rerr != nil || string(got) != string(body) {
		t.Fatalf("the published file is %q (%v)", got, rerr)
	}
	// The worker IS the user, so what it created belongs to the user — no
	// chown was asked for and none was needed.
	fi, err := os.Stat(filepath.Join(dir, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if uid := ownerOf(t, fi); uid != alice.UID {
		t.Fatalf("the uploaded file belongs to uid %d, want %d", uid, alice.UID)
	}
}

// TestUploadThroughARealWorkerRefusesWhatTheKernelRefuses: the permission check
// is the kernel's, made in the worker, at create time (INV-2).
func TestUploadThroughARealWorkerRefusesWhatTheKernelRefuses(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	bob := fixtureUser(t, "qfmbob", "qfmother")

	private := filepath.Join(base, "alice-only")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(private, alice.UID, alice.GID); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	ctx := context.Background()
	f, _, err := p.OpenWrite(ctx, principalOf(bob), wproto.OpenWriteReq{
		Dir: []byte("/alice-only"), Name: []byte("intrusion.txt"),
	})
	if err == nil {
		f.Close()
		t.Fatal("bob created a file in alice's 0700 directory")
	}
	if _, serr := os.Stat(filepath.Join(private, "intrusion.txt")); !os.IsNotExist(serr) {
		t.Errorf("a refused upload created something: %v", serr)
	}
}

// TestArchiveThroughARealWorker: the pipe's read end arrives on the reply
// frame and the archive comes down it.
func TestArchiveThroughARealWorker(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")

	tree := filepath.Join(base, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "sub", "deep.txt"), []byte("deeper"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	rc, resp, err := p.Archive(context.Background(), principalOf(alice), wproto.ArchiveReq{
		Paths: [][]byte{[]byte("/tree")}, Format: "zip",
	})
	if err != nil {
		t.Fatalf("Archive: %v", err)
	}
	defer rc.Close()
	if string(resp.Name) != "tree.zip" {
		t.Errorf("name = %q", resp.Name)
	}
	blob, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the archive from the pipe: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("the archive did not read back: %v", err)
	}
	found := false
	for _, m := range zr.File {
		if m.Name == "tree/sub/deep.txt" {
			found = true
			rd, oerr := m.Open()
			if oerr != nil {
				t.Fatal(oerr)
			}
			b, _ := io.ReadAll(rd)
			rd.Close()
			if string(b) != "deeper" {
				t.Errorf("content = %q", b)
			}
		}
		if m.Name == "ERROR.txt" {
			t.Error("a clean archive has no ERROR.txt")
		}
	}
	if !found {
		t.Fatal("the archive did not carry the file")
	}
}

// TestSearchJobThroughARealWorker: a search job over the socket, with the hits
// on the terminal frame.
func TestSearchJobThroughARealWorker(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")

	tree := filepath.Join(base, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "sub", "Report.txt"), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "other.bin"), []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	body, err := json.Marshal(wproto.SearchReq{
		Roots:       [][]byte{[]byte("/tree")},
		Query:       "report",
		MaxHits:     1000,
		MaxVisited:  500000,
		MaxDuration: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Job(context.Background(), principalOf(alice), wproto.JobReq{
		JobID: "search-root-1",
		Kind:  wproto.JobSearch,
		Body:  body,
	}, nil, nil)
	if err != nil {
		t.Fatalf("JobSearch: %v", err)
	}
	if len(res.Hits) != 1 || res.Hits[0].Name != "Report.txt" {
		t.Fatalf("hits = %+v", res.Hits)
	}
	if res.Hits[0].Path != "/tree/sub/Report.txt" {
		t.Errorf("path = %q", res.Hits[0].Path)
	}
}
