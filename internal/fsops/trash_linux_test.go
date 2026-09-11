package fsops

// The trash checks that only a real Linux kernel can be asked about (INV-2).

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestTrashSidecarMustBeARegularFile is F8. meta.json lives inside a directory
// in a 1777 tree, so it is attacker-controlled, and a fifo planted at that name
// would park a worker goroutine inside open(2) with no writer — where no
// deadline in this process can reach it. Sixty-four such entries would take
// every slot the worker has.
//
// The sidecar is therefore opened O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
// through the entry directory's own descriptor and then fstat'ed: a fifo is not
// a regular file, so it is skipped, and the open returned instead of blocking.
func TestTrashSidecarMustBeARegularFile(t *testing.T) {
	r, plat, base, _ := trashFixture(t)
	uid := selfUID()
	const id = "1700000000-f1f0f1f0"
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(entry, trashMetaName), 0o600); err != nil {
		t.Skipf("this filesystem will not take a fifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The listing must come back, and promptly: a blocked open would hang here
	// until the test binary's own timeout rather than failing.
	done := make(chan []string, 1)
	go func() {
		items, err := TrashList(context.Background(), r, plat, uid)
		if err != nil {
			done <- []string{"error: " + err.Error()}
			return
		}
		names := make([]string, 0, len(items))
		for _, it := range items {
			names = append(names, string(it.Name))
		}
		done <- names
	}()
	select {
	case names := <-done:
		if len(names) != 0 {
			t.Fatalf("TrashList = %v, want the fifo sidecar skipped", names)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("TrashList blocked on a fifo standing in for meta.json")
	}

	// And a restore of it is refused rather than blocked.
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if len(restore.warns) != 1 || restore.warns[0].Code != "protected" {
		t.Fatalf("warns = %v, want protected", restore.warns)
	}
}

// TestTrashSidecarMustBeOwnedByTheReader is the ownership half of F8, and it
// needs a second uid: only root can hand a file to somebody else. The CI root
// job runs it.
func TestTrashSidecarMustBeOwnedByTheReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file away needs root; the CI root job runs this one")
	}
	r, plat, base, api := trashFixture(t)
	uid := selfUID() // 0 here: an administrator's session, whose trash is <trash>/0/
	const id = "1700000000-0f0f0f0f"
	entry := trashEntryDir(base, uid, id)
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(entry, trashMetaName)
	if err := os.WriteFile(meta, []byte(`{"origPath":"`+api+`/planted.txt","name":"planted.txt","type":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, trashItemName), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The sidecar is nobody's business but the reader's, and this one is not
	// theirs: uid 65534 is nobody on every distribution the NAS resembles.
	if err := os.Chown(meta, 65534, 65534); err != nil {
		t.Skipf("cannot give the sidecar away here: %v", err)
	}

	items, err := TrashList(context.Background(), r, plat, uid)
	if err != nil {
		t.Fatalf("TrashList: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("TrashList = %+v, want the foreign sidecar skipped", items)
	}
	var restore jobLog
	res, err := TrashRestore(context.Background(), r, plat, uid, []string{id}, restore.emit())
	if err != nil {
		t.Fatalf("TrashRestore: %v", err)
	}
	if res.Files != 0 || res.Skipped != 1 {
		t.Fatalf("result = %+v, want the restore refused", res)
	}
	if exists(t, base, "planted.txt") {
		t.Fatal("a sidecar owned by somebody else chose where a root worker wrote")
	}
}
