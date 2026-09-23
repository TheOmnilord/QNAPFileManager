package fsops

// The recursive chmod against decision 9's read-only exception, on a real
// kernel and unprivileged: every file here is one this process owns, so the
// change itself is not a permission question (INV-2), only a crossing one.

import (
	"context"
	"path/filepath"
	"testing"

	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/wproto"
)

// TestChmodTreeNeverTakesTheReadRule: the mode job passes Mutating:false to the
// walk while it writes (mode_job.go), which is exactly why the read rule is an
// explicit opt-in and not "!Mutating". A recursive chmod of the RAM disk with
// "include mounted sub-folders" on must leave every volume under it alone.
func TestChmodTreeNeverTakesTheReadRule(t *testing.T) {
	base := ramDiskShare(t)
	r, api := hostRoot(t, base)
	plat := ramDiskPlatform(t, api)

	inside := filepath.Join(base, "share", "ZFS530_DATA", "Public", "qkvm-notes.txt")
	before := modeOf(t, inside)

	var warns []wproto.Warn
	if _, err := ChmodTree(context.Background(), r, plat, []string{api + "/share"}, ChmodOptions{
		Files:       perm.ModeSpec{Mask: 0o7777, Value: 0o0600},
		Dirs:        perm.ModeSpec{Mask: 0o7777, Value: 0o0700},
		Recursive:   true,
		CrossMounts: true,
	}, collect(&warns)); err != nil {
		t.Fatalf("ChmodTree = %v", err)
	}
	if after := modeOf(t, inside); after != before {
		t.Fatalf("mode of a file on a volume under the RAM disk went %o -> %o: the chmod crossed", before, after)
	}
	for _, rel := range []string{"ZFS530_DATA", "ZFS531_DATA"} {
		if m := modeOf(t, filepath.Join(base, "share", rel)); m == 0o700 {
			t.Errorf("%s was changed to 0700: a mount point the job may not enter was treated as its own", rel)
		}
	}
}
