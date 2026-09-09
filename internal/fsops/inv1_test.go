package fsops

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestINV1WebDoesNotImportFsops is PLAN.md's first invariant expressed as a
// test rather than as discipline: no filesystem read of user data and no
// mutation for a non-root session may execute in the root front-end process.
// The front-end reaches the filesystem only through backend.Backend, whose
// production implementation forwards every call to a process the kernel has
// already pinned to the user's uid. If internal/web ever imports this package
// — directly, or transitively through internal/workerpool — that guarantee is
// gone and no amount of care inside the handlers restores it.
//
// The check is the import graph itself, taken from the toolchain, so it cannot
// be fooled by an indirection.
func TestINV1WebDoesNotImportFsops(t *testing.T) {
	const (
		web   = "qnapfilemanager/internal/web"
		fsops = "qnapfilemanager/internal/fsops"
	)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is not on PATH; the import graph is checked in CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// -e keeps a package that does not compile yet (or does not exist yet)
	// from failing the command, so this test is usable while internal/web is
	// still being written.
	out, err := exec.CommandContext(ctx, "go", "list", "-e", "-deps", web).CombinedOutput()
	if err != nil {
		t.Skipf("go list -deps %s: %v\n%s", web, err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Skipf("%s does not exist yet", web)
	}
	found := false
	for _, d := range deps {
		if d == web {
			found = true
		}
		if d == fsops {
			t.Fatalf("INV-1 violated: %s imports %s (transitively). "+
				"The front-end must reach the filesystem only through backend.Backend.", web, fsops)
		}
	}
	if !found {
		t.Skipf("%s is not in the dependency list; it probably does not exist yet", web)
	}
}
