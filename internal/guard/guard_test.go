package guard

import (
	"errors"
	"testing"

	"qnapfilemanager/internal/fsx"
)

// The eight ops, in a fixed column order the golden matrix relies on.
var matrixOps = []struct {
	name string
	op   Op
}{
	{"read", OpRead},
	{"traverse", OpTraverse},
	{"create", OpCreate},
	{"write", OpWrite},
	{"delete", OpDelete},
	{"rename", OpRename},
	{"chmod", OpChmod},
	{"chown", OpChown},
}

// outcome collapses a Check result to one of the four words the matrix uses.
func outcome(err error) string {
	switch {
	case err == nil:
		return "allow"
	case errors.Is(err, ErrReadOnly):
		return "readonly"
	case errors.Is(err, ErrConfirmRequired):
		return "confirm"
	case errors.Is(err, ErrProtected):
		return "deny"
	default:
		return "unexpected(" + err.Error() + ")"
	}
}

const testInstall = "/share/CACHEDEV1_DATA/.qpkg/QNAPFileManager"

// newMatrixGuard is the guard the golden matrix is written against: /share is
// the RAM disk, the QPKG lives at testInstall, and CACHEDEV1_DATA is a mount
// point.
func newMatrixGuard() *Guard {
	g := New(testInstall, true)
	g.SetMountPointChecker(func(p string) bool {
		return p == "/share/CACHEDEV1_DATA"
	})
	return g
}

// TestGoldenMatrix is the checked-in table of ~20 paths × 8 ops. Each row is
// the expected outcome per column in matrixOps order.
func TestGoldenMatrix(t *testing.T) {
	const (
		A = "allow"
		C = "confirm"
		D = "deny"
	)
	// Columns:            read  trav  create write  delete rename chmod  chown
	rows := []struct {
		path string
		want [8]string
	}{
		{"/", [8]string{A, A, A, A, D, D, A, A}},
		{"/etc", [8]string{A, A, A, A, D, D, A, A}},
		{"/etc/config", [8]string{A, A, C, C, D, C, C, C}},
		{"/etc/config/smb.conf", [8]string{A, A, C, C, C, C, C, C}},
		{"/etc/configuration", [8]string{A, A, A, A, A, A, A, A}}, // boundary vs /etc/config
		{"/etc/passwd", [8]string{A, A, A, A, A, A, A, A}},
		{"/proc", [8]string{A, A, D, D, D, D, D, D}},
		{"/proc/1/status", [8]string{A, A, D, D, D, D, D, D}},
		{"/sys/kernel", [8]string{A, A, D, D, D, D, D, D}},
		{"/dev", [8]string{A, A, A, D, D, D, C, C}},
		{"/dev/sda", [8]string{A, A, A, D, D, D, C, C}},
		{"/share", [8]string{A, A, D, A, D, D, A, A}},                // RAM-disk create trap + top-level delete/rename
		{"/share/CACHEDEV1_DATA", [8]string{A, A, A, A, D, D, A, A}}, // mount point
		{"/share/CACHEDEV1_DATA/Public", [8]string{A, A, A, A, A, A, A, A}},
		{"/share/CACHEDEV1_DATA/Public/.zfs", [8]string{A, A, D, D, D, D, D, D}},
		{"/share/CACHEDEV1_DATA/Public/.zfs/snapshot/s1/f", [8]string{A, A, D, D, D, D, D, D}},
		{testInstall, [8]string{A, A, D, D, D, D, D, D}},
		{testInstall + "/config", [8]string{D, D, D, D, D, D, D, D}},
		{testInstall + "/config/config.json", [8]string{D, D, D, D, D, D, D, D}},
		{testInstall + "/logs/audit.jsonl", [8]string{D, D, D, D, D, D, D, D}},
		{"/mnt/HDA_ROOT/.config/uLinux.conf", [8]string{A, A, C, C, C, C, C, C}},
		{"/home/admin/file.txt", [8]string{A, A, A, A, A, A, A, A}},
	}

	g := newMatrixGuard()
	for _, row := range rows {
		for i, oc := range matrixOps {
			got := outcome(g.Check(oc.op, row.path))
			if got != row.want[i] {
				t.Errorf("Check(%s, %q) = %s, want %s", oc.name, row.path, got, row.want[i])
			}
		}
	}
}

// TestConfigBoundary is the headline prefix-boundary case, asserted on its own.
func TestConfigBoundary(t *testing.T) {
	g := New("", false)
	if err := g.Check(OpWrite, "/etc/config/smb.conf"); !errors.Is(err, ErrConfirmRequired) {
		t.Errorf("write under /etc/config should need confirmation, got %v", err)
	}
	if err := g.Check(OpWrite, "/etc/configuration/x"); err != nil {
		t.Errorf("write under /etc/configuration must not be caught by the /etc/config rule, got %v", err)
	}
	if err := g.Check(OpWrite, "/etc/config"); !errors.Is(err, ErrConfirmRequired) {
		t.Errorf("write to /etc/config itself should confirm, got %v", err)
	}
	if got := g.Classify("/etc/config"); got != "warn" {
		t.Errorf("Classify(/etc/config) = %q, want warn", got)
	}
	if got := g.Classify("/etc/configuration"); got != "normal" {
		t.Errorf("Classify(/etc/configuration) = %q, want normal", got)
	}
}

// TestReadOnlyBlanket asserts read-only mode refuses every mutating op on an
// otherwise-normal path while leaving reads and traversal alone, and that it
// takes precedence over a protected path.
func TestReadOnlyBlanket(t *testing.T) {
	g := New("", false)
	g.SetReadOnly(true)
	if !g.ReadOnly() {
		t.Fatal("ReadOnly() should report true")
	}
	const p = "/share/CACHEDEV1_DATA/Public/file"
	for _, oc := range matrixOps {
		err := g.Check(oc.op, p)
		if oc.op == OpRead || oc.op == OpTraverse {
			if err != nil {
				t.Errorf("read-only Check(%s) = %v, want nil", oc.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("read-only Check(%s) = %v, want ErrReadOnly", oc.name, err)
		}
	}
	// Precedence: a delete of /etc under read-only is refused as read-only,
	// short-circuiting before the protected-path rule is even consulted.
	if err := g.Check(OpDelete, "/etc"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("read-only delete of /etc = %v, want ErrReadOnly", err)
	}
	g.SetReadOnly(false)
	if err := g.Check(OpWrite, p); err != nil {
		t.Errorf("after unlocking, write should be allowed, got %v", err)
	}
}

// TestRAMDiskCreate covers the /share create trap toggling on shareIsRAM.
func TestRAMDiskCreate(t *testing.T) {
	ram := New("", true)
	if err := ram.Check(OpCreate, "/share"); !errors.Is(err, ErrProtected) {
		t.Errorf("create directly under /share (RAM) should be protected, got %v", err)
	}
	// A directory deeper down is unaffected.
	if err := ram.Check(OpCreate, "/share/CACHEDEV1_DATA/Public"); err != nil {
		t.Errorf("create under a real volume should be allowed, got %v", err)
	}
	notRam := New("", false)
	if err := notRam.Check(OpCreate, "/share"); err != nil {
		t.Errorf("create under /share when not RAM should be allowed, got %v", err)
	}
	// Even when not RAM, /share itself may not be deleted or renamed.
	if err := notRam.Check(OpDelete, "/share"); !errors.Is(err, ErrProtected) {
		t.Errorf("delete of /share should be protected, got %v", err)
	}
}

// TestInstallDirProtection covers write-deny on the install tree and read-deny
// on its config/logs.
func TestInstallDirProtection(t *testing.T) {
	g := New(testInstall, false)
	if err := g.Check(OpWrite, testInstall+"/bin/qnapfilemanager"); !errors.Is(err, ErrProtected) {
		t.Errorf("write inside the install dir should be protected, got %v", err)
	}
	if err := g.Check(OpRead, testInstall+"/bin/qnapfilemanager"); err != nil {
		t.Errorf("reading the binary itself is allowed (only config/logs are read-denied), got %v", err)
	}
	for _, p := range []string{testInstall + "/config/config.json", testInstall + "/logs/audit.jsonl"} {
		if err := g.Check(OpRead, p); !errors.Is(err, ErrProtected) {
			t.Errorf("read of %q should be protected, got %v", p, err)
		}
		if err := g.Check(OpTraverse, p); !errors.Is(err, ErrProtected) {
			t.Errorf("traverse of %q should be protected, got %v", p, err)
		}
	}
	// With no install dir configured, none of these rules exist.
	none := New("", false)
	if err := none.Check(OpRead, "/anywhere/config/config.json"); err != nil {
		t.Errorf("no install dir means no install rules, got %v", err)
	}
}

// TestNeverWriteComponents covers .zfs (any depth), /proc and /sys.
func TestNeverWriteComponents(t *testing.T) {
	g := New("", false)
	writePaths := []string{
		"/share/CACHEDEV1_DATA/Public/.zfs/snapshot/s/f",
		"/x/.zfs/y",
		"/proc/1/mem",
		"/sys/class/net",
	}
	for _, p := range writePaths {
		for _, op := range []Op{OpCreate, OpWrite, OpDelete, OpRename, OpChmod, OpChown} {
			if err := g.Check(op, p); !errors.Is(err, ErrProtected) {
				t.Errorf("write op on %q should be protected, got %v", p, err)
			}
		}
		// Reading and traversing them is fine.
		if err := g.Check(OpRead, p); err != nil {
			t.Errorf("read of %q should be allowed, got %v", p, err)
		}
		if got := g.Classify(p); got != "protected" {
			t.Errorf("Classify(%q) = %q, want protected", p, got)
		}
	}
	// A directory merely containing "zfs" (not the exact ".zfs" component) is fine.
	if err := g.Check(OpWrite, "/share/CACHEDEV1_DATA/zfs-backups/f"); err != nil {
		t.Errorf("a path with a zfs-ish name is not the .zfs component, got %v", err)
	}
}

// TestMountPointDeletion covers the injected mount-point checker.
func TestMountPointDeletion(t *testing.T) {
	g := New("", false)
	g.SetMountPointChecker(func(p string) bool { return p == "/share/CACHEDEV1_DATA" })
	if err := g.Check(OpDelete, "/share/CACHEDEV1_DATA"); !errors.Is(err, ErrProtected) {
		t.Errorf("deleting a mount point should be protected, got %v", err)
	}
	if err := g.Check(OpRename, "/share/CACHEDEV1_DATA"); !errors.Is(err, ErrProtected) {
		t.Errorf("renaming a mount point should be protected, got %v", err)
	}
	// Writing inside it, and other ops on the root, are not blocked by the hook.
	if err := g.Check(OpWrite, "/share/CACHEDEV1_DATA"); err != nil {
		t.Errorf("writing a mount-point root is not blocked by the hook, got %v", err)
	}
	if got := g.Classify("/share/CACHEDEV1_DATA"); got != "protected" {
		t.Errorf("Classify(mount point) = %q, want protected", got)
	}
	// Clearing the hook removes the protection.
	g.SetMountPointChecker(nil)
	if err := g.Check(OpDelete, "/share/CACHEDEV1_DATA"); err != nil {
		t.Errorf("with no checker, the mount-point delete is allowed, got %v", err)
	}
}

// TestErrorCodeMapping confirms fsx.Code renders the guard sentinels as the API
// vocabulary expects.
func TestErrorCodeMapping(t *testing.T) {
	cases := map[error]string{
		ErrReadOnly:        "readonly",
		ErrProtected:       "protected",
		ErrConfirmRequired: "confirm_required",
		ErrConfirmInvalid:  "bad_request",
	}
	for err, want := range cases {
		if got := fsx.Code(err); got != want {
			t.Errorf("fsx.Code(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestClassifyNormal(t *testing.T) {
	g := New(testInstall, true)
	if got := g.Classify("/home/admin/docs"); got != "normal" {
		t.Errorf("Classify(normal path) = %q, want normal", got)
	}
	if got := g.Classify("/etc"); got != "protected" {
		t.Errorf("Classify(/etc) = %q, want protected (delete/rename denied)", got)
	}
}

// TestCanonicalizeRootsSymlinkedProtectedRoot proves adv 1a's canonicalization:
// when a protected root is itself a symlink (/etc/config -> /ordinary/config),
// the resolved location is guarded too, while the lexical spelling keeps its
// rule.
func TestCanonicalizeRootsSymlinkedProtectedRoot(t *testing.T) {
	g := New("", false)
	g.CanonicalizeRoots(func(apiPath string) (string, bool) {
		if apiPath == "/etc/config" {
			return "/ordinary/config", true
		}
		return "", false // every other root resolves to itself: no duplicate
	})
	// The resolved location now carries the /etc/config warn rule.
	if err := g.Check(OpWrite, "/ordinary/config/smb.conf"); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("resolved protected root not guarded: %v", err)
	}
	if err := g.Check(OpDelete, "/ordinary/config"); !errors.Is(err, ErrProtected) {
		t.Fatalf("resolved protected root not denied for delete: %v", err)
	}
	// The lexical spelling keeps its protection.
	if err := g.Check(OpWrite, "/etc/config/smb.conf"); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("lexical protected root lost protection: %v", err)
	}
	// An unrelated path is still normal.
	if err := g.Check(OpWrite, "/ordinary/other/file"); err != nil {
		t.Fatalf("unrelated path wrongly guarded: %v", err)
	}
}

// TestCanonicalizeRootsNilAndIdentity proves a nil resolver and identity
// resolutions add no rules (no accidental broadening).
func TestCanonicalizeRootsNilAndIdentity(t *testing.T) {
	g := New("", false)
	before := len(g.rules)
	g.CanonicalizeRoots(nil)
	g.CanonicalizeRoots(func(p string) (string, bool) { return p, true })
	if len(g.rules) != before {
		t.Fatalf("rules changed: before %d after %d", before, len(g.rules))
	}
}
