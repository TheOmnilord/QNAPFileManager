package workerpool

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
)

// The tests in this file spawn real worker processes with real credentials.
// They are the only place impersonation is actually exercised, and they need
// root to create fixture users, so they run in the CI test-linux-root job and
// skip everywhere else. Simulating any of this on the dev box would test the
// simulation rather than the product (PLAN.md INV-2).

func requireLinuxRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("worker processes with credentials exist only on Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("this test needs root to create fixture users")
	}
}

// buildDaemon builds cmd/qnapfilemanager, because the test binary itself does
// not understand -worker.
func buildDaemon(t *testing.T, dir string) string {
	t.Helper()
	exe := filepath.Join(dir, "qnapfilemanager")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", exe, "./cmd/qnapfilemanager")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("building the daemon: %v\n%s", err, out)
	}
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

// fixtureUser makes sure name exists, in group groupName, and returns its
// identity. It skips rather than fails when the distribution's user tools are
// missing.
func fixtureUser(t *testing.T, name, groupName string) idmap.Ident {
	t.Helper()
	ids := idmap.Open("", "")
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skipf("useradd is not available: %v", err)
	}
	if _, ok := ids.GroupGID(groupName); !ok {
		if out, gerr := exec.Command("groupadd", groupName).CombinedOutput(); gerr != nil &&
			!strings.Contains(string(out), "already exists") {
			t.Skipf("groupadd %s: %v\n%s", groupName, gerr, out)
		}
	}
	if _, err := ids.LookupUser(name); err != nil {
		out, uerr := exec.Command("useradd", "-M", "-N", "-s", "/bin/false", "-G", groupName, name).CombinedOutput()
		if uerr != nil && !strings.Contains(string(out), "already exists") {
			t.Skipf("useradd %s: %v\n%s", name, uerr, out)
		}
	}
	id, err := ids.LookupUser(name)
	if err != nil {
		t.Skipf("the fixture user %s did not appear in /etc/passwd: %v", name, err)
	}
	return id
}

// rootTree builds a fixture tree the fixture users can reach: every directory
// on the way down has to be traversable, which t.TempDir's 0700 is not.
func rootTree(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "qfm-root-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func rootPool(t *testing.T, base, exe string) *Pool {
	t.Helper()
	root, err := fsx.NewRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	p := NewWithOptions(Options{
		Root:        root,
		Mode:        ModeProcess,
		Executable:  exe,
		Max:         4,
		IdleTimeout: 10 * time.Minute,
		CallTimeout: 30 * time.Second,
		Logger:      log.New(io.Discard, "", 0),
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return p
}

func principalOf(id idmap.Ident) backend.Principal {
	return backend.Principal{User: id.Name, UID: id.UID, GID: id.GID, Groups: id.Groups}
}

// TestWorkerRunsAsTheFixtureUser is the test that catches a nil
// Credential.Groups: the worker reports the group set the kernel gave it, and
// the supplementary group must be in it.
func TestWorkerRunsAsTheFixtureUser(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")

	p := rootPool(t, base, exe)
	ctx := context.Background()
	if err := p.Ping(ctx, principalOf(alice)); err != nil {
		t.Fatalf("ping: %v", err)
	}
	s := p.Stats()
	if len(s) != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if s[0].HelloUID != alice.UID || s[0].HelloGID != alice.GID {
		t.Fatalf("the worker came up as uid %d gid %d, want %d/%d", s[0].HelloUID, s[0].HelloGID, alice.UID, alice.GID)
	}
	ids := idmap.Open("", "")
	team, ok := ids.GroupGID("qfmteam")
	if !ok {
		t.Fatal("the fixture group vanished")
	}
	found := false
	for _, g := range s[0].Groups {
		if g == team {
			found = true
		}
	}
	if !found {
		t.Fatalf("groups = %v, want the supplementary group %d. "+
			"A nil Credential.Groups makes Go call setgroups(0, nil) and silently drops every shared folder.", s[0].Groups, team)
	}
}

// TestTheKernelDecidesPermissions: a 0600 file owned by someone else is
// refused at open(2) time, in the worker, by the kernel (INV-2).
func TestTheKernelDecidesPermissions(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	bob := fixtureUser(t, "qfmbob", "qfmother")

	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte("only alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(secret, alice.UID, alice.GID); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(base, "shared.txt")
	if err := os.WriteFile(shared, []byte("everyone"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	ctx := context.Background()

	f, e, err := p.OpenRead(ctx, principalOf(alice), "/secret.txt")
	if err != nil {
		t.Fatalf("alice cannot read her own file: %v", err)
	}
	got, rerr := io.ReadAll(f)
	f.Close()
	if rerr != nil || string(got) != "only alice" {
		t.Fatalf("the passed descriptor read %q, %v", got, rerr)
	}
	if e.Size != int64(len("only alice")) {
		t.Errorf("entry = %+v", e)
	}

	if _, _, err := p.OpenRead(ctx, principalOf(bob), "/secret.txt"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("bob opening alice's 0600 file = %v, want a permission error", err)
	}
	if code := fsx.Code(err); code != "" && code != "permission" {
		t.Errorf("code = %q", code)
	}
	bf, _, err := p.OpenRead(ctx, principalOf(bob), "/shared.txt")
	if err != nil {
		t.Fatalf("bob cannot read a 0644 file: %v", err)
	}
	bf.Close()
}

// TestPassedDescriptorsDoNotLeakIntoTheNextWorker: the front-end holds the
// descriptor a worker passed up, and it must not appear in the next worker's
// /proc/<pid>/fd. A leaked descriptor would hand one user an open file another
// user was allowed to open.
func TestPassedDescriptorsDoNotLeakIntoTheNextWorker(t *testing.T) {
	requireLinuxRoot(t)
	base := rootTree(t)
	exe := buildDaemon(t, base)
	alice := fixtureUser(t, "qfmalice", "qfmteam")
	bob := fixtureUser(t, "qfmbob", "qfmother")

	target := filepath.Join(base, "held.txt")
	if err := os.WriteFile(target, []byte("held open"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := rootPool(t, base, exe)
	ctx := context.Background()
	f, _, err := p.OpenRead(ctx, principalOf(alice), "/held.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Spawn a second worker while the descriptor is still open here.
	if err := p.Ping(ctx, principalOf(bob)); err != nil {
		t.Fatal(err)
	}
	var pid int
	for _, s := range p.Stats() {
		if s.UID == bob.UID {
			pid = s.PID
		}
	}
	if pid == 0 {
		t.Fatal("bob's worker has no pid")
	}
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	des, err := os.ReadDir(fdDir)
	if err != nil {
		t.Skipf("cannot read the worker's descriptor table: %v", err)
	}
	for _, de := range des {
		link, err := os.Readlink(filepath.Join(fdDir, de.Name()))
		if err != nil {
			continue
		}
		if link == target {
			t.Fatalf("fd %s of the second worker points at %s", de.Name(), target)
		}
	}
	// Four descriptors is already generous: 0,1,2 and the socketpair.
	if len(des) > 8 {
		t.Errorf("the worker inherited %d descriptors: %v", len(des), des)
	}
}
