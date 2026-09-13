package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/web"
)

// run drives the subcommand the way main does, with -stdin: that is the
// scripted path, it is what CI exercises, and it is the only one available off
// Linux, where the terminal echo cannot be turned off (contract §15).
func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runBreakGlass(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// newConfig writes a default config AND installs the unprivileged seam, which
// is what almost every test here wants: the CLI logic under test is not the
// root gate. The handful of tests that ARE about the gate use realGatesConfig.
func newConfig(t *testing.T) string {
	t.Helper()
	p := realGatesConfig(t)
	unprivileged(t)
	return p
}

// realGatesConfig writes a default config and leaves requireRoot and
// checkCredentialMode exactly as the platform defines them.
func realGatesConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(p, config.Default()); err != nil {
		t.Fatal(err)
	}
	return p
}

// unprivileged replaces the two platform gates for the duration of one test, so
// the CLI's own logic runs on the Linux race job (uid 1001) and on the root job
// alike.
//
// Without it every set-password test fails at "must be run as root" on the
// unprivileged runner, before reaching the rule it meant to check — and the
// root requirement itself is right and must stay. The gates keep their own
// Linux-gated tests (TestNonRootIsRefusedOnLinux, TestCredentialStoreModeIsRefused)
// which do NOT install this seam, so what is replaced here is still tested
// where it can be. Set and restored on the test goroutine, before and after the
// command runs; nothing else reads them.
func unprivileged(t *testing.T) {
	t.Helper()
	root, mode := requireRootFn, checkCredentialModeFn
	t.Cleanup(func() { requireRootFn, checkCredentialModeFn = root, mode })
	requireRootFn = func() error { return nil }
	checkCredentialModeFn = func(string, os.FileInfo) error { return nil }
}

// §16.3: set-password writes a hash and an updated stamp AND NOTHING ELSE.
func TestSetPasswordWritesOnlyTheCredential(t *testing.T) {
	p := newConfig(t)
	before, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, stdout, stderr)
	}
	after, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if after.Auth.Local.Hash == "" {
		t.Fatal("no hash was written")
	}
	if after.Auth.Local.Updated == "" {
		t.Fatal("no updated stamp was written; without it nothing evicts a live session")
	}
	if after.Auth.Local.Cost != 10 {
		t.Fatalf("cost = %d, want the requested 10", after.Auth.Local.Cost)
	}
	if err := breakglass.Verify(after.Auth.Local.Hash, "a long enough password"); err != nil {
		t.Fatalf("the written hash does not verify the password: %v", err)
	}
	// The hash is never echoed back to the terminal. (Captured before the
	// comparison below blanks it — Contains(x, "") is vacuously true.)
	hash := after.Auth.Local.Hash
	if strings.Contains(stdout, hash) || strings.Contains(stdout, "a long enough password") {
		t.Fatalf("set-password printed the credential:\n%s", stdout)
	}
	// Nothing else moved. Blanking the credential should make the two configs
	// identical, which is a stronger statement than checking a few fields.
	after.Auth.Local = before.Auth.Local
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("set-password changed more than the credential:\n before %+v\n after  %+v", before, after)
	}
}

func TestSetPasswordRules(t *testing.T) {
	for _, c := range []struct {
		name     string
		stdin    string
		args     []string
		wantCode int
		wantOut  string
	}{
		{"too short", "short\n", []string{"-cost", "10"}, 1, ""},
		{"only whitespace", "              \n", []string{"-cost", "10"}, 1, ""},
		{"cost below the floor", "a long enough password\n", []string{"-cost", "9"}, 1, ""},
		{"cost above the ceiling", "a long enough password\n", []string{"-cost", "16"}, 1, ""},
		// Past what bcrypt can read: refused by name, never accepted with a
		// silently ignored tail (see breakglass.CheckPassword).
		{"past the bcrypt limit", strings.Repeat("x", 80) + "\n", []string{"-cost", "10"}, 1, ""},
		{"accepted", "a long enough password\n", []string{"-cost", "10"}, 0, ""},
		// Near the bcrypt limit: accepted, with a notice naming it.
		{"near the bcrypt limit", strings.Repeat("x", 70) + "\n", []string{"-cost", "10"}, 0, "72"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newConfig(t)
			args := append([]string{"set-password", "-config", p, "-stdin"}, c.args...)
			code, stdout, stderr := run(t, c.stdin, args...)
			if code != c.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, c.wantCode, stdout, stderr)
			}
			if c.wantOut != "" && !strings.Contains(stdout, c.wantOut) {
				t.Fatalf("stdout = %q, want it to mention %q", stdout, c.wantOut)
			}
			if c.wantCode != 0 {
				cfg, err := config.Load(p)
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Auth.Local.Hash != "" {
					t.Fatal("a refused password must leave the config untouched")
				}
			}
		})
	}
}

func TestSetPasswordThenDisable(t *testing.T) {
	p := newConfig(t)
	if code, out, errOut := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin"); code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, out, errOut)
	}
	before, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "", "disable", "-config", p)
	if code != 0 {
		t.Fatalf("disable = %d\n%s\n%s", code, stdout, stderr)
	}
	after, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if after.Auth.Local.Hash != "" {
		t.Fatal("disable must clear the hash")
	}
	// The stamp still moves: that is what evicts the live sessions the cleared
	// hash is meant to lock out (§4.4).
	if after.Auth.Local.Updated == before.Auth.Local.Updated {
		t.Fatal("disable must bump the updated stamp, or it is a suggestion rather than an eviction")
	}
}

func TestStatusNeverPrintsTheHash(t *testing.T) {
	p := newConfig(t)
	// Before: no password at all.
	code, stdout, stderr := run(t, "", "status", "-config", p)
	if code != 0 {
		t.Fatalf("status = %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"enabled:", "addr:", "password:    not set", "certificate:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status is missing %q:\n%s", want, stdout)
		}
	}
	// After: set, with the time it was set and the cost, but never the hash.
	if code, out, errOut := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin"); code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, out, errOut)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	_, stdout, _ = run(t, "", "status", "-config", p)
	if strings.Contains(stdout, cfg.Auth.Local.Hash) {
		t.Fatalf("status printed the hash:\n%s", stdout)
	}
	if !strings.Contains(stdout, "password:    set") || !strings.Contains(stdout, cfg.Auth.Local.Updated) {
		t.Fatalf("status must report that a password exists and when it was set:\n%s", stdout)
	}
	if !strings.Contains(stdout, "cost:        10") {
		t.Fatalf("status must report the cost actually in force:\n%s", stdout)
	}
}

func TestCertSubcommandGeneratesAndRegenerates(t *testing.T) {
	p := newConfig(t)
	// A plain `cert` with nothing on disk READS and says so; it does not
	// generate. Nothing about reporting a fingerprint may change one.
	code, none, stderr := run(t, "", "cert", "-config", p)
	if code != 0 {
		t.Fatalf("cert = %d\n%s\n%s", code, none, stderr)
	}
	if !strings.Contains(none, "no certificate yet") {
		t.Fatalf("a plain cert on an empty config must report, not generate:\n%s", none)
	}
	certFile, _ := config.Default().BreakGlassFiles(p)
	if _, err := os.Stat(certFile); err == nil {
		t.Fatal("a plain `cert` generated a key pair")
	}

	code, first, stderr := run(t, "", "cert", "-config", p, "-regenerate")
	if code != 0 {
		t.Fatalf("cert -regenerate = %d\n%s\n%s", code, first, stderr)
	}
	if !strings.Contains(first, "fingerprint: sha256:") {
		t.Fatalf("cert -regenerate must print a fingerprint:\n%s", first)
	}
	// Now a plain run reports the SAME certificate, twice over.
	_, second, _ := run(t, "", "cert", "-config", p)
	if fingerprintOf(t, second) != fingerprintOf(t, first) {
		t.Fatalf("a plain `cert` changed the fingerprint:\n%s\n%s", first, second)
	}
	_, third, _ := run(t, "", "cert", "-config", p, "-regenerate")
	if fingerprintOf(t, third) == fingerprintOf(t, first) {
		t.Fatalf("-regenerate did not change the fingerprint:\n%s", third)
	}
	if !strings.Contains(third, "CHANGED") {
		t.Fatalf("-regenerate must say the fingerprint changed:\n%s", third)
	}
	// status then reports the regenerated one, and status never generates either.
	_, status, _ := run(t, "", "status", "-config", p)
	if fingerprintOf(t, status) != fingerprintOf(t, third) {
		t.Fatalf("status reports a different certificate:\n%s\n%s", status, third)
	}
}

// A plain `cert` must NOT regenerate even when the certificate is inside its
// 30-day renewal window — that was the whole of round-1 P3-10: an operator
// reading the fingerprint would have been the one who changed it, unprivileged
// and unannounced, while the running daemon went on serving the old one.
func TestPlainCertDoesNotRenewInsideTheWindow(t *testing.T) {
	p := newConfig(t)
	certFile, keyFile := config.Default().BreakGlassFiles(p)
	// A certificate that expires tomorrow: deep inside the renewal window.
	expiring, err := breakglass.Regenerate(certFile, keyFile, time.Now().Add(-breakglass.Validity+24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ := run(t, "", "cert", "-config", p)
	if fingerprintOf(t, out) != "sha256:"+expiring.Fingerprint {
		t.Fatalf("a plain `cert` renewed an expiring certificate:\n%s", out)
	}
	loaded, err := breakglass.Load(certFile, keyFile)
	if err != nil || loaded.Fingerprint != expiring.Fingerprint {
		t.Fatalf("the on-disk certificate changed: %v %+v", err, loaded)
	}
}

// -regenerate goes through the same store guard set-password does, so it cannot
// be the unprivileged way to rewrite the credential directory.
func TestCertRegenerateIsGuarded(t *testing.T) {
	p := newConfig(t) // installs the seam
	refused := errors.New("not root")
	requireRootFn = func() error { return refused }
	if code, _, stderr := run(t, "", "cert", "-config", p, "-regenerate"); code == 0 || !strings.Contains(stderr, "not root") {
		t.Fatalf("-regenerate ran without the root gate: exit %d, stderr %q", code, stderr)
	}
	// The read-only form is not gated: an operator comparing a fingerprint does
	// not need to be root to look.
	if code, _, stderr := run(t, "", "cert", "-config", p); code != 0 {
		t.Fatalf("a plain `cert` must not require root: exit %d, stderr %q", code, stderr)
	}
}

// §16.3, the two-prompt path: one shared reader, or the second line is lost to
// the first reader's discarded buffer and the passwords never match.
func TestInteractivePromptReadsTwoLines(t *testing.T) {
	p := newConfig(t)
	code, stdout, stderr := run(t, "a long enough password\na long enough password\n", "set-password", "-config", p, "-cost", "10")
	if code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, stdout, stderr)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := breakglass.Verify(cfg.Auth.Local.Hash, "a long enough password"); err != nil {
		t.Fatalf("the two prompts did not read the same password: %v", err)
	}
	// And two DIFFERENT lines are refused rather than half-read.
	q := newConfig(t)
	code, _, _ = run(t, "a long enough password\na different password!\n", "set-password", "-config", q, "-cost", "10")
	if code == 0 {
		t.Fatal("mismatched passwords must be refused")
	}
	after, err := config.Load(q)
	if err != nil {
		t.Fatal(err)
	}
	if after.Auth.Local.Hash != "" {
		t.Fatal("a mismatch must leave the config untouched")
	}
}

func fingerprintOf(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "fingerprint:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "fingerprint:"))
		}
	}
	t.Fatalf("no fingerprint in:\n%s", out)
	return ""
}

func TestBreakGlassUnknownSubcommand(t *testing.T) {
	if code, _, stderr := run(t, "", "reset-everything"); code != 2 || !strings.Contains(stderr, "unknown subcommand") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := run(t, ""); code != 2 || !strings.Contains(stderr, "set-password") {
		t.Fatalf("no subcommand: exit %d, stderr %q", code, stderr)
	}
	if code, stdout, _ := run(t, "", "help"); code != 0 || !strings.Contains(stdout, "break-glass") {
		t.Fatalf("help: exit %d, stdout %q", code, stdout)
	}
}

// Linux-only: the mode and ownership refusals need real Unix semantics, and
// INV-2 says never to simulate the kernel.
func TestCredentialStoreModeIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes are approximate on Windows")
	}
	if os.Geteuid() != 0 {
		// requireRoot fires first and the mode check is never reached, so the
		// assertion below would be testing the wrong refusal.
		t.Skip("the root refusal comes first when not running as root")
	}
	p := realGatesConfig(t)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code == 0 {
		t.Fatalf("a group/world-readable credential store was accepted\n%s\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "mode") {
		t.Fatalf("the refusal must name the mode: %q", stderr)
	}
}

// Linux-only, non-root: the geteuid refusal. Off Linux the CLI says it did not
// check rather than pretending to have checked.
func TestNonRootIsRefusedOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("there is no effective uid off Linux")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	p := realGatesConfig(t)
	code, _, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code == 0 {
		t.Fatal("set-password must refuse to run as a non-root user")
	}
	if !strings.Contains(stderr, "root") {
		t.Fatalf("the refusal must say so: %q", stderr)
	}
}

func TestOffLinuxTheRootCheckIsAnnouncedNotFaked(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("the check is real on Linux")
	}
	p := realGatesConfig(t)
	code, _, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "root check was not performed") {
		t.Fatalf("the CLI must say what it did not check: %q", stderr)
	}
}

// --- round-2 P2-3: the documented first run works without a restart ----------

// The procedure is: install, run set-password, compare the fingerprint, open
// https://<nas>:8771/. Until set-password generated the certificate there was
// no fingerprint to compare — `status` said "not generated yet" and the door
// was unreachable until someone restarted the app they were repairing with.
func TestSetPasswordPreparesTheCertificate(t *testing.T) {
	p := newConfig(t)
	certFile, keyFile := config.Default().BreakGlassFiles(p)
	if _, err := os.Stat(certFile); err == nil {
		t.Fatal("the fixture already has a certificate")
	}
	code, stdout, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, stdout, stderr)
	}
	cert, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		t.Fatalf("set-password did not prepare the certificate: %v", err)
	}
	// It prints the fingerprint, so the operator can compare it before typing
	// the password into a page the browser has warned about.
	if !strings.Contains(stdout, "sha256:"+cert.Fingerprint) {
		t.Fatalf("set-password did not print the fingerprint:\n%s", stdout)
	}
	if !strings.Contains(stdout, "restart is not needed") {
		t.Fatalf("set-password must say the app picks the password up on its own:\n%s", stdout)
	}
	// And `status` now has one to report, with no further command.
	_, status, _ := run(t, "", "status", "-config", p)
	if !strings.Contains(status, "sha256:"+cert.Fingerprint) {
		t.Fatalf("status still reports no fingerprint:\n%s", status)
	}
	// A disabled listener does not generate one: there would be nothing to
	// serve it.
	q := newConfig(t)
	if err := config.Update(q, false, func(c *config.Config) error {
		c.Web.BreakGlass.Enabled = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := run(t, "a long enough password\n", "set-password", "-config", q, "-cost", "10", "-stdin"); code != 0 {
		t.Fatalf("set-password = %d\n%s\n%s", code, out, errOut)
	}
	qc, _ := config.Default().BreakGlassFiles(q)
	if _, err := os.Stat(qc); err == nil {
		t.Fatal("a disabled listener generated a certificate")
	}
}

// --- round-2 P3-6: the CLI can read a -dev configuration ---------------------

func TestCLIAcceptsADevConfigurationOnlyWithTheFlag(t *testing.T) {
	p := newConfig(t)
	if err := config.SaveDev(p, func() config.Config {
		c, err := config.LoadDev(p, true)
		if err != nil {
			t.Fatal(err)
		}
		c.Auth.Mode = config.AuthLocal
		return c
	}(), true); err != nil {
		t.Fatal(err)
	}
	for _, sub := range [][]string{
		{"status", "-config", p},
		{"cert", "-config", p},
	} {
		if code, _, stderr := run(t, "", sub...); code == 0 {
			t.Errorf("%v accepted a development configuration without -dev", sub)
		} else if !strings.Contains(stderr, "auth.mode") {
			t.Errorf("%v: the refusal must name the key: %q", sub, stderr)
		}
		if code, _, stderr := run(t, "", append(sub, "-dev")...); code != 0 {
			t.Errorf("%v -dev = %d, stderr %q", sub, code, stderr)
		}
	}
	// And set-password can write it back.
	if code, out, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin", "-dev"); code != 0 {
		t.Fatalf("set-password -dev = %d\n%s\n%s", code, out, stderr)
	}
	got, err := config.LoadDev(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth.Mode != config.AuthLocal || got.Auth.Local.Hash == "" {
		t.Fatalf("set-password -dev = %+v", got.Auth)
	}
}

// --- round-2 P3-8: the directory is guarded too ------------------------------

// The certificate's private key, the lock file and every scratch file live in
// the config DIRECTORY. Checking only config.json misses the thing that
// actually matters: a group-readable config/ exposes the key the emergency door
// serves, however tight config.json itself is.
func TestTheCredentialDirectoryIsGuarded(t *testing.T) {
	p := realGatesConfig(t)
	root, mode := requireRootFn, checkCredentialModeFn
	t.Cleanup(func() { requireRootFn, checkCredentialModeFn = root, mode })
	requireRootFn = func() error { return nil }
	var checked []string
	checkCredentialModeFn = func(path string, _ os.FileInfo) error {
		checked = append(checked, path)
		if path == filepath.Dir(p) {
			return errors.New("the directory is group-readable")
		}
		return nil
	}
	code, _, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin")
	if code == 0 {
		t.Fatal("a bad credential directory was accepted")
	}
	if !strings.Contains(stderr, "group-readable") {
		t.Fatalf("stderr = %q", stderr)
	}
	if len(checked) == 0 || checked[0] != filepath.Dir(p) {
		t.Fatalf("the directory was not checked first: %v", checked)
	}
	// The config file is still checked too.
	checked = nil
	checkCredentialModeFn = func(path string, _ os.FileInfo) error {
		checked = append(checked, path)
		return nil
	}
	if code, _, stderr := run(t, "a long enough password\n", "set-password", "-config", p, "-cost", "10", "-stdin"); code != 0 {
		t.Fatalf("set-password = %d, stderr %q", code, stderr)
	}
	var sawFile bool
	for _, c := range checked {
		if c == p {
			sawFile = true
		}
	}
	if !sawFile {
		t.Fatalf("the config file itself was no longer checked: %v", checked)
	}
}

// --- round-5: every cert writer holds the credential-store lock -------------

// The key pair is two files and therefore two atomic renames, so two generators
// running at once can leave one's certificate beside the other's key — a pair
// the listener cannot serve at all. The three writers hold the same lock the
// credential itself is written under; this asserts that they do, by holding it
// against them.
func TestCertWritersHoldTheCredentialLock(t *testing.T) {
	defaultWait := config.LockWait
	t.Cleanup(func() { config.LockWait = defaultWait })
	config.LockWait = 80 * time.Millisecond

	for _, c := range []struct {
		name string
		args []string
		in   string
	}{
		{"cert -regenerate", []string{"cert", "-regenerate"}, ""},
		{"set-password", []string{"set-password", "-cost", "10", "-stdin"}, "a long enough password\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newConfig(t)
			// Somebody else is mid-write.
			release, err := config.Lock(p)
			if err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, c.args...), "-config", p)
			code, stdout, stderr := run(t, c.in, args...)
			if code == 0 {
				release()
				t.Fatalf("%s wrote the key pair while another writer held the lock\n%s\n%s", c.name, stdout, stderr)
			}
			if !strings.Contains(stderr, "being written by another process") {
				release()
				t.Fatalf("%s: the refusal must name the reason: %q", c.name, stderr)
			}
			release()
			// And it succeeds once the other writer is done.
			if code, out, errOut := run(t, c.in, args...); code != 0 {
				t.Fatalf("%s after the lock was released = %d\n%s\n%s", c.name, code, out, errOut)
			}
			certFile, keyFile := config.Default().BreakGlassFiles(p)
			if _, err := breakglass.Load(certFile, keyFile); err != nil {
				t.Fatalf("%s left an unusable pair: %v", c.name, err)
			}
		})
	}
}

// The daemon's own arm path takes the same lock, so a `cert -regenerate` run
// while the app is starting cannot interleave with it.
func TestArmBreakGlassHoldsTheCredentialLock(t *testing.T) {
	defaultWait := config.LockWait
	t.Cleanup(func() { config.LockWait = defaultWait })
	config.LockWait = 80 * time.Millisecond

	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-14T09:00:00Z"}
	if err := config.Save(p, cfg); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	logger := log.New(&logged, "", 0)
	srv := &server{cfg: cfg, logger: logger}
	frontend := web.New(cfg, nil, nil, nil, nil, nil, "test", logger, nil, nil, nil)

	release, err := config.Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := armBreakGlass(srv, frontend, cfg, p, logger); err == nil {
		release()
		t.Fatal("the daemon generated a key pair while another writer held the lock")
	}
	release()
	if err := armBreakGlass(srv, frontend, cfg, p, logger); err != nil {
		t.Fatalf("arming after the lock was released: %v", err)
	}
	certFile, keyFile := cfg.BreakGlassFiles(p)
	if _, err := breakglass.Load(certFile, keyFile); err != nil {
		t.Fatalf("the daemon left an unusable pair: %v", err)
	}
}
