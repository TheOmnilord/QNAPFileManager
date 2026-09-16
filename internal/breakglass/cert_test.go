package breakglass

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/config"
)

func certPaths(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	return filepath.Join(dir, "breakglass-cert.pem"), filepath.Join(dir, "breakglass-key.pem")
}

func TestEnsureGeneratesPersistsAndReloads(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	first, err := EnsureUsable(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Generated || first.Reason != "absent" {
		t.Fatalf("first EnsureUsable = %+v, want a generation because the file was absent", first)
	}
	if first.Fingerprint == "" || len(first.Fingerprint) != 64 {
		t.Fatalf("fingerprint = %q, want 64 hex characters", first.Fingerprint)
	}
	// 397 days, not ten years: Apple's 398-day ceiling (contract §3.2).
	if want := now.Add(Validity); !first.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", first.NotAfter, want)
	}
	for _, p := range []string{certFile, keyFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was not persisted: %v", p, err)
		}
	}

	// A restart must serve the SAME certificate: a fingerprint that changed on
	// every start would train the operator to ignore the one comparison that
	// protects them.
	second, err := EnsureUsable(certFile, keyFile, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Generated {
		t.Fatal("a valid certificate must be reloaded, not regenerated")
	}
	if second.Fingerprint != first.Fingerprint {
		t.Fatalf("fingerprint changed across restarts: %s -> %s", first.Fingerprint, second.Fingerprint)
	}
}

// Astra r2 #3: the daemon never renews silently. A pair inside its renewal
// window is served exactly as it is — the caller warns — and only an EXPIRED
// one, which no browser would accept anyway, is replaced.
func TestExpiringIsServedAndExpiredIsReplaced(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	first, err := EnsureUsable(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	expiry := first.NotAfter

	// Deep inside the 30-day window, and one second before expiry: the same
	// pair, both times. A fingerprint an operator was told to compare does not
	// change because a daemon restarted.
	for _, at := range []time.Time{
		expiry.Add(-RenewWithin).Add(time.Second),
		expiry.Add(-time.Second),
	} {
		got, err := EnsureUsable(certFile, keyFile, at)
		if err != nil {
			t.Fatal(err)
		}
		if got.Generated || got.Fingerprint != first.Fingerprint {
			t.Fatalf("EnsureUsable at %v = %+v, want the pair on disk served unchanged", at, got)
		}
	}

	// Expired: worth nothing to any browser, so it is replaced and the new
	// fingerprint is the caller's to log and audit.
	after := expiry.Add(time.Second)
	got, err := EnsureUsable(certFile, keyFile, after)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Generated || got.Reason != "expired" {
		t.Fatalf("EnsureUsable at %v = %+v, want a regeneration with reason \"expired\"", after, got)
	}
	if got.Fingerprint == first.Fingerprint {
		t.Fatal("a regenerated certificate must have a new fingerprint")
	}
	if want := after.Add(Validity); !got.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", got.NotAfter, want)
	}
}

func TestEnsureReplacesAnUnreadablePair(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Now()
	if _, err := EnsureUsable(certFile, keyFile, now); err != nil {
		t.Fatal(err)
	}
	// A half-written or corrupted pair must not leave the door unopenable.
	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := EnsureUsable(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Generated || got.Reason != "unreadable" {
		t.Fatalf("EnsureUsable over a corrupt pair = %+v, want a regeneration", got)
	}
}

func TestRegenerateAlwaysChangesTheFingerprint(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Now()
	first, err := EnsureUsable(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Regenerate(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Generated || second.Reason != "requested" || second.Fingerprint == first.Fingerprint {
		t.Fatalf("Regenerate = %+v, want a new key pair", second)
	}
	// And the new one is what a later Load reads back.
	loaded, err := Load(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != second.Fingerprint {
		t.Fatalf("Load = %s, want the regenerated %s", loaded.Fingerprint, second.Fingerprint)
	}
	if loaded.Generated {
		t.Fatal("Load must never generate: reporting a fingerprint cannot be the thing that changes it")
	}
}

func TestGeneratedCertificateCarriesTheExpectedSANs(t *testing.T) {
	certFile, keyFile := certPaths(t)
	// The hostname SAN comes from /etc/hostname; point it at a fixture so the
	// assertion does not depend on the machine running the test.
	hostFile := filepath.Join(t.TempDir(), "hostname")
	if err := os.WriteFile(hostFile, []byte("nas-under-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := HostnameFile
	HostnameFile = hostFile
	t.Cleanup(func() { HostnameFile = old })

	got, err := EnsureUsable(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf := got.TLS.Leaf
	names := map[string]bool{}
	for _, n := range leaf.DNSNames {
		names[n] = true
	}
	if !names["nas-under-test"] {
		t.Fatalf("DNS SANs = %v, want /etc/hostname's value", leaf.DNSNames)
	}
	// IP SANs matter: an operator with a broken desktop reaches this by IP, and
	// a certificate with no IP SAN produces a DIFFERENT, scarier warning than
	// the expected self-signed one (contract §3.3).
	var v4, v6 bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			v4 = true
		}
		if ip.Equal(net.IPv6loopback) {
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Fatalf("IP SANs = %v, want 127.0.0.1 and ::1", leaf.IPAddresses)
	}
	if leaf.Subject.CommonName != "nas-under-test" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
}

// The mode assertion is Linux-only: 0600 is approximate on Windows and INV-2
// says never to simulate the kernel (contract §15).
func TestCertificateFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes are approximate on Windows")
	}
	certFile, keyFile := certPaths(t)
	if _, err := EnsureUsable(certFile, keyFile, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certFile, keyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", p, fi.Mode().Perm())
		}
	}
	dir, err := os.Stat(filepath.Dir(certFile))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm()&0o077 != 0 {
		t.Errorf("%s is mode %04o, want no group or other access", filepath.Dir(certFile), dir.Mode().Perm())
	}
	// No temporary file is left beside them.
	for _, p := range []string{certFile + ".tmp", keyFile + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was left behind", p)
		}
	}
}

func TestEnsureRefusesEmptyPaths(t *testing.T) {
	if _, err := EnsureUsable("", "", time.Now()); err == nil {
		t.Fatal("empty certificate paths must be an error, never a silent skip")
	}
}

// Round-1 P2-6: a SERVER leaf, never a certificate authority. §3.4's procedure
// invites an operator to look the certificate up and compare it; some will go on
// to import it to stop the warning. With IsCA and KeyUsageCertSign set, that
// import would trust this key to sign a certificate for ANY name, on the very
// machine they administer the NAS from.
func TestGeneratedCertificateIsNotACertificateAuthority(t *testing.T) {
	certFile, keyFile := certPaths(t)
	got, err := EnsureUsable(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf := got.TLS.Leaf
	if leaf.IsCA {
		t.Error("IsCA is set; importing this certificate would trust it to sign for any name")
	}
	if !leaf.BasicConstraintsValid {
		t.Error("BasicConstraintsValid must be set, or IsCA=false says nothing")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("KeyUsageCertSign is set on a TLS server leaf")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %b, want DigitalSignature alone", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want ServerAuth alone", leaf.ExtKeyUsage)
	}
	// It still works as a TLS server certificate, which is the whole point.
	if got.TLS.PrivateKey == nil {
		t.Fatal("the loaded pair has no private key")
	}
}

// --- round-5: the pair is two files, so its writers must be serialised -------

// Two generators each publish cert.pem and key.pem by separate atomic renames,
// so without a lock a mixed pair — A's certificate beside B's key — can land,
// and the listener then cannot serve it at all. The fix is not in this package:
// the pair cannot be published as one operation, so every WRITER holds the
// credential-store lock. This test runs the real one, which is why it reaches
// for internal/config here (a test-only import; the package itself stays free
// of it, and of net/http, on purpose).
func TestConcurrentGenerationUnderTheLockLeavesOneUsablePair(t *testing.T) {
	certFile, keyFile := certPaths(t)
	// The lock lives beside the credential; in production that is config.json
	// in the same 0700 directory as the pair.
	configPath := filepath.Join(filepath.Dir(certFile), "config.json")
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		t.Fatal(err)
	}

	defaultWait := config.LockWait
	t.Cleanup(func() { config.LockWait = defaultWait })
	config.LockWait = 5 * time.Second // every writer must get its turn, not give up

	var wg sync.WaitGroup
	fingerprints := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := config.Lock(configPath)
			if err != nil {
				t.Errorf("a generator could not take the lock: %v", err)
				return
			}
			defer release()
			got, err := Regenerate(certFile, keyFile, time.Now())
			if err != nil {
				t.Errorf("Regenerate: %v", err)
				return
			}
			fingerprints <- got.Fingerprint
		}()
	}
	wg.Wait()
	close(fingerprints)

	// What is on disk is a usable pair — the failure this guards against is
	// exactly "private key does not match public key".
	loaded, err := Load(certFile, keyFile)
	if err != nil {
		t.Fatalf("serialised generation still left a torn pair: %v", err)
	}
	// And it is one of the pairs that were actually generated, not a mixture of
	// two: exactly one writer's fingerprint is the one standing.
	var seen, matched int
	for f := range fingerprints {
		seen++
		if f == loaded.Fingerprint {
			matched++
		}
	}
	if seen != 8 {
		t.Fatalf("%d generators finished, want 8", seen)
	}
	if matched != 1 {
		t.Fatalf("the pair on disk matches %d of the %d generated fingerprints, want exactly 1", matched, seen)
	}
	// No temporary file survives any of it.
	entries, err := os.ReadDir(filepath.Dir(certFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// A crash between the two renames leaves a certificate from one generation
// beside a key from another. The lock cannot prevent that — nothing can, with
// two files — so EnsureUsable heals it at the next start instead of refusing to
// serve.
func TestEnsureHealsATornPair(t *testing.T) {
	certFile, keyFile := certPaths(t)
	first, err := EnsureUsable(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A second generation, kept aside, standing in for the half that landed.
	otherCert, otherKey := certPaths(t)
	second, err := EnsureUsable(otherCert, otherKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("the two generations are identical; the fixture proves nothing")
	}

	for _, c := range []struct {
		name string
		tear func(t *testing.T)
	}{
		{"the certificate landed, the key did not", func(t *testing.T) {
			copyFile(t, otherCert, certFile) // new cert, old key
		}},
		{"the key landed, the certificate did not", func(t *testing.T) {
			copyFile(t, otherKey, keyFile) // old cert, new key
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Start from a known-good pair each time.
			fresh, err := Regenerate(certFile, keyFile, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.tear(t)
			// Load says exactly what is wrong, by a name a caller can match on.
			if _, err := Load(certFile, keyFile); !errors.Is(err, ErrPairMismatch) {
				t.Fatalf("Load over a torn pair = %v, want ErrPairMismatch", err)
			}
			// EnsureUsable heals it rather than failing: this is what makes a crash
			// between the two renames survivable without an operator.
			healed, err := EnsureUsable(certFile, keyFile, time.Now())
			if err != nil {
				t.Fatalf("EnsureUsable over a torn pair = %v, want a regeneration", err)
			}
			if !healed.Generated || healed.Reason != "mismatched" {
				t.Fatalf("EnsureUsable = %+v, want a regeneration with reason \"mismatched\"", healed)
			}
			if healed.Fingerprint == fresh.Fingerprint {
				t.Fatal("the torn pair was reported healed without changing")
			}
			// And what is on disk now loads.
			loaded, err := Load(certFile, keyFile)
			if err != nil {
				t.Fatalf("the healed pair does not load: %v", err)
			}
			if loaded.Fingerprint != healed.Fingerprint {
				t.Fatalf("Load = %s, want the healed %s", loaded.Fingerprint, healed.Fingerprint)
			}
		})
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// bindTreeTop points the ancestor walk at a test's own temporary root. /tmp is
// mode 1777 on every Linux box, so without it no pair a test can create could
// pass a rule whose whole point is that nobody but root may write any ancestor.
func bindTreeTop(t *testing.T, dir string) {
	t.Helper()
	old := treeTop
	treeTop = dir
	t.Cleanup(func() { treeTop = old })
}

// Astra r2 #1: the old check looked at the LEXICAL parent of the configured
// path. A root-owned 0700 directory holding root-owned SYMLINKS into a share
// anybody can write passed it, and the loader then followed them — so the key
// the emergency door terminates TLS with was one that user could replace. The
// check is now bound to what is actually opened: the path is resolved, the
// RESOLVED ancestry is walked, and the open is O_NOFOLLOW on the resolved name.
func TestExplicitPairRefusesASymlinkChainIntoAWritableDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ownership and POSIX modes are a Linux question (contract §15)")
	}
	root := t.TempDir()
	bindTreeTop(t, root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// The real pair lives in a directory anybody can write.
	writable := filepath.Join(root, "share")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	realCert := filepath.Join(writable, "cert.pem")
	realKey := filepath.Join(writable, "key.pem")
	if _, err := EnsureUsable(realCert, realKey, time.Now()); err != nil {
		t.Fatal(err)
	}

	// The configured location is a 0700 directory of links into it — exactly
	// what the lexical parent check accepted.
	tight := filepath.Join(root, "tight")
	if err := os.Mkdir(tight, 0o700); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(tight, "breakglass-cert.pem")
	keyFile := filepath.Join(tight, "breakglass-key.pem")
	if err := os.Symlink(realCert, certFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realKey, keyFile); err != nil {
		t.Fatal(err)
	}

	loc := Location{CertFile: certFile, KeyFile: keyFile, Explicit: true}
	if _, err := loc.Load(); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("Load through a symlink into a world-writable directory = %v, want ErrUnsafeLocation", err)
	}
	// And it is a REFUSAL, not a reason to generate: writing a fresh private key
	// into that directory would hand it to whoever can write there.
	got, err := loc.EnsureUsable(time.Now())
	if !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("EnsureUsable = (%+v, %v), want ErrUnsafeLocation", got, err)
	}
	if got.Generated {
		t.Fatal("a pair was generated into a location the check refused")
	}
	// The same refusal before anything exists: the directory a key is about to
	// be written into is checked too.
	fresh := Location{
		CertFile: filepath.Join(writable, "new-cert.pem"),
		KeyFile:  filepath.Join(writable, "new-key.pem"),
		Explicit: true,
	}
	if _, err := fresh.EnsureUsable(time.Now()); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("EnsureUsable into a world-writable directory = %v, want ErrUnsafeLocation", err)
	}
	if _, err := os.Stat(fresh.KeyFile); !os.IsNotExist(err) {
		t.Fatalf("a key was published into the refused directory (%v)", err)
	}
}

// Astra r3 #3: the same arrangement read backwards. Astra r2 #1 closed the
// chain that pointed OUT of a tight directory into a writable share; this is
// links that point IN — from a root-owned 0700 directory that happens to sit
// under a writable share, to a pair that is perfectly safe under a directory
// nobody else can touch. The resolved walk approves the target and says nothing
// about where the names live, while generate publishes by renaming over those
// names: the links are replaced and the new private key is written into the
// directory under the share. The pair that was checked and the pair that was
// written were never the same pair.
func TestExplicitPairRefusesSymlinksPointingAtASafeTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ownership and POSIX modes are a Linux question (contract §15)")
	}
	root := t.TempDir()
	bindTreeTop(t, root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// The target is beyond reproach: a 0700 directory with a tight ancestry.
	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	safeCert := filepath.Join(safe, "cert.pem")
	safeKey := filepath.Join(safe, "key.pem")
	target, err := EnsureUsable(safeCert, safeKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The configured location: a root-owned 0700 directory of links, under a
	// share anybody can write.
	share := filepath.Join(root, "share")
	if err := os.Mkdir(share, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(share, 0o777); err != nil {
		t.Fatal(err)
	}
	tight := filepath.Join(share, "tight")
	if err := os.Mkdir(tight, 0o700); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(tight, "breakglass-cert.pem")
	keyFile := filepath.Join(tight, "breakglass-key.pem")
	if err := os.Symlink(safeCert, certFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(safeKey, keyFile); err != nil {
		t.Fatal(err)
	}

	loc := Location{CertFile: certFile, KeyFile: keyFile, Explicit: true}
	if _, err := loc.Load(); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("Load through a link whose NAME lives in a writable ancestry = %v, want ErrUnsafeLocation", err)
	}
	// And nothing is generated over it: that is the write this finding is about.
	// An expired pair is enough to reach it without anybody deciding to.
	got, err := loc.EnsureUsable(time.Now().Add(Validity + 24*time.Hour))
	if !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("EnsureUsable = (%+v, %v), want ErrUnsafeLocation", got, err)
	}
	for _, p := range []string{certFile, keyFile} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s was replaced by a real file: a key pair was published into %s", p, tight)
		}
	}
	// The safe pair is untouched too — a refusal writes nothing anywhere.
	after, err := Load(safeCert, safeKey)
	if err != nil || after.Fingerprint != target.Fingerprint {
		t.Fatalf("the target pair changed: %v %+v", err, after)
	}

	// The plain case behind the links: names spelled directly in that same
	// directory are refused for the ancestry alone, whether or not they exist.
	plain := Location{
		CertFile: filepath.Join(tight, "plain-cert.pem"),
		KeyFile:  filepath.Join(tight, "plain-key.pem"),
		Explicit: true,
	}
	if _, err := plain.EnsureUsable(time.Now()); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("EnsureUsable under a world-writable share = %v, want ErrUnsafeLocation", err)
	}
	if _, err := os.Stat(plain.KeyFile); !os.IsNotExist(err) {
		t.Fatalf("a key was published under the writable share (%v)", err)
	}
}

// The other half of the rule: a plain pair in a tight, owner-only ancestry is
// served. Run as root — the CI root job — this is the production rule exactly,
// every ancestor owned by uid 0.
func TestExplicitPairAcceptsATightLocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ownership and POSIX modes are a Linux question (contract §15)")
	}
	root := t.TempDir()
	bindTreeTop(t, root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	loc := Location{
		CertFile: filepath.Join(dir, "breakglass-cert.pem"),
		KeyFile:  filepath.Join(dir, "breakglass-key.pem"),
		Explicit: true,
	}
	made, err := loc.EnsureUsable(time.Now())
	if err != nil {
		t.Fatalf("a tight, owner-only location was refused: %v", err)
	}
	loaded, err := loc.Load()
	if err != nil {
		t.Fatalf("the pair it had just written was refused: %v", err)
	}
	if loaded.Fingerprint != made.Fingerprint {
		t.Fatalf("Load = %s, want %s", loaded.Fingerprint, made.Fingerprint)
	}

	// A key group or other can read is refused wherever it lives: that half is a
	// property of the FILE, so the default location is covered by it too.
	if err := os.Chmod(loc.KeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(loc.CertFile, loc.KeyFile); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("Load of a 0644 key = %v, want ErrUnsafeLocation", err)
	}
}

// The ownership half needs a uid this process does not own, so it needs root.
func TestKeyOwnedByAnotherUidIsRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ownership is a Linux question (contract §15)")
	}
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file away (INV-2: never simulate the kernel)")
	}
	certFile, keyFile := certPaths(t)
	if _, err := EnsureUsable(certFile, keyFile, time.Now()); err != nil {
		t.Fatal(err)
	}
	// uid 1 (bin): a uid that is neither root nor this process.
	if err := os.Chown(keyFile, 1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certFile, keyFile); !errors.Is(err, ErrUnsafeLocation) {
		t.Fatalf("Load of a key owned by uid 1 = %v, want ErrUnsafeLocation", err)
	}
}
