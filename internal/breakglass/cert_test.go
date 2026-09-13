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

	first, err := Ensure(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Generated || first.Reason != "absent" {
		t.Fatalf("first Ensure = %+v, want a generation because the file was absent", first)
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
	second, err := Ensure(certFile, keyFile, now.Add(24*time.Hour))
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

func TestEnsureRegeneratesInsideTheRenewalWindow(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	first, err := Ensure(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	expiry := first.NotAfter

	// One second before the window opens: still reloaded.
	justOutside := expiry.Add(-RenewWithin).Add(-time.Second)
	got, err := Ensure(certFile, keyFile, justOutside)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generated || got.Fingerprint != first.Fingerprint {
		t.Fatalf("regenerated %v before the window opened", justOutside)
	}

	// Inside the 30-day window: regenerated, in the process that is already
	// running, so it costs the operator nothing.
	inside := expiry.Add(-RenewWithin).Add(time.Second)
	got, err = Ensure(certFile, keyFile, inside)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Generated || got.Reason != "expiring" {
		t.Fatalf("Ensure at %v = %+v, want a regeneration", inside, got)
	}
	if got.Fingerprint == first.Fingerprint {
		t.Fatal("a regenerated certificate must have a new fingerprint")
	}
	if want := inside.Add(Validity); !got.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", got.NotAfter, want)
	}
}

func TestEnsureReplacesAnUnreadablePair(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Now()
	if _, err := Ensure(certFile, keyFile, now); err != nil {
		t.Fatal(err)
	}
	// A half-written or corrupted pair must not leave the door unopenable.
	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Ensure(certFile, keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Generated || got.Reason != "unreadable" {
		t.Fatalf("Ensure over a corrupt pair = %+v, want a regeneration", got)
	}
}

func TestRegenerateAlwaysChangesTheFingerprint(t *testing.T) {
	certFile, keyFile := certPaths(t)
	now := time.Now()
	first, err := Ensure(certFile, keyFile, now)
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

	got, err := Ensure(certFile, keyFile, time.Now())
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
	if _, err := Ensure(certFile, keyFile, time.Now()); err != nil {
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
	if _, err := Ensure("", "", time.Now()); err == nil {
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
	got, err := Ensure(certFile, keyFile, time.Now())
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
// two files — so Ensure heals it at the next start instead of refusing to
// serve.
func TestEnsureHealsATornPair(t *testing.T) {
	certFile, keyFile := certPaths(t)
	first, err := Ensure(certFile, keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A second generation, kept aside, standing in for the half that landed.
	otherCert, otherKey := certPaths(t)
	second, err := Ensure(otherCert, otherKey, time.Now())
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
			// Ensure heals it rather than failing: this is what makes a crash
			// between the two renames survivable without an operator.
			healed, err := Ensure(certFile, keyFile, time.Now())
			if err != nil {
				t.Fatalf("Ensure over a torn pair = %v, want a regeneration", err)
			}
			if !healed.Generated || healed.Reason != "mismatched" {
				t.Fatalf("Ensure = %+v, want a regeneration with reason \"mismatched\"", healed)
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
