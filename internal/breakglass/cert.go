package breakglass

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Certificate lifetime (M4 contract §3.2).
//
// 397 days, not ten years: Apple's 398-day ceiling makes a long-lived
// certificate one that Safari may simply refuse, and an emergency door one
// family of browsers cannot open is not an emergency door. The daemon
// regenerates inside RenewWithin of expiry at start-up, in the process that is
// already running, so it costs the operator nothing.
const (
	Validity    = 397 * 24 * time.Hour
	RenewWithin = 30 * 24 * time.Hour
)

// HostnameFile is where the certificate's primary DNS SAN comes from. It is a
// variable so a test can point it at a fixture instead of the host's own name.
var HostnameFile = "/etc/hostname"

// Cert is a loaded or freshly generated break-glass certificate.
type Cert struct {
	TLS *tls.Certificate
	// Fingerprint is the SHA-256 of the DER certificate, lowercase hex. It is
	// what an operator compares against the browser's warning before typing a
	// password, so it is logged at every start and printed by
	// `break-glass status` (contract §3.4).
	Fingerprint string
	NotAfter    time.Time
	// Generated reports that this call wrote a new key pair, which is a forced
	// audit milestone: a silently changed fingerprint and a man in the middle
	// look identical from the browser.
	Generated bool
	// Reason says why it was generated ("absent", "unreadable", "expiring"),
	// for the log line and the milestone detail. Empty when it was loaded.
	Reason string
}

// ErrPairMismatch is a certificate and a key on disk that are not each other's.
//
// It is a real state, not a hypothetical: the pair is published as two separate
// atomic renames, so a crash — or, before the writers were serialised, a second
// generator — between the two leaves A's certificate beside B's key. Ensure
// treats it as a reason to regenerate rather than an error, which is what makes
// that torn state self-heal at the next start (round-5).
var ErrPairMismatch = errors.New("breakglass: the certificate and key on disk are not a pair")

// Ensure loads the certificate at certFile/keyFile, generating a new one when
// it is absent, unreadable, mismatched, or within RenewWithin of expiry. now is
// the clock seam: production passes time.Now().
//
// Both files are written at 0600 and their directory is created at 0700. The
// mode is approximate on Windows, which is why the mode assertion is a
// Linux-only test (contract §15).
//
// CALLERS MUST SERIALISE THIS. The pair is two files and therefore two
// publications, and nothing here can make them one; every writer — the daemon
// arming or re-arming the door, `break-glass set-password`, `break-glass cert
// -regenerate` — takes the credential-store lock (config.Lock, flock on the
// NAS) around the call. The self-heal below is what covers a crash between the
// two renames; the lock is what stops two live writers producing that state in
// the first place.
func Ensure(certFile, keyFile string, now time.Time) (Cert, error) {
	return ensure(certFile, keyFile, now, true)
}

// EnsureUsable generates a pair only when there is not a usable one already:
// absent, unreadable, or torn between the two renames. A certificate inside its
// renewal window is left exactly where it is.
//
// It exists for `break-glass set-password` (Astra r1 #16). That command called
// Ensure, which renews — so an operator setting a password on a unit whose
// certificate happened to be 20 days from expiry got a NEW fingerprint printed
// with the instruction to compare it in the browser, while the running daemon
// went on serving the old pair. The operator then compares two different
// fingerprints and concludes, correctly by every rule the documentation gave
// them, that they are being intercepted. Renewal belongs to the daemon's own
// start-up and to `cert -regenerate`, both of which say a restart is involved.
func EnsureUsable(certFile, keyFile string, now time.Time) (Cert, error) {
	return ensure(certFile, keyFile, now, false)
}

func ensure(certFile, keyFile string, now time.Time, renew bool) (Cert, error) {
	if certFile == "" || keyFile == "" {
		return Cert{}, fmt.Errorf("breakglass: certificate paths are empty")
	}
	reason := ""
	loaded, err := load(certFile, keyFile)
	switch {
	case err != nil && os.IsNotExist(err):
		reason = "absent"
	case errors.Is(err, ErrPairMismatch):
		// Named separately from "unreadable" so the start-up log and the audit
		// milestone say what actually happened: a half-published pair is a very
		// different event from a corrupt file, and an operator who sees
		// "mismatched" knows a write was interrupted.
		reason = "mismatched"
	case err != nil:
		reason = "unreadable"
	case renew && !now.Add(RenewWithin).Before(loaded.NotAfter):
		reason = "expiring"
	default:
		return loaded, nil
	}
	generated, err := generate(certFile, keyFile, now)
	if err != nil {
		return Cert{}, err
	}
	generated.Generated, generated.Reason = true, reason
	return generated, nil
}

// Regenerate writes a fresh key pair unconditionally. It is what
// `break-glass cert -regenerate` calls after an IP change or a suspected key
// compromise.
func Regenerate(certFile, keyFile string, now time.Time) (Cert, error) {
	c, err := generate(certFile, keyFile, now)
	if err != nil {
		return Cert{}, err
	}
	c.Generated, c.Reason = true, "requested"
	return c, nil
}

// Load reads an existing certificate without generating anything. It is what
// `break-glass status` uses: reporting a fingerprint must never be the thing
// that changes it.
func Load(certFile, keyFile string) (Cert, error) { return load(certFile, keyFile) }

func load(certFile, keyFile string) (Cert, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return Cert{}, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return Cert{}, err
	}
	// The certificate is parsed on its own FIRST, so a corrupt file reads as
	// unreadable rather than as a mismatch: the two are different events and the
	// start-up log should not conflate them. A malformed KEY still surfaces as a
	// mismatch below, because a pair that cannot be verified is not a pair — and
	// either way Ensure regenerates.
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return Cert{}, fmt.Errorf("breakglass: %s is not a PEM certificate", certFile)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: parsing %s: %w", certFile, err)
	}
	// X509KeyPair is what verifies that the private key really belongs to the
	// certificate's public key — the check a torn publication fails.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Cert{}, fmt.Errorf("%w (%s): %v", ErrPairMismatch, certFile, err)
	}
	if len(pair.Certificate) == 0 {
		return Cert{}, fmt.Errorf("breakglass: %s holds no certificate", certFile)
	}
	pair.Leaf = leaf
	return Cert{TLS: &pair, Fingerprint: Fingerprint(pair.Certificate[0]), NotAfter: leaf.NotAfter}, nil
}

// Fingerprint is the SHA-256 of a DER certificate as lowercase hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func generate(certFile, keyFile string, now time.Time) (Cert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: generating a key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: generating a serial: %w", err)
	}
	names, ips := SANs()
	cn := "qnapfilemanager"
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"QNAPFileManager break-glass"}},
		NotBefore:    now.Add(-time.Hour), // tolerate a NAS clock a little behind the browser's
		NotAfter:     now.Add(Validity),
		// A SERVER leaf, never a certificate authority (round-1 P2-6). An
		// operator who imports this to stop the browser warning — which is
		// exactly what §3.4's fingerprint procedure invites them to consider —
		// would otherwise be trusting it to sign certificates for any name at
		// all, on the machine they use to administer the NAS. DigitalSignature
		// and ServerAuth are the whole of what a TLS server needs.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: creating the certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: marshalling the key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// The key is written before the certificate and both at 0600: a reader that
	// catches the pair half-written sees an unusable pair (Ensure regenerates),
	// never a certificate with a world-readable key beside it.
	if err := writePrivate(keyFile, keyPEM); err != nil {
		return Cert{}, err
	}
	if err := writePrivate(certFile, certPEM); err != nil {
		return Cert{}, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: the generated pair does not load: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: parsing the generated certificate: %w", err)
	}
	pair.Leaf = leaf
	return Cert{TLS: &pair, Fingerprint: Fingerprint(der), NotAfter: leaf.NotAfter}, nil
}

// writePrivate writes data at 0600, creating the parent directory at 0700. It
// publishes by rename so a crash cannot leave a truncated key where a valid one
// was, and it creates the temporary file at 0600 too — a key that is briefly
// world-readable is a key that leaked.
//
// The temporary name is unique per call: a fixed "<path>.tmp" is a collision
// between two concurrent writers (a daemon regenerating at start-up while an
// operator runs `break-glass cert -regenerate`) in which each could publish half
// of the other's pair.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("breakglass: creating %s: %w", dir, err)
	}
	tmp := fmt.Sprintf("%s.tmp-%d-%d", path, os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("breakglass: writing %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("breakglass: writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("breakglass: syncing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("breakglass: closing %s: %w", path, err)
	}
	if err := publish(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("breakglass: publishing %s: %w", path, err)
	}
	// Chmod again after the rename: the mode is what the umask may have
	// narrowed or widened, and this file holds a private key.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("breakglass: tightening %s: %w", path, err)
	}
	return nil
}

// SANs is the subject-alternative-name set a generated certificate carries:
// the host's own name, every non-loopback IP it has right now, and the two
// loopback literals.
//
// IP SANs matter here (contract §3.3). An operator with a broken desktop
// reaches this door by IP, and a certificate with no IP SAN produces a
// different, scarier browser warning than the expected self-signed one.
func SANs() (names []string, ips []net.IP) {
	if h := hostname(); h != "" {
		names = append(names, h)
	}
	names = append(names, "localhost")
	ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return names, ips
}

func hostname() string {
	if data, err := os.ReadFile(HostnameFile); err == nil {
		if h := strings.TrimSpace(string(data)); h != "" {
			return h
		}
	}
	// Not a fallback to something invented: os.Hostname is the same fact by
	// another route, and an empty name simply means no DNS SAN.
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(h)
}
