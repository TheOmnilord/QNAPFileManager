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
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Certificate lifetime (M4 contract §3.2, amended by Astra r2 #3).
//
// 397 days, not ten years: Apple's 398-day ceiling makes a long-lived
// certificate one that Safari may simply refuse, and an emergency door one
// family of browsers cannot open is not an emergency door.
//
// RenewWithin is a WARNING window, not a renewal one: the daemon never rotates
// this pair by itself. An operator is told to compare a fingerprint against the
// browser's warning before typing the emergency password, and a daemon that
// changes that fingerprint on a restart nobody connected to the change teaches
// them that a changed fingerprint is normal — which is the one lesson this door
// must never teach. Inside the window the daemon says how many days are left
// and names `break-glass cert -regenerate`; the operator rotates when they are
// ready to compare the new one. An EXPIRED pair is different: no browser will
// open that door at all, so it is worth nothing and is replaced, loudly.
const (
	Validity    = 397 * 24 * time.Hour
	RenewWithin = 30 * 24 * time.Hour
)

// maxPEMBytes bounds what the loader reads from either half of the pair. A key
// pair is a couple of kilobytes; this is what stops a file that has become
// something else — a log, a device, a mistake — from being read into the memory
// of a root daemon at start-up.
const maxPEMBytes = 1 << 20

// treeTop bounds the ancestor walk of an explicit location. It is empty in
// production, which means the walk runs to the filesystem root. A test sets it
// to its own temporary root: /tmp is mode 1777 on every Linux box, so nothing
// under it can ever pass a rule whose whole point is that nobody but root may
// write any ancestor, and a rule that can only be tested by its refusals is a
// rule that is half tested. Nothing reads it from a goroutine.
var treeTop = ""

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
	// Reason says why it was generated — one of the Reason* constants below —
	// for the log line and the milestone detail. Empty when it was loaded.
	Reason string
}

// Why a pair was generated. They are constants because the CLI decides what to
// TELL an operator from them (Astra r3 #1), and a decision that turns on a
// string literal spelled in two places is one refactor away from being wrong in
// the one moment this door is used.
const (
	// ReasonAbsent: there was no pair at all. Nothing was replaced, so nothing
	// is being served from memory either — a daemon that had armed this door
	// would have generated one.
	ReasonAbsent = "absent"
	// ReasonUnreadable: something was there and could not be read as a pair.
	ReasonUnreadable = "unreadable"
	// ReasonMismatched: a certificate beside a key that is not its own, which is
	// what a crash between the two renames leaves.
	ReasonMismatched = "mismatched"
	// ReasonExpired: a pair no browser will accept any more.
	ReasonExpired = "expired"
	// ReasonRequested: `break-glass cert -regenerate`, the only rotation there
	// is.
	ReasonRequested = "requested"
)

// Replaced reports that this call generated a pair over one that was ALREADY
// there — expired, torn, unreadable, or rotated on request (Astra r3 #1).
//
// It is the question the CLI has to answer before it prints a fingerprint: a
// running daemon holds its pair in memory and the credential watcher has
// stopped once the door is armed, so a REPLACEMENT is not what the browser will
// be shown until the app is restarted. A first generation (ReasonAbsent) is the
// opposite case — no daemon can be serving a pair that did not exist — and the
// documented first run rightly says no restart is needed.
func (c Cert) Replaced() bool { return c.Generated && c.Reason != ReasonAbsent }

// ErrPairMismatch is a certificate and a key on disk that are not each other's.
//
// It is a real state, not a hypothetical: the pair is published as two separate
// atomic renames, so a crash — or, before the writers were serialised, a second
// generator — between the two leaves A's certificate beside B's key. Ensure
// treats it as a reason to regenerate rather than an error, which is what makes
// that torn state self-heal at the next start (round-5).
var ErrPairMismatch = errors.New("breakglass: the certificate and key on disk are not a pair")

// ErrUnsafeLocation is a pair the kernel says somebody other than root can
// replace: a key owned by another uid, a key group or other can read, a
// non-regular file where a key should be, or — for a location the operator
// named — an ancestor directory that is not root-owned or that group or other
// can write (Astra r2 #1).
//
// It is never healed by generating a new pair. Writing a fresh private key into
// a directory somebody else can write would hand them that key; the door stays
// shut, and the log says which path and why.
var ErrUnsafeLocation = errors.New("breakglass: the key pair location is not root-only")

// Location is where the pair lives, and how far the loader checks what it
// opens.
//
// Explicit marks a location the OPERATOR named in web.breakGlass.certFile /
// keyFile rather than the QPKG's own config directory. That is the case whose
// whole resolved ancestry is walked. The default location is created and
// tightened by package_routines and checked by the CLI's own credential-store
// guard whenever it writes a credential; checking it twice, with two sets of
// rules, is how the two come to disagree (Astra r1 #9, kept). A location the
// operator chose has no such owner — and its lexical parent says almost
// nothing, because a root-owned 0700 directory of root-owned SYMLINKS into a
// share anybody can write passes a parent check and still hands over the key
// (Astra r2 #1).
type Location struct {
	CertFile string
	KeyFile  string
	Explicit bool
}

// EnsureUsable generates a pair only when there is not a usable one already:
// absent, unreadable, torn between the two renames, or expired. A certificate
// inside its renewal window is left exactly where it is and the caller warns
// about it — nothing here rotates a fingerprint an operator has been told to
// compare (Astra r1 #16, Astra r2 #3). now is the clock seam: production passes
// time.Now().
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
func EnsureUsable(certFile, keyFile string, now time.Time) (Cert, error) {
	return Location{CertFile: certFile, KeyFile: keyFile}.EnsureUsable(now)
}

// EnsureUsable is EnsureUsable for a location the operator may have named. The
// strict checks of an explicit location are refusals, never reasons to
// generate: see ErrUnsafeLocation.
func (l Location) EnsureUsable(now time.Time) (Cert, error) {
	if l.CertFile == "" || l.KeyFile == "" {
		return Cert{}, fmt.Errorf("breakglass: certificate paths are empty")
	}
	reason := ""
	loaded, err := l.Load()
	switch {
	case errors.Is(err, ErrUnsafeLocation):
		return Cert{}, err
	case err != nil && os.IsNotExist(err):
		reason = ReasonAbsent
	case errors.Is(err, ErrPairMismatch):
		// Named separately from "unreadable" so the start-up log and the audit
		// milestone say what actually happened: a half-published pair is a very
		// different event from a corrupt file, and an operator who sees
		// "mismatched" knows a write was interrupted.
		reason = ReasonMismatched
	case err != nil:
		reason = ReasonUnreadable
	case !now.Before(loaded.NotAfter):
		// EXPIRED, not expiring. A certificate no browser will accept opens
		// nothing, so replacing it costs the operator nothing either — and the
		// new fingerprint is logged and audited like every other generation.
		reason = ReasonExpired
	default:
		return loaded, nil
	}
	generated, err := l.generate(now)
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
	return Location{CertFile: certFile, KeyFile: keyFile}.Regenerate(now)
}

// Regenerate is Regenerate for a location the operator may have named.
func (l Location) Regenerate(now time.Time) (Cert, error) {
	c, err := l.generate(now)
	if err != nil {
		return Cert{}, err
	}
	c.Generated, c.Reason = true, ReasonRequested
	return c, nil
}

// Load reads an existing certificate without generating anything. It is what
// `break-glass status` uses: reporting a fingerprint must never be the thing
// that changes it.
func Load(certFile, keyFile string) (Cert, error) {
	return Location{CertFile: certFile, KeyFile: keyFile}.Load()
}

// Load is Load for a location the operator may have named.
func (l Location) Load() (Cert, error) {
	certPEM, err := l.read(l.CertFile, false)
	if err != nil {
		return Cert{}, err
	}
	keyPEM, err := l.read(l.KeyFile, true)
	if err != nil {
		return Cert{}, err
	}
	// The certificate is parsed on its own FIRST, so a corrupt file reads as
	// unreadable rather than as a mismatch: the two are different events and the
	// start-up log should not conflate them. A malformed KEY still surfaces as a
	// mismatch below, because a pair that cannot be verified is not a pair — and
	// either way EnsureUsable regenerates.
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return Cert{}, fmt.Errorf("breakglass: %s is not a PEM certificate", l.CertFile)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Cert{}, fmt.Errorf("breakglass: parsing %s: %w", l.CertFile, err)
	}
	// X509KeyPair is what verifies that the private key really belongs to the
	// certificate's public key — the check a torn publication fails.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Cert{}, fmt.Errorf("%w (%s): %v", ErrPairMismatch, l.CertFile, err)
	}
	if len(pair.Certificate) == 0 {
		return Cert{}, fmt.Errorf("breakglass: %s holds no certificate", l.CertFile)
	}
	pair.Leaf = leaf
	return Cert{TLS: &pair, Fingerprint: Fingerprint(pair.Certificate[0]), NotAfter: leaf.NotAfter}, nil
}

// read opens one half of the pair and asks the KERNEL about the file it
// actually opened (Astra r2 #1).
//
// The path is resolved first, so the ancestry that is checked is the ancestry
// the bytes really come from and not the one the config file spells — a
// root-owned 0700 directory of symlinks into a share anybody can write is
// exactly what the old lexical parent check could not see. The final open is
// O_NOFOLLOW on the RESOLVED path, so a link swapped in between resolving and
// opening is refused rather than followed, and the mode and owner come from
// fstat(2) on the descriptor that was opened rather than from a second lookup
// of a name that may by then mean something else.
func (l Location) read(path string, isKey bool) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("breakglass: certificate paths are empty")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// An absent file stays an absent file: EnsureUsable reads ENOENT as
		// "absent" and generates.
		return nil, err
	}
	if l.Explicit {
		// The LITERAL name first (Astra r3 #3), then the resolved ancestry. A
		// final component that is a symlink means the two are different
		// directories, and then neither check is about the other's: whoever can
		// write the directory holding the link decides which file the door
		// serves, while the walk below approves the target they pointed it at.
		if err := l.literalStrict(path); err != nil {
			return nil, err
		}
		if err := treeStrict(resolved); err != nil {
			return nil, err
		}
	}
	f, err := openNoFollow(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := fileStrict(fi, resolved, isKey); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPEMBytes {
		return nil, fmt.Errorf("breakglass: %s is larger than %d bytes, so it is not a key pair", path, maxPEMBytes)
	}
	return data, nil
}

// literalStrict checks the name as it is SPELLED, which is the direction a
// write goes (Astra r3 #3).
//
// Astra r2 #1 closed the chain that pointed outwards: a tight directory of
// symlinks into a share anybody could write. The same arrangement read
// backwards was still open. Put root-owned symlinks in a root-owned 0700
// directory that sits under a writable share, point them at a perfectly safe
// pair under /root, and the resolved walk approves /root — but writePrivate
// publishes by renaming a temporary file over CertFile and KeyFile THEMSELVES,
// so a regeneration replaces the links and writes the new private key into the
// directory under the share. The pair the check approved and the pair that was
// written were in two different places, and an expired-pair start-up is enough
// to trigger it without anybody choosing to.
//
// So: the final component may not be a symlink at all, and the directory the
// rename lands in — the literal parent, with its own ancestry — must be
// root-only. A link is REFUSED rather than silently replaced, because a refusal
// names the path and the app stays out of a location it cannot reason about.
// Nothing is lost by the rule: an operator who wants the pair elsewhere names
// it elsewhere in web.breakGlass.certFile / keyFile.
func (l Location) literalStrict(path string) error {
	if path == "" {
		return fmt.Errorf("breakglass: certificate paths are empty")
	}
	// Lstat, so the link itself is what is stat'ed rather than what it points
	// at. An absent name is not an error here: the directory below is what a
	// pair that does not exist yet is about to be published into.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symbolic link, and the pair is published by renaming over that name — the key would be written in %s, not where the link points", ErrUnsafeLocation, path, filepath.Dir(path))
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%w: %s could not be read: %v", ErrUnsafeLocation, path, err)
	}
	return treeStrict(filepath.Dir(path))
}

// Fingerprint is the SHA-256 of a DER certificate as lowercase hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func (l Location) generate(now time.Time) (Cert, error) {
	if l.Explicit {
		// Checked before the pair exists, too. An absent file resolves to
		// nothing, so the ancestry the loader walks has nothing to walk yet —
		// and the moment that matters most is this one: publishing a fresh
		// private key into a directory somebody else can write hands them the
		// key (Astra r2 #1).
		//
		// The directory that is checked is the one the rename will really land
		// in (Astra r3 #3): literalStrict walks the LITERAL parent and refuses a
		// final component that is a symlink, because writePrivate publishes over
		// these names rather than through them.
		if err := l.literalStrict(l.KeyFile); err != nil {
			return Cert{}, err
		}
		if err := l.literalStrict(l.CertFile); err != nil {
			return Cert{}, err
		}
	}
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
	// catches the pair half-written sees an unusable pair (EnsureUsable
	// regenerates), never a certificate with a world-readable key beside it.
	if err := writePrivate(l.KeyFile, keyPEM); err != nil {
		return Cert{}, err
	}
	if err := writePrivate(l.CertFile, certPEM); err != nil {
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
