package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// realHash is a bcrypt hash of a throwaway password at cost, produced once per
// call. Validation parses the stored hash now (Astra r1 #10), so a fixture that
// merely LOOKS like a hash is no longer a valid config — which is the whole
// point of that finding, and means every fixture here has to be real.
func realHash(t *testing.T, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("a long enough password"), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// TestListenMustBeLoopback is M4 contract §13.1 as a table of spellings. The
// main listener carries the QTS cookie door and is reached through the QTS
// proxy; the break-glass listener is the one sanctioned non-loopback surface,
// and there is deliberately NO override key — so this table is the whole rule.
func TestListenMustBeLoopback(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:8770", true},
		{"127.0.0.1:1", true},
		{"127.0.0.5:8770", true}, // the whole 127.0.0.0/8 block is loopback
		{"127.255.255.254:1", true},
		{"[::1]:8770", true},
		{"0.0.0.0:8770", false},
		{":8770", false},     // the empty host binds every interface
		{"[::]:8770", false}, // and so does the v6 wildcard
		{"192.168.1.10:8770", false},
		{"10.0.0.1:8770", false},
		{"[2001:db8::1]:8770", false},
		{"nas.local:8770", false}, // a hostname is refused before the loopback test
		{"localhost:8770", false}, // including the one that happens to resolve to loopback
		{"127.0.0.1", false},      // no port
		{"8770", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			cfg := Default()
			cfg.Web.Listen = c.addr
			err := cfg.Validate()
			if c.ok && err != nil {
				t.Fatalf("Validate(%q) = %v, want it accepted", c.addr, err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("Validate(%q) = nil, want it refused", c.addr)
				}
				if !strings.Contains(err.Error(), "web.listen") {
					t.Fatalf("the error must name the key it is about: %v", err)
				}
			}
			// -dev relaxes auth.mode and nothing else: there is no development
			// escape hatch for exposing the main listener.
			if got := cfg.ValidateDev(true); (got == nil) != c.ok {
				t.Fatalf("ValidateDev(%q) = %v, want the same verdict as Validate", c.addr, got)
			}
		})
	}
}

// The break-glass listener is the exception, and it is meant to be: 0.0.0.0 is
// its default, because a door you can only reach from the machine you cannot
// log in to is not a door.
func TestBreakGlassAddrMayBeNonLoopback(t *testing.T) {
	cfg := Default()
	if cfg.Web.BreakGlass.Addr != "0.0.0.0:8771" {
		t.Fatalf("breakGlass.addr default = %q, want 0.0.0.0:8771", cfg.Web.BreakGlass.Addr)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default must validate: %v", err)
	}
	for _, addr := range []string{"0.0.0.0:8771", "127.0.0.1:8771", "[::]:8771", "192.168.1.10:8771"} {
		cfg.Web.BreakGlass.Addr = addr
		if err := cfg.Validate(); err != nil {
			t.Errorf("breakGlass.addr %q = %v, want it accepted", addr, err)
		}
	}
	// It still has to be an address, and it still cannot collide with the main
	// listener.
	cfg.Web.BreakGlass.Addr = "not-an-address"
	if err := cfg.Validate(); err == nil {
		t.Error("a malformed break-glass address must be refused")
	}
	cfg.Web.BreakGlass.Addr = cfg.Web.Listen
	if err := cfg.Validate(); err == nil {
		t.Error("the two listeners must not share an address")
	}
	// Disabled means inert: the address is not even looked at.
	cfg.Web.BreakGlass.Enabled = false
	cfg.Web.BreakGlass.Addr = "nonsense"
	if err := cfg.Validate(); err != nil {
		t.Errorf("a disabled break-glass listener must not be validated: %v", err)
	}
}

// M4 §2.2: the local account moved entirely to its own listener, so "local" and
// "both" are no longer modes of the main one — except under -dev, where the
// Windows loop has no QTS to talk to.
func TestAuthModeIsNarrowedToQTS(t *testing.T) {
	for _, c := range []struct {
		mode          string
		prodOK, devOK bool
	}{
		{AuthQTS, true, true},
		{AuthLocal, false, true},
		{AuthBoth, false, true},
		{"", false, false},
		{"ldap", false, false},
	} {
		t.Run("mode="+c.mode, func(t *testing.T) {
			cfg := Default()
			cfg.Auth.Mode = c.mode
			if err := cfg.Validate(); (err == nil) != c.prodOK {
				t.Errorf("Validate(mode=%q) = %v, want accepted %v", c.mode, err, c.prodOK)
			}
			if err := cfg.ValidateDev(true); (err == nil) != c.devOK {
				t.Errorf("ValidateDev(mode=%q) = %v, want accepted %v", c.mode, err, c.devOK)
			}
			if !c.prodOK && c.devOK {
				// The refusal has to say where the local account actually lives,
				// or the operator just picks another wrong value.
				err := cfg.Validate()
				if !strings.Contains(err.Error(), "breakGlass") {
					t.Errorf("the refusal must point at the break-glass listener: %v", err)
				}
			}
		})
	}
}

func TestLocalCredentialValidation(t *testing.T) {
	for _, c := range []struct {
		name  string
		local Local
		ok    bool
	}{
		{"empty is the first-run state", Local{}, true},
		{"default cost", Local{Cost: DefaultLocalCost}, true},
		{"floor", Local{Cost: MinLocalCost}, true},
		{"ceiling", Local{Cost: MaxLocalCost}, true},
		{"below the floor", Local{Cost: MinLocalCost - 1}, false},
		{"above the ceiling", Local{Cost: MaxLocalCost + 1}, false},
		{"a stamp", Local{Updated: "2026-09-13T12:00:00Z"}, true},
		{"a bad stamp", Local{Updated: "yesterday"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			cfg.Auth.Local = c.local
			if err := cfg.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate(%+v) = %v, want accepted %v", c.local, err, c.ok)
			}
		})
	}
	if got := (Local{}).LocalCost(); got != DefaultLocalCost {
		t.Fatalf("LocalCost() on a zero value = %d, want %d", got, DefaultLocalCost)
	}
	if got := (Local{Cost: 13}).LocalCost(); got != 13 {
		t.Fatalf("LocalCost() = %d, want 13", got)
	}
}

// Astra r1 #10: the HASH is validated, not only the cost key beside it. The
// cost that matters is the one embedded in the hash — that is what bcrypt will
// actually run — and nothing checked it: `hash: " "` armed a listener no
// password could pass, and a cost-31 hash would run for minutes per attempt,
// from an unauthenticated caller on the LAN.
func TestTheStoredHashMustBeABcryptHash(t *testing.T) {
	// Cost 31 is generated by rewriting a real hash's cost field: actually
	// hashing at 31 would take longer than this project will exist.
	real10 := realHash(t, MinLocalCost)
	cost31 := "$2a$31$" + real10[7:]
	cost04 := "$2a$04$" + real10[7:]
	for _, c := range []struct {
		name string
		hash string
		ok   bool
	}{
		{"empty is the first-run state", "", true},
		{"a real hash at the floor", real10, true},
		{"a real hash at the ceiling", realHash(t, MaxLocalCost), true},
		{"one space", " ", false},
		{"whitespace", "   \t ", false},
		{"not a hash at all", "hunter2", false},
		{"the right shape, the wrong content", "$2a$10$notarealhashbutlongenoughtolook", false},
		{"cost 31", cost31, false},
		{"cost 4", cost04, false},
		// Astra r2 #4: bcrypt.Cost reads the HEADER and stops, so everything
		// below parsed as a cost-10 hash and was accepted — then failed every
		// comparison the operator ever made. The shape is checked structurally,
		// without running one.
		{"a valid header and 53 characters of nothing", "$2a$10$" + strings.Repeat("!", 53), false},
		{"a valid header and a truncated tail", real10[:50], false},
		{"a valid header and a long tail", real10 + "AAAA", false},
		{"$2b$ is written by some implementations", "$2b$" + real10[4:], true},
		{"$2y$ likewise", "$2y$" + real10[4:], true},
		{"$2x$ is the broken variant", "$2x$" + real10[4:], false},
		{"a standard-base64 character bcrypt never writes", real10[:59] + "+", false},
		// Astra r3 #4: the last character of the checksum carries only the tail
		// of a byte, and base64 writes the spare bits as zero. This one is in the
		// alphabet, is the right length and has a valid header — and no password
		// can ever match it, which is a door that arms and then refuses the
		// operator who just set the password.
		{"a checksum whose last character sets bits bcrypt never writes", real10[:59] + "A", false},
		// Astra r4 #4: the SALT's tail is the same arithmetic and the opposite
		// verdict. bcrypt throws the padding bits away on decode and re-encodes
		// the spelling it was given, so a non-canonical salt tail verifies — and
		// refusing it would stop a daemon that had been serving that hash.
		{"a salt whose last character sets spare bits verifies anyway", real10[:28] + "B" + real10[29:], true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			cfg.Auth.Local.Hash = c.hash
			err := cfg.Validate()
			if (err == nil) != c.ok {
				t.Fatalf("Validate(hash=%q) = %v, want accepted %v", c.hash, err, c.ok)
			}
			if err != nil {
				// The credential is never echoed back, not even a rejected one.
				if strings.Contains(err.Error(), c.hash) && strings.TrimSpace(c.hash) != "" {
					t.Fatalf("the refusal echoes the hash: %v", err)
				}
				if !strings.Contains(err.Error(), "auth.local.hash") {
					t.Fatalf("the refusal must name the key: %v", err)
				}
			}
		})
	}
}

// The other direction of Astra r3 #4, and the one an operator would feel rather
// than an attacker: a mask in the wrong place refuses hashes bcrypt really did
// write, and it would do it only some of the time — one sample proves nothing
// about a four-bit rule. Sixteen real hashes is enough that a misplaced or
// inverted mask cannot get through on luck.
func TestRealHashesAreNeverRefusedForTheirSpareBits(t *testing.T) {
	for i := 0; i < 16; i++ {
		cfg := Default()
		cfg.Auth.Local.Hash = realHash(t, MinLocalCost)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("a real bcrypt hash was refused: %v", err)
		}
	}
}

// Astra r4 #4: the salt tail is not a rule bcrypt enforces, and the proof is
// bcrypt itself. A hash whose 22nd salt character has its low bit flipped is
// exactly the value the round-3 mask refused — and the library still verifies
// the original password against it, because the decode discards the padding bits
// and the comparison re-encodes the salt spelling it was handed. So validation
// must accept it: this check runs on every load, and refusing a credential that
// works would lock an operator out of their own emergency door at the first
// restart after an upgrade, which is the precise opposite of what it is for.
func TestASaltTailBcryptItselfAcceptsIsNotRefused(t *testing.T) {
	const password = "a long enough password"
	h, err := bcrypt.GenerateFromPassword([]byte(password), MinLocalCost)
	if err != nil {
		t.Fatal(err)
	}
	// The 22nd salt character is hash[28]; flipping the low bit of its 6-bit
	// value moves it within bcrypt's own alphabet, so nothing else about the
	// shape changes.
	v := strings.IndexByte(bcryptSalt64, h[28])
	if v < 0 {
		t.Fatalf("a real hash carries a salt character outside the alphabet at offset 28")
	}
	flipped := string(h[:28]) + string(bcryptSalt64[v^1]) + string(h[29:])
	if flipped == string(h) {
		t.Fatal("the flip changed nothing")
	}
	// bcrypt's verdict first: if the library refused this too, the finding would
	// be wrong and the mask would have been right.
	if err := bcrypt.CompareHashAndPassword([]byte(flipped), []byte(password)); err != nil {
		t.Fatalf("bcrypt refused the flipped-salt hash, so it is not a valid credential after all: %v", err)
	}
	cfg := Default()
	cfg.Auth.Local.Hash = flipped
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation refused a hash bcrypt verifies: %v", err)
	}
}

// Astra r1 #9: an explicit key location outside the QPKG's own config directory
// is accepted, but not one anybody except root can write to — replacing a file
// is a property of its directory, and the key is what the emergency door
// terminates TLS with.
func TestExplicitKeyDirectoryMustBeRootOwnedAndTight(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory ownership and POSIX modes are a Linux question (contract §15)")
	}
	dir := t.TempDir()
	// The DEFAULT location is not checked here at all: it is beside config.json
	// in the QPKG's 0700 config/, which the CLI's own store guard covers.
	cfg := Default()
	if err := cfg.CheckBreakGlassKeyDir(filepath.Join(dir, "config.json")); err != nil {
		t.Fatalf("the default location was refused: %v", err)
	}

	tight := filepath.Join(dir, "tight")
	if err := os.Mkdir(tight, 0o700); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's mode is the test process's business; assert what we set.
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}

	explicit := func(d string) Config {
		c := Default()
		c.Web.BreakGlass.KeyFile = filepath.Join(d, "breakglass-key.pem")
		c.Web.BreakGlass.CertFile = filepath.Join(d, "breakglass-cert.pem")
		return c
	}
	err := explicit(loose).CheckBreakGlassKeyDir("")
	if err == nil {
		t.Fatal("a world-writable key directory was accepted")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("the refusal must say why: %v", err)
	}

	// The ownership half needs the two cases to be run by the right uid, so
	// each asserts only what its own uid can prove (INV-2: never simulate).
	err = explicit(tight).CheckBreakGlassKeyDir("")
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("a root-owned 0700 directory was refused: %v", err)
		}
	} else {
		if err == nil {
			t.Fatal("a directory owned by a non-root uid was accepted")
		}
		if !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("the refusal must name the owner: %v", err)
		}
	}

	// A directory that does not exist yet is not a finding: the daemon creates
	// it at 0700 when it generates the pair.
	if err := explicit(filepath.Join(dir, "not-yet")).CheckBreakGlassKeyDir(""); err != nil {
		t.Fatalf("an absent directory was refused: %v", err)
	}
}

func TestLocalCredentialRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.Auth.Local = Local{Hash: realHash(t, 12), Cost: 12, Updated: time.Now().UTC().Format(time.RFC3339)}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth.Local != c.Auth.Local {
		t.Fatalf("auth.local round trip = %+v, want %+v", got.Auth.Local, c.Auth.Local)
	}
}

func TestBreakGlassFilesDefaultBesideTheConfig(t *testing.T) {
	c := Default()
	cert, key := c.BreakGlassFiles(filepath.Join("install", "config", "config.json"))
	if cert != filepath.Join("install", "config", "breakglass-cert.pem") {
		t.Errorf("certFile = %q", cert)
	}
	if key != filepath.Join("install", "config", "breakglass-key.pem") {
		t.Errorf("keyFile = %q", key)
	}
	// An explicit setting wins.
	c.Web.BreakGlass.CertFile = "/somewhere/else/c.pem"
	c.Web.BreakGlass.KeyFile = "/somewhere/else/k.pem"
	cert, key = c.BreakGlassFiles("install/config/config.json")
	if cert != "/somewhere/else/c.pem" || key != "/somewhere/else/k.pem" {
		t.Errorf("explicit paths lost: %q %q", cert, key)
	}
	// No config file at all still yields usable paths.
	cert, key = Default().BreakGlassFiles("")
	if cert == "" || key == "" {
		t.Error("BreakGlassFiles must always name a path")
	}
}

func TestLoadDevRelaxesOnlyTheAuthMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := writeFile(p, `{"auth":{"mode":"local"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want the production refusal", err)
	}
	if _, err := LoadDev(p, true); err != nil {
		t.Fatalf("LoadDev = %v, want it accepted for the dev loop", err)
	}
	// But not the loopback rule.
	q := filepath.Join(dir, "d.json")
	if err := writeFile(q, `{"web":{"listen":"0.0.0.0:8770"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDev(q, true); err == nil {
		t.Fatal("-dev must not be a way to expose the main listener")
	}
}

// writeFile is a local helper so the table above reads as a table.
func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

// --- round-2 P3-5: the cross-process lock ------------------------------------

// The daemon's read-only toggle and `break-glass set-password` are two
// processes doing a read-modify-write on one file. Without the lock, whichever
// saved second published its own stale copy of everything it had not changed —
// silently reverting a password that had just been set, or restoring one that
// had just been disabled.
func TestUpdateSerialisesConcurrentWriters(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := Save(p, Default()); err != nil {
		t.Fatal(err)
	}
	// One writer owns readOnly, the other owns the credential — exactly the
	// split the daemon and the CLI have. Interleaved without the lock, one of
	// the two changes disappears.
	// One real hash, generated once: every writer stores the same credential,
	// and what this test is about is whether it survives at all.
	hash := realHash(t, MinLocalCost)
	var wg sync.WaitGroup
	const rounds = 25
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			_ = Update(p, false, func(c *Config) error {
				c.ReadOnly = n%2 == 0
				return nil
			})
		}(i)
		go func(n int) {
			defer wg.Done()
			_ = Update(p, false, func(c *Config) error {
				c.Auth.Local.Hash = hash
				c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
				return nil
			})
		}(i)
	}
	wg.Wait()
	got, err := Load(p)
	if err != nil {
		t.Fatalf("the config did not survive concurrent writers: %v", err)
	}
	// Whatever the interleaving, BOTH fields are written: neither writer's
	// section was rolled back to a value nobody asked for.
	if got.Auth.Local.Hash == "" {
		t.Fatal("the credential was lost to a concurrent read-only toggle")
	}
	if got.Auth.Local.Updated != "2026-09-14T09:00:00Z" {
		t.Fatalf("the eviction stamp was lost: %+v", got.Auth.Local)
	}
	// Nothing is left behind that a later writer would have to reason about.
	// On Linux the empty lock FILE is expected to persist — flock lives on the
	// inode, and unlinking the name would let a third writer create a fresh one
	// and lock that instead — but no broken-lock debris ever is.
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".dead-") {
			t.Errorf("%s was left behind", e.Name())
		}
	}
	if runtime.GOOS != "linux" {
		if _, err := os.Stat(p + ".lock"); err == nil {
			t.Error("the O_EXCL lock file was left behind")
		}
	}
}

func TestLockIsExclusiveAndBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second Lock = %v, want ErrLocked", err)
	}
	if waited := time.Since(start); waited < LockWait/2 {
		t.Fatalf("the second Lock gave up after %v; it must wait for the holder", waited)
	}
	release()
	release() // releasing twice is harmless
	if got, err := Lock(p); err != nil {
		t.Fatalf("the lock was not released: %v", err)
	} else {
		got()
	}
}

// The published file is at its final mode the instant the rename makes it
// visible: chmodding afterwards left a window in which the break-glass password
// hash was world-readable under the name every reader knows.
func TestSavedConfigIsNeverBrieflyWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes are approximate on Windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c := Default()
	c.Auth.Local = Local{Hash: realHash(t, MinLocalCost), Cost: MinLocalCost}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", fi.Mode().Perm())
	}
	// No scratch file survives at a wider mode either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(p) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %04o", e.Name(), info.Mode().Perm())
		}
	}
}

// SaveDev is what lets a -dev daemon write back the configuration it started
// from; Save must still refuse it.
func TestSaveDevAcceptsWhatSaveRefuses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.Auth.Mode = AuthLocal
	if err := Save(p, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Save(mode=local) = %v, want ErrInvalid", err)
	}
	if err := SaveDev(p, c, true); err != nil {
		t.Fatalf("SaveDev(mode=local) = %v, want it accepted", err)
	}
	if err := Update(p, true, func(c *Config) error { c.ReadOnly = false; return nil }); err != nil {
		t.Fatalf("Update on a dev config = %v", err)
	}
	if err := Update(p, false, func(c *Config) error { c.ReadOnly = true; return nil }); err == nil {
		t.Fatal("a strict Update must refuse a development configuration")
	}
}
