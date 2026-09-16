package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
)

// The break-glass credential is written here and nowhere else. There is no HTTP
// route that sets, changes, resets or reveals the password — not an admin-only
// one, not a first-run one (M4 contract §4.1). This replaces the backend plan's
// §5.5 claim window outright: a 15-minute unauthenticated window on a root
// daemon is a worse door than the one it was protecting.
//
// These subcommands write nothing to the audit log. They run as a different
// process, with no logger and no QuLog access, and a durable line written by a
// process that is not the daemon would be a second writer to a single-writer
// file (§6.4). What they change is audited the moment the daemon notices.

const breakGlassUsage = `qnapfilemanager break-glass <subcommand>

  set-password [-config <path>] [-cost <n>] [-stdin]
        set or replace the emergency password (prompted twice, echo off)
  disable [-config <path>]
        clear the hash; the break-glass listener then binds nothing
  status [-config <path>]
        report whether it is enabled, the address, whether a hash is set and
        when, the cost, and the certificate fingerprint
  cert [-config <path>] [-regenerate]
        print the certificate fingerprint, or generate a new key pair

Run as root on the NAS shell. Changing or clearing the password destroys every
live break-glass session on the daemon's next request.
`

func runBreakGlass(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, breakGlassUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "set-password":
		err = breakGlassSetPassword(rest, stdin, stdout, stderr)
	case "disable":
		err = breakGlassDisable(rest, stdout, stderr)
	case "status":
		err = breakGlassStatus(rest, stdout, stderr)
	case "cert":
		err = breakGlassCert(rest, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, breakGlassUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "qnapfilemanager break-glass: unknown subcommand %q\n", sub)
		fmt.Fprint(stderr, breakGlassUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "qnapfilemanager break-glass %s: %v\n", sub, err)
		return 1
	}
	return 0
}

// The fallback config location, and the QPKG registry the real one comes from.
//
// The hard-coded path is right on exactly one kind of unit: a QTS box whose
// first volume is CACHEDEV1_DATA. On QuTS hero, or on any unit where App Center
// installed to another volume, it names a file that does not exist — and a
// subcommand acting on a file the daemon does not read is worse than one that
// fails, because `status` then reports "no password" while the listener is
// armed, and `disable` cannot revoke anything (Astra r1 #14).
const (
	legacyConfigPath = "/share/CACHEDEV1_DATA/.qpkg/QNAPFileManager/config/config.json"
	qpkgSection      = "QNAPFileManager"
	qpkgConfigKey    = "Install_Path"
)

// qpkgConfPath is where App Center records every installed QPKG's real install
// path. It is a variable so a test can point it at a fixture; QNAPFileManager.sh
// reads the same file with getcfg.
var qpkgConfPath = "/etc/config/qpkg.conf"

// defaultConfigPath resolves where the daemon's config actually is, in the same
// order of confidence the service script uses: what App Center recorded, then
// this executable's own installation tree, then the historical default.
//
// It returns the path and a short word naming where that path came from, so
// `status` can print it: a subcommand silently acting on the wrong file is the
// failure this exists to prevent, and the only way an operator can see which
// file was chosen is if it is printed.
func defaultConfigPath() (path, source string) {
	if dir := qpkgInstallPath(qpkgConfPath, qpkgSection); dir != "" {
		return filepath.Join(dir, "config", "config.json"), "qpkg.conf"
	}
	// The executable's own tree: <install>/bin/qnapfilemanager (or
	// <install>/qnapfilemanager) beside <install>/config/config.json. Only
	// accepted when the file is really there — an executable run from a build
	// directory must not name a config that does not exist and thereby hide the
	// fallback below.
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		for _, root := range []string{dir, filepath.Dir(dir)} {
			candidate := filepath.Join(root, "config", "config.json")
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				return candidate, "the installation tree"
			}
		}
	}
	return legacyConfigPath, "the default location"
}

// qpkgInstallPath reads one key out of one section of /etc/config/qpkg.conf.
//
// A tiny INI reader rather than a dependency or a shell-out to getcfg: this may
// run on a NAS whose firmware is the thing being repaired, and a subcommand
// that needs another program to find its own config file is one more thing that
// can be broken. The file is small, root-owned and written by App Center.
func qpkgInstallPath(path, section string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	// Bounded: this is a configuration file, not a stream, and a corrupt or
	// hostile one must not be read without limit.
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)
	inSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// QTS section names are case-insensitive in practice.
			inSection = strings.EqualFold(strings.Trim(line, "[]"), section)
			continue
		}
		if !inSection {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), qpkgConfigKey) {
			continue
		}
		// getcfg strips surrounding quotes; so does this.
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"`)
		if value == "" {
			return ""
		}
		return value
	}
	return ""
}

// breakGlassFlags is the flag set every subcommand shares. -dev exists because
// a daemon started with -dev may be running on a config whose auth.mode is
// "local" or "both", which strict validation refuses: without it the CLI would
// refuse to read the very file that daemon is using (round-2 P3-6).
func breakGlassFlags(name string, args []string, stderr io.Writer) (fs *flag.FlagSet, path *string, dev *bool) {
	fs = flag.NewFlagSet("break-glass "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path = fs.String("config", "", "JSON config file (default: the QPKG's config/config.json)")
	dev = fs.Bool("dev", false, "accept a development configuration (auth.mode local or both), as `serve -dev` does")
	return fs, path, dev
}

// resolveConfigPath answers where a subcommand with no -config should act, and
// says where that answer came from.
func resolveConfigPath(p string) (path, source string) {
	if p != "" {
		return p, "-config"
	}
	return defaultConfigPath()
}

// withCertLock serialises everything that WRITES the break-glass key pair
// (round-5).
//
// The certificate and the key are two files, so publishing them is two atomic
// renames and never one — which means two generators running at once can leave
// A's certificate beside B's key, a pair that matches nothing and that the
// listener cannot serve. The three writers are the daemon arming the door,
// `set-password` and `cert -regenerate`, and they hold the same lock the
// credential itself is written under: one credential store, one lock.
//
// An empty path (a dev run with no config file) has nothing to serialise
// against and runs the work directly.
func withCertLock(configPath string, fn func() error) error {
	if configPath == "" {
		return fn()
	}
	release, err := config.Lock(configPath)
	if err != nil {
		if hint := lockHintFor(configPath); hint != "" {
			return fmt.Errorf("%w (%s)", err, hint)
		}
		return err
	}
	defer release()
	return fn()
}

// certLocation is where the break-glass pair lives, and whether the OPERATOR
// named that location — which is what decides how far the loader checks it
// (Astra r2 #1). A location config owns is checked by the credential-store
// guard; one web.breakGlass.certFile/keyFile named has its whole resolved
// ancestry walked, because nothing else is checking it.
func certLocation(cfg config.Config, configPath string) breakglass.Location {
	certFile, keyFile := cfg.BreakGlassFiles(configPath)
	return breakglass.Location{
		CertFile: certFile,
		KeyFile:  keyFile,
		Explicit: cfg.BreakGlassExplicit(),
	}
}

// lockHintFor reports who holds a stuck lock, for an error message. It reads
// the lock file directly because config keeps its own hint unexported.
func lockHintFor(configPath string) string {
	data, err := os.ReadFile(configPath + ".lock")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// requireRootFn and checkCredentialModeFn are the two platform gates, held in
// variables so a test can exercise the CLI's own logic in process without being
// root.
//
// CI runs this package unprivileged on Linux (the race job, as uid 1001) and as
// root (the root job), and every set-password test would otherwise fail on the
// first of those before reaching anything it meant to check. The gates
// themselves keep their own Linux-only tests — TestNonRootIsRefusedOnLinux and
// TestCredentialStoreModeIsRefused — so replacing them here does not stop them
// being tested; it stops them being the only thing that is. Nothing reads these
// from a goroutine: a test sets them before running a command and restores them
// in t.Cleanup.
var (
	requireRootFn         = requireRoot
	checkCredentialModeFn = checkCredentialMode
)

// guardCredentialStore is the refusal set of §4.1: not root, a config file not
// owned by uid 0, or one that is group- or world-readable. A credential store
// with the wrong mode is a bug worth stopping for, not warning about.
//
// The DIRECTORY is checked too (round-2 P3-8). Checking only the file misses
// the thing that actually matters: the certificate's private key, the lock file
// and every future scratch file are created in that directory, so a
// group-writable config/ lets anyone in the group replace the key the emergency
// door serves — and a group-readable one lets them read it — no matter how
// tight config.json itself is.
func guardCredentialStore(path string, stderr io.Writer) error {
	if err := requireRootFn(); err != nil {
		return err
	}
	if note := rootCheckNote(); note != "" {
		fmt.Fprintln(stderr, "warning: "+note)
	}
	dir := filepath.Dir(path)
	if di, err := os.Stat(dir); err == nil {
		if err := checkCredentialModeFn(dir, di); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // First run: the file is about to be created at 0600.
		}
		return err
	}
	return checkCredentialModeFn(path, fi)
}

func breakGlassSetPassword(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, path, dev := breakGlassFlags("set-password", args, stderr)
	cost := fs.Int("cost", 0, fmt.Sprintf("bcrypt cost %d-%d (default %d)", breakglass.MinCost, breakglass.MaxCost, breakglass.DefaultCost))
	fromStdin := fs.Bool("stdin", false, "read the password as one line from standard input (scripted use)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	p, _ := resolveConfigPath(*path)
	if err := guardCredentialStore(p, stderr); err != nil {
		return err
	}
	resolvedCost, err := breakglass.CheckCost(*cost)
	if err != nil {
		return err
	}

	// ONE reader for the whole command. A fresh bufio.Reader per prompt buffers
	// ahead and throws the buffer away with itself, so the second read off a
	// pipe or a here-doc silently loses the line the first one had already
	// consumed into the buffer — the two passwords then never match, or worse,
	// the second read returns EOF and an empty string (round-1 P3-9).
	in := bufio.NewReader(stdin)
	var password string
	if *fromStdin {
		line, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("reading the password: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		first, err := readPassword(in, stdout, stderr, "Emergency password: ")
		if err != nil {
			return err
		}
		again, err := readPassword(in, stdout, stderr, "Repeat it: ")
		if err != nil {
			return err
		}
		if first != again {
			return errors.New("the two passwords do not match; nothing was changed")
		}
		password = first
	}
	notice, err := breakglass.CheckPassword(password)
	if err != nil {
		return err
	}
	if notice != "" {
		fmt.Fprintln(stdout, notice)
	}
	hash, err := breakglass.Hash(password, resolvedCost)
	if err != nil {
		return err
	}

	// Read-modify-write under the cross-process lock: the daemon's read-only
	// toggle writes the same file, and a save that lost this credential — or
	// restored one that was just disabled — would be silent (round-2 P3-5).
	var cfg config.Config
	// UpdateCredential, not Update (Astra r2 #5): a hash the daemon refuses is
	// exactly the state this command exists to leave, so it must not be what
	// stops it from running. The result is validated strictly before it is
	// written.
	if err := config.UpdateCredential(p, *dev, func(c *config.Config) error {
		// The hash, the cost and the stamp: nothing else. Bumping Updated is
		// what evicts every live break-glass session on the daemon's next
		// request (§4.4), so it is written even when the password happens to be
		// the same.
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = resolvedCost
		c.Auth.Local.Updated = time.Now().UTC().Format(time.RFC3339Nano)
		cfg = *c
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "break-glass password set in %s (cost %d).\n", p, resolvedCost)
	fmt.Fprintln(stdout, "Any live emergency session is destroyed on its next request.")

	// The certificate is generated HERE, not left for the next restart
	// (round-2 P2-3). The documented first run is "set the password, compare
	// the fingerprint, open the page" — and until this existed there was no
	// fingerprint to compare, because nothing had generated one. This is also
	// the only moment the CLI is guaranteed to be root in the config directory.
	if cfg.Web.BreakGlass.Enabled {
		loc := certLocation(cfg, p)
		certFile := loc.CertFile
		var cert breakglass.Cert
		// EnsureUsable (Astra r1 #16): setting a password must never be the thing
		// that RENEWS a certificate. A usable pair is left alone; only a missing,
		// torn or expired one is generated, which is what makes the documented
		// first run — set the password, compare the fingerprint, open the page —
		// work without a restart. Rotation is `cert -regenerate`'s job and says
		// so. Since Astra r2 #3 the daemon does not renew either: nothing changes
		// this fingerprint without an operator asking for it.
		cerr := withCertLock(p, func() error {
			var err error
			cert, err = loc.EnsureUsable(time.Now())
			return err
		})
		if cerr != nil {
			// Not fatal: the password IS set, and the running daemon (or the
			// next start) will generate the certificate itself. Saying so is
			// better than implying the whole command failed.
			fmt.Fprintf(stderr, "warning: the certificate could not be prepared (%v); the app will generate it when the listener binds\n", cerr)
		} else {
			fmt.Fprintf(stdout, "certificate: %s\n", certFile)
			fmt.Fprintf(stdout, "fingerprint: sha256:%s\n", cert.Fingerprint)
			fmt.Fprintln(stdout, "Compare that fingerprint in the browser before typing this password into a page it has warned about.")
		}
		fmt.Fprintf(stdout, "The listener binds %s; a running app picks the password up within a minute, and a restart is not needed.\n", cfg.Web.BreakGlass.Addr)
	} else {
		fmt.Fprintln(stdout, "web.breakGlass.enabled is false, so the listener stays off and this password is inert.")
	}
	return nil
}

func breakGlassDisable(args []string, stdout, stderr io.Writer) error {
	fs, path, dev := breakGlassFlags("disable", args, stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	p, _ := resolveConfigPath(*path)
	if err := guardCredentialStore(p, stderr); err != nil {
		return err
	}
	// UpdateCredential, not Update (Astra r2 #5): revoking a credential the
	// daemon refuses to load is the case that matters most, and until this it
	// was the case that failed.
	if err := config.UpdateCredential(p, *dev, func(c *config.Config) error {
		c.Auth.Local.Hash = ""
		// The cost key goes with it: it describes a credential that no longer
		// exists, and leaving an out-of-range one behind would leave the file
		// invalid for the daemon that has to load it next.
		c.Auth.Local.Cost = 0
		// The stamp still moves: that is what evicts the sessions the cleared
		// hash is meant to lock out. An eviction that waited for a restart
		// would not be an eviction.
		c.Auth.Local.Updated = time.Now().UTC().Format(time.RFC3339Nano)
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "break-glass password cleared in %s.\n", p)
	fmt.Fprintln(stdout, "Live emergency sessions are destroyed on their next request; the listener binds nothing after the next restart.")
	return nil
}

func breakGlassStatus(args []string, stdout, stderr io.Writer) error {
	fs, path, dev := breakGlassFlags("status", args, stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	p, source := resolveConfigPath(*path)
	cfg, err := config.LoadDev(p, *dev)
	if err != nil {
		return err
	}
	// Which file, and how it was found (Astra r1 #14). An operator whose unit
	// installed to another volume needs to see that this is the file the daemon
	// reads — "password: not set" against the wrong config is the exact wrong
	// answer to give someone locked out of a NAS.
	fmt.Fprintf(stdout, "config:      %s (from %s)\n", p, source)
	fmt.Fprintf(stdout, "enabled:     %v\n", cfg.Web.BreakGlass.Enabled)
	fmt.Fprintf(stdout, "addr:        %s\n", cfg.Web.BreakGlass.Addr)
	// The hash itself is never printed. What an audit needs is whether one
	// exists and how old it is — a permanent root credential nobody has touched
	// in three years is the finding (§18.3).
	if cfg.Auth.Local.Hash == "" {
		fmt.Fprintln(stdout, "password:    not set (the listener binds nothing)")
	} else {
		when := cfg.Auth.Local.Updated
		if when == "" {
			when = "unknown"
		}
		cost := cfg.Auth.Local.LocalCost()
		if c, err := breakglass.HashCost(cfg.Auth.Local.Hash); err == nil {
			cost = c
		}
		fmt.Fprintf(stdout, "password:    set (%s)\n", when)
		fmt.Fprintf(stdout, "cost:        %d\n", cost)
	}
	loc := certLocation(cfg, p)
	fmt.Fprintf(stdout, "certificate: %s\n", loc.CertFile)
	cert, err := loc.Load()
	if err != nil {
		// A location the loader REFUSES is not the same news as one that has not
		// been generated yet, and an operator reading this while locked out has
		// to be able to tell them apart: the second is the first run, the first
		// is a listener that will not bind until a directory is fixed
		// (Astra r2 #1).
		if errors.Is(err, breakglass.ErrUnsafeLocation) {
			fmt.Fprintf(stdout, "fingerprint: refused — %v\n", err)
			return nil
		}
		fmt.Fprintf(stdout, "fingerprint: not generated yet (%v)\n", err)
		return nil
	}
	fmt.Fprintf(stdout, "fingerprint: sha256:%s\n", cert.Fingerprint)
	fmt.Fprintf(stdout, "expires:     %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	// Inside the renewal window, `status` says so in the same place the
	// fingerprint is read (Astra r2 #3): nothing rotates this pair on its own,
	// so the only way an operator learns it is running out is by being told.
	if !time.Now().Add(breakglass.RenewWithin).Before(cert.NotAfter) {
		fmt.Fprintf(stdout, "warning:     this certificate expires in %d days; run `qnapfilemanager break-glass cert -regenerate` and restart the app when you are ready to compare a new fingerprint.\n", daysUntil(cert.NotAfter, time.Now()))
	}
	return nil
}

// daysUntil is whole days, rounded down, and never negative: "expires in 0
// days" is today, and an expired pair is reported as expired rather than as a
// negative number of days.
func daysUntil(when, now time.Time) int {
	d := when.Sub(now)
	if d < 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

func breakGlassCert(args []string, stdout, stderr io.Writer) error {
	fs, path, dev := breakGlassFlags("cert", args, stderr)
	regen := fs.Bool("regenerate", false, "generate a new key pair (an IP change, or a suspected key compromise)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	p, _ := resolveConfigPath(*path)
	cfg, err := config.LoadDev(p, *dev)
	if err != nil {
		return err
	}
	loc := certLocation(cfg, p)
	certFile := loc.CertFile
	var cert breakglass.Cert
	if !*regen {
		// Plain `cert` READS and nothing else (round-1 P3-10). It used to call
		// Ensure, which regenerated inside the 30-day renewal window — so an
		// operator running it to read the fingerprint could be the one who
		// changed it, without root, without a warning, and while the running
		// daemon went on serving the old one. Reporting a fingerprint must never
		// be the thing that changes it. Since Astra r2 #3 nothing renews inside
		// that window at all: this command is the only thing that rotates the
		// pair, and only with -regenerate.
		cert, err = loc.Load()
		if err != nil {
			fmt.Fprintf(stdout, "certificate: %s\n", certFile)
			if errors.Is(err, breakglass.ErrUnsafeLocation) {
				fmt.Fprintf(stdout, "fingerprint: refused — %v\n", err)
				fmt.Fprintln(stdout, "             The listener will not bind until that path is root-owned and")
				fmt.Fprintln(stdout, "             writable by nobody else, every directory above it included.")
				return nil
			}
			fmt.Fprintln(stdout, "fingerprint: no certificate yet — the daemon generates one the first time the")
			fmt.Fprintln(stdout, "             break-glass listener binds, or run `break-glass cert -regenerate`.")
			return nil
		}
	} else {
		// Writing one is a root operation against the credential directory, and
		// it goes through the same store guard set-password does.
		if err := guardCredentialStore(p, stderr); err != nil {
			return err
		}
		if err := withCertLock(p, func() error {
			var gerr error
			cert, gerr = loc.Regenerate(time.Now())
			return gerr
		}); err != nil {
			return err
		}
	}
	if cert.Generated {
		fmt.Fprintf(stdout, "generated a new certificate (%s).\n", cert.Reason)
		// Said plainly, because the fingerprint below is NOT what a browser will
		// show until the app restarts: the running daemon holds the old pair in
		// memory and goes on terminating TLS with it. An operator who compares
		// the two and sees a mismatch must be able to recognise this, rather
		// than conclude they are being intercepted (Astra r1 #16).
		fmt.Fprintln(stdout, "The fingerprint has CHANGED. A running app keeps serving the OLD pair until it is restarted,")
		fmt.Fprintln(stdout, "so restart it before comparing this fingerprint in a browser, and tell anyone else who compares it.")
	}
	fmt.Fprintf(stdout, "certificate: %s\n", certFile)
	fmt.Fprintf(stdout, "fingerprint: sha256:%s\n", cert.Fingerprint)
	fmt.Fprintf(stdout, "expires:     %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	// The renewal window is a REMINDER, not a countdown to something automatic
	// (Astra r2 #3): no daemon start and no password change rotates this pair,
	// so the operator is the only one who can, and they should do it when they
	// are ready to compare the new fingerprint rather than be surprised by it.
	if !cert.Generated && !time.Now().Add(breakglass.RenewWithin).Before(cert.NotAfter) {
		fmt.Fprintf(stdout, "This certificate expires in %d days. Nothing rotates it for you: run `break-glass cert -regenerate`\nand restart the app when you are ready to compare a new fingerprint.\n", daysUntil(cert.NotAfter, time.Now()))
	}
	fmt.Fprintln(stdout, "Compare this fingerprint in the browser before typing a password into a page it has warned about.")
	return nil
}

// readPassword prompts and reads one line with the terminal's echo off.
// golang.org/x/term is not available — bcrypt is the ONE dependency this
// project allows — so the Linux implementation shells out to stty and every
// other platform warns that the password will echo (contract §15).
// It takes the caller's shared *bufio.Reader rather than making its own, so two
// prompts read two consecutive lines rather than losing the second to a
// discarded buffer.
func readPassword(in *bufio.Reader, stdout, stderr io.Writer, prompt string) (string, error) {
	fmt.Fprint(stdout, prompt)
	restore, echoOff := disableEcho()
	if !echoOff {
		fmt.Fprintln(stderr, "\nwarning: the terminal echo could not be turned off, so the password will be visible as you type it. Use -stdin for scripted use.")
		fmt.Fprint(stdout, prompt)
	}
	line, err := in.ReadString('\n')
	restore()
	fmt.Fprintln(stdout)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
