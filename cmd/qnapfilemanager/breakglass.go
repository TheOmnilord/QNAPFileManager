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

// defaultConfigPath is where the QPKG keeps the config. A subcommand run with
// no -config on a NAS should act on the file the daemon actually reads.
const defaultConfigPath = "/share/CACHEDEV1_DATA/.qpkg/QNAPFileManager/config/config.json"

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

func resolveConfigPath(p string) string {
	if p != "" {
		return p
	}
	return defaultConfigPath
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
	p := resolveConfigPath(*path)
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
	if err := config.Update(p, *dev, func(c *config.Config) error {
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
		certFile, keyFile := cfg.BreakGlassFiles(p)
		var cert breakglass.Cert
		cerr := withCertLock(p, func() error {
			var err error
			cert, err = breakglass.Ensure(certFile, keyFile, time.Now())
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
	p := resolveConfigPath(*path)
	if err := guardCredentialStore(p, stderr); err != nil {
		return err
	}
	if err := config.Update(p, *dev, func(c *config.Config) error {
		c.Auth.Local.Hash = ""
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
	p := resolveConfigPath(*path)
	cfg, err := config.LoadDev(p, *dev)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config:      %s\n", p)
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
	certFile, keyFile := cfg.BreakGlassFiles(p)
	fmt.Fprintf(stdout, "certificate: %s\n", certFile)
	cert, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		fmt.Fprintf(stdout, "fingerprint: not generated yet (%v)\n", err)
		return nil
	}
	fmt.Fprintf(stdout, "fingerprint: sha256:%s\n", cert.Fingerprint)
	fmt.Fprintf(stdout, "expires:     %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	return nil
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
	p := resolveConfigPath(*path)
	cfg, err := config.LoadDev(p, *dev)
	if err != nil {
		return err
	}
	certFile, keyFile := cfg.BreakGlassFiles(p)
	var cert breakglass.Cert
	if !*regen {
		// Plain `cert` READS and nothing else (round-1 P3-10). It used to call
		// Ensure, which regenerates inside the 30-day renewal window — so an
		// operator running it to read the fingerprint could be the one who
		// changed it, without root, without a warning, and while the running
		// daemon went on serving the old one. Reporting a fingerprint must never
		// be the thing that changes it.
		cert, err = breakglass.Load(certFile, keyFile)
		if err != nil {
			fmt.Fprintf(stdout, "certificate: %s\n", certFile)
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
			cert, gerr = breakglass.Regenerate(certFile, keyFile, time.Now())
			return gerr
		}); err != nil {
			return err
		}
	}
	if cert.Generated {
		fmt.Fprintf(stdout, "generated a new certificate (%s).\n", cert.Reason)
		fmt.Fprintln(stdout, "The fingerprint has CHANGED: tell anyone who compares it, and restart the app so the listener serves it.")
	}
	fmt.Fprintf(stdout, "certificate: %s\n", certFile)
	fmt.Fprintf(stdout, "fingerprint: sha256:%s\n", cert.Fingerprint)
	fmt.Fprintf(stdout, "expires:     %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
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
