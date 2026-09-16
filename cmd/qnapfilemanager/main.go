// Command qnapfilemanager is the QNAPFileManager daemon: a root front-end
// that serves the web UI, and — re-executing itself with -worker — one
// unprivileged worker process per signed-in user, which is where every
// filesystem operation actually runs.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/logfile"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/qtsauth"
	"qnapfilemanager/internal/trashroot"
	"qnapfilemanager/internal/web"
	"qnapfilemanager/internal/worker"
	"qnapfilemanager/internal/workerpool"
)

// version is set by the linker: -X main.version=$VERSION. "dev" is what a
// `go run` from the source tree reports.
var version = "dev"

func main() {
	// The worker check comes first, before flag parsing, config loading,
	// logging or anything else that could touch the filesystem or open a
	// port. A worker is re-executed by the front-end with a Credential
	// already applied by the kernel, and it must not inherit any of the
	// front-end's startup behaviour — least of all binding the web port a
	// second time.
	if isWorkerInvocation(os.Args[1:]) {
		os.Exit(runWorker(os.Args[1:], os.Stdout, os.Stderr))
	}

	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "serve":
		if err := runServe(args[1:], os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "qnapfilemanager: %v\n", err)
			os.Exit(1)
		}
	case "break-glass":
		os.Exit(runBreakGlass(args[1:], os.Stdin, os.Stdout, os.Stderr))
	case "version", "-version", "--version":
		fmt.Println(version)
	case "help", "-h", "-help", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "qnapfilemanager: unknown command %q\n", args[0])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `qnapfilemanager %s

Usage:
  qnapfilemanager serve [flags]        run the daemon
  qnapfilemanager break-glass <sub>    manage the emergency-access password and
                                       certificate (set-password, disable,
                                       status, cert) — root, on the NAS shell
  qnapfilemanager version              print the version
  qnapfilemanager -worker -uid N       internal: the per-user worker process

serve flags:
  -config <path>        JSON config file (a missing file means defaults)
  -log <path>           app log file, rotated at 8 MiB (default: stderr)
  -addr <host:port>     override web.listen
  -jail <dir>           reroot every filesystem path under <dir> (dev loop)
  -proxy-prefix <path>  serve the mux at <path> as well as / (QTS proxy)
  -readonly[=false]     override readOnly
  -dev                  development mode: run the workers inside this process,
                        read identities from inside -jail, and allow
                        -impersonate. Never use it on a NAS.
  -impersonate <user>   run every operation as <user>, without a QTS session
                        (requires -dev)
`, version)
}

// isWorkerInvocation looks for the -worker switch anywhere in the arguments.
// It is deliberately a plain scan rather than a flag.FlagSet: the check has to
// happen before any other initialisation, and "--" would let a later argument
// hide the switch from a parser.
func isWorkerInvocation(args []string) bool {
	for _, a := range args {
		if a == "-worker" || a == "--worker" {
			return true
		}
		// -worker=true is not a form this ever uses, but accepting it costs
		// nothing and misreading it as "not a worker" would be a root process
		// running worker arguments.
		if strings.HasPrefix(a, "-worker=") || strings.HasPrefix(a, "--worker=") {
			return true
		}
	}
	return false
}

// runWorker consumes the inherited socket only after checking its effective uid.
func runWorker(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.Bool("worker", false, "run as the per-user worker process")
	uid := fs.Int("uid", -1, "the uid this worker was spawned for, for logging and self-checks")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *uid < 0 || runtime.GOOS != "linux" || os.Getuid() != *uid {
		fmt.Fprintf(stderr, "worker identity mismatch or unsupported platform (uid %d)\n", *uid)
		return 2
	}
	file := os.NewFile(3, "qfm-worker")
	if file == nil {
		fmt.Fprintln(stderr, "missing worker socket")
		return 2
	}
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		fmt.Fprintf(stderr, "worker socket: %v\n", err)
		return 2
	}
	defer conn.Close()
	if _, ok := conn.(*net.UnixConn); !ok {
		fmt.Fprintln(stderr, "worker requires a Unix socket")
		return 2
	}
	if err := worker.Run(context.Background(), conn, worker.Options{Version: version, Log: log.New(stderr, "worker: ", log.LstdFlags)}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type serveOptions struct {
	configPath  string
	logPath     string
	addr        string
	jail        string
	proxyPrefix string
	readOnly    bool
	impersonate string
	dev         bool
	// set records which flags the operator actually gave, so an unset
	// -readonly leaves the config's value alone instead of overwriting it
	// with the flag's default.
	set map[string]bool
}

// inProcessWorkers reports whether this run serves requests from goroutines in
// the front-end rather than from real, credential-carrying worker processes.
// That is the case on any host without Unix credentials, and on Linux only when
// the operator asked for it with -dev.
func inProcessWorkers(dev bool) bool { return dev || runtime.GOOS != "linux" }

// identityFiles picks where uid/gid names and group memberships are read from.
//
// In production — a Linux host spawning real worker processes — they always
// come from the host's own /etc/passwd and /etc/group, whatever -jail says. The
// jail is a path mapping for user data; it is not a source of identities.
// Reading them from inside it was a privilege escalation: with a writable jail
// such as "-jail /share/Public", anyone who could create etc/passwd there could
// map their own authenticated QTS name to uid 0, and a worker forked with
// Credential{Uid: 0} is root whether or not Principal.Root was ever set.
//
// Fixture identity files are read out of the jail only where no worker process
// is spawned at all and there is therefore no credential to forge: the Windows
// dev box, or an explicit -dev.
func identityFiles(root fsx.Root, inProcess bool) (passwd, group string, err error) {
	if !inProcess || !root.Jailed() {
		return idmap.DefaultPasswdPath, idmap.DefaultGroupPath, nil
	}
	if passwd, err = root.OS("/etc/passwd"); err != nil {
		return "", "", err
	}
	if group, err = root.OS("/etc/group"); err != nil {
		return "", "", err
	}
	return passwd, group, nil
}

func parseServeFlags(args []string, stderr io.Writer) (serveOptions, error) {
	var o serveOptions
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.configPath, "config", "", "JSON config file")
	fs.StringVar(&o.logPath, "log", "", "app log file (default: stderr)")
	fs.StringVar(&o.addr, "addr", "", "override web.listen")
	fs.StringVar(&o.jail, "jail", "", "reroot every filesystem path under this directory")
	fs.StringVar(&o.proxyPrefix, "proxy-prefix", "", "also serve the mux under this path")
	fs.BoolVar(&o.readOnly, "readonly", true, "override readOnly")
	fs.BoolVar(&o.dev, "dev", false, "development mode: in-process workers, identities read from inside -jail, -impersonate allowed")
	fs.StringVar(&o.impersonate, "impersonate", "", "run every operation as this user, without a QTS session (requires -dev)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	o.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	return o, nil
}

// apply folds the flags into the loaded config. Flags win, but only the ones
// that were actually given.
func (o serveOptions) apply(c config.Config) config.Config {
	if o.set["addr"] {
		c.Web.Listen = o.addr
	}
	if o.set["proxy-prefix"] {
		c.Web.ProxyPrefix = o.proxyPrefix
	}
	if o.set["readonly"] {
		c.ReadOnly = o.readOnly
	}
	if o.set["log"] {
		c.Logging.File = o.logPath
	}
	c.Normalize()
	return c
}

func runServe(args []string, stderr io.Writer) error {
	o, err := parseServeFlags(args, stderr)
	if err != nil {
		return err
	}
	// -impersonate serves every request as one user with no QTS session at all.
	// That is the dev loop's whole point and a total authentication bypass
	// anywhere else, so it is gated on the flag that says "this is a
	// development run" rather than on nobody noticing.
	if o.impersonate != "" && !o.dev {
		return fmt.Errorf("-impersonate %s runs every request as that user with no QTS session and is refused outside development mode; add -dev if that is really what you want", o.impersonate)
	}
	inProcess := inProcessWorkers(o.dev)
	cfg := config.Default()
	if o.configPath != "" {
		// A missing file is the first-run state and Load returns the defaults
		// for it; anything else — unreadable, malformed, invalid — must stop
		// the daemon rather than silently start with different settings.
		cfg, err = config.LoadDev(o.configPath, o.dev)
		if err != nil {
			return err
		}
	}
	cfg = o.apply(cfg)
	// Forced BEFORE validation, so the forced address is itself validated — a
	// dev run whose forcing would collide the two listeners on one port is a
	// startup error, not a bind failure later.
	cfg = forceLoopbackBreakGlass(cfg, o.dev)
	// -addr goes through the same validation as the config key, never around it
	// (contract §13.1): the loopback rule on the main listener has no override,
	// by flag or by key.
	if err := cfg.ValidateDev(o.dev); err != nil {
		return err
	}
	// The jail is validated here so a typo fails at startup rather than on
	// the first listing.
	root, err := fsx.NewRoot(o.jail)
	if err != nil {
		return err
	}
	if root.Jailed() {
		if fi, err := os.Stat(root.Base()); err != nil {
			return fmt.Errorf("-jail %s: %w", o.jail, err)
		} else if !fi.IsDir() {
			return fmt.Errorf("-jail %s is not a directory", o.jail)
		}
	}

	logw := io.Writer(stderr)
	if cfg.Logging.File != "" {
		w, err := logfile.Open(cfg.Logging.File, int64(cfg.Logging.MaxSizeMB)<<20)
		if err != nil {
			return fmt.Errorf("opening the log: %w", err)
		}
		defer w.Close()
		logw = w
	}
	logger := log.New(logw, "", log.LstdFlags|log.LUTC)
	// The trash root reports here what it cannot return to its caller — notably a
	// temporary directory it could not prove was its own and so left behind, on a
	// call that then goes on to succeed (R4-2, trashroot.Logf). Assigned once,
	// before anything serves.
	trashroot.Logf = logger.Printf

	passwdPath, groupPath, err := identityFiles(root, inProcess)
	if err != nil {
		return err
	}
	if o.dev {
		logger.Printf("development mode: workers run inside this process, identities come from %s, and -impersonate is allowed. This is not a production configuration.", passwdPath)
	}
	ids := idmap.Open(passwdPath, groupPath)
	var pinned *backend.Principal
	if o.impersonate != "" {
		ident, resolveErr := ids.Resolve(context.Background(), o.impersonate)
		if resolveErr != nil {
			if runtime.GOOS != "windows" || !root.Jailed() {
				return fmt.Errorf("resolving -impersonate: %w", resolveErr)
			}
			// Windows has no Unix credentials. This label is confined to the dev jail;
			// it is never a root fallback or a simulation of kernel permissions.
			ident = idmap.Ident{Name: o.impersonate, UID: 1000, GID: 1000, Groups: []int{1000}}
			logger.Printf("Windows dev identity %q uses the current Windows account; Unix permissions are not simulated", o.impersonate)
		}
		pinned = &backend.Principal{User: ident.Name, UID: ident.UID, GID: ident.GID, Groups: ident.Groups, Root: false}
	}
	var verifier *qtsauth.Verifier
	if runtime.GOOS == "linux" && cfg.Auth.Mode != config.AuthLocal {
		client := qtsauth.Detect("/etc/config/uLinux.conf")
		if cfg.Auth.QTSPort != 0 {
			// Override only the HTTP base; keep the detected SSL port so a
			// Force-HTTPS unit still has its loopback fallback.
			client.BaseURL = fmt.Sprintf("http://127.0.0.1:%d", cfg.Auth.QTSPort)
			client.HTTP = qtsauth.NewHTTPClient(client.BaseURL, qtsauth.DefaultTimeout)
		}
		verifier = qtsauth.NewVerifier(client)
	}
	plat := platform.Detect()
	b := workerpool.New(cfg, root, plat, ids, logger, inProcess)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := b.Shutdown(ctx); err != nil {
			logger.Printf("worker shutdown: %v", err)
		}
	}()

	// The guard is the front-end safety layer (INV-1): read-only mode, the
	// protected-path table, mount-point roots and confirmation tokens, all
	// decided from the path alone before any dispatch to a worker.
	g := guard.New(guardInstallDir(o.configPath, root), shareIsRAM(plat))
	g.SetMountPointChecker(plat.IsMountPointByTable)
	// Canonicalize the protected roots so a protected root that is itself a
	// symlink — /etc/config -> /ordinary/config — still matches once a caller
	// reaches it by its resolved name (adv 1a). Uses the same front-end symlink
	// resolution INV-1 permits, before any request is served.
	g.CanonicalizeRoots(func(apiPath string) (string, bool) {
		return web.ResolveAPIPath(root, apiPath)
	})
	g.SetReadOnly(cfg.ReadOnly)

	// The audit log lives beside the app log (or config.logging.audit when set)
	// and records every mutation with intent and result phases.
	auditPath := cfg.Logging.Audit
	if auditPath == "" {
		dir := "."
		if cfg.Logging.File != "" {
			dir = filepath.Dir(cfg.Logging.File)
		}
		auditPath = filepath.Join(dir, "audit.jsonl")
	}
	auditor, err := audit.Open(auditPath, cfg.Logging.QuLog)
	if err != nil {
		return fmt.Errorf("opening the audit log: %w", err)
	}
	defer auditor.Close()

	srv := newServer(cfg, root, logger)
	srv.dev = o.dev
	frontend := web.New(cfg, poolBackend{b}, verifier, ids, plat, pinned, version, logger, g, auditor, nil)
	frontend.ConfigPath = o.configPath
	frontend.AuditPath = auditPath
	// The settings route re-reads this file to change readOnly alone; a -dev run
	// must be able to save the configuration it started from (round-2 P3-6).
	frontend.Dev = o.dev
	// The guard resolves parent symlinks through this same jail mapping before a
	// mutation (resolveForGuard). It is also how a delete-to-trash maps an API
	// path to the OS path trashroot.Ensure needs. The zero Root production uses
	// is the identity mapping; a -jail dev loop passes its own.
	frontend.Root = root

	// The M2-A job spine. The manager is the front-end's bookkeeping (queue,
	// progress, cancellation, retention); the pool is what actually runs a job,
	// as one long-lived RPC to the worker that carries the user's credentials.
	// Jobs are in-memory only — the audit log is the durable record — so the
	// manager is closed, not persisted, at shutdown.
	jobMgr := jobs.New(jobs.LimitsFrom(cfg.Jobs))
	defer func() {
		// Runs before the pool's own Shutdown (defers are LIFO and the pool's was
		// registered first): stop the work, then the workers doing it.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := jobMgr.Close(ctx); err != nil {
			logger.Printf("job manager shutdown: %v", err)
		}
	}()
	reapCtx, stopReap := context.WithCancel(context.Background())
	defer stopReap()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-reapCtx.Done():
				return
			case <-ticker.C:
				jobMgr.Reap()
				// Abandoned archive selection tickets expire on their own clock; the
				// sweep on select/consume covers a busy daemon, this one an idle one.
				frontend.ReapArchiveSelections()
				// Search hits live in the front-end ledger, not in the job manager, so
				// a reaped job's hits need this to go on an idle daemon.
				frontend.PruneSearchResults()
			}
		}
	}()
	frontend.SetJobs(poolBackend{b}, jobMgr)
	srv.frontend = frontend.Handler()
	srv.bgFrontend, srv.bgConfigPath = frontend, o.configPath
	if err := armBreakGlass(srv, frontend, cfg, o.configPath, logger); err != nil {
		if !errors.Is(err, errArmRefused) {
			return err
		}
		// Said once here, and the watcher takes it from there: it repeats the
		// line only when the reason changes and arms the door as soon as the
		// reason is gone, without a restart (Astra r2 #2).
		logger.Printf("%v", err)
		srv.bgPending = true
	}
	return srv.run(context.Background())
}

// forceLoopbackBreakGlass pins the break-glass address to loopback under -dev,
// so a development run never opens a LAN port (contract §15).
//
// Forced rather than validated, deliberately: the dev loop is allowed to load
// the production config, ask for its 0.0.0.0 default, and simply not get it —
// refusing to start would push a developer into editing the very file whose
// production shape they are trying to reproduce.
func forceLoopbackBreakGlass(cfg config.Config, dev bool) config.Config {
	if !dev || !cfg.Web.BreakGlass.Enabled || cfg.Web.BreakGlass.Addr == "" {
		return cfg
	}
	host, port, err := net.SplitHostPort(cfg.Web.BreakGlass.Addr)
	if err != nil {
		return cfg
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return cfg
	}
	cfg.Web.BreakGlass.Addr = net.JoinHostPort("127.0.0.1", port)
	return cfg
}

// errArmRefused is a refusal to arm the emergency door that a LATER attempt can
// still resolve: a key directory anyone but root can write, a pair whose
// resolved ancestry the loader refuses.
//
// It is an ERROR rather than a logged nil (Astra r2 #2). Returning nil told the
// watcher the door had been dealt with for that credential, so it recorded the
// hash as armed and never called this again — and fixing the directory then did
// nothing until the app was restarted, which is precisely the restart this
// whole path exists to avoid. It is distinguishable from a fatal error because
// the daemon must NOT refuse to start over it: the main listener and the QTS
// door are unaffected, and a daemon that will not start at all is a worse
// outcome than one whose emergency door is off and says why.
var errArmRefused = errors.New("break-glass is enabled but the listener will not bind")

// armBreakGlass decides whether the second listener exists at all, and prepares
// its certificate if it does.
//
// The listener does NOT bind until a password exists (contract §2.5): an open
// port that can never authenticate is pure surface, and this is also what
// replaces the backend plan's claim window — there is no unauthenticated
// bootstrap path over HTTP at all, in any window, ever.
//
// A refusal that a later tick could resolve is returned as errArmRefused and is
// NOT logged here: the caller decides how often that line is worth repeating
// (start-up says it once; the watcher says it once per distinct reason).
func armBreakGlass(srv *server, frontend *web.Server, cfg config.Config, configPath string, logger *log.Logger) error {
	if !cfg.Web.BreakGlass.Enabled {
		logger.Printf("break-glass is disabled (web.breakGlass.enabled=false); the daemon is loopback-only")
		return nil
	}
	if cfg.Auth.Local.Hash == "" {
		logger.Printf("break-glass is enabled but no password is set; run `qnapfilemanager break-glass set-password` on the NAS shell. Nothing is bound on %s; the listener binds within a minute of a password being set, without a restart.", cfg.Web.BreakGlass.Addr)
		srv.bgPending = true
		return nil
	}
	// An explicitly configured key location is checked before anything is
	// generated into it (Astra r1 #9): a group- or other-writable parent, or one
	// not owned by root, lets someone other than root replace the key this
	// listener terminates TLS with. Refused rather than fatal — the caller logs
	// it and keeps the daemon running, because the main listener and the QTS
	// door are unaffected and a daemon that will not start at all is a worse
	// outcome than one whose emergency door is off and says so.
	//
	// This is the PRE-FLIGHT and not the authority: the loader below resolves
	// the path, walks the resolved ancestry and fstats what it opened, which is
	// what a directory of symlinks into somebody else's share fails
	// (Astra r2 #1). Both failures come back as errArmRefused.
	if err := cfg.CheckBreakGlassKeyDir(configPath); err != nil {
		return fmt.Errorf("%w: %v. Fix the directory (root-owned, mode 0700) or remove web.breakGlass.certFile/keyFile to use the QPKG's own config directory", errArmRefused, err)
	}
	loc := certLocation(cfg, configPath)
	// Under the credential-store lock: the pair is two files and therefore two
	// publications, so a CLI `cert -regenerate` running at the same moment as
	// this could otherwise leave one generator's certificate beside the other's
	// key (round-5).
	//
	// EnsureUsable, not a renewing Ensure (Astra r2 #3): the daemon generates a
	// pair that is absent, unreadable, torn or EXPIRED, and never rotates a
	// usable one. An operator is told to compare this fingerprint against the
	// browser's warning, so a restart that silently changed it would teach them
	// that a changed fingerprint is normal — the one lesson this door must not
	// teach. Inside the renewal window the daemon says so, once, and serves what
	// it has.
	var cert breakglass.Cert
	if err := withCertLock(configPath, func() error {
		var gerr error
		cert, gerr = loc.EnsureUsable(time.Now())
		return gerr
	}); err != nil {
		if errors.Is(err, breakglass.ErrUnsafeLocation) {
			// A refusal, not a fatal error: the main listener and the QTS door
			// are unaffected, the daemon keeps running, and fixing the directory
			// re-arms the door within a minute (Astra r2 #1, #2).
			return fmt.Errorf("%w: %v", errArmRefused, err)
		}
		return fmt.Errorf("break-glass certificate: %w", err)
	}
	// The fingerprint is logged at EVERY start, not only when it changes: an
	// operator comparing it against a browser warning needs to find it in the
	// log they already have open (contract §3.4).
	logger.Printf("break-glass certificate %s sha256:%s expires %s", loc.CertFile, cert.Fingerprint, cert.NotAfter.UTC().Format(time.RFC3339))
	if cert.Generated {
		logger.Printf("break-glass certificate was generated (%s); its fingerprint has changed", cert.Reason)
		frontend.AuditBreakGlass("breakglass-cert", "ok", fmt.Sprintf("door=local cert generated (%s), sha256=%s", cert.Reason, cert.Fingerprint))
	} else if now := time.Now(); !now.Add(breakglass.RenewWithin).Before(cert.NotAfter) {
		// Once per arm — once at start-up, once per late bind — because nothing
		// else will ever say it: the pair is not rotated by this process
		// (Astra r2 #3). Audited as well as logged, because the day this door
		// stops opening is the day nobody can read the log through the app.
		days := daysUntil(cert.NotAfter, now)
		logger.Printf("break-glass certificate expires in %d days; run `qnapfilemanager break-glass cert -regenerate` and restart the app when you are ready to compare a new fingerprint", days)
		frontend.AuditBreakGlass("breakglass-cert", "warn", fmt.Sprintf("door=local cert expires in %d days (sha256=%s); run `break-glass cert -regenerate`", days, cert.Fingerprint))
	}
	frontend.EnableBreakGlass(configPath)
	srv.bgHandler = frontend.BreakGlassHandler()
	srv.bgCert = cert.TLS
	srv.bgAddr = cfg.Web.BreakGlass.Addr
	srv.auditBG = frontend.AuditBreakGlass
	srv.bgPending = false
	return nil
}

// armBreakGlassFn is armBreakGlass, in a variable so a test can count how often
// the watcher actually re-arms — arming loads or generates a certificate and
// measures a bcrypt, and doing that once a minute behind a failing bind would
// be a self-inflicted load on a NAS that is already in trouble (round-3 P3).
var armBreakGlassFn = armBreakGlass

// breakGlassWatchInterval is how often a daemon that started with no password
// looks for one. A minute is the difference between "run this command" and "run
// this command, then restart the app you are trying to repair".
var breakGlassWatchInterval = time.Minute

// watchForCredential binds the break-glass listener when a password appears
// under a running daemon (round-2 P2-3).
//
// The documented first run is: install, run `break-glass set-password`, compare
// the fingerprint, open https://<nas>:8771/. Until this existed the last step
// failed — the listener had decided at start-up that there was no password and
// nothing ever revisited it — so the procedure silently required a restart of
// the very app an operator may be using to repair the NAS. The credential
// itself is already re-read per attempt (localCred); this is the one decision
// that was frozen.
//
// It stops at the first success: from then on the listener is bound and the
// password is read live.
func (s *server) watchForCredential(ctx context.Context, frontend *web.Server, configPath string, serve func(*http.Server, net.Listener)) {
	if !s.bgPending || configPath == "" {
		return
	}
	ticker := time.NewTicker(breakGlassWatchInterval)
	defer ticker.Stop()
	// The hash the door is already prepared for. Arming is expensive — it loads
	// or generates a certificate and measures one bcrypt at the configured cost,
	// which on a slow ARM core at cost 15 is seconds — so a bind that failed and
	// is being retried must not redo it every minute (round-3 P3). Only a hash
	// that actually CHANGED re-arms.
	armedFor := ""
	// The last refusal already reported. A key directory anyone can write is a
	// standing condition, not an event: repeating the same line every minute
	// would bury the log of a NAS that is already in trouble, and saying it
	// once and then never again would hide a reason that CHANGED. One line per
	// distinct reason is both (Astra r2 #2).
	lastRefusal := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg, err := config.LoadDev(configPath, s.dev)
		if err != nil || !cfg.Web.BreakGlass.Enabled || cfg.Auth.Local.Hash == "" {
			continue
		}
		// The SAME forcing the start-up path applies (Astra r1 #5). This path
		// re-reads the file from disk, so without it a -dev daemon that binds
		// late — the documented first run, where the password is set after the
		// daemon is already up — would take the config's own 0.0.0.0 default and
		// open a LAN port on a development box, which contract §15 says never
		// happens. Validated afterwards for the same reason start-up validates
		// after forcing: the forced address could collide with web.listen.
		cfg = forceLoopbackBreakGlass(cfg, s.dev)
		if err := cfg.ValidateDev(s.dev); err != nil {
			s.logger.Printf("break-glass: the reloaded configuration is not usable: %v", err)
			continue
		}
		if cfg.Auth.Local.Hash != armedFor {
			if err := armBreakGlassFn(s, frontend, cfg, configPath, s.logger); err != nil {
				// armedFor is deliberately NOT recorded: the hash has not been
				// armed for, so the next tick tries again and an operator who
				// fixes the directory gets their door back without a restart
				// (Astra r2 #2).
				if reason := err.Error(); reason != lastRefusal {
					lastRefusal = reason
					if errors.Is(err, errArmRefused) {
						s.logger.Printf("%v", err)
					} else {
						s.logger.Printf("break-glass could not be armed after a password appeared: %v", err)
					}
				}
				continue
			}
			lastRefusal = ""
			armedFor = cfg.Auth.Local.Hash
		}
		if s.bgHandler == nil {
			continue
		}
		httpSrv, ln, err := s.listenBreakGlass()
		if err != nil {
			// Log and keep watching: the port may be momentarily taken, and an
			// operator who has just set a password should not have to set it
			// again to get another attempt.
			s.logger.Printf("break-glass listener could not bind after a password appeared: %v", err)
			continue
		}
		serve(httpSrv, ln)
		return
	}
}

// guardInstallDir is the API path of the daemon's own installation tree, used
// by the guard to refuse deleting or rewriting itself and to hide its config
// and logs from the file manager. It is left empty inside a -jail (dev loop),
// where no real install path maps to a jailed API path and the rules would only
// misfire. In production the config sits at <install>/config/<file>, so the
// grandparent of the config path is the install root; the executable's
// grandparent is the fallback.
func guardInstallDir(configPath string, root fsx.Root) string {
	if root.Jailed() {
		return ""
	}
	if configPath != "" {
		return filepath.ToSlash(filepath.Dir(filepath.Dir(configPath)))
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.ToSlash(filepath.Dir(filepath.Dir(exe)))
	}
	return ""
}

// shareIsRAM reports whether /share is the QTS system tmpfs, so the guard
// refuses creating files that would be lost on reboot. It mirrors the display
// hint web.ramShare uses.
func shareIsRAM(plat *platform.Platform) bool {
	m, ok := plat.MountFor("/share")
	return ok && m.MountPoint == "/share" && m.FSType == "tmpfs"
}

// server owns listener lifetime; internal/web owns the HTTP application.
type server struct {
	cfg      config.Config
	root     fsx.Root
	dev      bool
	logger   *log.Logger
	frontend http.Handler

	// The break-glass listener. All four are set together by armBreakGlass, or
	// none of them are: a nil bgHandler is what "the listener does not bind"
	// looks like from here.
	bgHandler http.Handler
	bgCert    *tls.Certificate
	bgAddr    string
	auditBG   func(op, result, detail string)
	// bgPending is "enabled, but no password yet": the listener binds nothing
	// and a watcher looks for a credential appearing under the running daemon
	// (round-2 P2-3). bgFrontend and bgConfigPath are what that watcher needs.
	bgPending    bool
	bgFrontend   *web.Server
	bgConfigPath string
}

// Adapt the pool's concrete diagnostic slice to web's optional Stats contract.
type poolBackend struct{ *workerpool.Pool }

func (b poolBackend) Stats() any { return b.Pool.Stats() }

func newServer(cfg config.Config, root fsx.Root, logger *log.Logger) *server {
	return &server{cfg: cfg, root: root, logger: logger, frontend: web.New(cfg, nil, nil, nil, nil, nil, version, logger, nil, nil, nil).Handler()}
}

// sessionResponse is the shape the UI polls on first load.
type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Version       string `json:"version"`
	ReadOnly      bool   `json:"readOnly"`
}

func (s *server) handler() http.Handler { return s.frontend }

func (s *server) run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Web.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.Web.Listen, err)
	}
	httpSrv := &http.Server{
		Handler: s.handler(),
		// No WriteTimeout (multi-gigabyte downloads) and no ReadTimeout
		// (multi-gigabyte uploads); the header timeout is what protects
		// against a stalled client holding a connection open (§4.3).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	jail := "none"
	if s.root.Jailed() {
		jail = s.root.Base()
	}
	s.logger.Printf("qnapfilemanager %s listening on %s (readOnly=%v, jail=%s, proxyPrefix=%q, dev=%v)",
		version, ln.Addr(), s.cfg.ReadOnly, jail, s.cfg.Web.ProxyPrefix, s.dev)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// errc is sized for the two listeners plus a late-bound break-glass one.
	errc := make(chan error, 3)
	// live is the set of servers shutdown must drain. The credential watcher can
	// add to it from its own goroutine long after start-up, so it has a mutex:
	// a slice appended to by one goroutine and ranged over by another during
	// shutdown is the kind of race that only ever shows up on a NAS.
	listeners := &listenerSet{servers: []*http.Server{httpSrv}, started: 1}
	serveOne := func(srv *http.Server, l net.Listener, tls bool) {
		if !listeners.add(srv, l) {
			return
		}
		go func() {
			var err error
			if tls {
				err = srv.ServeTLS(l, "", "")
			} else {
				err = srv.Serve(l)
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
	}
	go func() {
		err := httpSrv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	if s.bgHandler != nil {
		bgSrv, bgLn, err := s.listenBreakGlass()
		if err != nil {
			// Refusing to start is right: an operator who configured an
			// emergency door and got a daemon that silently has none would
			// discover it at the worst possible moment.
			_ = httpSrv.Close()
			return err
		}
		serveOne(bgSrv, bgLn, true)
	} else if s.bgPending {
		// Enabled, but no password yet. Watch for one rather than requiring a
		// restart of the app the operator may be repairing with (round-2 P2-3).
		watchCtx, stopWatch := context.WithCancel(ctx)
		defer stopWatch()
		go s.watchForCredential(watchCtx, s.bgFrontend, s.bgConfigPath, func(srv *http.Server, l net.Listener) {
			serveOne(srv, l, true)
		})
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		s.logger.Printf("shutting down")
		// QPKG_TIMEOUT is "30,60", so there is room to drain before App
		// Center loses patience. EVERY listener drains inside the one budget.
		shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		draining, count := listeners.beginShutdown()
		var firstErr error
		for _, srv := range draining {
			if err := srv.Shutdown(shutCtx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return firstErr
		}
		for range count {
			if err := <-errc; err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

// listenerSet is every HTTP server this daemon has running, and the one place
// that decides whether a NEW one may still start.
//
// The credential watcher can bind the break-glass listener at any moment,
// including while the daemon is already draining (round-3 P3). A listener that
// arrived after shutdown took its snapshot would serve on past Shutdown with
// nothing left to stop it — a root daemon's LAN port outliving the daemon's own
// shutdown. Registration and the snapshot take the same lock, so there is no
// window between them at all.
type listenerSet struct {
	mu       sync.Mutex
	servers  []*http.Server
	started  int
	draining bool
}

// add registers srv as live and reports whether it may serve. When the daemon
// is already shutting down it closes l and answers false: the caller must not
// start serving, and nothing is added to the count shutdown waits for.
func (s *listenerSet) add(srv *http.Server, l net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		_ = l.Close()
		return false
	}
	s.servers = append(s.servers, srv)
	s.started++
	return true
}

// beginShutdown closes the set to new listeners and returns what to drain,
// with the number of Serve goroutines that will report back.
func (s *listenerSet) beginShutdown() ([]*http.Server, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draining = true
	return append([]*http.Server(nil), s.servers...), s.started
}

// listenBreakGlass binds and configures the second listener. HTTP/2 is declined
// on purpose (contract §13.5): every streaming, admission and deadline argument
// in M2-C was reasoned over HTTP/1.1 semantics, and a release is not the place
// to re-derive them.
func (s *server) listenBreakGlass() (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", s.bgAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listening on the break-glass address %s: %w", s.bgAddr, err)
	}
	// Deliberately NO ReadTimeout, on this listener as on the main one. It would
	// bound the whole request body, and this listener serves the same API —
	// uploads included — so a ten-second one would cut every large upload made
	// through the emergency door at ten seconds, which is the one situation
	// where an operator has no other route. The slow-body lever it would have
	// closed is closed where it actually lives instead: the login handler reads
	// its bounded body under its own read deadline BEFORE taking an admission
	// slot, and the door routes arm a 15 s request context (web/breakglass.go).
	srv := &http.Server{
		Handler:           s.bgHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Advertised, but NOT what does the declining (Astra r1 #2):
			// ServeTLS appends "h2" to whatever NextProtos holds when HTTP/2 is
			// still enabled on the server, so a client offering only h2
			// negotiated it and the listener spoke a protocol none of M2-C's
			// streaming, admission and deadline reasoning was done over.
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{*s.bgCert},
		},
		// This is what declines it. Protocols says HTTP/1 and nothing else, so
		// net/http neither appends h2 to NextProtos nor configures an HTTP/2
		// server; the empty TLSNextProto is the older half of the same
		// statement, kept because it is what an ALPN-negotiated "h2" would be
		// looked up in if anything ever put it back.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	srv.Protocols = protocols
	s.logger.Printf("break-glass listening on %s (TLS, local administrator account only)", ln.Addr())
	if s.auditBG != nil {
		s.auditBG("breakglass-listen", "ok", fmt.Sprintf("door=local listener bound %s", ln.Addr()))
	}
	return srv, ln, nil
}
