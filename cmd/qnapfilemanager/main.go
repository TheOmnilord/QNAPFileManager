// Command qnapfilemanager is the QNAPFileManager daemon: a root front-end
// that serves the web UI, and — re-executing itself with -worker — one
// unprivileged worker process per signed-in user, which is where every
// filesystem operation actually runs.
package main

import (
	"context"
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
	"syscall"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
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
  qnapfilemanager serve [flags]   run the daemon
  qnapfilemanager version         print the version
  qnapfilemanager -worker -uid N  internal: the per-user worker process

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
		cfg, err = config.Load(o.configPath)
		if err != nil {
			return err
		}
	}
	cfg = o.apply(cfg)
	if err := cfg.Validate(); err != nil {
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
			}
		}
	}()
	frontend.SetJobs(poolBackend{b}, jobMgr)
	srv.frontend = frontend.Handler()
	return srv.run(context.Background())
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

	errc := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		s.logger.Printf("shutting down")
		// QPKG_TIMEOUT is "30,60", so there is room to drain before App
		// Center loses patience.
		shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			return err
		}
		return <-errc
	}
}
