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
	"strings"
	"syscall"
	"time"

	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/logfile"
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
  -impersonate <user>   run every operation as <user>, without a QTS session
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

// runWorker is the entry point of an impersonated worker process. The worker
// milestone fills this in; until then it exits non-zero so a front-end that
// spawns one gets a clear failure rather than a process that sits there.
func runWorker(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.Bool("worker", false, "run as the per-user worker process")
	uid := fs.Int("uid", -1, "the uid this worker was spawned for, for logging and self-checks")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stdout, "worker mode not implemented (uid %d)\n", *uid)
	return 2
}

type serveOptions struct {
	configPath  string
	logPath     string
	addr        string
	jail        string
	proxyPrefix string
	readOnly    bool
	impersonate string
	// set records which flags the operator actually gave, so an unset
	// -readonly leaves the config's value alone instead of overwriting it
	// with the flag's default.
	set map[string]bool
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
	fs.StringVar(&o.impersonate, "impersonate", "", "run every operation as this user, without a QTS session")
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

	srv := newServer(cfg, root, logger)
	return srv.run(context.Background())
}

// server is the placeholder front-end. It answers /api/session so the CI smoke
// test and the dev loop have something real to talk to; internal/web replaces
// it wholesale in M1.
type server struct {
	cfg    config.Config
	root   fsx.Root
	logger *log.Logger
}

func newServer(cfg config.Config, root fsx.Root, logger *log.Logger) *server {
	return &server{cfg: cfg, root: root, logger: logger}
}

// sessionResponse is the shape the UI polls on first load.
type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Version       string `json:"version"`
	ReadOnly      bool   `json:"readOnly"`
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", s.handleSession)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	if p := s.cfg.Web.ProxyPrefix; p != "" {
		// QTS's generated Apache rule may or may not strip the prefix
		// (identity plan §5.2, still to be verified on the NAS), so the mux is
		// mounted under both. StripPrefix hands the inner mux the same paths
		// either way.
		outer := http.NewServeMux()
		outer.Handle(p+"/", http.StripPrefix(p, mux))
		outer.Handle(p, http.RedirectHandler(p+"/", http.StatusMovedPermanently))
		outer.Handle("/", mux)
		return outer
	}
	return mux
}

func (s *server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSONError(w, http.StatusMethodNotAllowed, "bad_request", "use GET")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{
		Authenticated: false,
		Version:       version,
		ReadOnly:      s.cfg.ReadOnly,
	})
}

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
	s.logger.Printf("qnapfilemanager %s listening on %s (readOnly=%v, jail=%s, proxyPrefix=%q)",
		version, ln.Addr(), s.cfg.ReadOnly, jail, s.cfg.Web.ProxyPrefix)

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
