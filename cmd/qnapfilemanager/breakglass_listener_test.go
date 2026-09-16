package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/breakglass"
	"qnapfilemanager/internal/config"
	"qnapfilemanager/internal/web"
)

func armFixture(t *testing.T, mutate func(*config.Config)) (*server, config.Config, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	logger := log.New(&logged, "", 0)
	srv := &server{cfg: cfg, logger: logger}
	frontend := web.New(cfg, nil, nil, nil, nil, nil, "test", logger, nil, nil, nil)
	if err := armBreakGlass(srv, frontend, cfg, configPath, logger); err != nil {
		t.Fatalf("armBreakGlass: %v", err)
	}
	return srv, cfg, configPath, &logged
}

// §2.5, the property the qemu smoke also asserts and the one most likely to
// regress silently: with no password hash the listener binds NOTHING. An open
// port that can never authenticate is pure surface, and nothing in the UI would
// look different if this broke.
func TestTheListenerDoesNotBindWithoutAPassword(t *testing.T) {
	srv, _, configPath, logged := armFixture(t, nil)
	if srv.bgHandler != nil || srv.bgCert != nil || srv.bgAddr != "" {
		t.Fatalf("the break-glass listener was armed with no password: %+v", srv)
	}
	// And it says why, naming the command that fixes it.
	out := logged.String()
	if !strings.Contains(out, "no password is set") || !strings.Contains(out, "break-glass set-password") {
		t.Fatalf("the log must say what to run:\n%s", out)
	}
	// No certificate is generated either: there is nothing to serve it.
	cert, _ := config.Default().BreakGlassFiles(configPath)
	if _, err := os.Stat(cert); err == nil {
		t.Fatal("a certificate was generated for a listener that never binds")
	}
}

func TestTheListenerIsInertWhenDisabled(t *testing.T) {
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, _, logged := armFixture(t, func(c *config.Config) {
		c.Web.BreakGlass.Enabled = false
		c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
	})
	// §1: the owner reverses the whole decision with one config key and no code
	// change. Even with a password set, the feature is inert.
	if srv.bgHandler != nil || srv.bgAddr != "" {
		t.Fatalf("web.breakGlass.enabled=false did not disable the listener: %+v", srv)
	}
	if !strings.Contains(logged.String(), "loopback-only") {
		t.Fatalf("the log must say the daemon is loopback-only:\n%s", logged.String())
	}
}

func TestArmedListenerGeneratesACertificateAndLogsItsFingerprint(t *testing.T) {
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, configPath, logged := armFixture(t, func(c *config.Config) {
		c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
	})
	if srv.bgHandler == nil || srv.bgCert == nil {
		t.Fatal("the listener was not armed with a password set")
	}
	if srv.bgAddr != "0.0.0.0:8771" {
		t.Fatalf("bgAddr = %q", srv.bgAddr)
	}
	certFile, keyFile := config.Default().BreakGlassFiles(configPath)
	loaded, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		t.Fatalf("the certificate was not persisted: %v", err)
	}
	// The fingerprint is logged at EVERY start: an operator comparing it against
	// a browser warning needs to find it in the log they already have open.
	if !strings.Contains(logged.String(), loaded.Fingerprint) {
		t.Fatalf("the fingerprint is not in the log:\n%s", logged.String())
	}
}

// §13.5: both listeners carry the same timeouts, and the break-glass one
// declines HTTP/2 on purpose — every streaming, admission and deadline argument
// in M2-C was reasoned over HTTP/1.1 semantics.
func TestBreakGlassListenerTimeoutsAndProtocols(t *testing.T) {
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, _, _ := armFixture(t, func(c *config.Config) {
		c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
	})
	srv.bgAddr = "127.0.0.1:0" // never a LAN port in a test
	httpSrv, ln, err := srv.listenBreakGlass()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if httpSrv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", httpSrv.ReadHeaderTimeout)
	}
	if httpSrv.IdleTimeout != 2*time.Minute {
		t.Errorf("IdleTimeout = %v, want 2m", httpSrv.IdleTimeout)
	}
	if httpSrv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want 64 KiB", httpSrv.MaxHeaderBytes)
	}
	// No ReadTimeout and no WriteTimeout: multi-gigabyte uploads and downloads
	// cross this listener too (backend plan §4.3).
	if httpSrv.ReadTimeout != 0 || httpSrv.WriteTimeout != 0 {
		t.Errorf("read/write timeouts = %v/%v, want none", httpSrv.ReadTimeout, httpSrv.WriteTimeout)
	}
	if httpSrv.TLSConfig == nil {
		t.Fatal("the break-glass listener must terminate TLS")
	}
	if httpSrv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", httpSrv.TLSConfig.MinVersion)
	}
	if len(httpSrv.TLSConfig.NextProtos) != 1 || httpSrv.TLSConfig.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want exactly http/1.1", httpSrv.TLSConfig.NextProtos)
	}
	if len(httpSrv.TLSConfig.Certificates) != 1 {
		t.Errorf("the listener has %d certificates", len(httpSrv.TLSConfig.Certificates))
	}
	if _, ok := ln.Addr().(*net.TCPAddr); !ok {
		t.Errorf("listener address %v is not TCP", ln.Addr())
	}
}

// Astra r1 #2: NextProtos alone does not decline HTTP/2. ServeTLS APPENDS "h2"
// to it while HTTP/2 is still enabled on the server, so a client offering only
// h2 negotiated it — and the previous test asserted the CONFIG rather than a
// handshake, which is exactly how that went unnoticed. This one dials.
func TestTheBreakGlassListenerRefusesHTTP2OnTheWire(t *testing.T) {
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, _, _ := armFixture(t, func(c *config.Config) {
		c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
	})
	srv.bgAddr = "127.0.0.1:0"
	httpSrv, ln, err := srv.listenBreakGlass()
	if err != nil {
		t.Fatal(err)
	}
	// A handler is not needed: ALPN is settled during the handshake.
	httpSrv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	go func() { _ = httpSrv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})
	addr := ln.Addr().String()

	// A client offering ONLY h2 must not come away speaking it. Either the
	// handshake fails outright (no_application_protocol) or it succeeds with no
	// protocol negotiated; what must never happen is "h2".
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err == nil {
		got := conn.ConnectionState().NegotiatedProtocol
		conn.Close()
		if got == "h2" {
			t.Fatalf("the listener negotiated HTTP/2; every streaming, admission and deadline argument in M2-C was reasoned over HTTP/1.1")
		}
	} else if !strings.Contains(err.Error(), "no application protocol") && !strings.Contains(err.Error(), "alert") {
		t.Fatalf("the h2-only dial failed for an unexpected reason: %v", err)
	}

	// And http/1.1 still works, because refusing h2 must not refuse everything.
	ok, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("an http/1.1 client could not reach the emergency door: %v", err)
	}
	defer ok.Close()
	if got := ok.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q, want http/1.1", got)
	}
}

// -dev never opens a LAN port (contract §15): the address is FORCED to
// loopback, not merely validated, so a development run may ask for the
// production default and simply not get it.
func TestDevForcesTheBreakGlassAddressToLoopback(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"0.0.0.0:8771", "127.0.0.1:8771"},
		{"[::]:8771", "127.0.0.1:8771"},
		{"192.168.1.10:9000", "127.0.0.1:9000"},
		{"127.0.0.1:8771", "127.0.0.1:8771"},
		{"[::1]:8771", "[::1]:8771"},
	} {
		t.Run(c.in, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "config.json")
			cfg := config.Default()
			cfg.Web.BreakGlass.Addr = c.in
			if err := config.Save(p, cfg); err != nil {
				t.Fatal(err)
			}
			// runServe's own forcing, exercised through the flag path it lives on.
			var stderr bytes.Buffer
			o, err := parseServeFlags([]string{"-config", p, "-dev", "-addr", "127.0.0.1:0"}, &stderr)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadDev(o.configPath, o.dev)
			if err != nil {
				t.Fatal(err)
			}
			got := forceLoopbackBreakGlass(o.apply(loaded), o.dev)
			if got.Web.BreakGlass.Addr != c.want {
				t.Fatalf("-dev left the break-glass address at %q, want %q", got.Web.BreakGlass.Addr, c.want)
			}
		})
	}
}

// Astra r1 #9: an explicitly configured key location that is not root's alone
// stops the listener binding, and says why. The daemon still starts — the main
// listener and the QTS door are unaffected — because a daemon that refuses to
// start at all is a worse outcome than one whose emergency door is off.
func TestAWritableKeyDirectoryStopsTheListenerBinding(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory ownership and POSIX modes are a Linux question (contract §15)")
	}
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, _, logged := armFixture(t, func(c *config.Config) {
		c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
		c.Web.BreakGlass.KeyFile = filepath.Join(loose, "breakglass-key.pem")
		c.Web.BreakGlass.CertFile = filepath.Join(loose, "breakglass-cert.pem")
	})
	if srv.bgHandler != nil || srv.bgCert != nil || srv.bgAddr != "" {
		t.Fatalf("the listener armed over a world-writable key directory: %+v", srv)
	}
	out := logged.String()
	if !strings.Contains(out, "will not bind") || !strings.Contains(out, "writable") {
		t.Fatalf("the log must say why the door is off:\n%s", out)
	}
	// Nothing was generated into it either: a key written there is a key
	// somebody else can replace.
	if _, err := os.Stat(filepath.Join(loose, "breakglass-key.pem")); err == nil {
		t.Fatal("a key was generated into a world-writable directory")
	}
}

// --- round-2 P2-3: the listener binds when a password appears ----------------

// A daemon that started with no password decided once, at start-up, that the
// break-glass listener did not exist, and nothing ever revisited it — so the
// documented "set the password, then open https://nas:8771/" silently required
// a restart of the very app the operator may be repairing with.
func TestTheListenerBindsWhenAPasswordAppears(t *testing.T) {
	srv, _, configPath, logged := armFixture(t, nil)
	if !srv.bgPending {
		t.Fatal("a break-glass listener with no password must be marked pending")
	}
	// A tight interval so the test does not wait a minute; set before the
	// watcher goroutine exists.
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 10 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })
	srv.bgAddr = "127.0.0.1:0"

	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	srv.bgFrontend, srv.bgConfigPath = frontend, configPath

	bound := make(chan *http.Server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(h *http.Server, l net.Listener) {
			_ = l.Close()
			bound <- h
		})
	}()

	// The operator runs set-password. Nothing restarts.
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MinCost
		c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case h := <-bound:
		if h == nil {
			t.Fatal("the watcher produced no server")
		}
	case <-ctx.Done():
		t.Fatalf("the listener never bound after a password appeared:\n%s", logged.String())
	}
	<-done
	// The certificate was generated and its fingerprint logged, exactly as a
	// start-up bind would have done.
	certFile, keyFile := srv.cfg.BreakGlassFiles(configPath)
	cert, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		t.Fatalf("no certificate was prepared: %v", err)
	}
	if !strings.Contains(logged.String(), cert.Fingerprint) {
		t.Fatalf("the fingerprint was not logged:\n%s", logged.String())
	}
	if srv.bgPending {
		t.Fatal("the daemon is still waiting for a password it already found")
	}
}

// Astra r1 #5: the late-bind path re-reads the config FROM DISK, so start-up's
// forcing has to run again. Without it, a -dev daemon that binds late — which is
// the documented first run, where the password is set after the daemon is
// already up — took the file's own 0.0.0.0 default and opened a LAN port on a
// development box, which contract §15 says never happens.
func TestTheLateBindPathReappliesTheDevLoopbackForcing(t *testing.T) {
	srv, _, configPath, _ := armFixture(t, func(c *config.Config) {
		c.Web.BreakGlass.Addr = "0.0.0.0:8771" // the production default, on disk
	})
	srv.dev = true
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })

	// The arm seam reports the address the watcher decided to arm with, without
	// binding anything.
	armed := make(chan string, 1)
	realArm := armBreakGlassFn
	t.Cleanup(func() { armBreakGlassFn = realArm })
	armBreakGlassFn = func(s *server, f *web.Server, cfg config.Config, path string, lg *log.Logger) error {
		select {
		case armed <- cfg.Web.BreakGlass.Addr:
		default:
		}
		// Nothing is generated or bound: the address is the whole assertion.
		return nil
	}

	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MinCost
		c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(*http.Server, net.Listener) {
			t.Error("nothing should bind: the arm seam left bgHandler nil")
		})
	}()
	select {
	case addr := <-armed:
		if addr != "127.0.0.1:8771" {
			t.Fatalf("the late bind armed %q; a -dev run must never open a LAN port", addr)
		}
	case <-ctx.Done():
		t.Fatal("the watcher never armed")
	}
	cancel()
	<-done
}

// The watcher stops with the daemon rather than outliving it.
func TestTheCredentialWatcherStopsWithTheDaemon(t *testing.T) {
	srv, _, configPath, _ := armFixture(t, nil)
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })
	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(*http.Server, net.Listener) {
			t.Error("nothing should bind: no password was ever set")
		})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher outlived its context")
	}
}

// A daemon that is NOT pending never starts a watcher at all.
func TestNoWatcherWhenTheListenerIsAlreadyArmedOrDisabled(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"disabled", func(c *config.Config) { c.Web.BreakGlass.Enabled = false }},
		{"already armed", func(c *config.Config) {
			hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
			if err != nil {
				panic(err)
			}
			c.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-13T12:00:00Z"}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, _, configPath, _ := armFixture(t, c.mutate)
			if srv.bgPending {
				t.Fatal("bgPending must be false")
			}
			frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.watchForCredential(context.Background(), frontend, configPath, func(*http.Server, net.Listener) {
					t.Error("a watcher ran for a daemon that is not pending")
				})
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("watchForCredential did not return immediately")
			}
		})
	}
}

// --- round-3 P3: a failing bind must not re-arm every minute -----------------

// Arming loads or generates a certificate and measures one bcrypt at the
// configured cost — seconds on a slow ARM core at cost 15. Redoing that once a
// minute behind a bind that keeps failing would be a self-inflicted load on a
// NAS that is already in trouble, so only a hash that actually CHANGED re-arms.
func TestABindThatKeepsFailingDoesNotReArm(t *testing.T) {
	srv, _, configPath, _ := armFixture(t, nil)
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })

	// A bind that cannot succeed: an address nothing can listen on.
	srv.bgAddr = "127.0.0.1:0"
	arms := 0
	realArm := armBreakGlassFn
	t.Cleanup(func() { armBreakGlassFn = realArm })
	armBreakGlassFn = func(s *server, f *web.Server, cfg config.Config, path string, lg *log.Logger) error {
		arms++
		if err := realArm(s, f, cfg, path, lg); err != nil {
			return err
		}
		// Force every bind attempt to fail, without touching the arming path.
		s.bgAddr = "127.0.0.1:-1"
		return nil
	}

	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MinCost
		c.Auth.Local.Updated = "2026-09-14T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(*http.Server, net.Listener) {
			t.Error("the bind was supposed to keep failing")
		})
	}()
	// Many ticks pass; the arm must have happened once.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if arms == 0 {
		t.Fatal("the watcher never armed at all")
	}
	if arms > 1 {
		t.Fatalf("the watcher re-armed %d times behind a failing bind; only a changed hash may re-arm", arms)
	}

	// A hash that DOES change re-arms, which is the other half of the rule.
	// armBreakGlass cleared bgPending when it succeeded; the bind is what never
	// did, so put the watcher back at its entry condition by hand.
	srv.bgPending = true
	arms = 0
	next, err := breakglass.Hash("a different long password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = next
		c.Auth.Local.Updated = "2026-09-14T11:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		srv.watchForCredential(ctx2, frontend, configPath, func(*http.Server, net.Listener) {})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2
	if arms == 0 {
		t.Fatal("a changed hash did not re-arm the door")
	}
}

// --- round-3 P3: a listener bound during the drain is not left serving -------

// The credential watcher can bind the break-glass listener at any moment,
// including while the daemon is already draining. A listener that arrived after
// shutdown took its snapshot would serve on past Shutdown with nothing left to
// stop it — a root daemon's LAN port outliving the daemon's own shutdown.
func TestAListenerBoundDuringShutdownIsClosed(t *testing.T) {
	first := &http.Server{}
	set := &listenerSet{servers: []*http.Server{first}, started: 1}

	// Before the drain: admitted, counted, and the listener is left open for
	// the caller to serve on.
	early := mustListen(t)
	if !set.add(&http.Server{}, early) {
		t.Fatal("a listener was refused before shutdown began")
	}
	draining, count := set.beginShutdown()
	if len(draining) != 2 || count != 2 {
		t.Fatalf("the snapshot holds %d servers and expects %d goroutines, want 2 and 2", len(draining), count)
	}

	// After it: refused AND closed, so nothing serves past the drain and
	// shutdown does not wait for a goroutine that was never started.
	late := mustListen(t)
	addr := late.Addr().String()
	if set.add(&http.Server{}, late) {
		t.Fatal("a listener bound during the drain was admitted")
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatalf("the refused listener is still accepting on %s", addr)
	}
	after, count := set.beginShutdown()
	if len(after) != 2 || count != 2 {
		t.Fatalf("the late listener was counted: %d servers, %d goroutines", len(after), count)
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// --- Astra r2 #2: a refused arm is retried -----------------------------------

// A strict-mode refusal used to be logged and returned as nil, so the watcher
// recorded the hash as armed and never called arm again: fixing the directory
// did nothing until the app was restarted, which is exactly the restart this
// path exists to avoid. The refusal is now an error the watcher can tell from a
// success, so the SAME hash is retried on the next tick.
func TestARefusedArmIsRetriedAndArmsOnceTheReasonIsFixed(t *testing.T) {
	srv, _, configPath, _ := armFixture(t, nil) // no password yet: pending
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })

	var mu sync.Mutex
	refusing, arms := true, 0
	realArm := armBreakGlassFn
	t.Cleanup(func() { armBreakGlassFn = realArm })
	armBreakGlassFn = func(s *server, f *web.Server, cfg config.Config, path string, lg *log.Logger) error {
		mu.Lock()
		arms++
		refuse := refusing
		mu.Unlock()
		if refuse {
			return fmt.Errorf("%w: %v", errArmRefused, errors.New("the break-glass key directory is group-writable"))
		}
		// Armed, but never on a LAN port: the address is the test's own.
		s.bgHandler, s.bgCert, s.bgAddr = http.NotFoundHandler(), &tls.Certificate{}, "127.0.0.1:0"
		return nil
	}

	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MinCost
		c.Auth.Local.Updated = "2026-09-17T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	bound := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(h *http.Server, l net.Listener) {
			_ = l.Close()
			bound <- struct{}{}
		})
	}()

	// The hash never changes, so a second attempt can only come from the
	// refusal not being recorded as an arm.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := arms
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the watcher stopped retrying after %d attempts; a refused arm was recorded as armed", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The directory is fixed: the very next tick arms and binds, with no
	// restart and no password change.
	mu.Lock()
	refusing = false
	mu.Unlock()
	select {
	case <-bound:
	case <-ctx.Done():
		t.Fatal("the listener never bound after the reason was fixed")
	}
	cancel()
	<-done
}

// The line is worth saying once, not once a minute: a key directory anyone can
// write is a standing condition, and a daemon that repeats it every tick buries
// the log of a NAS that is already in trouble. A reason that CHANGES is said
// again.
func TestARepeatedRefusalIsLoggedOncePerReason(t *testing.T) {
	srv, _, configPath, logged := armFixture(t, nil)
	old := breakGlassWatchInterval
	breakGlassWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { breakGlassWatchInterval = old })

	var mu sync.Mutex
	reason, arms := "the break-glass key directory is group-writable", 0
	realArm := armBreakGlassFn
	t.Cleanup(func() { armBreakGlassFn = realArm })
	armBreakGlassFn = func(s *server, f *web.Server, cfg config.Config, path string, lg *log.Logger) error {
		mu.Lock()
		arms++
		r := reason
		mu.Unlock()
		return fmt.Errorf("%w: %s", errArmRefused, r)
	}
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Update(configPath, false, func(c *config.Config) error {
		c.Auth.Local.Hash = hash
		c.Auth.Local.Cost = breakglass.MinCost
		c.Auth.Local.Updated = "2026-09-17T09:00:00Z"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	frontend := web.New(srv.cfg, nil, nil, nil, nil, nil, "test", srv.logger, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.watchForCredential(ctx, frontend, configPath, func(*http.Server, net.Listener) {
			t.Error("nothing should bind: every arm was refused")
		})
	}()
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	reason = "the break-glass key directory is owned by uid 1000, not root"
	mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	tries := arms
	mu.Unlock()
	if tries < 4 {
		t.Fatalf("only %d arm attempts in 300ms; the retry is not running", tries)
	}
	out := logged.String()
	if got := strings.Count(out, "group-writable"); got != 1 {
		t.Fatalf("the first reason was logged %d times, want once:\n%s", got, out)
	}
	if got := strings.Count(out, "owned by uid 1000"); got != 1 {
		t.Fatalf("the second reason was logged %d times, want once:\n%s", got, out)
	}
}

// The other half of #2: armBreakGlass itself reports a strict-mode refusal as
// errArmRefused. It is a REFUSAL, not a fatal error — the daemon starts, the
// main listener and the QTS door are unaffected — and not a nil either, which
// is what let the watcher record the hash as armed and stop trying.
func TestAnUnsafeExplicitKeyLocationRefusesTheArm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("directory ownership and POSIX modes are a Linux question (contract §15)")
	}
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-17T09:00:00Z"}
	cfg.Web.BreakGlass.CertFile = filepath.Join(loose, "breakglass-cert.pem")
	cfg.Web.BreakGlass.KeyFile = filepath.Join(loose, "breakglass-key.pem")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	logger := log.New(&logged, "", 0)
	srv := &server{cfg: cfg, logger: logger}
	frontend := web.New(cfg, nil, nil, nil, nil, nil, "test", logger, nil, nil, nil)
	err = armBreakGlass(srv, frontend, cfg, configPath, logger)
	if !errors.Is(err, errArmRefused) {
		t.Fatalf("armBreakGlass = %v, want errArmRefused", err)
	}
	if srv.bgHandler != nil || srv.bgCert != nil {
		t.Fatalf("the door was armed over a refused location: %+v", srv)
	}
	// And nothing was published into it: generating a key there would hand it
	// to whoever can write there.
	if _, err := os.Stat(cfg.Web.BreakGlass.KeyFile); !os.IsNotExist(err) {
		t.Fatalf("a key was generated into the refused directory (%v)", err)
	}
}

// --- Astra r2 #3: the daemon never renews silently ---------------------------

// A pair inside its 30-day window is SERVED, not replaced, and the daemon says
// how many days are left. An operator is told to compare this fingerprint
// against the browser's warning; a restart that changed it under them would
// teach them that a changed fingerprint is normal.
func TestAnExpiringCertificateIsServedWithAWarning(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-17T09:00:00Z"}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := cfg.BreakGlassFiles(configPath)
	// Ten days left: deep inside the renewal window.
	expiring, err := breakglass.Regenerate(certFile, keyFile, time.Now().Add(-breakglass.Validity+10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	logger := log.New(&logged, "", 0)
	srv := &server{cfg: cfg, logger: logger}
	frontend := web.New(cfg, nil, nil, nil, nil, nil, "test", logger, nil, nil, nil)
	if err := armBreakGlass(srv, frontend, cfg, configPath, logger); err != nil {
		t.Fatalf("armBreakGlass: %v", err)
	}
	served, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if served.Fingerprint != expiring.Fingerprint {
		t.Fatalf("the daemon renewed an expiring certificate: %s -> %s", expiring.Fingerprint, served.Fingerprint)
	}
	out := logged.String()
	if !strings.Contains(out, "expires in 9 days") && !strings.Contains(out, "expires in 10 days") {
		t.Fatalf("the warning must say how long is left:\n%s", out)
	}
	if !strings.Contains(out, "cert -regenerate") {
		t.Fatalf("the warning must name the command that rotates it:\n%s", out)
	}
	if strings.Contains(out, "was generated") {
		t.Fatalf("an expiring certificate was reported as generated:\n%s", out)
	}
}

// An EXPIRED pair is a different thing: no browser will open that door at all,
// so it is replaced and the new fingerprint is logged like every other
// generation.
func TestAnExpiredCertificateIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	hash, err := breakglass.Hash("a long enough password", breakglass.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.Local = config.Local{Hash: hash, Cost: breakglass.MinCost, Updated: "2026-09-17T09:00:00Z"}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := cfg.BreakGlassFiles(configPath)
	dead, err := breakglass.Regenerate(certFile, keyFile, time.Now().Add(-breakglass.Validity-time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	logger := log.New(&logged, "", 0)
	srv := &server{cfg: cfg, logger: logger}
	frontend := web.New(cfg, nil, nil, nil, nil, nil, "test", logger, nil, nil, nil)
	if err := armBreakGlass(srv, frontend, cfg, configPath, logger); err != nil {
		t.Fatalf("armBreakGlass: %v", err)
	}
	fresh, err := breakglass.Load(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Fingerprint == dead.Fingerprint {
		t.Fatal("an expired certificate was served unchanged")
	}
	out := logged.String()
	if !strings.Contains(out, "was generated (expired)") {
		t.Fatalf("the log must say the pair was replaced and why:\n%s", out)
	}
	if !strings.Contains(out, fresh.Fingerprint) {
		t.Fatalf("the new fingerprint is not in the log:\n%s", out)
	}
}
