// Package config is the daemon's JSON configuration: defaults, loading,
// validation and atomic saving.
//
// JSON rather than YAML (backend plan §0): the UI has to render and write this
// file, and every browser can parse JSON without a dependency.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"qnapfilemanager/internal/jsonfile"
)

// Config is the whole file. Every field has a working default, so an absent
// config is not an error — it is the first-run state.
type Config struct {
	Web  Web  `json:"web"`
	Auth Auth `json:"auth"`

	// ReadOnly is the global safety switch. It defaults to true at first
	// install: a root daemon that can rewrite the firmware's configuration
	// should not be able to do so until someone has said so once.
	ReadOnly bool `json:"readOnly"`

	Trash   Trash   `json:"trash"`
	Worker  Worker  `json:"worker"`
	Limits  Limits  `json:"limits"`
	Logging Logging `json:"logging"`
	Jobs    Jobs    `json:"jobs"`
}

// Jobs bounds the M2 job manager (design §3). Two independent classes so a
// folder-size probe is never stuck behind a 200 GB copy.
type Jobs struct {
	// ByteMovers caps concurrent copy/move/archive jobs; a spinning-disk NAS
	// thrashes beyond two.
	ByteMovers int `json:"byteMovers"`
	// Metadata caps concurrent delete/size/search/trash jobs.
	Metadata int `json:"metadata"`
	// QueueDepth caps queued jobs per class; beyond it a submit is refused
	// with queue_full rather than silently waiting.
	QueueDepth int `json:"queueDepth"`
	// RetainMinutes keeps a finished job visible this long, or RetainCount
	// most recent, whichever keeps more. Jobs are in-memory only; the audit
	// log is the durable record.
	RetainMinutes int `json:"retainMinutes"`
	RetainCount   int `json:"retainCount"`
}

type Web struct {
	// Listen is loopback by default: the app is reached through the QTS
	// Apache proxy, which is the smallest attack surface for a root daemon.
	Listen string `json:"listen"`
	// ProxyPrefix is QPKG_PROXY_PATH, e.g. "/qnapfilemanager". The mux is
	// served at both "/" and the prefix, so it works whether or not QTS's
	// generated rule strips it. No trailing slash.
	ProxyPrefix    string     `json:"proxyPrefix"`
	FrameAncestors []string   `json:"frameAncestors,omitempty"`
	BreakGlass     BreakGlass `json:"breakGlass"`
}

// BreakGlass is the second listener. It exists because this is the tool an
// operator would use to fix a NAS whose Apache or App Center is broken, and it
// must not depend on the thing it may have to repair. It serves only the local
// bcrypt auth mode (M4 contract §2.1).
type BreakGlass struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
	// CertFile and KeyFile hold the self-signed certificate the listener
	// terminates TLS with. Empty means "beside the config file", as
	// BreakGlassFiles derives it; both are generated on first start and
	// regenerated within 30 days of expiry (M4 contract §3).
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

type Auth struct {
	// Mode is "qts" (the QTS session), "local" (the break-glass account) or
	// "both". Outside -dev only "qts" is accepted: M4 moved the local account
	// to its own listener, so it is no longer a mode of the main one
	// (contract §2.2).
	Mode string `json:"mode"`
	// AdminRequiresBoth makes an administrator prove both identities before
	// root mode can be armed: the QTS session says isAdmin, and the local
	// account confirms it. Default on — this is what unlocks writes outside
	// /share.
	AdminRequiresBoth bool `json:"adminRequiresBoth"`
	// QTSPort is the loopback port of authLogin.cgi. 0 means read it from
	// /etc/config/uLinux.conf, falling back to 8080.
	QTSPort int `json:"qtsPort"`
	// Local is the break-glass administrator account. It is written only by
	// `qnapfilemanager break-glass` on the NAS shell; there is no HTTP route
	// that sets, changes, resets or reveals it (M4 contract §4.1).
	Local Local `json:"local"`
}

// Local is the break-glass credential as it sits in the config file. The daemon
// re-reads it rather than caching it (guarded by an mtime+size check), so a
// password change from the shell takes effect on the next attempt without a
// restart (M4 contract §4.3).
type Local struct {
	// Hash is the bcrypt hash of the password. Empty means the break-glass
	// listener does not bind at all (contract §2.5).
	Hash string `json:"hash,omitempty"`
	// Cost is the bcrypt cost the hash was written with; 0 means DefaultCost.
	Cost int `json:"cost,omitempty"`
	// Updated is an RFC3339 stamp. Every live break-glass session carries the
	// value it was issued under, so bumping it evicts them all (contract §4.4).
	Updated string `json:"updated,omitempty"`
}

// bcrypt cost bounds (M4 contract §4.2). Cost 12 on the ARM cores these units
// ship is seconds rather than milliseconds, and verification is a CPU cost an
// unauthenticated caller controls; the ceiling keeps an operator from
// configuring a self-inflicted denial of service.
const (
	DefaultLocalCost = 11
	MinLocalCost     = 10
	MaxLocalCost     = 15
)

// LocalCost is Local.Cost with the zero value resolved to the default.
func (l Local) LocalCost() int {
	if l.Cost == 0 {
		return DefaultLocalCost
	}
	return l.Cost
}

type Trash struct {
	Enabled bool `json:"enabled"`
	// Days is how long a trashed item is kept; 0 means never sweep.
	Days int `json:"days"`
}

type Worker struct {
	// Max is the number of live per-uid worker processes.
	Max int `json:"max"`
	// IdleTimeout is a Go duration string. A worker is never reaped while one
	// of its jobs is running.
	IdleTimeout string `json:"idleTimeout"`
	// Umask is octal, as a string, so it reads like the shell command it
	// mirrors: "0022".
	Umask string `json:"umask"`
}

type Limits struct {
	// ListMax is the default page size of a directory listing.
	ListMax int `json:"listMax"`
	// MaxTextBytes bounds the built-in text editor.
	MaxTextBytes int64 `json:"maxTextBytes"`
}

type Logging struct {
	// File is the app log; empty means stderr. The QPKG service script passes
	// -log, which wins over this.
	File string `json:"file,omitempty"`
	// Audit is the JSON-lines audit log, empty for "beside the app log".
	Audit string `json:"audit,omitempty"`
	// MaxSizeMB is the rotation threshold for both.
	MaxSizeMB int `json:"maxSizeMB"`
	// QuLog mirrors milestone events to the QNAP system event log.
	QuLog bool `json:"quLog"`
}

// Auth modes.
const (
	AuthQTS   = "qts"
	AuthLocal = "local"
	AuthBoth  = "both"
)

// Default is the configuration a fresh install runs with.
func Default() Config {
	return Config{
		Web: Web{
			Listen:      "127.0.0.1:8770",
			ProxyPrefix: "",
			BreakGlass: BreakGlass{
				Enabled: true,
				Addr:    "0.0.0.0:8771",
			},
		},
		Auth: Auth{
			Mode:              AuthQTS,
			AdminRequiresBoth: true,
			QTSPort:           0,
			Local:             Local{Cost: DefaultLocalCost},
		},
		ReadOnly: true,
		Trash:    Trash{Enabled: true, Days: 30},
		Worker:   Worker{Max: 8, IdleTimeout: "10m", Umask: "0022"},
		Limits:   Limits{ListMax: 5000, MaxTextBytes: 2 << 20},
		Logging:  Logging{MaxSizeMB: 8, QuLog: true},
		Jobs:     Jobs{ByteMovers: 2, Metadata: 4, QueueDepth: 64, RetainMinutes: 60, RetainCount: 50},
	}
}

// Load reads path. A missing file yields the defaults with no error: that is
// the first-run state, and the claim window depends on being able to start
// without one. Anything else that stops the file being read — a permission
// error, malformed JSON — is an error, because starting with defaults on top
// of a config that exists but could not be read would silently discard the
// operator's settings, read-only mode included.
func Load(path string) (Config, error) { return LoadDev(path, false) }

// LoadDev is Load with the development relaxations of Validate: auth.mode
// "local" and "both" are accepted so the Windows dev loop can exercise the
// local door without a QTS to talk to. Everything else is validated identically.
// Production callers use Load.
func LoadDev(path string, dev bool) (Config, error) { return loadFile(path, dev, false) }

// loadFile is LoadDev with one extra knob, lenientHash, which skips the
// validation of the credential keys and nothing else (Astra r2 #5). Only
// UpdateCredential sets it; every other reader, the daemon included, loads
// strictly.
func loadFile(path string, dev, lenientHash bool) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return c, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	// An unknown key is almost always a typo in a hand-edited file, and a
	// silently ignored safety switch is exactly the failure this daemon must
	// not have. (Go matches JSON keys case-insensitively, so "readonly" still
	// binds to ReadOnly; what this catches is a wrong key, not a wrong case.)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	c.Normalize()
	if err := c.validate(dev, lenientHash); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// BreakGlassFiles resolves where the break-glass certificate and key live.
// Explicit config values win; otherwise they sit beside the config file (the
// QPKG's config/ directory, which package_routines already tightens to 0700),
// falling back to the working directory when the daemon runs without a config
// file at all. M4 contract §3.1.
func (c Config) BreakGlassFiles(configPath string) (certFile, keyFile string) {
	dir := "."
	if configPath != "" {
		dir = filepath.Dir(configPath)
	}
	certFile, keyFile = c.Web.BreakGlass.CertFile, c.Web.BreakGlass.KeyFile
	if certFile == "" {
		certFile = filepath.Join(dir, "breakglass-cert.pem")
	}
	if keyFile == "" {
		keyFile = filepath.Join(dir, "breakglass-key.pem")
	}
	return certFile, keyFile
}

// BreakGlassExplicit reports whether the OPERATOR named the pair's location in
// web.breakGlass.certFile/keyFile rather than letting it sit beside the config
// file. It is what decides how far the loader checks what it opens: a location
// this package's own installer owns is checked once, by the credential-store
// guard; one the operator chose has its whole resolved ancestry walked
// (Astra r2 #1, breakglass.Location).
func (c Config) BreakGlassExplicit() bool {
	return c.Web.BreakGlass.CertFile != "" || c.Web.BreakGlass.KeyFile != ""
}

// CheckBreakGlassKeyDir refuses an EXPLICIT key location whose parent directory
// anyone but root can write (Astra r1 #9, narrowed).
//
// This is the PRE-FLIGHT, not the authority. It runs before anything is
// generated, so the start-up log can name the directory and the fix in one
// line; the check that actually governs the key the door serves is in the
// loader, which resolves the path, walks the resolved ancestry and fstats the
// descriptor it opened (Astra r2 #1). A lexical parent is not enough on its own:
// a root-owned 0700 directory of root-owned symlinks into a user-writable share
// passes this and is refused there.
//
// An explicit web.breakGlass.keyFile is accepted — an operator may have reasons
// to put the pair somewhere else — but the directory it lives in decides who
// owns the key the emergency door serves. A group- or other-writable parent
// lets anyone in that group replace the key with their own and terminate TLS
// for the door, on a root daemon, and no mode on the key file itself prevents
// it: replacing a file is a property of the directory, not of the file. sshd
// refuses to use a key under such a directory for the same reason, and so does
// this: at arm time the listener is not bound and the log says why.
//
// The DEFAULT location is not checked here. It sits beside config.json in the
// QPKG's 0700 config/, which package_routines tightens and which the CLI's own
// store guard checks whenever it writes a credential — checking it twice, with
// two sets of rules, is how the two come to disagree.
//
// Ownership is a Linux question and is skipped elsewhere (contract §15): a
// Windows dev box has no uid 0, and its mode bits are not POSIX ones.
func (c Config) CheckBreakGlassKeyDir(configPath string) error {
	explicit := map[string]bool{}
	if c.Web.BreakGlass.KeyFile != "" {
		explicit[filepath.Dir(c.Web.BreakGlass.KeyFile)] = true
	}
	if c.Web.BreakGlass.CertFile != "" {
		// The certificate is public, but it is published into the same directory
		// and a writable one lets a pair be swapped wholesale.
		explicit[filepath.Dir(c.Web.BreakGlass.CertFile)] = true
	}
	for dir := range explicit {
		if err := keyDirStrict(dir); err != nil {
			return err
		}
	}
	return nil
}

// Save writes the config atomically — through jsonfile, which publishes by
// rename after flushing, so a crash cannot leave a half-written file where the
// last good one was — and then tightens the mode: this file holds the
// break-glass password hash.
func Save(path string, c Config) error { return SaveDev(path, c, false) }

// SaveDev is Save with LoadDev's validation relaxations, so a daemon or a CLI
// run that loaded a -dev configuration can write it back (round-2 P3-6).
func SaveDev(path string, c Config, dev bool) error {
	c.Normalize()
	if err := c.ValidateDev(dev); err != nil {
		return err
	}
	// 0600 on the SCRATCH file, so the published document is never briefly
	// world-readable under its own name: this file holds the break-glass
	// password hash (round-2 P3-5).
	if err := jsonfile.WriteMode(path, c, 0o600); err != nil {
		return err
	}
	// Belt and braces for a pre-existing file whose mode was already wrong.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("tightening the mode of %s: %w", path, err)
	}
	return nil
}

// Update is the read-modify-write every writer of this file must use: it takes
// the cross-process lock, loads, applies change, and saves — so the daemon's
// read-only toggle and the CLI's `break-glass set-password` cannot interleave
// and publish each other's stale copy (round-2 P3-5).
//
// dev selects the validation relaxations of LoadDev, because a daemon started
// with -dev must still be able to save the file it started from (round-2 P3-6).
func Update(path string, dev bool, change func(*Config) error) error {
	return update(path, dev, false, change)
}

// UpdateCredential is Update for the two commands that exist to REPLACE the
// break-glass credential — `break-glass set-password` and `break-glass disable`
// (Astra r2 #5).
//
// It differs from Update in one way: the load is lenient about auth.local, so a
// hash the daemon refuses (" ", a cost outside 10-15, a truncated tail) is not
// what stops the command that would overwrite it. Everything else is identical,
// the cross-process lock included, and SaveDev validates the RESULT strictly —
// so nothing invalid is ever written, and the only thing leniency buys is a way
// back out of a broken credential store without hand-editing the credential
// store.
func UpdateCredential(path string, dev bool, change func(*Config) error) error {
	return update(path, dev, true, change)
}

// Update and UpdateCredential differ only in lenientHash; the lock, the load,
// the change and the strict save are one sequence and must stay one.
func update(path string, dev, lenientHash bool, change func(*Config) error) error {
	release, err := Lock(path)
	if err != nil {
		if hint := lockHint(path); hint != "" {
			return fmt.Errorf("%w (%s)", err, hint)
		}
		return err
	}
	defer release()
	c, err := loadFile(path, dev, lenientHash)
	if err != nil {
		return err
	}
	if err := change(&c); err != nil {
		return err
	}
	return SaveDev(path, c, dev)
}

// Normalize fixes up the shapes that have one obviously intended form, so
// Validate can be strict about the rest.
func (c *Config) Normalize() {
	c.Web.Listen = strings.TrimSpace(c.Web.Listen)
	c.Web.BreakGlass.Addr = strings.TrimSpace(c.Web.BreakGlass.Addr)
	c.Auth.Mode = strings.ToLower(strings.TrimSpace(c.Auth.Mode))
	c.Worker.Umask = strings.TrimSpace(c.Worker.Umask)
	c.Worker.IdleTimeout = strings.TrimSpace(c.Worker.IdleTimeout)

	p := strings.TrimSpace(c.Web.ProxyPrefix)
	if p != "" {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		for len(p) > 1 && strings.HasSuffix(p, "/") {
			p = strings.TrimSuffix(p, "/")
		}
		if p == "/" {
			p = ""
		}
	}
	c.Web.ProxyPrefix = p
}

// IdleTimeoutDuration parses Worker.IdleTimeout.
func (w Worker) IdleTimeoutDuration() (time.Duration, error) {
	if w.IdleTimeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(w.IdleTimeout)
	if err != nil {
		return 0, fmt.Errorf("worker.idleTimeout %q: %w", w.IdleTimeout, err)
	}
	return d, nil
}

// UmaskValue parses Worker.Umask as octal, the way the shell command is
// written. A leading "0" is optional but conventional.
func (w Worker) UmaskValue() (uint32, error) {
	s := w.Umask
	if s == "" {
		return 0o022, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("worker.umask %q is not octal: %w", s, err)
	}
	if v > 0o777 {
		return 0, fmt.Errorf("worker.umask %q is out of range", s)
	}
	return uint32(v), nil
}
