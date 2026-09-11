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
// bcrypt auth mode.
type BreakGlass struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
}

type Auth struct {
	// Mode is "qts" (the QTS session), "local" (the break-glass account) or
	// "both".
	Mode string `json:"mode"`
	// AdminRequiresBoth makes an administrator prove both identities before
	// root mode can be armed: the QTS session says isAdmin, and the local
	// account confirms it. Default on — this is what unlocks writes outside
	// /share.
	AdminRequiresBoth bool `json:"adminRequiresBoth"`
	// QTSPort is the loopback port of authLogin.cgi. 0 means read it from
	// /etc/config/uLinux.conf, falling back to 8080.
	QTSPort int `json:"qtsPort"`
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
func Load(path string) (Config, error) {
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
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically — through jsonfile, which publishes by
// rename after flushing, so a crash cannot leave a half-written file where the
// last good one was — and then tightens the mode: this file holds the
// break-glass password hash.
func Save(path string, c Config) error {
	c.Normalize()
	if err := c.Validate(); err != nil {
		return err
	}
	if err := jsonfile.Write(path, c); err != nil {
		return err
	}
	// jsonfile publishes archive data at 0644; a credential store is not that.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("tightening the mode of %s: %w", path, err)
	}
	return nil
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
