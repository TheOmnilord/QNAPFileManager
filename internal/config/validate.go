package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrInvalid wraps every validation failure so a caller can tell a bad config
// from a missing file or an I/O error.
var ErrInvalid = errors.New("invalid configuration")

// Validate checks the config the daemon is about to run with. It is
// deliberately strict: this process runs as root, and a listen address that
// quietly fell back to 0.0.0.0 because it was unparsable is exactly the kind
// of failure nobody notices until it matters.
func (c Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.Web.Listen == "" {
		add("web.listen is empty")
	} else if err := checkAddr(c.Web.Listen); err != nil {
		add("web.listen: %v", err)
	}
	if c.Web.BreakGlass.Enabled {
		if c.Web.BreakGlass.Addr == "" {
			add("web.breakGlass.addr is empty while breakGlass is enabled")
		} else if err := checkAddr(c.Web.BreakGlass.Addr); err != nil {
			add("web.breakGlass.addr: %v", err)
		} else if c.Web.BreakGlass.Addr == c.Web.Listen {
			add("web.breakGlass.addr must differ from web.listen (%s)", c.Web.Listen)
		}
	}
	if c.Web.ProxyPrefix != "" {
		if !strings.HasPrefix(c.Web.ProxyPrefix, "/") {
			add("web.proxyPrefix %q must start with /", c.Web.ProxyPrefix)
		}
		if strings.HasSuffix(c.Web.ProxyPrefix, "/") {
			add("web.proxyPrefix %q must not end with /", c.Web.ProxyPrefix)
		}
	}

	switch c.Auth.Mode {
	case AuthQTS, AuthLocal, AuthBoth:
	case "":
		add("auth.mode is empty; use %q, %q or %q", AuthQTS, AuthLocal, AuthBoth)
	default:
		add("auth.mode %q is not one of %q, %q, %q", c.Auth.Mode, AuthQTS, AuthLocal, AuthBoth)
	}
	// The break-glass listener is deliberately legal alongside auth.mode
	// "qts": PLAN.md decision 3 makes the local account the last door in the
	// fallback chain, not a separate mode the operator has to select in
	// advance — the point is that it still works when Apache is broken.
	if c.Auth.QTSPort < 0 || c.Auth.QTSPort > 65535 {
		add("auth.qtsPort %d is not a port (0 means read it from uLinux.conf)", c.Auth.QTSPort)
	}

	if c.Trash.Days < 0 {
		add("trash.days %d cannot be negative", c.Trash.Days)
	}

	if c.Worker.Max < 1 {
		add("worker.max %d must be at least 1", c.Worker.Max)
	}
	if c.Worker.Max > 64 {
		add("worker.max %d is more processes than a NAS should hold open", c.Worker.Max)
	}
	if d, err := c.Worker.IdleTimeoutDuration(); err != nil {
		add("%v", err)
	} else if d < 0 {
		add("worker.idleTimeout %q cannot be negative", c.Worker.IdleTimeout)
	}
	if _, err := c.Worker.UmaskValue(); err != nil {
		add("%v", err)
	}

	if c.Limits.ListMax < 1 {
		add("limits.listMax %d must be at least 1", c.Limits.ListMax)
	}
	if c.Limits.ListMax > 50000 {
		add("limits.listMax %d exceeds the hard cap of 50000", c.Limits.ListMax)
	}
	if c.Limits.MaxTextBytes < 1 {
		add("limits.maxTextBytes %d must be positive", c.Limits.MaxTextBytes)
	}
	if c.Limits.MaxTextBytes > 64<<20 {
		add("limits.maxTextBytes %d is too large for an in-browser editor", c.Limits.MaxTextBytes)
	}

	if c.Logging.MaxSizeMB < 1 {
		add("logging.maxSizeMB %d must be at least 1", c.Logging.MaxSizeMB)
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// checkAddr accepts anything net.Listen would: "host:port", ":port",
// "127.0.0.1:8770", "[::1]:8770". A missing port is the mistake worth naming
// explicitly, because "127.0.0.1" alone looks right to a human.
func checkAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port (%v)", addr, err)
	}
	if port == "" {
		return fmt.Errorf("%q has no port", addr)
	}
	// Parsed rather than looked up: net.LookupPort would consult /etc/services
	// for a name, and this runs at startup on a NAS whose name resolution may
	// be exactly what is broken.
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q is not a TCP port number", port)
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			// A hostname is legal for net.Listen but is a support question
			// waiting to happen on a NAS whose name resolution is the thing
			// being repaired.
			return fmt.Errorf("%q is not an IP address; use 127.0.0.1 or 0.0.0.0", host)
		}
	}
	return nil
}
