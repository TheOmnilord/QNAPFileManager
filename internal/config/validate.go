package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalid wraps every validation failure so a caller can tell a bad config
// from a missing file or an I/O error.
var ErrInvalid = errors.New("invalid configuration")

// Validate checks the config the daemon is about to run with. It is
// deliberately strict: this process runs as root, and a listen address that
// quietly fell back to 0.0.0.0 because it was unparsable is exactly the kind
// of failure nobody notices until it matters.
func (c Config) Validate() error { return c.ValidateDev(false) }

// ValidateDev is Validate with the two development relaxations named in the M4
// contract: auth.mode may be "local" or "both" (§2.2), which exist only for the
// Windows dev loop. The loopback rule on web.listen is NOT relaxed — there is
// no override key for it anywhere, in any mode (§13.1).
func (c Config) ValidateDev(dev bool) error { return c.validate(dev, false) }

// validate's lenientHash skips the checks on auth.local.hash, and nothing else.
// It exists for the two commands whose whole purpose is to REPLACE that key
// (Astra r2 #5): with a rejected hash on disk — " ", a cost of 31, a truncated
// tail — `break-glass set-password` and `break-glass disable` failed on the
// load, before they could write the value that would have fixed it, so the one
// documented way out of a broken credential was to hand-edit the credential
// store of a NAS the operator may already be locked out of. They load
// leniently and the RESULT is validated strictly on the way out, which is where
// it matters: nothing invalid is ever written, and the daemon's own load is
// unchanged.
func (c Config) validate(dev, lenientHash bool) error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.Web.Listen == "" {
		add("web.listen is empty")
	} else if err := checkAddr(c.Web.Listen); err != nil {
		add("web.listen: %v", err)
	} else if err := checkLoopback(c.Web.Listen); err != nil {
		// The main listener carries the QTS cookie door and is reached through
		// the QTS reverse proxy; exposing it is exposing the whole app to the
		// LAN. The break-glass listener is the ONE sanctioned non-loopback
		// surface, and a second way to expose this one would be a second way to
		// get it wrong — so there is deliberately no override key (§13.1).
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
	case AuthQTS:
	case AuthLocal, AuthBoth:
		// M4 §2.2: the local account moved entirely to its own listener, so it
		// is no longer a door on the main one. Refused outside -dev, where it
		// survives only because the Windows loop has no QTS to talk to.
		if !dev {
			add("auth.mode %q is refused: the local account is served by the break-glass listener (web.breakGlass), not by web.listen; use %q", c.Auth.Mode, AuthQTS)
		}
	case "":
		add("auth.mode is empty; use %q", AuthQTS)
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
	if !lenientHash && c.Auth.Local.Cost != 0 && (c.Auth.Local.Cost < MinLocalCost || c.Auth.Local.Cost > MaxLocalCost) {
		// The cost key travels with the hash, so it is skipped with it: an
		// out-of-range cost beside the credential must not be what stops the
		// command that replaces the credential (Astra r2 #5). set-password
		// writes the cost it used; disable clears it with the hash.
		add("auth.local.cost %d is outside %d-%d (0 means %d)", c.Auth.Local.Cost, MinLocalCost, MaxLocalCost, DefaultLocalCost)
	}
	// The HASH itself, not only the cost key beside it (Astra r1 #10). The cost
	// that matters is the one EMBEDDED in the hash — that is what bcrypt will
	// actually run — and nothing checked it. `hash: " "` armed a listener no
	// password could ever pass (§2.5's "no hash, no bind" reads it as present),
	// and an embedded cost of 31 would run for minutes per attempt on a NAS
	// core, from an unauthenticated caller, which is the denial of service
	// §4.2's ceiling exists to prevent.
	if lenientHash {
		// Nothing about the hash is checked, including the whitespace rule
		// below: `disable` clears it and `set-password` overwrites it.
	} else if strings.TrimSpace(c.Auth.Local.Hash) != "" {
		cost, err := bcrypt.Cost([]byte(c.Auth.Local.Hash))
		switch {
		case err != nil:
			// Never echoed: this is the credential. What it is not is enough.
			add("auth.local.hash is not a bcrypt hash (%v); it is written only by `qnapfilemanager break-glass set-password`", err)
		case cost < MinLocalCost || cost > MaxLocalCost:
			add("auth.local.hash carries bcrypt cost %d, outside %d-%d", cost, MinLocalCost, MaxLocalCost)
		default:
			// The whole shape, not only the header bcrypt.Cost reads (Astra r2
			// #4). Cost parses "$2a$11$" and stops, so a hash with a truncated
			// or corrupted tail passed validation and then failed every single
			// comparison — a listener that binds, accepts the password the
			// operator set, and refuses it, with no way to tell from the config
			// that anything is wrong. Checked structurally rather than by
			// running a comparison, because validation must not cost a bcrypt.
			if err := checkBcryptShape(c.Auth.Local.Hash); err != nil {
				add("auth.local.hash %v; it is written only by `qnapfilemanager break-glass set-password`", err)
			}
		}
	} else if c.Auth.Local.Hash != "" {
		add("auth.local.hash is whitespace; use `qnapfilemanager break-glass disable` to clear it")
	}
	if c.Auth.Local.Updated != "" {
		if _, err := time.Parse(time.RFC3339, c.Auth.Local.Updated); err != nil {
			add("auth.local.updated %q is not an RFC3339 timestamp", c.Auth.Local.Updated)
		}
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

// bcryptSalt64 is bcrypt's own base64 alphabet — NOT the standard one: it
// starts at "." and "/" and has no padding. The 22-character salt and the
// 31-character digest are both written in it.
const bcryptSalt64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// checkBcryptShape is the structural half of the hash check (Astra r2 #4):
// exactly 60 bytes, a recognised prefix, a two-digit cost, and 53 characters of
// bcrypt's own base64 after the third "$". It never runs a comparison — a
// config validation that cost a bcrypt would be a lever on a root daemon — and
// it never echoes the value, because the value is the credential. The error
// says what is wrong with the SHAPE; only `break-glass set-password` writes
// this key, so a wrong shape is corruption or a hand edit, not a typo worth
// helping along.
//
// $2a$, $2b$ and $2y$ only. $2$ and $2x$ are the broken-implementation
// variants, and this file is written by exactly one program.
func checkBcryptShape(hash string) error {
	if len(hash) != 60 {
		return fmt.Errorf("is %d bytes long, not the 60 a bcrypt hash always is", len(hash))
	}
	switch hash[:4] {
	case "$2a$", "$2b$", "$2y$":
	default:
		return fmt.Errorf("does not start with $2a$, $2b$ or $2y$")
	}
	if hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9' {
		return fmt.Errorf("does not carry a two-digit bcrypt cost")
	}
	if hash[6] != '$' {
		return fmt.Errorf("is not $2<v>$<cost>$<salt><digest>")
	}
	for i := 7; i < len(hash); i++ {
		if !strings.ContainsRune(bcryptSalt64, rune(hash[i])) {
			// The position, never the character: this is the credential.
			return fmt.Errorf("carries a character at offset %d that is not in bcrypt's base64 alphabet", i)
		}
	}
	// The last character of the checksum, whose low two bits bcrypt never sets
	// (Astra r3 #4).
	//
	// The checksum is 31 characters standing for 23 bytes, so it ends on a
	// character carrying only the tail of a byte — two spare bits — and base64
	// writes the spare ones as zero. A hash whose last character is "A" passes
	// every check above and is still a hash bcrypt did not write, so no password
	// on earth matches it: the listener arms, the operator types the password
	// they just set, and the door refuses them. That is the exact failure this
	// whole check exists to catch before the door is needed.
	//
	// The SALT's tail is deliberately NOT checked (Astra r4 #4). It has four
	// spare bits and the same arithmetic, but bcrypt does not compare salts: the
	// decode throws the padding bits away, and the verification re-encodes the
	// salt spelling it was GIVEN, so a hash whose salt tail is non-canonical
	// verifies perfectly well. Refusing it would reject a credential that works —
	// and this check runs on every load, so it would stop a daemon that had been
	// serving that hash for months the first time it was restarted after an
	// upgrade. A structural check may only refuse what genuinely cannot work.
	if b64Value(hash[59])&0x03 != 0 {
		return fmt.Errorf("carries a checksum whose last character sets two bits bcrypt never writes, so no password can match it")
	}
	return nil
}

// b64Value is one character's 6-bit value in bcrypt's alphabet, which is what
// the mask above is asking about. Every character is known to be in the
// alphabet by the time this runs, so the not-found -1 cannot reach here — and
// it would fail the mask anyway, which is the safe direction.
func b64Value(c byte) int { return strings.IndexByte(bcryptSalt64, c) }

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

// checkLoopback refuses any address that is not a loopback literal. It is
// deliberately a whole-address check rather than a host one so the empty host
// (":8770") — which binds every interface — is caught alongside "0.0.0.0" and
// "[::]". checkAddr has already rejected hostnames by the time this runs.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port (%v)", addr, err)
	}
	if host == "" {
		return fmt.Errorf("%q binds every interface; the main listener must be loopback (127.0.0.1 or [::1])", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback address; the main listener is reached through the QTS proxy and must bind 127.0.0.0/8 or ::1 (the break-glass listener is the only LAN-facing one)", addr)
	}
	return nil
}
