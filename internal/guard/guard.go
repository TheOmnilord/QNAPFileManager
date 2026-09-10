// Package guard is the front-end safety layer of the root daemon. It runs in
// the root front-end process, before any operation is dispatched to a per-user
// worker (INV-1), and decides — from the path and the operation alone, with no
// filesystem access of its own — whether an operation is allowed outright,
// needs an explicit confirmation token, or is refused.
//
// Everything here is pure logic over already-cleaned absolute API paths (the
// shape fsx.Clean produces): stdlib only, no syscalls, no imports of fsops.
// Permission is still the kernel's to enforce inside the worker (INV-2); the
// guard is a deliberate second layer that stops a root session from doing
// something catastrophic by accident (deleting /etc, unmounting a volume by
// rm -rf, writing into the /share RAM disk, descending a ZFS snapshot tree).
package guard

import (
	"fmt"
	"path"
	"sync"
	"sync/atomic"

	"qnapfilemanager/internal/fsx"
)

// Op is a bit flag naming one class of filesystem operation the guard reasons
// about. A single Check call carries exactly one Op; the flags are a set only
// so a Rule can name several ops at once.
type Op uint16

const (
	// OpRead is reading a file's contents or metadata.
	OpRead Op = 1 << iota
	// OpTraverse is listing or descending into a directory.
	OpTraverse
	// OpCreate is making a new entry inside a directory; it is checked against
	// the parent directory's path, so "/share" with OpCreate asks "may I create
	// something directly inside /share?".
	OpCreate
	// OpWrite is modifying an existing file's contents.
	OpWrite
	// OpDelete is removing an entry.
	OpDelete
	// OpRename is renaming or moving an entry.
	OpRename
	// OpChmod is changing an entry's mode bits.
	OpChmod
	// OpChown is changing an entry's owner or group.
	OpChown
)

// writeOps is every op that mutates the filesystem — everything except reading
// and traversing. Read-only mode and the never-write component rule refuse all
// of these.
const writeOps = OpCreate | OpWrite | OpDelete | OpRename | OpChmod | OpChown

// Rule is one row of the protected-path table. Prefix matching is always on
// path boundaries (see matches), so "/etc/config" never matches
// "/etc/configuration". An Exact rule matches only the path itself, never a
// child.
type Rule struct {
	// Prefix is the API path this rule governs.
	Prefix string
	// Deny names the ops refused outright on a match (ErrProtected).
	Deny Op
	// Warn names the ops allowed only with a confirmation token
	// (ErrConfirmRequired).
	Warn Op
	// Reason is the human-readable justification, surfaced to the UI.
	Reason string
	// Exact restricts the rule to the Prefix path itself, not its children.
	Exact bool
}

// The guard's error sentinels. Three of them are re-exported fsx sentinels so
// that fsx.Code maps them onto the API's error vocabulary without the guard
// needing to know that vocabulary; a caller may test either name.
var (
	// ErrReadOnly: global read-only mode is on and the op mutates.
	ErrReadOnly = fsx.ErrReadOnly
	// ErrProtected: a Deny rule (or the never-write component rule, or a
	// mount-point root) refuses this op.
	ErrProtected = fsx.ErrProtected
	// ErrConfirmRequired: a Warn rule (or a threshold) requires a confirmation
	// token before this op may proceed.
	ErrConfirmRequired = fsx.ErrConfirmRequired
	// ErrConfirmInvalid: a confirmation token that does not verify, was already
	// spent, has expired, or was issued for a different op or set of paths. It
	// wraps fsx.ErrBadName so fsx.Code reports it as bad_request.
	ErrConfirmInvalid = fmt.Errorf("confirmation token is invalid or expired: %w", fsx.ErrBadName)
)

// Guard holds the rule table, the read-only flag, the mount-point hook and the
// confirmation-token machinery. It is safe for concurrent use.
type Guard struct {
	rules      []Rule
	installDir string
	shareIsRAM bool
	readOnly   atomic.Bool

	mu      sync.RWMutex
	mountFn func(apiPath string) bool

	// Confirmation-token state (confirm.go).
	serverKey []byte
	seenMu    sync.Mutex
	seen      map[string]int64 // spent token -> expiry unix, swept lazily
}

// New builds a Guard for a daemon whose own installation lives at installDir
// (an absolute API path; empty disables the install-dir rules) and whose /share
// is the QTS RAM disk when shareIsRAM is true. A fresh 32-byte HMAC key is
// generated here, so confirmation tokens do not survive a restart.
func New(installDir string, shareIsRAM bool) *Guard {
	if installDir != "" {
		installDir = path.Clean(installDir)
	}
	g := &Guard{
		installDir: installDir,
		shareIsRAM: shareIsRAM,
		serverKey:  newServerKey(),
		seen:       make(map[string]int64),
	}
	g.rules = defaultRules(installDir, shareIsRAM)
	return g
}

// CanonicalizeRoots duplicates every protected-path rule whose Prefix is itself
// a symlink — /etc/config -> /ordinary/config — so the rule still governs the
// location once a caller reaches it by its resolved name (adv 1a). resolve maps
// a rule's prefix to its canonical API path, returning false when the prefix
// does not resolve (absent, or escapes the jail); a prefix that resolves to a
// different spelling gains a second rule under the canonical prefix. The route
// layer already checks both the requested and the resolved spelling of an
// operation's own path and takes the stricter verdict; this closes the gap where
// only the resolved spelling of a *protected root* is ever presented. Call once
// at startup, before serving. It never removes a rule, so the lexical spelling
// keeps its protection too.
func (g *Guard) CanonicalizeRoots(resolve func(apiPath string) (string, bool)) {
	if resolve == nil {
		return
	}
	// Startup-only, like New's own rule construction: Check reads g.rules
	// without a lock, so this must complete before any request is served.
	extra := make([]Rule, 0, len(g.rules))
	for i := range g.rules {
		r := g.rules[i]
		canon, ok := resolve(r.Prefix)
		if !ok || canon == "" || canon == r.Prefix {
			continue
		}
		dup := r
		dup.Prefix = canon
		extra = append(extra, dup)
	}
	g.rules = append(g.rules, extra...)
}

// SetReadOnly turns global read-only mode on or off. When on, Check refuses
// every mutating op regardless of path, so no route can forget the toggle.
func (g *Guard) SetReadOnly(v bool) { g.readOnly.Store(v) }

// ReadOnly reports whether global read-only mode is on.
func (g *Guard) ReadOnly() bool { return g.readOnly.Load() }

// SetMountPointChecker wires the daemon's mount-point predicate (typically
// platform.IsMountPointByTable). When set, Check refuses OpDelete and OpRename
// on any path the predicate calls a mount point: unmounting a volume by
// deleting or renaming its root is the single worst thing this app could do.
// Passing nil clears the hook.
func (g *Guard) SetMountPointChecker(fn func(apiPath string) bool) {
	g.mu.Lock()
	g.mountFn = fn
	g.mu.Unlock()
}

func (g *Guard) mountChecker() func(string) bool {
	g.mu.RLock()
	fn := g.mountFn
	g.mu.RUnlock()
	return fn
}

// Check decides a single operation on a single already-cleaned absolute API
// path. It returns nil when the op is allowed, ErrReadOnly when read-only mode
// blocks a mutation, ErrProtected when a Deny rule (or the never-write
// component rule, or a mount-point root) refuses it, and ErrConfirmRequired
// when a Warn rule requires a confirmation token. The path must already be of
// fsx.Clean shape and, for a write, the resolved (symlink-hardened) path — a
// symlink must never be allowed to slip a write past a prefix rule.
func (g *Guard) Check(op Op, p string) error {
	// 1. Read-only mode short-circuits every mutation, whatever the path.
	if g.readOnly.Load() && op&writeOps != 0 {
		return fmt.Errorf("read-only mode blocks this operation on %s: %w", p, ErrReadOnly)
	}

	// 2. Never-write components (.zfs anywhere, /proc, /sys): all mutation
	//    refused. Reading and traversing them is fine.
	if op&writeOps != 0 {
		if reason, hit := neverWriteReason(p); hit {
			return fmt.Errorf("%s is never writable (%s): %w", p, reason, ErrProtected)
		}
	}

	// 3. Mount-point roots: deleting or renaming one unmounts a volume.
	if op&(OpDelete|OpRename) != 0 {
		if fn := g.mountChecker(); fn != nil && fn(p) {
			return fmt.Errorf("%s is a mount point; deleting or renaming it would unmount a volume: %w", p, ErrProtected)
		}
	}

	// 4. The rule table. A Deny match wins over everything and returns at once;
	//    a Warn match is remembered and reported only if nothing denies.
	warn := ""
	for i := range g.rules {
		r := &g.rules[i]
		if !matches(r, p) {
			continue
		}
		if r.Deny&op != 0 {
			return fmt.Errorf("%s is protected: %s: %w", p, r.Reason, ErrProtected)
		}
		if r.Warn&op != 0 && warn == "" {
			warn = r.Reason
		}
	}
	if warn != "" {
		return fmt.Errorf("%s needs confirmation: %s: %w", p, warn, ErrConfirmRequired)
	}
	return nil
}

// Classify reports the worst classification of a path for the UI badge:
// "protected" (some op is denied outright), "warn" (some op needs
// confirmation), or "normal". It considers the never-write component rule, the
// mount-point hook and the rule table, in that order of severity.
func (g *Guard) Classify(p string) string {
	if _, hit := neverWriteReason(p); hit {
		return "protected"
	}
	if fn := g.mountChecker(); fn != nil && fn(p) {
		return "protected"
	}
	// A path that offers any confirmable operation is a caution ("warn") area
	// even if one narrow op is denied — /etc/config may be edited with a
	// confirmation though its own directory may not be deleted, and the badge
	// should invite the edit rather than read as a hard block. A path with only
	// denials and no warns (a top-level system dir, the install tree) is
	// "protected".
	var deny, warn bool
	for i := range g.rules {
		r := &g.rules[i]
		if !matches(r, p) {
			continue
		}
		if r.Warn != 0 {
			warn = true
		}
		if r.Deny != 0 {
			deny = true
		}
	}
	switch {
	case warn:
		return "warn"
	case deny:
		return "protected"
	default:
		return "normal"
	}
}

// Reasons returns the human explanations for why op on p is warned or denied —
// the matching rules' Reason strings, the never-write reason, and the
// mount-point note — for display in a confirmation dialog. The path itself is
// deliberately omitted from every string, so a summary built from a
// symlink-resolved path never discloses that resolved spelling to the client
// (adv resolve.go / round-3 finding 2 disclosure). The result is de-duplicated
// and empty for an ordinary path.
func (g *Guard) Reasons(op Op, p string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if op&writeOps != 0 {
		if reason, hit := neverWriteReason(p); hit {
			add(reason)
		}
	}
	if op&(OpDelete|OpRename) != 0 {
		if fn := g.mountChecker(); fn != nil && fn(p) {
			add("this is a mount point; deleting or renaming it would unmount a volume")
		}
	}
	for i := range g.rules {
		r := &g.rules[i]
		if !matches(r, p) {
			continue
		}
		if r.Deny&op != 0 || r.Warn&op != 0 {
			add(r.Reason)
		}
	}
	return out
}

// matches applies a rule to a path with path-boundary semantics: an Exact rule
// matches only the path itself, a prefix rule matches the path or anything
// beneath it, never a sibling that merely shares a textual prefix.
func matches(r *Rule, p string) bool {
	if r.Exact {
		return p == r.Prefix
	}
	return fsx.IsWithin(p, r.Prefix)
}

// neverWriteReason reports whether p is inside a never-write region and why.
// ".zfs" is matched as a path *component* anywhere in the path (a ZFS snapshot
// tree, or — acceptably — a user directory that happens to be named ".zfs");
// /proc and /sys are matched as whole-path prefixes. Writes to any of these
// fail in the kernel anyway (EROFS/EPERM); the guard just makes the refusal
// honest and early.
// The reasons are deliberately PATH-FREE: they carry no filesystem path (not
// even "/proc" or ".zfs"), so a reason built from a symlink-resolved path can be
// surfaced to the client without disclosing that resolved spelling (adv 2).
func neverWriteReason(p string) (string, bool) {
	if fsx.IsWithin(p, "/proc") || fsx.IsWithin(p, "/sys") {
		return "a kernel pseudo-filesystem", true
	}
	// Walk the components looking for ".zfs".
	for _, el := range splitComponents(p) {
		if el == ".zfs" {
			return "a read-only ZFS snapshot directory", true
		}
	}
	return "", false
}

// splitComponents returns the non-empty path components of an absolute API
// path. "/a/b" -> ["a","b"]; "/" -> nil.
func splitComponents(p string) []string {
	if p == "" || p == "/" {
		return nil
	}
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}
