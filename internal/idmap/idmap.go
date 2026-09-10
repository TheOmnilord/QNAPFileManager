// Package idmap resolves QTS user names to Linux identities (uid, primary gid,
// supplementary groups, home) without cgo and without os/user.
//
// The primary source is a pure-Go parser of /etc/passwd and /etc/group, which
// covers every local QTS user. Domain (AD/LDAP) users do not appear in those
// files; they are resolved by a bounded exec of id(1)/getent(1) once per
// session (see LookupNSS) and cached (see Cache).
//
// Two rules are load bearing:
//
//   - The primary gid from /etc/passwd is almost never repeated in the member
//     list of /etc/group, so it is always added to Ident.Groups explicitly.
//   - The NSS path never yields uid 0. If a helper claims uid 0 for a name that
//     /etc/passwd does not also map to uid 0, resolution fails closed.
//   - The NSS path is name bound. getent(1) and id(1) read an all-digit operand
//     as a uid, so an authenticated user literally named "1000" would come back
//     as whoever owns uid 1000; such names are refused unless /etc/passwd lists
//     them, and every helper answer must name the user that was asked for.
//
// A Map is safe for concurrent use. On Windows the files simply do not exist,
// every lookup misses, and the default NSS runner returns an error.
package idmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default file locations and tunables.
const (
	DefaultPasswdPath = "/etc/passwd"
	DefaultGroupPath  = "/etc/group"

	// DefaultCacheTTL is how long a resolved identity stays in a Cache after
	// its last use.
	DefaultCacheTTL = 10 * time.Minute

	// AdminGroup is the QNAP local administrators group name.
	AdminGroup = "administrators"

	// defaultCheckInterval bounds how often the passwd/group files are
	// stat'ed for staleness.
	defaultCheckInterval = time.Second

	// nssTimeout bounds each individual helper execution.
	nssTimeout = 3 * time.Second
)

// Errors returned by this package. Callers should use errors.Is.
var (
	ErrNotFound    = errors.New("idmap: user not found")
	ErrInvalidName = errors.New("idmap: invalid user name")
	ErrNoHelper    = errors.New("idmap: no NSS helper available")
	ErrBadOutput   = errors.New("idmap: unexpected helper output")
	ErrRootRefused = errors.New("idmap: refusing uid 0 from the NSS path for a user absent from passwd")

	// ErrNumericName is returned for an all-digit user name that /etc/passwd
	// does not list: the NSS helpers would read it as a uid and answer for a
	// different account.
	ErrNumericName = errors.New("idmap: refusing a numeric user name on the NSS path")

	// ErrNameMismatch is returned when a helper answers with a passwd entry
	// belonging to some other user than the one that was looked up.
	ErrNameMismatch = errors.New("idmap: helper answered for a different user name")
)

// nameRE is the whitelist a name must match before it is ever handed to an
// external program. It allows the backslash of DOMAIN\user and nothing that a
// shell or an option parser could misread.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{1,64}$`)

// ValidName reports whether name is safe to pass to the NSS helpers: it must
// match nameRE and must not start with '-', which id(1) and getent(1) would
// read as an option rather than an operand.
func ValidName(name string) bool {
	return !strings.HasPrefix(name, "-") && nameRE.MatchString(name)
}

// Ident is a resolved Linux identity.
type Ident struct {
	Name    string
	UID     int
	GID     int   // primary
	Groups  []int // sorted, deduped, always includes GID
	Home    string
	Source  string // "passwd" | "nss-helper" | "cache"
	Partial bool   // true when supplementary groups could not be enumerated
}

// clone returns a deep copy so callers cannot mutate a Map's internal state.
func (id Ident) clone() Ident {
	if id.Groups != nil {
		g := make([]int, len(id.Groups))
		copy(g, id.Groups)
		id.Groups = g
	}
	return id
}

// HasGroup reports whether gid is in the identity's group set.
func (id Ident) HasGroup(gid int) bool {
	for _, g := range id.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// Group is one /etc/group entry.
type Group struct {
	GID     int
	Name    string
	Members []string
}

func (g Group) clone() Group {
	if g.Members != nil {
		m := make([]string, len(g.Members))
		copy(m, g.Members)
		g.Members = m
	}
	return g
}

// ExecFunc runs a helper program. name is the bare program name ("id",
// "getent"); the implementation is responsible for locating it. No shell is
// involved and args are passed verbatim.
type ExecFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// Map is a live view of /etc/passwd and /etc/group plus the NSS exec fallback.
// The zero value is not usable; call Open.
type Map struct {
	// Exec runs the NSS helpers. It is read (never written) by the Map, so
	// set it immediately after Open and before first use. When nil the
	// platform default runner is used, which on Windows always fails.
	Exec ExecFunc

	passwdPath string
	groupPath  string

	// checkInterval bounds staleness probes; tests set it to zero.
	checkInterval time.Duration

	mu        sync.Mutex
	snap      *snapshot
	lastCheck time.Time
	passwdSt  fileState
	groupSt   fileState
}

// Open returns a Map over the given files. Empty paths select
// DefaultPasswdPath and DefaultGroupPath. The files are read lazily on first
// use and re-read whenever their size or modification time changes, probed at
// most once a second. os.Stat is used, not os.Lstat, so a symlinked
// /etc/passwd (as on QTS, which links into /mnt/HDA_ROOT/.config) tracks the
// target's timestamps.
func Open(passwdPath, groupPath string) *Map {
	if passwdPath == "" {
		passwdPath = DefaultPasswdPath
	}
	if groupPath == "" {
		groupPath = DefaultGroupPath
	}
	return &Map{
		passwdPath:    passwdPath,
		groupPath:     groupPath,
		checkInterval: defaultCheckInterval,
	}
}

// PasswdPath and GroupPath report the files this Map reads.
func (m *Map) PasswdPath() string { return m.passwdPath }
func (m *Map) GroupPath() string  { return m.groupPath }

type fileState struct {
	size int64
	mod  time.Time
	ok   bool
}

func (a fileState) same(b fileState) bool {
	return a.ok == b.ok && a.size == b.size && a.mod.Equal(b.mod)
}

func statOf(path string) fileState {
	fi, err := os.Stat(path) // follow symlinks on purpose
	if err != nil {
		return fileState{}
	}
	return fileState{size: fi.Size(), mod: fi.ModTime(), ok: true}
}

type passwdEnt struct {
	name string
	uid  int
	gid  int
	home string
}

type snapshot struct {
	uidToName  map[int]string
	byName     map[string]passwdEnt
	users      []Ident // file order
	gidToGroup map[int]Group
	groupByGID map[int]int // gid -> index into groups
	groups     []Group     // file order
	nameToGID  map[string]int
	foldToGID  map[string]int
	memberOf   map[string][]int // user name -> gids from group member lists
}

func newSnapshot() *snapshot {
	return &snapshot{
		uidToName:  map[int]string{},
		byName:     map[string]passwdEnt{},
		gidToGroup: map[int]Group{},
		groupByGID: map[int]int{},
		nameToGID:  map[string]int{},
		foldToGID:  map[string]int{},
		memberOf:   map[string][]int{},
	}
}

// load returns the current snapshot, reloading the files when they changed.
func (m *Map) load() *snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if m.snap != nil && m.checkInterval > 0 && now.Sub(m.lastCheck) < m.checkInterval {
		return m.snap
	}
	ps, gs := statOf(m.passwdPath), statOf(m.groupPath)
	m.lastCheck = now
	if m.snap != nil && ps.same(m.passwdSt) && gs.same(m.groupSt) {
		return m.snap
	}
	m.passwdSt, m.groupSt = ps, gs
	m.snap = parse(readFile(m.passwdPath), readFile(m.groupPath))
	return m.snap
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// parse builds a snapshot from raw passwd and group bytes. Malformed rows,
// comments and NIS +/- compat lines are skipped; for duplicate ids and names
// the first row wins.
func parse(passwd, group []byte) *snapshot {
	s := newSnapshot()

	for _, line := range lines(passwd) {
		e, ok := parsePasswdRow(line)
		if !ok {
			continue
		}
		if _, dup := s.byName[e.name]; dup {
			continue // first entry wins
		}
		s.byName[e.name] = e
		if _, dup := s.uidToName[e.uid]; !dup {
			s.uidToName[e.uid] = e.name
		}
		s.users = append(s.users, Ident{Name: e.name, UID: e.uid, GID: e.gid, Home: e.home, Source: SourcePasswd})
	}

	for _, line := range lines(group) {
		if skipLine(line) {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		name := f[0]
		if name == "" {
			continue
		}
		gid, ok := atoiStrict(f[2])
		if !ok {
			continue
		}
		var members []string
		if len(f) >= 4 {
			for _, mem := range strings.Split(f[3], ",") {
				mem = strings.TrimSpace(mem)
				if mem != "" {
					members = append(members, mem)
				}
			}
		}
		g := Group{GID: gid, Name: name, Members: members}
		if _, dup := s.gidToGroup[gid]; !dup {
			s.gidToGroup[gid] = g
			s.groupByGID[gid] = len(s.groups)
		}
		if _, dup := s.nameToGID[name]; !dup {
			s.nameToGID[name] = gid
		}
		fold := strings.ToLower(name)
		if _, dup := s.foldToGID[fold]; !dup {
			s.foldToGID[fold] = gid
		}
		s.groups = append(s.groups, g)
		for _, mem := range members {
			s.memberOf[mem] = append(s.memberOf[mem], gid)
		}
	}

	// Fill in the group set of every passwd user now that groups are known.
	for i := range s.users {
		u := &s.users[i]
		u.Groups = mergeGroups(u.GID, s.memberOf[u.Name])
	}
	return s
}

// lines splits raw file bytes into trimmed lines, tolerating CRLF.
func lines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	out := strings.Split(string(b), "\n")
	for i := range out {
		out[i] = strings.TrimRight(out[i], "\r")
	}
	return out
}

// skipLine reports whether a passwd/group row carries no entry: blanks,
// comments, and the NIS compat forms (+, -, +name, +@netgroup, +::::::).
func skipLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return true
	}
	switch t[0] {
	case '#', '+', '-':
		return true
	}
	return false
}

// atoiStrict parses a non-negative decimal id, rejecting anything else.
func atoiStrict(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// mergeGroups returns gid plus extra, sorted and deduped.
func mergeGroups(gid int, extra []int) []int {
	out := make([]int, 0, len(extra)+1)
	out = append(out, gid)
	out = append(out, extra...)
	return sortDedup(out)
}

// sortDedup sorts ids in place and removes duplicates.
func sortDedup(out []int) []int {
	sort.Ints(out)
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

// Source values for Ident.Source.
const (
	SourcePasswd = "passwd"
	SourceNSS    = "nss-helper"
	SourceCache  = "cache"
)

// User returns the name for uid, or "" when unknown.
func (m *Map) User(uid int) string { return m.load().uidToName[uid] }

// Group returns the group name for gid, or "" when unknown.
func (m *Map) Group(gid int) string { return m.load().gidToGroup[gid].Name }

// GroupGID returns the gid of the named group and whether it exists. The name
// is matched exactly first, then case-insensitively.
func (m *Map) GroupGID(name string) (int, bool) {
	s := m.load()
	if gid, ok := s.nameToGID[name]; ok {
		return gid, true
	}
	gid, ok := s.foldToGID[strings.ToLower(name)]
	return gid, ok
}

// Users returns every passwd entry, in file order, with group sets filled in.
func (m *Map) Users() []Ident {
	s := m.load()
	out := make([]Ident, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u.clone())
	}
	return out
}

// Groups returns every group entry, in file order.
func (m *Map) Groups() []Group {
	s := m.load()
	out := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g.clone())
	}
	return out
}

// GroupsOf returns the group set of name from the files alone: every group
// whose member list contains name, plus the primary gid from passwd when the
// user is local. Sorted and deduped; nil when nothing is known.
func (m *Map) GroupsOf(name string) []int {
	s := m.load()
	extra := s.memberOf[name]
	if e, ok := s.byName[name]; ok {
		return mergeGroups(e.gid, extra)
	}
	if len(extra) == 0 {
		return nil
	}
	cp := make([]int, len(extra))
	copy(cp, extra)
	return sortDedup(cp)
}

// LookupUser resolves name from /etc/passwd and /etc/group only.
func (m *Map) LookupUser(name string) (Ident, error) {
	s := m.load()
	e, ok := s.byName[name]
	if !ok {
		return Ident{}, fmt.Errorf("%w: %q not in %s", ErrNotFound, name, m.passwdPath)
	}
	return Ident{
		Name:   e.name,
		UID:    e.uid,
		GID:    e.gid,
		Groups: mergeGroups(e.gid, s.memberOf[e.name]),
		Home:   e.home,
		Source: SourcePasswd,
	}, nil
}

// runHelper executes one helper with its own 3 s deadline.
func (m *Map) runHelper(ctx context.Context, name string, args ...string) ([]byte, error) {
	run := m.Exec
	if run == nil {
		run = defaultExec
	}
	cctx, cancel := context.WithTimeout(ctx, nssTimeout)
	defer cancel()
	return run(cctx, name, args...)
}

// LookupNSS resolves a user that is not in /etc/passwd by executing helper
// programs once: getent passwd <name> when available, otherwise id -u and
// id -g, and then id -G for supplementary groups. No shell is used and the
// name is validated first. When id -G is unavailable the identity is returned
// with only the primary group and Partial set, so the UI can say so out loud.
//
// The lookup is bound to the name throughout. An all-digit name is never
// handed to a helper, because both getent(1) and id(1) would treat it as a uid
// and answer for whoever owns that uid; it resolves only when /etc/passwd
// lists that exact name, and otherwise fails with ErrNumericName. Every helper
// answer that carries a passwd name field must repeat the requested name byte
// for byte, or the lookup fails with ErrNameMismatch.
func (m *Map) LookupNSS(ctx context.Context, name string) (Ident, error) {
	if !ValidName(name) {
		return Ident{}, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	if isNumericName(name) {
		// /etc/passwd is keyed by name, so a local user really called "1000"
		// is still resolvable; the helpers are not asked.
		if local, lerr := m.LookupUser(name); lerr == nil {
			return local, nil
		}
		return Ident{}, fmt.Errorf("%w: %q would be read as a uid by getent and id", ErrNumericName, name)
	}

	id := Ident{Name: name, Source: SourceNSS}
	haveUID := false

	// Preferred: one getent call gives uid, gid and home together. The answer
	// counts only when its name field is the name we asked for.
	if out, err := m.runHelper(ctx, "getent", "passwd", name); err == nil {
		e, match, other := passwdEntFor(out, name)
		switch {
		case match:
			id.UID, id.GID, id.Home = e.uid, e.gid, e.home
			haveUID = true
		case other:
			return Ident{}, fmt.Errorf("%w: getent passwd %s answered for %q", ErrNameMismatch, name, e.name)
		}
	}

	if !haveUID {
		out, err := m.runHelper(ctx, "id", "-u", name)
		if err != nil {
			return Ident{}, fmt.Errorf("idmap: id -u %s: %w", name, err)
		}
		uid, ok := singleNumber(out)
		if !ok {
			return Ident{}, fmt.Errorf("%w: id -u %s", ErrBadOutput, name)
		}
		// Cross-check the uid against getent where getent exists: if that uid
		// belongs to a different passwd name, the identity is ambiguous and is
		// refused rather than issued.
		if cout, cerr := m.runHelper(ctx, "getent", "passwd", strconv.Itoa(uid)); cerr == nil {
			if e, ok := firstPasswdEnt(cout); ok && e.name != name {
				return Ident{}, fmt.Errorf("%w: id -u %s gave uid %d, which getent maps to %q", ErrNameMismatch, name, uid, e.name)
			}
		}
		out, err = m.runHelper(ctx, "id", "-g", name)
		if err != nil {
			return Ident{}, fmt.Errorf("idmap: id -g %s: %w", name, err)
		}
		gid, ok := singleNumber(out)
		if !ok {
			return Ident{}, fmt.Errorf("%w: id -g %s", ErrBadOutput, name)
		}
		id.UID, id.GID = uid, gid
	}

	// Supplementary groups. Missing or unparseable output is not fatal.
	out, err := m.runHelper(ctx, "id", "-G", name)
	if err != nil {
		id.Groups = mergeGroups(id.GID, nil)
		id.Partial = true
		return id, nil
	}
	gids, ok := numberList(out)
	if !ok {
		id.Groups = mergeGroups(id.GID, nil)
		id.Partial = true
		return id, nil
	}
	id.Groups = mergeGroups(id.GID, gids)
	return id, nil
}

// isNumericName reports whether name consists only of decimal digits, i.e.
// whether getent(1) and id(1) would take it for a uid rather than a name.
func isNumericName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// parsePasswdRow parses one passwd-format row, rejecting comments, NIS compat
// lines, short rows and non-numeric ids.
func parsePasswdRow(line string) (passwdEnt, bool) {
	if skipLine(line) {
		return passwdEnt{}, false
	}
	f := strings.Split(line, ":")
	if len(f) < 6 || f[0] == "" {
		return passwdEnt{}, false
	}
	uid, ok := atoiStrict(f[2])
	if !ok {
		return passwdEnt{}, false
	}
	gid, ok := atoiStrict(f[3])
	if !ok {
		return passwdEnt{}, false
	}
	return passwdEnt{name: f[0], uid: uid, gid: gid, home: f[5]}, true
}

// firstPasswdEnt parses the first usable row of getent passwd output.
func firstPasswdEnt(out []byte) (passwdEnt, bool) {
	for _, line := range lines(out) {
		if e, ok := parsePasswdRow(line); ok {
			return e, true
		}
	}
	return passwdEnt{}, false
}

// passwdEntFor picks the row of getent passwd output that belongs to want.
// match is true when a row names want exactly. When no row does but rows were
// parsed, the first of them is returned with other true, so the caller can
// refuse an answer about somebody else instead of silently adopting it.
func passwdEntFor(out []byte, want string) (ent passwdEnt, match, other bool) {
	for _, line := range lines(out) {
		e, ok := parsePasswdRow(line)
		if !ok {
			continue
		}
		if e.name == want {
			return e, true, false
		}
		if !other {
			ent, other = e, true
		}
	}
	return ent, false, other
}

// singleNumber requires the output to be exactly one all-numeric token.
func singleNumber(out []byte) (int, bool) {
	f := strings.Fields(string(out))
	if len(f) != 1 {
		return 0, false
	}
	return atoiStrict(f[0])
}

// numberList requires every whitespace-separated token to be all-numeric.
func numberList(out []byte) ([]int, bool) {
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return nil, false
	}
	ids := make([]int, 0, len(f))
	for _, tok := range f {
		n, ok := atoiStrict(tok)
		if !ok {
			return nil, false
		}
		ids = append(ids, n)
	}
	return ids, true
}

// Resolve looks name up in /etc/passwd first and falls back to the NSS
// helpers. It never invents root: an NSS answer of uid 0 for a name the passwd
// file does not also map to uid 0 is refused. An all-digit name that passwd
// does not list is refused as well (ErrNumericName), and a helper answer that
// names another user is refused (ErrNameMismatch).
func (m *Map) Resolve(ctx context.Context, name string) (Ident, error) {
	if id, err := m.LookupUser(name); err == nil {
		return id, nil
	}
	return m.resolveNSS(ctx, name)
}

// resolveNSS is LookupNSS plus the fail-closed root check.
func (m *Map) resolveNSS(ctx context.Context, name string) (Ident, error) {
	id, err := m.LookupNSS(ctx, name)
	if err != nil {
		return Ident{}, err
	}
	if id.UID == 0 {
		if local, lerr := m.LookupUser(name); lerr != nil || local.UID != 0 {
			return Ident{}, fmt.Errorf("%w: %q", ErrRootRefused, name)
		}
	}
	return id, nil
}

// Cache is a session-scoped cache in front of a Map's NSS path. Local passwd
// users are never cached: reading them is cheap and the files reload on change.
// Entries expire ttl after their last use.
type Cache struct {
	m   *Map
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]*cacheEnt
}

type cacheEnt struct {
	id   Ident
	used time.Time
}

// NewCache returns a Cache over m. A ttl of zero or less selects
// DefaultCacheTTL.
func NewCache(m *Map, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{m: m, ttl: ttl, entries: map[string]*cacheEnt{}}
}

// TTL reports the cache lifetime.
func (c *Cache) TTL() time.Duration { return c.ttl }

// Resolve is Map.Resolve with the NSS result cached for the session. A cache
// hit is returned with Source "cache".
func (c *Cache) Resolve(ctx context.Context, name string) (Ident, error) {
	if id, err := c.m.LookupUser(name); err == nil {
		return id, nil
	}
	now := time.Now()

	c.mu.Lock()
	c.pruneLocked(now)
	if e, ok := c.entries[name]; ok {
		e.used = now
		id := e.id.clone()
		c.mu.Unlock()
		id.Source = SourceCache
		return id, nil
	}
	c.mu.Unlock()

	id, err := c.m.resolveNSS(ctx, name)
	if err != nil {
		return Ident{}, err
	}

	c.mu.Lock()
	c.entries[name] = &cacheEnt{id: id.clone(), used: time.Now()}
	c.mu.Unlock()
	return id, nil
}

// Forget drops any cached entry for name, e.g. when a session ends.
func (c *Cache) Forget(name string) {
	c.mu.Lock()
	delete(c.entries, name)
	c.mu.Unlock()
}

// Len reports how many identities are currently cached.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(time.Now())
	return len(c.entries)
}

func (c *Cache) pruneLocked(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.used) > c.ttl {
			delete(c.entries, k)
		}
	}
}

// DecideAdmin combines QTS's own answer with local group membership.
//
// The local signal is uid 0 or membership of the group named "administrators".
// With requireBoth (the default, config auth.adminRequiresBoth) the two signals
// must agree; on disagreement the lower privilege is taken and note explains
// why, for the audit log, QuLog and /api/diag. Without requireBoth the QTS
// answer alone decides, but a disagreement still produces a note.
func DecideAdmin(qtsIsAdmin bool, id Ident, m *Map, requireBoth bool) (admin bool, note string) {
	local := IsLocalAdmin(id, m)
	switch {
	case qtsIsAdmin && local:
		return true, ""
	case qtsIsAdmin && !local:
		note = "QTS reports admin but the account is not in the " + AdminGroup + " group"
		return !requireBoth, note
	case !qtsIsAdmin && local:
		return false, "account is in " + AdminGroup + " but QTS did not report admin"
	default:
		return false, ""
	}
}

// IsLocalAdmin reports the local half of the admin decision: uid 0, or
// membership of the group named "administrators" as resolved through m.
func IsLocalAdmin(id Ident, m *Map) bool {
	if id.UID == 0 {
		return true
	}
	if m == nil {
		return false
	}
	gid, ok := m.GroupGID(AdminGroup)
	if !ok {
		return false
	}
	if id.HasGroup(gid) {
		return true
	}
	// Fall back to the member list, for an identity whose group set was not
	// enumerated (Partial) but whose name QTS still lists in the group.
	if id.Name == "" {
		return false
	}
	for _, g := range m.Groups() {
		if g.GID != gid {
			continue
		}
		for _, mem := range g.Members {
			if mem == id.Name {
				return true
			}
		}
	}
	return false
}
