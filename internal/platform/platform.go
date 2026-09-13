package platform

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Family labels. The family is a label for diagnostics, the UI and the audit
// log only. No operation may branch on it (PLAN.md decision 8).
const (
	FamilyQTS     = "qts"
	FamilyHero    = "quts_hero"
	FamilyLinux   = "linux"
	FamilyUnknown = "unknown"
)

// mountinfoPath is the kernel table we parse on Linux.
const mountinfoPath = "/proc/self/mountinfo"

// uLinuxConfPath holds the QNAP firmware configuration.
const uLinuxConfPath = "/etc/config/uLinux.conf"

// refreshInterval is how long a parsed mount table is trusted before For()
// re-reads /proc on Linux.
const refreshInterval = 5 * time.Second

// zfsTimeout bounds the `zfs get` probe.
const zfsTimeout = 3 * time.Second

// Errors returned by the injectable xattr probe. The real Linux probe maps
// errno values onto these so that tests can simulate them on any OS.
var (
	// ErrNoData means the attribute name is supported by the filesystem but
	// not set on the file (ENODATA / ENOATTR).
	ErrNoData = errors.New("platform: attribute not set")
	// ErrNotSupported means the filesystem does not know the attribute
	// namespace at all (ENOTSUP / EOPNOTSUPP), or the OS has no xattrs.
	ErrNotSupported = errors.New("platform: extended attributes not supported")
)

// XattrProbe reads the size of an extended attribute. It returns ErrNoData
// when the attribute is supported but unset.
type XattrProbe func(path, name string) (int, error)

// CommandRunner executes a helper binary. It exists so that the `zfs` probe
// can be replaced in tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Platform is the mount table plus the (label-only) product identification.
// It is safe for concurrent use.
type Platform struct {
	Family   string // "qts" | "quts_hero" | "linux" | "unknown"
	Firmware string // e.g. "5.1.0" or "h5.1.0"; "" off-NAS

	mu     sync.RWMutex
	mounts []Mount
	caps   map[string]FSCaps // keyed by mount point
	order  []string          // mount points, longest first
	read   time.Time         // when the table was last parsed
	live   bool              // true when /proc/self/mountinfo is readable

	getxattr XattrProbe
	run      CommandRunner
}

// FromMountinfo builds a Platform from mountinfo data. It is pure: it performs
// no I/O beyond reading r, never refreshes, and is how the QuTS hero code
// paths are tested on Windows (PLAN.md decision 15).
func FromMountinfo(r io.Reader) (*Platform, error) {
	mounts, err := ParseMountinfo(r)
	if err != nil {
		return nil, err
	}
	p := newPlatform()
	p.setMounts(mounts)
	p.Family = FamilyUnknown
	return p, nil
}

func newPlatform() *Platform {
	return &Platform{
		Family:   FamilyUnknown,
		caps:     map[string]FSCaps{},
		getxattr: defaultGetxattr,
		run:      defaultRunner,
	}
}

// SetXattrProbe replaces the extended-attribute probe used by ACLBackendFor.
func (p *Platform) SetXattrProbe(fn XattrProbe) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if fn == nil {
		fn = defaultGetxattr
	}
	p.getxattr = fn
}

// SetCommandRunner replaces the helper-process runner used by ZFSAclmode.
func (p *Platform) SetCommandRunner(fn CommandRunner) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if fn == nil {
		fn = defaultRunner
	}
	p.run = fn
}

func (p *Platform) setMounts(mounts []Mount) {
	caps := make(map[string]FSCaps, len(mounts))
	for _, m := range mounts {
		// A later line at the same mount point over-mounts the earlier one.
		caps[m.MountPoint] = CapsFor(m)
	}
	order := make([]string, 0, len(caps))
	for mp := range caps {
		order = append(order, mp)
	}
	sort.Slice(order, func(i, j int) bool {
		if len(order[i]) != len(order[j]) {
			return len(order[i]) > len(order[j])
		}
		return order[i] < order[j]
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	// Carry probed fields across a refresh so we do not re-probe every 5 s.
	for mp, c := range caps {
		if old, ok := p.caps[mp]; ok && old.FSType == c.FSType {
			c.ACLBackend = old.ACLBackend
			c.ACLXattr = old.ACLXattr
			c.ZFSAclmode = old.ZFSAclmode
			caps[mp] = c
		}
	}
	p.mounts = mounts
	p.caps = caps
	p.order = order
	p.read = time.Now()
}

// Detect inspects the running system. On Linux it parses the mount table,
// reads the firmware version and looks for ZFS signals; everywhere else it
// returns an empty table with Family "unknown".
func Detect() *Platform {
	p := newPlatform()
	if runtime.GOOS != "linux" {
		p.Family = FamilyUnknown
		return p
	}
	p.live = true
	if err := p.Refresh(); err != nil {
		p.live = false
	}

	version, _ := GetCfg(uLinuxConfPath, "System", "Version")
	hasULinux := fileExists(uLinuxConfPath)
	hasSPL := fileExists("/proc/spl") || fileExists("/proc/spl/kstat/zfs")
	hasZFSBin := fileExists("/sbin/zfs") || fileExists("/usr/sbin/zfs")

	p.Firmware = version
	p.Family = deriveFamily(version, p.hasZFSMount(), hasSPL, hasZFSBin, hasULinux)
	p.Probe()
	return p
}

// deriveFamily maps the detection signals of identity plan §4.5 onto a label.
// The label is never a behavioural switch.
func deriveFamily(version string, hasZFSMount, hasSPL, hasZFSBin, hasULinux bool) string {
	heroVersion := strings.HasPrefix(strings.ToLower(strings.TrimSpace(version)), "h")
	switch {
	case hasULinux && (heroVersion || hasZFSMount):
		return FamilyHero
	case hasULinux:
		return FamilyQTS
	case hasZFSMount || hasSPL || hasZFSBin:
		// A plain Linux box with ZFS. Not a NAS: no uLinux.conf.
		return FamilyLinux
	default:
		return FamilyLinux
	}
}

func (p *Platform) hasZFSMount() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, m := range p.mounts {
		if strings.EqualFold(m.FSType, "zfs") {
			return true
		}
	}
	return false
}

// Refresh re-reads the mount table. It is a no-op when the table did not come
// from /proc (FromMountinfo, or a non-Linux host).
func (p *Platform) Refresh() error {
	p.mu.RLock()
	live := p.live
	p.mu.RUnlock()
	if !live {
		// A static table (FromMountinfo, or a host without /proc) is never
		// silently replaced by the running system's mounts.
		return nil
	}
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return err
	}
	defer f.Close()
	mounts, err := ParseMountinfo(bufio.NewReader(f))
	if err != nil {
		return err
	}
	p.setMounts(mounts)
	return nil
}

func (p *Platform) maybeRefresh() {
	p.mu.RLock()
	stale := p.live && time.Since(p.read) > refreshInterval
	p.mu.RUnlock()
	if !stale {
		return
	}
	// Refresh takes the write lock itself; a concurrent caller may refresh
	// twice at worst, which is harmless.
	_ = p.Refresh()
}

// Mounts returns a copy of the current mount table.
func (p *Platform) Mounts() []Mount {
	p.maybeRefresh()
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Mount, len(p.mounts))
	copy(out, p.mounts)
	return out
}

// For returns the capabilities of the mount that holds osPath, using a
// path-boundary aware longest-prefix match. "/" matches everything. An unknown
// or relative path yields the zero FSCaps, whose Storage is false, so callers
// that forget to check still get the safe answer.
func (p *Platform) For(osPath string) FSCaps {
	p.maybeRefresh()
	clean := normalizePath(osPath)
	if clean == "" {
		return FSCaps{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, mp := range p.order {
		if pathHasPrefix(clean, mp) {
			return p.caps[mp]
		}
	}
	return FSCaps{}
}

// ForLiteral is For without the normalisation: the longest mount point that is
// the path or a path-boundary prefix of it, matched byte for byte. It exists
// for the one question that must be answered before anything is resolved or
// stat'ed — "is this root inside a mount we must never touch?" (a dead hard NFS
// mount hangs any lookup) — where For's backslash-to-slash and Clean would let
// a Linux name such as "remote\backup" fall through to the enclosing local
// filesystem (M2-C review round 3). A spelling that is not already absolute
// and canonical matches only what it literally is, which is the safe answer:
// the caller then goes on to the descriptor-based checks.
func (p *Platform) ForLiteral(osPath string) (FSCaps, bool) {
	p.maybeRefresh()
	key := literalMountKey(osPath)
	if key == "" {
		return FSCaps{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, mp := range p.order {
		if pathHasPrefix(key, mp) {
			return p.caps[mp], true
		}
	}
	return FSCaps{}, false
}

// MountByLiteralPath returns the capabilities of the mount whose mount point is
// EXACTLY osPath, comparing the bytes the kernel wrote rather than a tidied-up
// spelling of them.
//
// It exists for one caller — the walk's pre-lstat mount check (fsops), which
// must decide "is this name a mount point" before it is allowed to touch the
// name at all — and the exactness is the whole point of it. Every other lookup
// here goes through normalizePath, which turns a backslash into a separator and
// then Cleans the result; on Linux a backslash is an ORDINARY CHARACTER in a
// filename, so a regular file called `..\export` normalises to "/export" and
// would be mistaken for a mount of that name, while a real mount point with a
// backslash in it would never match its own row. A check made before the item
// can be stat'ed cannot afford either mistake: the first hides a file from a
// delete, the second lets a walk reach the syscall it was supposed to avoid.
//
// The map keys are the mount points as mountinfo spells them, with the kernel's
// octal escapes already decoded (unescapeOctal), so an exact match against a
// path built the same way — a directory's own mount-table spelling plus one
// entry name — is a match on the kernel's own bytes. The normalisation off Linux
// stays, because there the caller's paths are the dev box's and not a kernel's
// (INV-2); literalMountKey is where that difference is stated.
func (p *Platform) MountByLiteralPath(osPath string) (FSCaps, bool) {
	key := literalMountKey(osPath)
	if key == "" {
		return FSCaps{}, false
	}
	p.maybeRefresh()
	p.mu.RLock()
	defer p.mu.RUnlock()
	c, ok := p.caps[key]
	return c, ok
}

// MountFor returns the mount holding osPath, or false when none matches.
func (p *Platform) MountFor(osPath string) (Mount, bool) {
	p.maybeRefresh()
	clean := normalizePath(osPath)
	if clean == "" {
		return Mount{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	best := -1
	for i, m := range p.mounts {
		if !pathHasPrefix(clean, m.MountPoint) {
			continue
		}
		// Longest wins; on ties the later line over-mounts the earlier.
		if best < 0 || len(m.MountPoint) >= len(p.mounts[best].MountPoint) {
			best = i
		}
	}
	if best < 0 {
		return Mount{}, false
	}
	return p.mounts[best], true
}

// MayCross reports whether a recursive operation that is walking a tree on
// "from" may descend into "to" (identity plan §4.2). It is the only crossing
// rule in the app.
func (p *Platform) MayCross(from, to FSCaps) bool {
	return to.Storage && !to.Network && to.Domain == from.Domain
}

// TrashRootFor returns the mount root under which a trash directory for
// osPath belongs (PLAN.md decision 10 / identity plan §4.2): the NEAREST
// enclosing mount, which must itself be a Storage, non-network filesystem. On
// QTS that is the volume (or bind-mounted share) root; on QuTS hero the share's
// own dataset root, next to @Recycle.
//
// It never climbs past the nearest mount to a Storage parent. The item's data
// lives on that nearest mount, so a rename into any parent would cross devices
// (EXDEV) — and for a pseudo-filesystem it would be wrong outright: nothing
// under /proc, /sys, /dev, a tmpfs RAM disk or a network mount is ever
// trashed, even on a QTS whose root filesystem is itself flash storage. In all
// those cases ok is false and the caller must treat the delete as permanent.
//
// It never touches the filesystem: it is a pure mount-table lookup, which is
// exactly why the root front-end (which creates the 1777 trash directory) and
// the user's worker (which renames into it) agree on the same root by
// construction.
func (p *Platform) TrashRootFor(osPath string) (mountRoot string, caps FSCaps, ok bool) {
	m, found := p.MountFor(osPath)
	if !found {
		return "", FSCaps{}, false
	}
	c := p.For(m.MountPoint)
	if !c.Storage || c.Network {
		return "", FSCaps{}, false
	}
	return m.MountPoint, c, true
}

// IsMountPointByTable reports whether osPath is a mount point according to the
// mount table alone. It touches the filesystem only to re-read
// /proc/self/mountinfo, and never resolves osPath: no stat, no symlink
// following, nothing the caller's own confinement did not already permit.
//
// This is the entry point for anything holding a path inside a jail. Its
// path-resolving sibling below is fine for a name the caller chose (a configured
// mount, a diagnostic) and wrong for one a user supplied: under -jail, a symlink
// inside the jail pointing at /proc would have IsMountPoint stat /proc and
// report what it found there, which is a lookup outside the jail however
// harmless the answer looks.
func (p *Platform) IsMountPointByTable(osPath string) bool {
	clean := normalizePath(osPath)
	if clean == "" {
		return false
	}
	p.maybeRefresh()
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.caps[clean]
	return ok
}

// IsMountPoint reports whether osPath is itself a mount point. The mount table
// is authoritative; on Linux a st_dev comparison against the parent catches
// mounts that appeared since the last refresh.
//
// The fallback resolves osPath by pathname and follows symlinks doing it, so a
// caller that got its path from a user must use IsMountPointByTable instead and
// compare devices through descriptors it already holds.
func (p *Platform) IsMountPoint(osPath string) bool {
	if p.IsMountPointByTable(osPath) {
		return true
	}
	clean := normalizePath(osPath)
	if clean == "" {
		return false
	}
	return mountProbe(clean)
}

// mountProbe is the stat fallback IsMountPoint uses. It is a variable so that a
// test can record whether the path-based probe was reached at all.
var mountProbe = statIsMountPoint

// VolumeRoots returns the storage mounts that are direct children of /share:
// the volume roots on QTS (CACHEDEV1_DATA), on QuTS hero (ZFS530_DATA) and on
// the legacy HDA_DATA layout, derived from the table with no pattern to
// maintain. The result is sorted by mount point.
func (p *Platform) VolumeRoots() []Mount {
	p.maybeRefresh()
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []Mount
	seen := map[string]bool{}
	for _, m := range p.mounts {
		if !IsStorageFS(m.FSType) {
			continue
		}
		if path.Dir(m.MountPoint) != "/share" || m.MountPoint == "/share" {
			continue
		}
		if seen[m.MountPoint] {
			continue
		}
		seen[m.MountPoint] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MountPoint < out[j].MountPoint })
	return out
}

// Probe fills in the per-mount ACL backend and, for ZFS, the dataset aclmode.
// It only touches storage mounts and is safe to call more than once.
func (p *Platform) Probe() {
	p.mu.RLock()
	mounts := make([]Mount, len(p.mounts))
	copy(mounts, p.mounts)
	p.mu.RUnlock()

	for _, m := range mounts {
		if !IsStorageFS(m.FSType) {
			continue
		}
		backend, xattr := p.aclBackend(m.MountPoint)
		aclmode := ""
		if strings.EqualFold(m.FSType, "zfs") {
			aclmode = p.ZFSAclmode(m.Source)
		}
		p.mu.Lock()
		if c, ok := p.caps[m.MountPoint]; ok {
			c.ACLBackend = backend
			c.ACLXattr = xattr
			c.ZFSAclmode = aclmode
			p.caps[m.MountPoint] = c
		}
		p.mu.Unlock()
	}
}

// ACLBackendFor probes the ACL backend of a mount root: "posix" when
// system.posix_acl_access is supported (present, or absent with ENODATA),
// "nfs4" when system.nfs4_acl or system.richacl answers the same way, and
// "none" otherwise. On Windows it is always "none".
func (p *Platform) ACLBackendFor(mountRoot string) string {
	backend, _ := p.aclBackend(mountRoot)
	return backend
}

func (p *Platform) aclBackend(mountRoot string) (backend, xattr string) {
	p.mu.RLock()
	probe := p.getxattr
	p.mu.RUnlock()
	if probe == nil {
		return ACLNone, ""
	}
	if xattrSupported(probe, mountRoot, XattrPosixACL) {
		return ACLPosix, XattrPosixACL
	}
	for _, name := range []string{XattrNFS4ACL, XattrRichACL} {
		if xattrSupported(probe, mountRoot, name) {
			return ACLNFS4, name
		}
	}
	return ACLNone, ""
}

// xattrSupported reports whether the filesystem understands the attribute
// name. A successful read and ENODATA both mean "supported"; ENOTSUP and every
// other error mean "not supported".
func xattrSupported(probe XattrProbe, path, name string) bool {
	_, err := probe(path, name)
	if err == nil {
		return true
	}
	return errors.Is(err, ErrNoData)
}

// ZFSAclmode returns the aclmode property of a ZFS dataset, or "" when it
// cannot be read. It never guesses: an unknown aclmode makes the UI show the
// pessimistic warning (identity plan §4.4).
func (p *Platform) ZFSAclmode(dataset string) string {
	if strings.TrimSpace(dataset) == "" {
		return ""
	}
	p.mu.RLock()
	run := p.run
	p.mu.RUnlock()
	if run == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), zfsTimeout)
	defer cancel()
	out, err := run(ctx, "zfs", "get", "-Hp", "-o", "value", "aclmode", dataset)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if i := strings.IndexAny(v, "\r\n"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" || v == "-" {
		return ""
	}
	return v
}

// Diag summarises the platform for /api/diag, so that a wrong answer in the
// field is diagnosable without SSH.
func (p *Platform) Diag() map[string]any {
	p.maybeRefresh()
	roots := p.VolumeRoots()
	p.mu.RLock()
	defer p.mu.RUnlock()

	mounts := make([]map[string]any, 0, len(p.mounts))
	acl := make(map[string]string, len(p.caps))
	for _, m := range p.mounts {
		c := p.caps[m.MountPoint]
		mounts = append(mounts, map[string]any{
			"mountPoint": m.MountPoint,
			"fsType":     m.FSType,
			"source":     m.Source,
			"dev":        m.Dev(),
			"root":       m.Root,
			"storage":    c.Storage,
			"network":    c.Network,
			"tmpfs":      c.Tmpfs,
			"domain":     c.Domain,
			"aclBackend": c.ACLBackend,
			"aclXattr":   c.ACLXattr,
			"zfsAclmode": c.ZFSAclmode,
		})
		if c.Storage {
			acl[m.MountPoint] = c.ACLBackend
		}
	}
	vols := make([]map[string]any, 0, len(roots))
	for _, m := range roots {
		c := p.caps[m.MountPoint]
		vols = append(vols, map[string]any{
			"mountPoint": m.MountPoint,
			"name":       path.Base(m.MountPoint),
			"label":      VolumeLabel(path.Base(m.MountPoint)),
			"fsType":     m.FSType,
			"source":     m.Source,
			"domain":     c.Domain,
		})
	}
	return map[string]any{
		"family":      p.Family,
		"firmware":    p.Firmware,
		"live":        p.live,
		"readAt":      p.read.UTC().Format(time.RFC3339),
		"mountCount":  len(p.mounts),
		"mounts":      mounts,
		"volumeRoots": vols,
		"aclBackends": acl,
	}
}

// GetCfg reads one key from a QNAP-style INI file, the pure-Go equivalent of
// `getcfg <section> <key> -f <path>`. Section and key match case-insensitively.
func GetCfg(path, section, key string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	inSection := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			inSection = strings.EqualFold(name, section)
			continue
		}
		if !inSection {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		return v, true
	}
	return "", false
}

// normalizePath turns an incoming path into the absolute slash form used by
// the mount table, or "" when it is not absolute.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	s := strings.ReplaceAll(p, `\`, "/")
	if !strings.HasPrefix(s, "/") {
		return ""
	}
	s = path.Clean(s)
	return s
}

// pathHasPrefix reports whether p is mp or lies underneath it, respecting path
// boundaries so that /share/Publication is not inside /share/Public.
func pathHasPrefix(p, mp string) bool {
	if mp == "/" {
		return true
	}
	if p == mp {
		return true
	}
	return strings.HasPrefix(p, mp+"/")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// defaultRunner executes a helper binary, preferring the absolute paths QNAP
// firmware uses before falling back to PATH.
func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin := name
	if !strings.ContainsAny(name, `/\`) {
		found := ""
		for _, cand := range []string{"/sbin/" + name, "/usr/sbin/" + name, "/usr/local/sbin/" + name} {
			if fileExists(cand) {
				found = cand
				break
			}
		}
		if found == "" {
			var err error
			if found, err = exec.LookPath(name); err != nil {
				return nil, err
			}
		}
		bin = found
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	return cmd.Output()
}
