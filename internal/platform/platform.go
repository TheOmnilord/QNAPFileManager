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

// openMountinfo opens the kernel's mount table, and newXattrProbe and
// newCommandRunner are the two syscall seams a freshly built Platform starts
// with. All three are variables so that the REAL start-up and refresh paths —
// Detect's sequence and refresh(), not Probe() and kickProbe() called by hand —
// can be driven over a synthetic table (Astra r3 #5).
//
// The instance setters (SetXattrProbe, SetCommandRunner) cannot reach the
// Platform Detect constructs for itself: by the time Detect returns it, the
// start-up probe has already run. A test that instead assembles the sequence
// itself proves nothing about the order Detect puts it in, which is exactly what
// round-2 #14 was about, so the tests take the whole path and these are the only
// places where the syscalls are replaced. Production never assigns to them.
var (
	openMountinfo                  = func() (io.ReadCloser, error) { return os.Open(mountinfoPath) }
	newXattrProbe    XattrProbe    = defaultGetxattr
	newCommandRunner CommandRunner = defaultRunner
)

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
	// incarnation counts, per mount point, how many distinct mounts have
	// occupied it. A row that survives a refresh unchanged keeps its number; one
	// that changes, disappears, or appears takes the next one, and the numbers
	// only ever go up. It is what an in-flight probe carries and checks before it
	// publishes (Astra r3 #10): comparing the mountinfo FIELDS cannot see a mount
	// that went away and came back between the probe and the publish, because
	// Linux reuses mount IDs and a remount of the same dataset repeats every
	// field the row has while its aclmode changes underneath.
	incarnation map[string]uint64
	nextInc     uint64
	// probeDone is the in-flight background probe pass, or nil when none is
	// running. It is the single-flight latch AND the way a test waits for the
	// pass it started: the channel is closed after the results are published.
	probeDone chan struct{}

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
		Family:      FamilyUnknown,
		caps:        map[string]FSCaps{},
		incarnation: map[string]uint64{},
		getxattr:    newXattrProbe,
		run:         newCommandRunner,
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
	// Carry probed fields across a refresh so we do not re-probe every 5 s — but
	// only for a mount point where the VISIBLE row is still the same mount (Astra
	// r2 #13). Matching on the filesystem type alone carried one dataset's
	// aclmode onto another that replaced it at the same path, which is the same
	// wrong answer the stacked-mount case gives and just as sticky, because a
	// cached answer is never probed again.
	previous := visibleRows(p.mounts)
	current := visibleRows(mounts)
	incarnation := make(map[string]uint64, len(caps))
	for mp, c := range caps {
		// The same mount still at that point keeps its incarnation, and with it
		// whatever was probed for it; anything else is a NEW incarnation, whose
		// number no earlier probe of that point can hold (Astra r3 #10).
		if n, ok := p.incarnation[mp]; ok && sameMountRow(previous[mp], current[mp]) {
			incarnation[mp] = n
		} else {
			p.nextInc++
			incarnation[mp] = p.nextInc
			continue
		}
		old, ok := p.caps[mp]
		if !ok {
			continue
		}
		c.ACLBackend = old.ACLBackend
		c.ACLXattr = old.ACLXattr
		c.ZFSAclmode = old.ZFSAclmode
		caps[mp] = c
	}
	p.mounts = mounts
	p.caps = caps
	p.incarnation = incarnation
	p.order = order
	p.read = time.Now()
}

// Detect inspects the running system. On Linux it parses the mount table,
// reads the firmware version and looks for ZFS signals; everywhere else it
// returns an empty table with Family "unknown".
func Detect() *Platform {
	if runtime.GOOS != "linux" {
		p := newPlatform()
		p.Family = FamilyUnknown
		return p
	}
	return detectLive()
}

// detectLive is Detect on a machine that has a kernel mount table: the start-up
// sequence itself, with only the GOOS gate left behind. It is separate so that
// the sequence — which is the thing round-2 #14 was about, and which builds its
// own Platform and so cannot be reached by the instance setters — is what the
// tests run, over the mountinfo and syscall seams (Astra r3 #5).
func detectLive() *Platform {
	p := newPlatform()
	p.live = true
	// Start-up parses the table and then probes it ONCE, synchronously (Astra r2
	// #14). The public Refresh kicks a background probe of what is new, and a
	// Detect that went through it would have every daemon and every spawned
	// worker probe the first batch of storage mounts twice — four datasets at the
	// `zfs get` timeout is 24 s of start-up, past workerpool's hello timeout,
	// before the machine has answered a single request.
	if err := p.refresh(false); err != nil {
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
//
// It returns as soon as the table is parsed. A mount that appeared since the
// last read carries no probed fields at all — setMounts can only carry them
// across for mount points it already knew — and an unprobed storage mount is
// exactly the dataset an operator is about to change permissions on (Astra M3
// round-1 finding 1), so the new ones are probed; but the probing happens in the
// BACKGROUND (Astra r2 #7). Refresh is reached from maybeRefresh on the request
// path, a probe is an lgetxattr plus a `zfs get` with a 3 s timeout, and a batch
// of sixteen of them is 48 s inside a 15 s handler that cannot cancel it. Until
// the answer lands the mount's backend stays "", which the ACL ladder already
// grades as the worst case — so the gap is pessimistic, not silent.
func (p *Platform) Refresh() error { return p.refresh(true) }

// refresh is Refresh with the probing decision made by the caller: start-up
// probes synchronously and exactly once (Detect), every later refresh kicks the
// background pass.
func (p *Platform) refresh(probe bool) error {
	p.mu.RLock()
	live := p.live
	p.mu.RUnlock()
	if !live {
		// A static table (FromMountinfo, or a host without /proc) is never
		// silently replaced by the running system's mounts.
		return nil
	}
	f, err := openMountinfo()
	if err != nil {
		return err
	}
	defer f.Close()
	mounts, err := ParseMountinfo(bufio.NewReader(f))
	if err != nil {
		return err
	}
	p.setMounts(mounts)
	if probe {
		p.kickProbe()
	}
	return nil
}

// kickProbe starts ONE background pass over the storage mounts that have never
// been probed, and does nothing at all when a pass is already running or when
// there is nothing to probe. Single flight matters for more than the wasted
// syscalls: every For() on the request path reaches maybeRefresh, so a table
// with fifty new datasets would otherwise start a goroutine per request, each
// running the same `zfs get` invocations against the same pool.
//
// The pass that is already running will not see mounts that appeared after it
// took its batch. That is the next refresh's work, and the unprobed-is-
// pessimistic rule covers the gap.
func (p *Platform) kickProbe() {
	p.mu.Lock()
	if p.probeDone != nil || len(p.pendingProbesLocked()) == 0 {
		p.mu.Unlock()
		return
	}
	done := make(chan struct{})
	p.probeDone = done
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			p.probeDone = nil
			p.mu.Unlock()
			// Closed last, so a waiter that sees the pass finished sees the latch
			// cleared and the results published too.
			close(done)
		}()
		p.probeMissing()
	}()
}

// probeInFlight returns the channel the running background probe closes when it
// finishes, or nil when no pass is running. It is how the tests wait for a pass
// they caused without polling, and how they tell one pass from two.
func (p *Platform) probeInFlight() <-chan struct{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.probeDone
}

// maxProbesPerRefresh bounds what one refresh may spend on newly appeared
// mounts. A probe is an lgetxattr plus, on ZFS, a `zfs get` with its own
// timeout, and a pool can present a dataset per share and per sub-folder — so a
// storage server that mounts fifty datasets at once must not make the next
// For() wait for fifty `zfs get` invocations. What is left over is simply not
// probed yet: its ACLBackend stays "", which every caller reads pessimistically,
// and the next refresh takes the next batch.
const maxProbesPerRefresh = 16

// probeMissing fills in the ACL backend (and, on ZFS, the aclmode) of storage
// mounts that have never been probed. It is Probe restricted to what is
// missing, so a refresh costs nothing at all on the ordinary case where the
// table did not change. It is the body of the background pass and it holds no
// lock across the syscalls.
func (p *Platform) probeMissing() {
	for _, t := range p.pendingProbes() {
		backend, xattr, aclmode := p.probeOne(t.mount)
		p.publishProbe(t, backend, xattr, aclmode, false)
	}
}

// probeOne asks the kernel about one mount. It holds no lock: an lgetxattr and a
// `zfs get` with its own timeout are not things to hold a table lock across.
func (p *Platform) probeOne(m Mount) (backend, xattr, aclmode string) {
	backend, xattr = p.aclBackend(m.MountPoint)
	if strings.EqualFold(m.FSType, "zfs") {
		aclmode = p.ZFSAclmode(m.Source)
	}
	return backend, xattr, aclmode
}

// probeTarget is one row to probe together with the incarnation its mount point
// had when the row was chosen. The pair is what makes a published answer
// provably about the filesystem that was asked (Astra r3 #10).
type probeTarget struct {
	mount Mount
	inc   uint64
}

// pendingProbes picks what one pass probes: the VISIBLE row at each mount point
// whose capabilities carry no backend yet, bounded by maxProbesPerRefresh.
//
// Visible is the point of it (Astra r2 #13). Two datasets stacked at the same
// mount point are two mountinfo lines and one reachable filesystem, and caps —
// like the kernel — describes the last line. Probing both put the lower row's
// `zfs get` answer beside the upper row's xattr answer under a first-write-wins
// assignment, so a passthrough dataset hidden under a discard one graded the
// discard's chmod as L1 and cached that for as long as the mount lived.
func (p *Platform) pendingProbes() []probeTarget {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pendingProbesLocked()
}

func (p *Platform) pendingProbesLocked() []probeTarget {
	visible := visibleRows(p.mounts)
	var pending []probeTarget
	seen := make(map[string]bool, len(visible))
	for _, row := range p.mounts {
		mp := row.MountPoint
		if seen[mp] {
			continue
		}
		seen[mp] = true
		m := visible[mp]
		if !IsStorageFS(m.FSType) {
			continue
		}
		if c, ok := p.caps[mp]; ok && c.ACLBackend != "" {
			continue // already probed, and the answer is cached
		}
		pending = append(pending, probeTarget{mount: m, inc: p.incarnation[mp]})
		if len(pending) >= maxProbesPerRefresh {
			break
		}
	}
	return pending
}

// publishProbe stores one probe's answer, if the mount it describes is still
// the one at that mount point — the same mount, and the same INCARNATION of it.
//
// A probe outlives the table it was started from: a mount can be unmounted, or
// replaced by another at the same path, while its `zfs get` is still running.
// Publishing regardless would give the replacement the previous filesystem's
// aclmode and cache it, which is the stacked-mount bug arriving a second way
// (Astra r2 #13). An answer that no longer describes anything is dropped, and the
// mount that IS there stays unprobed until the next pass takes it.
//
// Comparing the row's fields is not enough on its own (Astra r3 #10). The fields
// are the mount ID, the device, the source, the type and the in-filesystem root,
// and a dataset that is unmounted and mounted again repeats every one of them —
// Linux hands mount IDs back out — while `zfs set aclmode=discard` in between
// changes the only thing the probe went to find. That is an A-B-A, and the
// incarnation counter is what sees it: the number the probe captured when it
// took the row is not the number the mount point carries now.
//
// overwrite distinguishes the two callers: the start-up pass (Probe) states the
// answer for every storage mount, and the background pass fills in only what has
// none, so that a refresh every five seconds costs nothing on a table that did
// not change.
func (p *Platform) publishProbe(t probeTarget, backend, xattr, aclmode string, overwrite bool) {
	m := t.mount
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.incarnation[m.MountPoint] != t.inc {
		return
	}
	if !sameMountRow(visibleRows(p.mounts)[m.MountPoint], m) {
		return
	}
	c, ok := p.caps[m.MountPoint]
	if !ok || (!overwrite && c.ACLBackend != "") {
		return
	}
	c.ACLBackend = backend
	c.ACLXattr = xattr
	c.ZFSAclmode = aclmode
	p.caps[m.MountPoint] = c
}

// visibleRows indexes a mount table by mount point, keeping the row the kernel
// makes reachable: the LAST line for that path, which over-mounts the ones
// before it. It is the same rule setMounts applies when it builds caps, stated
// once so the probe and the capabilities cannot disagree about which filesystem
// a mount point is.
func visibleRows(mounts []Mount) map[string]Mount {
	out := make(map[string]Mount, len(mounts))
	for _, m := range mounts {
		out[m.MountPoint] = m
	}
	return out
}

// sameMountRow reports whether two mountinfo rows are the same mount. The mount
// ID is the kernel's own identity for it and is not reused while the mount
// lives; the device numbers, source, type and in-filesystem root are compared
// as well, so a table from a kernel that does not keep IDs stable still has to
// describe the same filesystem for an answer to be kept.
func sameMountRow(a, b Mount) bool {
	return a.ID == b.ID && a.Major == b.Major && a.Minor == b.Minor &&
		a.Root == b.Root && a.MountPoint == b.MountPoint &&
		a.FSType == b.FSType && a.Source == b.Source
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

// Live reports whether this table came from the running kernel
// (/proc/self/mountinfo) rather than from a static one built by FromMountinfo —
// the golden QTS and hero tables, and the tests (PLAN.md decision 15).
//
// Only a live table's mount IDs are the numbers statx reports as STATX_MNT_ID,
// so only on a live table may a worker's reported mount ID be compared with a
// row of this one; a static table's IDs are the fixture's. Diag publishes the
// same fact, but Diag copies the whole table, and this is asked per request.
func (p *Platform) Live() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.live
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

// MountForLiteral is MountFor without the normalisation, the companion of
// ForLiteral: the longest mount point that is the path or a path-boundary
// prefix of it, matched byte for byte.
//
// It exists because the two halves of one answer must come from the same
// lookup. A caller that took FSCaps from ForLiteral and the dataset name from
// MountFor could be told the aclmode of the filesystem the bytes really live on
// and the NAME of a sibling that normalisation walked to — which is a sentence
// naming the wrong dataset in a dialog about destroying an ACL.
func (p *Platform) MountForLiteral(osPath string) (Mount, bool) {
	p.maybeRefresh()
	key := literalMountKey(osPath)
	if key == "" {
		return Mount{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	best := -1
	for i, m := range p.mounts {
		if !pathHasPrefix(key, m.MountPoint) {
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
// It only touches storage mounts and is safe to call more than once. It is the
// synchronous start-up pass; later refreshes probe what is new in the
// background (kickProbe).
//
// One row per mount point, the visible one (Astra r2 #13): probing a shadowed
// dataset costs a `zfs get` for an answer about a filesystem nothing can reach,
// and it used to race the visible row's answer into caps.
func (p *Platform) Probe() {
	p.mu.RLock()
	visible := visibleRows(p.mounts)
	targets := make([]probeTarget, 0, len(visible))
	seen := make(map[string]bool, len(visible))
	for _, row := range p.mounts {
		if seen[row.MountPoint] {
			continue
		}
		seen[row.MountPoint] = true
		m := visible[row.MountPoint]
		if !IsStorageFS(m.FSType) {
			continue
		}
		targets = append(targets, probeTarget{mount: m, inc: p.incarnation[m.MountPoint]})
	}
	p.mu.RUnlock()

	for _, t := range targets {
		backend, xattr, aclmode := p.probeOne(t.mount)
		// Overwriting, because Probe states the answer rather than filling a gap —
		// but still only onto the mount it asked about (Astra r2 #13, r3 #10).
		p.publishProbe(t, backend, xattr, aclmode, true)
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
