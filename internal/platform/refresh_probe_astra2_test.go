package platform

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// The platform half of the gpt-6-astra M3 round-2 review (docs/reviews/
// m3-astra-round2.md): findings 7, 13 and 14. All three are about WHEN and over
// WHICH row the ACL probe runs — never about what the probe itself answers,
// which is the kernel's business and is asked of it on the NAS (INV-2).

// gatedProbe is probeSeams with a gate: the xattr probe announces that it has
// been entered and then blocks until release is called, so a test can look at
// the world — and change it — while a probe pass is genuinely in flight.
type gatedProbe struct {
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once

	mu       sync.Mutex
	probed   []string
	datasets []string
}

func gatedSeams(p *Platform) *gatedProbe {
	g := &gatedProbe{gate: make(chan struct{}), entered: make(chan struct{})}
	p.SetXattrProbe(func(path, name string) (int, error) {
		g.mu.Lock()
		select {
		case <-g.entered:
		default:
			close(g.entered)
		}
		g.mu.Unlock()
		<-g.gate
		g.mu.Lock()
		if name == XattrNFS4ACL {
			g.probed = append(g.probed, path)
		}
		g.mu.Unlock()
		if name == XattrNFS4ACL {
			return 88, nil
		}
		return 0, ErrNotSupported
	})
	p.SetCommandRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		g.mu.Lock()
		g.datasets = append(g.datasets, args[len(args)-1])
		g.mu.Unlock()
		return []byte("discard\n"), nil
	})
	return g
}

func (g *gatedProbe) release() { g.once.Do(func() { close(g.gate) }) }

// awaitEntry blocks until a probe has actually reached the seam, so that a test
// which mutates the mount table mid-probe is mutating it mid-probe.
func (g *gatedProbe) awaitEntry(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no probe reached the seam")
	}
}

func (g *gatedProbe) xattr() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.probed...)
}

func (g *gatedProbe) zfs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.datasets...)
}

// awaitProbe waits for the background pass a test started, with a bound so a
// latch that is never cleared fails the test instead of hanging the package.
func awaitProbe(t *testing.T, p *Platform) {
	t.Helper()
	done := p.probeInFlight()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the background probe never finished")
	}
}

func table(t *testing.T, lines string) []Mount {
	t.Helper()
	mounts, err := ParseMountinfo(strings.NewReader(lines))
	if err != nil {
		t.Fatal(err)
	}
	return mounts
}

// --- finding 7: the probe is off the request path --------------------------------

// TestKickProbeDoesNotBlockTheCaller is finding 7 at its source. probeMissing
// ran inside Refresh, Refresh is reached from maybeRefresh, and maybeRefresh is
// reached from every For() a request makes: a pool that mounted sixteen datasets
// at once put sixteen `zfs get` timeouts — up to 48 s — inside a handler with a
// 15 s budget and no way to cancel them. What the request sees now is the
// unprobed answer, which the ACL ladder grades as the worst case.
func TestKickProbeDoesNotBlockTheCaller(t *testing.T) {
	p := newPlatform()
	p.setMounts(table(t, "70 30 0:70 / /share/ZFS530_DATA/New rw,relatime - zfs zpool1/new rw\n"))
	g := gatedSeams(p)
	defer g.release()

	p.kickProbe() // returns while the probe is still blocked in the seam
	g.awaitEntry(t)
	if c := p.For("/share/ZFS530_DATA/New"); c.ACLBackend != "" {
		t.Fatalf("backend %q: the caller waited for the probe", c.ACLBackend)
	}
	if got := len(g.xattr()); got != 0 {
		t.Fatalf("%d probes completed before the gate opened", got)
	}

	g.release()
	awaitProbe(t, p)
	c := p.For("/share/ZFS530_DATA/New")
	if c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "discard" {
		t.Fatalf("the probed answer never landed: %+v", c)
	}
	if got := g.zfs(); len(got) != 1 || got[0] != "zpool1/new" {
		t.Fatalf("zfs get asked about %v", got)
	}
}

// TestKickProbeIsSingleFlight: the request path calls Refresh, so a second
// caller arriving while a pass is running must join it rather than start
// another. Fifty requests against a table with fifty new datasets would
// otherwise be fifty goroutines running the same `zfs get` invocations.
func TestKickProbeIsSingleFlight(t *testing.T) {
	p := newPlatform()
	p.setMounts(table(t,
		"70 30 0:70 / /share/ZFS530_DATA/A rw,relatime - zfs zpool1/a rw\n"+
			"71 30 0:71 / /share/ZFS530_DATA/B rw,relatime - zfs zpool1/b rw\n"))
	g := gatedSeams(p)
	defer g.release()

	p.kickProbe()
	g.awaitEntry(t)
	first := p.probeInFlight()
	if first == nil {
		t.Fatal("no pass was started")
	}
	p.kickProbe()
	if second := p.probeInFlight(); second != first {
		t.Fatal("a second pass started while the first was still running")
	}

	g.release()
	awaitProbe(t, p)
	if got := len(g.xattr()); got != 2 {
		t.Fatalf("%d mounts probed, want 2 — once each", got)
	}
	// And with nothing left to probe, a kick starts nothing at all.
	p.kickProbe()
	if p.probeInFlight() != nil {
		t.Fatal("a pass was started for a table with nothing missing")
	}
}

// --- finding 13: the visible row, and only while it is still there ---------------

// TestProbeTakesTheVisibleRowOfAStackedMount is finding 13. Two datasets stacked
// at one mount point are two mountinfo lines and one reachable filesystem: caps
// describes the LAST line, as the kernel does, but both lines used to be probed
// and the assignment was first-write-wins. The lower row therefore supplied the
// aclmode while the upper supplied the xattr answer — a passthrough hidden under
// a discard graded the discard's chmod as L1, and cached it.
func TestProbeTakesTheVisibleRowOfAStackedMount(t *testing.T) {
	const mp = "/share/ZFS530_DATA/Stacked"
	lines := "70 30 0:70 / " + mp + " rw,relatime - zfs zpool1/lower rw\n" +
		"71 30 0:71 / " + mp + " rw,relatime - zfs zpool1/upper rw\n"
	for _, tc := range []struct {
		name string
		pass func(p *Platform)
	}{
		{"the start-up pass", func(p *Platform) { p.Probe() }},
		{"the background pass", func(p *Platform) { p.probeMissing() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPlatform()
			p.setMounts(table(t, lines))
			var datasets []string
			var mu sync.Mutex
			p.SetXattrProbe(func(_, name string) (int, error) {
				if name == XattrNFS4ACL {
					return 88, nil
				}
				return 0, ErrNotSupported
			})
			p.SetCommandRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				dataset := args[len(args)-1]
				mu.Lock()
				datasets = append(datasets, dataset)
				mu.Unlock()
				if dataset == "zpool1/lower" {
					return []byte("passthrough\n"), nil
				}
				return []byte("discard\n"), nil
			})

			tc.pass(p)
			if c := p.For(mp); c.ZFSAclmode != "discard" {
				t.Fatalf("aclmode %q, want the VISIBLE dataset's: the answer came from the mount underneath", c.ZFSAclmode)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(datasets) != 1 || datasets[0] != "zpool1/upper" {
				t.Fatalf("zfs get asked about %v, want only the visible row", datasets)
			}
		})
	}
}

// TestAProbeOfAReplacedMountIsDiscarded is the other half of finding 13: a
// background pass outlives the table it started from. A `zfs get` with a 3 s
// timeout can still be running when the dataset it describes is unmounted and
// another takes its mount point, and publishing then would hand the replacement
// the previous filesystem's aclmode — cached, because a backend that is set is
// never probed again.
func TestAProbeOfAReplacedMountIsDiscarded(t *testing.T) {
	const mp = "/share/ZFS530_DATA/Swapped"
	p := newPlatform()
	p.setMounts(table(t, "70 30 0:70 / "+mp+" rw,relatime - zfs zpool1/before rw\n"))
	g := gatedSeams(p)
	defer g.release()

	p.kickProbe()
	g.awaitEntry(t) // the pass holds the OUTGOING row
	// The mount is replaced while the probe is in flight.
	p.setMounts(table(t, "81 30 0:81 / "+mp+" rw,relatime - zfs zpool1/after rw\n"))
	g.release()
	awaitProbe(t, p)

	if c := p.For(mp); c.ACLBackend != "" || c.ZFSAclmode != "" {
		t.Fatalf("caps %+v: the outgoing mount's probe was published onto its replacement", c)
	}
	// The replacement is simply unprobed, which every caller reads
	// pessimistically, and the next pass takes it.
	if len(p.pendingProbes()) != 1 {
		t.Fatalf("pending %v, want the replacement", p.pendingProbes())
	}
}

// TestProbedFieldsAreNotCarriedOntoADifferentMount: the same substitution across
// an ordinary refresh. setMounts used to carry the cached answers whenever the
// filesystem TYPE matched, so one zfs dataset replaced by another at the same
// path inherited its aclmode and was never probed again.
func TestProbedFieldsAreNotCarriedOntoADifferentMount(t *testing.T) {
	const mp = "/share/ZFS530_DATA/Swapped"
	p := newPlatform()
	p.setMounts(table(t, "70 30 0:70 / "+mp+" rw,relatime - zfs zpool1/before rw\n"))
	gatedSeams(p).release()
	p.probeMissing()
	if c := p.For(mp); c.ZFSAclmode != "discard" {
		t.Fatalf("the fixture never probed: %+v", c)
	}

	// The same row again: the answer is kept, which is what stops a refresh
	// every five seconds from re-probing the whole table.
	p.setMounts(table(t, "70 30 0:70 / "+mp+" rw,relatime - zfs zpool1/before rw\n"))
	if c := p.For(mp); c.ZFSAclmode != "discard" {
		t.Fatalf("a refresh of an unchanged table dropped the cached answer: %+v", c)
	}
	// A different mount at the same point: nothing is inherited.
	p.setMounts(table(t, "81 30 0:81 / "+mp+" rw,relatime - zfs zpool1/after rw\n"))
	if c := p.For(mp); c.ACLBackend != "" || c.ZFSAclmode != "" {
		t.Fatalf("caps %+v: the replacement inherited the previous dataset's answer", c)
	}
}

// --- finding 14: start-up probes once ---------------------------------------------

// TestStartUpProbesEachMountOnce is finding 14. Detect parsed the table through
// Refresh and then called Probe; once Refresh grew a probe of its own, every
// daemon AND every spawned worker paid for the first batch twice — four datasets
// at the `zfs get` timeout is 24 s of start-up, past workerpool's 20 s hello
// timeout, before the machine has answered a request. Detect now parses with the
// probing suppressed (refresh(false)) and probes exactly once, synchronously;
// the asynchronous pass is for later refreshes.
func TestStartUpProbesEachMountOnce(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")
	// A stacked row as well: one mount point is one probe, not one per line.
	p.setMounts(append(p.Mounts(),
		table(t, "99 40 0:99 / /share/ZFS530_DATA/Public rw,relatime - zfs zpool1/zfs530_data/Public_new rw\n")...))

	var mu sync.Mutex
	counts := map[string]int{}
	p.SetXattrProbe(func(path, name string) (int, error) {
		if name != XattrNFS4ACL {
			return 0, ErrNotSupported
		}
		mu.Lock()
		counts[path]++
		mu.Unlock()
		return 88, nil
	})
	var datasets []string
	p.SetCommandRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		mu.Lock()
		datasets = append(datasets, args[len(args)-1])
		mu.Unlock()
		return []byte("discard\n"), nil
	})

	// The Detect-shaped sequence: parse without probing, then one Probe.
	p.Probe()

	if p.probeInFlight() != nil {
		t.Fatal("start-up started a background pass as well as the synchronous one")
	}
	mu.Lock()
	for mp, n := range counts {
		if n != 1 {
			t.Fatalf("%s probed %d times in one start-up", mp, n)
		}
	}
	probed := len(counts)
	seen := map[string]bool{}
	for _, d := range datasets {
		if seen[d] {
			t.Fatalf("zfs get asked about %s twice", d)
		}
		seen[d] = true
	}
	mu.Unlock()
	if probed == 0 {
		t.Fatal("the fixture has no storage mounts to probe")
	}
	// And nothing is left over: the later, asynchronous path has no work after a
	// start-up that covered the table.
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending after start-up: %v", pending)
	}
	if c := p.For("/share/ZFS530_DATA/Public"); c.ACLBackend != ACLNFS4 {
		t.Fatalf("the visible row of the stacked mount is unprobed: %+v", c)
	}
}
