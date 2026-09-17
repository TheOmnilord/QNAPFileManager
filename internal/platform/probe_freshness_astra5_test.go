package platform

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The platform half of the gpt-6-astra M3 round-5 review (docs/reviews/
// m3-astra-round5.md): findings 2 and 3. Round 4 gave a probed fact a freshness
// bound; both findings are about what the bound actually delivered. Expiry only
// queued work — the expired answer kept being handed out until the queue reached
// it — and the queue was taken from the head of the mount table, so with more
// mounts than one pass can hold the head was re-probed for ever and the tail never
// at all.

// datasetRows builds n ZFS rows, one dataset per mount point, in table order. The
// names sort in that order too, which is what lets a test state exactly which
// sixteen a pass should have taken.
func datasetRows(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%d 30 0:%d / /share/ZFS530_DATA/D%02d rw,relatime - zfs zpool1/d%02d rw\n",
			100+i, 100+i, i, i)
	}
	return b.String()
}

func datasetMount(i int) string { return fmt.Sprintf("/share/ZFS530_DATA/D%02d", i) }

// instantSeams answers both probes without blocking and records every mount point
// the xattr probe was asked about, in order. delay is the per-probe cost — zero
// for the selection tests, a real one for the starvation test, where the point is
// that a pass takes longer than the facts stay fresh.
func instantSeams(p *Platform, delay time.Duration) (probed func() []string, reset func()) {
	var mu sync.Mutex
	var seen []string
	p.SetXattrProbe(func(path, name string) (int, error) {
		if delay > 0 {
			time.Sleep(delay)
		}
		if name != XattrNFS4ACL {
			return 0, ErrNotSupported
		}
		mu.Lock()
		seen = append(seen, path)
		mu.Unlock()
		return 88, nil
	})
	p.SetCommandRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("discard\n"), nil
	})
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), seen...)
		}, func() {
			mu.Lock()
			seen = nil
			mu.Unlock()
		}
}

func pendingPoints(targets []probeTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.mount.MountPoint)
	}
	return out
}

// --- finding 2: an expired fact is masked at the lookup, not merely queued ------

// TestAnExpiredAclmodeIsUnknownUntilTheReprobePublishes is the finding. The pass
// that would refresh the answer is held in the gate — which is every real reason a
// pass is late: another pass holds the single-flight latch, the sixteen-per-pass
// bound put this mount behind others, or the pool's own `zfs get` is wedged for its
// full timeout. While it is held, a lookup may not keep handing out the fact that
// has just been declared too old to trust: the aclmode reads unknown, which §7
// grades as discard, and the answer is honest again the moment the probe lands.
func TestAnExpiredAclmodeIsUnknownUntilTheReprobePublishes(t *testing.T) {
	const mp = "/share/ZFS530_DATA/A"
	p := newPlatform()
	p.setMounts(table(t, liveDatasetRow))

	// The start-up answer, taken through the ordinary synchronous pass.
	p.SetXattrProbe(func(_, name string) (int, error) {
		if name == XattrNFS4ACL {
			return 88, nil
		}
		return 0, ErrNotSupported
	})
	p.SetCommandRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("passthrough\n"), nil
	})
	p.Probe()
	if c, ok := p.ForLiteral(mp); !ok || c.ZFSAclmode != "passthrough" {
		t.Fatalf("caps %+v ok %v, want the probed passthrough; this test proves nothing", c, ok)
	}

	// A minute passes, and the world changed inside it: `zfs set aclmode=discard`,
	// which the gated seams are what the re-probe will find.
	g := gatedSeams(p)
	ageProbes(p, defaultProbeTTL+time.Second)

	p.kickProbe()
	g.awaitEntry(t)
	// The pass is in flight and blocked. This is the window the finding is about.
	c, ok := p.ForLiteral(mp)
	if !ok {
		t.Fatal("ForLiteral lost the row")
	}
	if c.ZFSAclmode != "" {
		t.Fatalf("aclmode %q while the re-probe is blocked: the expired answer is still being stated", c.ZFSAclmode)
	}
	if c.ACLBackend != ACLNFS4 {
		t.Fatalf("backend %q: the backend is not the destructive fact and is not masked with it", c.ACLBackend)
	}
	// For and MountByLiteralPath are the same lookup by another spelling, and one
	// caller may not be told what another is no longer allowed to state.
	if got := p.For(mp + "/file.txt").ZFSAclmode; got != "" {
		t.Fatalf("For reported %q: the mask is per lookup, not per caller", got)
	}
	if c, ok := p.MountByLiteralPath(mp); !ok || c.ZFSAclmode != "" {
		t.Fatalf("MountByLiteralPath reported %+v ok %v, want the same masked answer", c, ok)
	}

	g.release()
	awaitProbe(t, p)
	if c, ok := p.ForLiteral(mp); !ok || c.ZFSAclmode != "discard" {
		t.Fatalf("caps %+v ok %v, want the re-probed discard once the pass has published", c, ok)
	}
}

// TestAFreshAclmodeIsStillStated is the cost the mask may not have. Inside the
// bound nothing is hidden: a probed answer is the answer, or every hero chmod
// would ask for a typed phrase for no reason at all.
func TestAFreshAclmodeIsStillStated(t *testing.T) {
	const mp = "/share/ZFS530_DATA/A"
	p := newPlatform()
	p.setMounts(table(t, liveDatasetRow))
	instantSeams(p, 0)
	p.Probe()

	if c, ok := p.ForLiteral(mp); !ok || c.ZFSAclmode != "discard" {
		t.Fatalf("caps %+v ok %v, want the probed answer stated inside the bound", c, ok)
	}
	p.setProbeTTL(time.Millisecond)
	ageProbes(p, time.Minute)
	if c, _ := p.ForLiteral(mp); c.ZFSAclmode != "" {
		t.Fatalf("aclmode %q past the bound, want unknown", c.ZFSAclmode)
	}
}

// --- finding 3: the pending set is a queue, not the head of the table -----------

// TestEveryExpiredMountIsProbedWithinABoundedNumberOfPasses is the finding. Sixty-
// four datasets, a per-probe delay that makes one pass cost more than the facts
// stay fresh, and so a set that is fully expired again every time a pass ends.
// Selecting from the start of p.mounts then re-probed D00..D15 for ever: the first
// sixteen were always expired, always first, and D16..D63 were never reached.
// Coverage is what is asserted — how long a pass takes is the machine's business.
func TestEveryExpiredMountIsProbedWithinABoundedNumberOfPasses(t *testing.T) {
	const rows = 64
	p := newPlatform()
	p.setMounts(table(t, datasetRows(rows)))
	probed, reset := instantSeams(p, time.Millisecond)

	p.Probe() // every mount answered once, at start-up
	reset()
	// Shorter than one pass, so the head of the queue is expired again before the
	// tail of it has ever been probed.
	p.setProbeTTL(time.Millisecond)

	const passes = rows / maxProbesPerRefresh
	for i := 0; i < passes; i++ {
		p.kickProbe()
		awaitProbe(t, p)
	}

	seen := map[string]bool{}
	for _, mp := range probed() {
		seen[mp] = true
	}
	var missing []string
	for i := 0; i < rows; i++ {
		if !seen[datasetMount(i)] {
			missing = append(missing, datasetMount(i))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d of %d mounts were never probed in %d passes (from %s): the tail of the table starves",
			len(missing), rows, passes, missing[0])
	}
}

// TestANeverProbedRowIsTakenFirstWhereverItIsInTheTable: a dataset mounted at the
// TAIL of a table whose head is already an expired queue has no answer at all —
// its backend is empty and its aclmode unknown — and it is the one the next pass
// must take. The cursor left behind by the previous pass may not bury it.
func TestANeverProbedRowIsTakenFirstWhereverItIsInTheTable(t *testing.T) {
	const rows = 64
	p := newPlatform()
	p.setMounts(table(t, datasetRows(rows)))
	instantSeams(p, 0)
	p.Probe()
	p.setProbeTTL(time.Millisecond)
	ageProbes(p, time.Minute)

	// One ordinary pass, so there is a cursor pointing into the middle of the queue.
	p.kickProbe()
	awaitProbe(t, p)

	const newMount = "/share/ZFS530_DATA/Z99"
	p.setMounts(table(t, datasetRows(rows)+
		"400 30 0:400 / "+newMount+" rw,relatime - zfs zpool1/z99 rw\n"))

	pending := pendingPoints(p.pendingProbes())
	if len(pending) == 0 || pending[0] != newMount {
		t.Fatalf("pending %v, want the never-probed mount first: an unprobed storage mount is the one with no answer at all", pending)
	}
}

// TestTheProbeCursorContinuesWhereTheLastPassStopped states the cursor away from
// the timing. Age ordering alone is not enough on its own: a probe whose answer is
// DROPPED at publication — the mount was replaced while its `zfs get` ran — leaves
// the row exactly as old as it was, so it sorts first again and would be selected
// by every pass while the rows behind it are never reached.
func TestTheProbeCursorContinuesWhereTheLastPassStopped(t *testing.T) {
	const rows = 64
	p := newPlatform()
	p.setMounts(table(t, datasetRows(rows)))
	instantSeams(p, 0)
	p.Probe()
	p.setProbeTTL(time.Millisecond)
	ageProbes(p, time.Minute)

	first := pendingPoints(p.pendingProbes())
	if len(first) != maxProbesPerRefresh || first[0] != datasetMount(0) {
		t.Fatalf("first batch %v, want the %d oldest from the head", first, maxProbesPerRefresh)
	}
	p.setProbeCursor(first[len(first)-1])

	second := pendingPoints(p.pendingProbes())
	if len(second) != maxProbesPerRefresh || second[0] != datasetMount(maxProbesPerRefresh) {
		t.Fatalf("second batch %v, want the next %d: a pass that re-dated nothing repeats itself", second, maxProbesPerRefresh)
	}
	for _, mp := range second {
		for _, was := range first {
			if mp == was {
				t.Fatalf("batch %v overlaps the previous one at %s", second, mp)
			}
		}
	}

	// And it wraps: the end of the queue is followed by the start of it, not by
	// nothing at all.
	p.setProbeCursor(datasetMount(rows - 1))
	wrapped := pendingPoints(p.pendingProbes())
	if len(wrapped) == 0 || wrapped[0] != datasetMount(0) {
		t.Fatalf("batch after the last row %v, want the queue to wrap to the head", wrapped)
	}
}
