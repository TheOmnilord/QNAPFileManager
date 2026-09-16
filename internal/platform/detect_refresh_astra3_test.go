package platform

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The platform half of the gpt-6-astra M3 round-3 review (docs/reviews/
// m3-astra-round3.md): findings 5 and 10.
//
// Finding 5 is about the round-2 tests rather than the round-2 code. They called
// Probe() and kickProbe() by hand, so the SHAPE of the start-up sequence and of
// a refresh — which is what round-2 #14 and #7 were about — was asserted nowhere:
// putting Refresh() back in front of Probe() in Detect, or the probing back
// inside Refresh, left every one of them green. What follows drives the real
// paths instead, over the mountinfo and syscall seams, and the double probe and
// the synchronous refresh each fail one of them.

// mountinfoSeam points the kernel-table seam at a synthetic table for the rest of
// the test and returns the way to change it. Changing it is a mount appearing or
// going away as far as every path under test is concerned: refresh() re-reads it
// exactly as it re-reads /proc.
func mountinfoSeam(t *testing.T, lines string) func(string) {
	t.Helper()
	var mu sync.Mutex
	current := lines
	previous := openMountinfo
	openMountinfo = func() (io.ReadCloser, error) {
		mu.Lock()
		defer mu.Unlock()
		return io.NopCloser(strings.NewReader(current)), nil
	}
	t.Cleanup(func() { openMountinfo = previous })
	return func(next string) {
		mu.Lock()
		current = next
		mu.Unlock()
	}
}

// startUpSeams replaces the syscalls a NEWLY BUILT Platform starts with, which is
// the only way to reach the one the start-up sequence constructs for itself, and
// counts what each of them is asked. The answers are the QuTS hero shape: NFSv4
// through system.nfs4_acl, aclmode discard.
func startUpSeams(t *testing.T) (xattr func() map[string]int, zfs func() []string) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	var datasets []string
	prevProbe, prevRunner := newXattrProbe, newCommandRunner
	newXattrProbe = func(path, name string) (int, error) {
		if name != XattrNFS4ACL {
			return 0, ErrNotSupported
		}
		mu.Lock()
		counts[path]++
		mu.Unlock()
		return 88, nil
	}
	newCommandRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		mu.Lock()
		datasets = append(datasets, args[len(args)-1])
		mu.Unlock()
		return []byte("discard\n"), nil
	}
	t.Cleanup(func() { newXattrProbe, newCommandRunner = prevProbe, prevRunner })

	return func() map[string]int {
			mu.Lock()
			defer mu.Unlock()
			out := make(map[string]int, len(counts))
			for k, v := range counts {
				out[k] = v
			}
			return out
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), datasets...)
		}
}

func fixtureTable(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// --- finding 5: the sequence, not its pieces -------------------------------------

// TestTheStartUpSequenceProbesEachMountOnce is round-2 #14 asserted where it
// happened. Detect parsed the table through Refresh and then called Probe; once
// Refresh grew a probe of its own, every daemon AND every spawned worker paid for
// the first batch twice — four datasets at the `zfs get` timeout is 24 s of
// start-up, past workerpool's 20 s hello timeout, before the machine has answered
// a request. The round-2 test called Probe() on a synthetic platform, which is
// the half of the sequence that was never in doubt; this one runs the sequence.
//
// Two assertions carry it, and between them there is no window: the moment the
// sequence returns, a second pass is either still running (the latch is set) or
// has finished, and if it has finished the counts are two.
func TestTheStartUpSequenceProbesEachMountOnce(t *testing.T) {
	// The captured hero table plus a stacked row: one mount POINT is one probe,
	// not one per mountinfo line (round-2 #13).
	lines := fixtureTable(t, "hero_mountinfo.txt") +
		"99 40 0:99 / /share/ZFS530_DATA/Public rw,relatime - zfs zpool1/zfs530_data/Public_new rw\n"
	mountinfoSeam(t, lines)
	xattr, zfs := startUpSeams(t)

	p := detectLive()

	if p.probeInFlight() != nil {
		t.Fatal("start-up started a background pass as well as the synchronous one")
	}
	counts := xattr()
	for mp, n := range counts {
		if n != 1 {
			t.Fatalf("%s probed %d times in one start-up", mp, n)
		}
	}
	if len(counts) == 0 {
		t.Fatal("the fixture has no storage mounts to probe")
	}
	seen := map[string]bool{}
	for _, d := range zfs() {
		if seen[d] {
			t.Fatalf("zfs get asked about %s twice in one start-up", d)
		}
		seen[d] = true
	}
	// Nothing is left over either: the asynchronous path has no work after a
	// start-up that covered the table.
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending after start-up: %v", pending)
	}
	if c := p.For("/share/ZFS530_DATA/Public"); c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "discard" {
		t.Fatalf("the visible row of the stacked mount is unprobed: %+v", c)
	}
	// And the sequence read the table itself, rather than being handed one.
	if !p.Live() || len(p.Mounts()) == 0 {
		t.Fatal("the start-up sequence did not parse the kernel table")
	}
}

// TestRefreshDoesNotProbeOnTheCallersPath is round-2 #7 asserted through
// Refresh() itself. probeMissing ran inside Refresh, Refresh is reached from
// maybeRefresh, and maybeRefresh is reached from every For() a request makes: a
// pool that mounted sixteen datasets at once put sixteen `zfs get` timeouts — up
// to 48 s — inside a handler with a 15 s budget and no way to cancel them.
//
// The gate is what makes the claim real. A probe that has entered the seam stays
// there until this test lets it out, so a Refresh that waited for it could not
// return, and the assertion is that it returned anyway.
func TestRefreshDoesNotProbeOnTheCallersPath(t *testing.T) {
	const rowA = "70 30 0:70 / /share/ZFS530_DATA/A rw,relatime - zfs zpool1/a rw\n"
	const rowB = "71 30 0:71 / /share/ZFS530_DATA/B rw,relatime - zfs zpool1/b rw\n"
	setTable := mountinfoSeam(t, rowA)
	xattr, _ := startUpSeams(t)

	p := detectLive()
	if c := p.For("/share/ZFS530_DATA/A"); c.ACLBackend != ACLNFS4 {
		t.Fatalf("start-up left the first dataset unprobed (%+v); this test proves nothing", c)
	}

	// A dataset appears, and its probe will block inside the seam.
	g := gatedSeams(p)
	defer g.release()
	setTable(rowA + rowB)

	returned := make(chan error, 1)
	go func() { returned <- p.Refresh() }()
	g.awaitEntry(t) // a probe is in the seam, and it is not coming out yet
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Refresh did not return while the probe was still in the seam: the probing is back on the request path")
	}
	if c := p.For("/share/ZFS530_DATA/B"); c.ACLBackend != "" {
		t.Fatalf("backend %q: the caller waited for the probe after all", c.ACLBackend)
	}

	g.release()
	awaitProbe(t, p)
	if c := p.For("/share/ZFS530_DATA/B"); c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "discard" {
		t.Fatalf("the probed answer never landed: %+v", c)
	}
	// And the refresh probed the NEW mount only: the cached answer for the one
	// already in the table is not paid for again every five seconds.
	if got := g.xattr(); len(got) != 1 || got[0] != "/share/ZFS530_DATA/B" {
		t.Fatalf("the refresh probed %v, want the new mount alone", got)
	}
	if n := xattr()["/share/ZFS530_DATA/A"]; n != 1 {
		t.Fatalf("the first dataset was probed %d times, want once at start-up", n)
	}
}

// --- finding 10: a mount that comes back is a different mount --------------------

// TestAProbeIsNotPublishedOntoTheMountThatCameBack is the A-B-A. Round 2 taught
// publishProbe to compare the row it probed with the row that is there now, and
// every field of a mountinfo line is repeatable: Linux hands mount IDs back out,
// and a dataset unmounted and mounted again keeps its device, source, type and
// root. `zfs set aclmode=discard` in between changes the one thing the probe went
// to find, and publishing the old answer would cache `passthrough` — "other
// entries are kept" — over a filesystem that discards them.
func TestAProbeIsNotPublishedOntoTheMountThatCameBack(t *testing.T) {
	const mp = "/share/ZFS530_DATA/Pool"
	row := "70 30 0:70 / " + mp + " rw,relatime - zfs zpool1/data rw\n"
	p := newPlatform()
	p.setMounts(table(t, row))
	g := gatedSeams(p)
	defer g.release()
	// The answer the OUTGOING incarnation had.
	p.SetCommandRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("passthrough\n"), nil
	})

	p.kickProbe()
	g.awaitEntry(t)            // the pass holds the outgoing row
	p.setMounts(nil)           // unmounted
	p.setMounts(table(t, row)) // and mounted again, byte for byte the same line
	g.release()
	awaitProbe(t, p)

	if c := p.For(mp); c.ACLBackend != "" || c.ZFSAclmode != "" {
		t.Fatalf("caps %+v: the probe of the mount that went away was published onto the one that came back", c)
	}
	// The mount that IS there is simply unprobed, which every caller reads
	// pessimistically, and the next pass takes it.
	if pending := p.pendingProbes(); len(pending) != 1 || pending[0].mount.MountPoint != mp {
		t.Fatalf("pending %v, want the returned mount", pending)
	}
}

// TestAnUnchangedRowKeepsItsProbeAcrossARefresh is the other side of the same
// counter: it must not invalidate everything on every refresh, or the cache it
// guards is gone and a request path that refreshes every five seconds re-probes
// the whole table.
func TestAnUnchangedRowKeepsItsProbeAcrossARefresh(t *testing.T) {
	const rowA = "70 30 0:70 / /share/ZFS530_DATA/A rw,relatime - zfs zpool1/a rw\n"
	const rowB = "71 30 0:71 / /share/ZFS530_DATA/B rw,relatime - zfs zpool1/b rw\n"
	setTable := mountinfoSeam(t, rowA)
	xattr, _ := startUpSeams(t)
	p := detectLive()

	// A second dataset appears; the first one's row is untouched.
	setTable(rowA + rowB)
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	awaitProbe(t, p)
	if n := xattr()["/share/ZFS530_DATA/A"]; n != 1 {
		t.Fatalf("the unchanged mount was probed %d times, want once", n)
	}
	if c := p.For("/share/ZFS530_DATA/A"); c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "discard" {
		t.Fatalf("the unchanged mount lost its probed answer: %+v", c)
	}
}
