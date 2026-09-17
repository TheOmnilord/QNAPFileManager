package platform

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The platform half of the gpt-6-astra M3 round-4 review (docs/reviews/
// m3-astra-round4.md): finding 6.
//
// The incarnation counter (round 3 #10) is built on the mountinfo ROW, and it
// only moves when a refresh sees that row change. Two things it therefore cannot
// see: `zfs set aclmode=discard` on a live dataset, which changes no field of any
// row, and a remount that starts and finishes between two five-second refreshes,
// which repeats every field it had. In both cases the cached `passthrough` — "the
// mode is set, other entries are kept" — stayed cached for the life of the mount
// over a filesystem that discards them. A probed fact now expires.

// aclmodeSeam points the newly built Platform's syscall seams at a mutable
// answer: NFSv4 through system.nfs4_acl, and an aclmode this test can change
// under a running daemon exactly as `zfs set` changes it under a running NAS.
// It returns the setter and the two call counters.
func aclmodeSeam(t *testing.T, initial string) (set func(string), xattrs func() map[string]int, gets func() []string) {
	t.Helper()
	var mu sync.Mutex
	aclmode := initial
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
		defer mu.Unlock()
		datasets = append(datasets, args[len(args)-1])
		return []byte(aclmode + "\n"), nil
	}
	t.Cleanup(func() { newXattrProbe, newCommandRunner = prevProbe, prevRunner })

	return func(next string) {
			mu.Lock()
			aclmode = next
			mu.Unlock()
		}, func() map[string]int {
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

// ageProbes back-dates every probed fact, which is how this test lets a minute
// pass without spending one. It moves nothing else: the rows, the incarnations
// and the cached answers are all exactly as the real paths left them.
func ageProbes(p *Platform, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for mp, at := range p.probedAt {
		p.probedAt[mp] = at.Add(-d)
	}
}

func incarnationOf(p *Platform, mountPoint string) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.incarnation[mountPoint]
}

const liveDatasetRow = "70 30 0:70 / /share/ZFS530_DATA/A rw,relatime - zfs zpool1/a rw\n"

// TestAnAclmodeChangedUnderTheDaemonIsPickedUpAfterTheTTL is the finding. No row
// changes at any point — the dataset stays mounted, the mountinfo line is
// identical byte for byte, the incarnation never moves — and the answer still
// has to catch up, because `zfs set` is not a mount event.
func TestAnAclmodeChangedUnderTheDaemonIsPickedUpAfterTheTTL(t *testing.T) {
	const mp = "/share/ZFS530_DATA/A"
	mountinfoSeam(t, liveDatasetRow)
	setAclmode, xattrs, gets := aclmodeSeam(t, "passthrough")

	p := detectLive()
	if c := p.For(mp); c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "passthrough" {
		t.Fatalf("start-up %+v, want the probed passthrough; this test proves nothing", c)
	}
	inc := incarnationOf(p, mp)

	// The operator runs `zfs set aclmode=discard`. Nothing in the mount table
	// moves, so nothing the incarnation rule watches moves either.
	setAclmode("discard")

	// Inside the bound the cached answer is kept, and no helper process is spent
	// on it: a refresh every five seconds may not re-probe a pool every time.
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	awaitProbe(t, p)
	if c := p.For(mp); c.ZFSAclmode != "passthrough" {
		t.Fatalf("aclmode %q: the fresh answer was thrown away and re-probed", c.ZFSAclmode)
	}
	if n := len(gets()); n != 1 {
		t.Fatalf("zfs get ran %d times inside the freshness bound, want once at start-up", n)
	}

	// A minute later the same refresh asks again.
	ageProbes(p, defaultProbeTTL+time.Second)
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	awaitProbe(t, p)
	if c := p.For(mp); c.ZFSAclmode != "discard" {
		t.Fatalf("aclmode %q, want the re-probed discard: a stale passthrough is cached for the life of the mount", c.ZFSAclmode)
	}
	if c := p.For(mp); c.ACLBackend != ACLNFS4 {
		t.Fatalf("backend %q: the re-probe lost the backend", c.ACLBackend)
	}
	if n := xattrs()[mp]; n != 2 {
		t.Fatalf("the mount was probed %d times, want one start-up probe and one refresh", n)
	}
	if got := incarnationOf(p, mp); got != inc {
		t.Fatalf("incarnation %d, was %d: the row did not change, so nothing may have been invalidated", got, inc)
	}
}

// TestTheFreshnessBoundIsPerTableAndSettable pins the seam itself: the bound is
// the instance's, so a test can shorten it without racing the package, and a
// probe older than it is pending work for the ordinary background pass rather
// than a path of its own.
func TestTheFreshnessBoundIsPerTableAndSettable(t *testing.T) {
	const mp = "/share/ZFS530_DATA/A"
	p := newPlatform()
	p.setMounts(table(t, liveDatasetRow))
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
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending %v, want nothing right after a probe", pending)
	}
	// An hour's bound keeps it; a zero bound expires it. Both are read from the
	// instance, which is what makes the shortening safe.
	p.setProbeTTL(time.Hour)
	ageProbes(p, time.Minute)
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending %v: a minute is not past an hour", pending)
	}
	p.setProbeTTL(time.Second)
	ageProbes(p, time.Minute)
	if pending := p.pendingProbes(); len(pending) != 1 || pending[0].mount.MountPoint != mp {
		t.Fatalf("pending %v, want the expired mount", pending)
	}
	// And it is the SAME pass that takes it — no second mechanism.
	p.kickProbe()
	awaitProbe(t, p)
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending %v after the pass, want the answer re-dated", pending)
	}
}
