package platform

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Astra M3 round-1 finding 1, at its source. setMounts carries probed fields
// across a refresh only for mount points it ALREADY KNEW, so a dataset mounted
// after start-up entered the table with ACLBackend "" and was never probed
// again — and an empty backend is the one answer the ACL ladder used to read as
// "nothing to warn about". A new storage mount is now probed on refresh, the
// same bounded way start-up probes, and the answer is cached like every other.

// probeSeams installs counting xattr and `zfs get` seams and returns how many
// mount roots each was asked about.
func probeSeams(p *Platform) (xattr func() []string, zfs func() []string) {
	var mu sync.Mutex
	var probed, datasets []string
	p.SetXattrProbe(func(path, name string) (int, error) {
		mu.Lock()
		if name == XattrNFS4ACL {
			probed = append(probed, path)
		}
		mu.Unlock()
		if name == XattrNFS4ACL {
			return 88, nil
		}
		return 0, ErrNotSupported
	})
	p.SetCommandRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		mu.Lock()
		datasets = append(datasets, args[len(args)-1])
		mu.Unlock()
		return []byte("discard\n"), nil
	})
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), probed...)
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), datasets...)
		}
}

func TestProbeMissingCoversAMountThatAppearedLater(t *testing.T) {
	p := load(t, "hero_mountinfo.txt")
	xattr, zfs := probeSeams(p)
	p.Probe()
	firstPass := len(xattr())
	if firstPass == 0 {
		t.Fatal("the fixture has no storage mounts to probe")
	}

	// A dataset appears. This is what a refresh does: re-parse, keep what was
	// probed for the mounts we knew, and leave the new one with nothing.
	const line = "99 30 0:99 / /share/ZFS530_DATA/Late rw,relatime shared:99 - zfs zpool1/zfs530_data/Late rw,xattr,posixacl\n"
	mounts, err := ParseMountinfo(strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	p.setMounts(append(p.Mounts(), mounts...))
	if c := p.For("/share/ZFS530_DATA/Late"); c.ACLBackend != "" {
		t.Fatalf("the new mount arrived pre-probed (%q); this test proves nothing", c.ACLBackend)
	}

	p.probeMissing()
	c := p.For("/share/ZFS530_DATA/Late")
	if c.ACLBackend != ACLNFS4 || c.ZFSAclmode != "discard" {
		t.Fatalf("the new dataset is still unprobed: %+v", c)
	}
	// Only the new one was probed: the cached answers for the mounts that were
	// already known are not paid for again on every refresh.
	if got := len(xattr()); got != firstPass+1 {
		t.Fatalf("xattr probes %d, want %d — a refresh re-probed the whole table", got, firstPass+1)
	}
	if last := zfs(); last[len(last)-1] != "zpool1/zfs530_data/Late" {
		t.Fatalf("zfs get was asked about %q", last[len(last)-1])
	}

	// And it is cached: a second pass costs nothing.
	before := len(xattr())
	p.probeMissing()
	if got := len(xattr()); got != before {
		t.Fatalf("probes %d, want %d — the answer is not cached", got, before)
	}
}

func TestProbeMissingIsBounded(t *testing.T) {
	var b strings.Builder
	total := maxProbesPerRefresh * 2
	for i := 0; i < total; i++ {
		fmt.Fprintf(&b, "%d 25 0:%d / /share/ZFS530_DATA/d%02d rw,relatime - zfs zpool1/d%02d rw\n", 100+i, 100+i, i, i)
	}
	mounts, err := ParseMountinfo(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	p := newPlatform()
	p.setMounts(mounts)
	xattr, _ := probeSeams(p)

	// One refresh must not turn fifty new datasets into fifty `zfs get`
	// invocations in front of the next For(); what is left over stays unprobed,
	// which every caller reads pessimistically, and the next refresh takes it.
	p.probeMissing()
	if got := len(xattr()); got != maxProbesPerRefresh {
		t.Fatalf("probes in one pass = %d, want %d", got, maxProbesPerRefresh)
	}
	p.probeMissing()
	if got := len(xattr()); got != 2*maxProbesPerRefresh {
		t.Fatalf("probes after two passes = %d, want %d", got, 2*maxProbesPerRefresh)
	}
}

// TestForLiteralDoesNotWalkABackslashOntoASibling is the platform half of
// finding 2: For normalises a backslash into a separator and then Cleans, so a
// Linux filename containing one is answered for a mount it is not on. The
// literal lookup answers for the bytes.
func TestForLiteralDoesNotWalkABackslashOntoASibling(t *testing.T) {
	if literalMountKey(`/a\b`) != `/a\b` {
		t.Skip("this dev box keeps the lenient mount key on purpose (mountkey_other.go)")
	}
	p := load(t, "hero_mountinfo.txt")
	const literal = `/share/ZFS530_DATA/Public/danger\..\..\Media`
	m, ok := p.MountForLiteral(literal)
	if !ok || m.MountPoint != "/share/ZFS530_DATA/Public" {
		t.Fatalf("MountForLiteral = %+v (ok %v), want the Public dataset", m, ok)
	}
	if n, _ := p.MountFor(literal); n.MountPoint == m.MountPoint {
		t.Fatal("MountFor and MountForLiteral agree here, so the fixture does not exercise the difference")
	}
}
