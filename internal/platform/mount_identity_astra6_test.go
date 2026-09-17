package platform

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The platform half of the gpt-6-astra M3 round-6 review (docs/reviews/
// m3-astra-round6.md): finding 2. Round 5 masked an expired ACLMODE at every
// lookup and deliberately left the BACKEND cached, on the reasoning that only a
// remount can change a backend and that a remount advances the incarnation. The
// second half of that was not true. sameMountRow never looked at the mount
// OPTIONS, so `mount -o remount,acl` over an ext4 mounted `noacl` was the same row
// by every field it compared: the incarnation stood, setMounts carried the `none`
// probed under `noacl` across every later refresh, and a chmod over that mount was
// graded as touching no ACL at all — not the pessimistic answer, silence.
//
// What the masked backend costs the ROUTE is pinned in the web package rather than
// here: internal/web/perm_astra3_test.go grades a storage mount whose backend is
// empty as the L2 floor, through chmodACLNotice and end to end through
// /api/fs/chmod, and chmodJobLadder reaches that same rung over every dataset
// ladderFacts collects — the job's roots and, with crossMounts, every child mount
// below them, all of them looked up through Platform.ForLiteral, which is the
// lookup masked here. The web package cannot stage the expiry itself (probedAt and
// the TTL seam are this package's own), so the mask is stated here and the rung it
// lands on is stated there.

const (
	// The same ext4 filesystem before and after `mount -o remount,acl`. Every
	// field round 3's rule compared is identical — mount ID, device, in-filesystem
	// root, mount point, type, source — and `acl` is a SUPERBLOCK option (field 11).
	ext4NoaclRow = "80 30 8:3 / /share/CACHEDEV1_DATA rw,relatime - ext4 /dev/sda3 rw,noacl\n"
	ext4AclRow   = "80 30 8:3 / /share/CACHEDEV1_DATA rw,relatime - ext4 /dev/sda3 rw,acl\n"
	// And the other half of the pair: `ro` is a PER-MOUNT option (field 6), so a
	// rule that watched only the superblock list would miss this one.
	ext4ReadOnlyRow = "80 30 8:3 / /share/CACHEDEV1_DATA ro,relatime - ext4 /dev/sda3 rw,noacl\n"

	ext4MountPoint = "/share/CACHEDEV1_DATA"
)

// noACLSeams answer the way a filesystem mounted `noacl` does: it knows no ACL
// attribute namespace at all. There is no `zfs` to ask either, because an ext4
// mount is not a dataset and the probe never asks — a runner that fails loudly is
// how this test would find out if it did.
func noACLSeams(p *Platform) {
	p.SetXattrProbe(func(string, string) (int, error) { return 0, ErrNotSupported })
	p.SetCommandRunner(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("zfs: not a ZFS dataset")
	})
}

// posixGate is the xattr seam held open. A re-probe is late for reasons this
// package cannot shorten — another pass holds the single-flight latch, the
// sixteen-per-pass bound put this row behind others, a `zfs get` is wedged on a
// hung pool for its full timeout — and holding the seam is how a test stands
// inside that window. Released, it answers the way an ext4 remounted with `acl`
// does.
type posixGate struct {
	gate     chan struct{}
	entered  chan struct{}
	announce sync.Once
	opened   sync.Once
}

func holdPosixProbe(p *Platform) *posixGate {
	g := &posixGate{gate: make(chan struct{}), entered: make(chan struct{})}
	p.SetXattrProbe(func(_, name string) (int, error) {
		g.announce.Do(func() { close(g.entered) })
		<-g.gate
		if name == XattrPosixACL {
			return 88, nil
		}
		return 0, ErrNotSupported
	})
	return g
}

func (g *posixGate) release() { g.opened.Do(func() { close(g.gate) }) }

func (g *posixGate) awaitEntry(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no probe reached the seam")
	}
}

// diagRow returns one mount's diagnostic row.
func diagRow(t *testing.T, p *Platform, mountPoint string) map[string]any {
	t.Helper()
	rows, ok := p.Diag()["mounts"].([]map[string]any)
	if !ok {
		t.Fatal("Diag has no mount rows")
	}
	for _, row := range rows {
		if row["mountPoint"] == mountPoint {
			return row
		}
	}
	t.Fatalf("Diag has no row for %s", mountPoint)
	return nil
}

// --- the mask: an expired backend is unknown, exactly as an expired aclmode is ---

// TestAnExpiredBackendIsUnknownUntilTheReprobePublishes is the first half of the
// finding. The mount is probed while it is `noacl` and answers `none`; a minute
// later that answer is past its freshness bound and the pass that would replace it
// is held. In that window a lookup may not keep stating `none`, because `none` is
// the one answer that produces no warning whatsoever: the ladder reads it as "there
// are no ACLs here" and grades an ACL-destroying chmod as ordinary. Unknown is what
// an expired fact is, and an unknown backend on a storage mount is the L2 floor.
func TestAnExpiredBackendIsUnknownUntilTheReprobePublishes(t *testing.T) {
	p := newPlatform()
	p.setMounts(table(t, ext4NoaclRow))
	noACLSeams(p)
	p.Probe()
	if c, ok := p.ForLiteral(ext4MountPoint); !ok || c.ACLBackend != ACLNone {
		t.Fatalf("caps %+v ok %v, want the probed none; this test proves nothing", c, ok)
	}

	// A minute passes, and the world changed inside it: `mount -o remount,acl`,
	// which is what the gated seam will report once the pass is allowed to finish.
	g := holdPosixProbe(p)
	ageProbes(p, defaultProbeTTL+time.Second)

	p.kickProbe()
	g.awaitEntry(t)
	c, ok := p.ForLiteral(ext4MountPoint)
	if !ok {
		t.Fatal("ForLiteral lost the row")
	}
	if c.ACLBackend != "" || c.ACLXattr != "" {
		t.Fatalf("backend %q xattr %q while the re-probe is blocked: the expired answer is still being stated, and `none` is the answer that warns about nothing at all", c.ACLBackend, c.ACLXattr)
	}
	if !c.Storage {
		t.Fatal("Storage comes from the fstype and is not a probed fact: masking it would turn the L2 floor into a shrug")
	}
	// The other two spellings of the same lookup: one caller may not be told what
	// another is no longer allowed to state.
	if got := p.For(ext4MountPoint + "/file.txt"); got.ACLBackend != "" {
		t.Fatalf("For reported %q: the mask is per lookup, not per caller", got.ACLBackend)
	}
	if got, ok := p.MountByLiteralPath(ext4MountPoint); !ok || got.ACLBackend != "" {
		t.Fatalf("MountByLiteralPath reported %+v ok %v, want the same masked answer", got, ok)
	}
	// The diagnostic is the one place that still sees the cached value, beside the
	// flag that says no lookup will state it. "Probed none and stopped trusting it"
	// and "never probed" are different faults and a field report needs to tell them
	// apart.
	row := diagRow(t, p, ext4MountPoint)
	if row["aclBackend"] != ACLNone || row["aclBackendStale"] != true {
		t.Fatalf("diag row %v, want the cached backend beside a stale flag", row)
	}

	g.release()
	awaitProbe(t, p)
	if c, ok := p.ForLiteral(ext4MountPoint); !ok || c.ACLBackend != ACLPosix || c.ACLXattr != XattrPosixACL {
		t.Fatalf("caps %+v ok %v, want the re-probed posix once the pass has published", c, ok)
	}
	if row := diagRow(t, p, ext4MountPoint); row["aclBackendStale"] != false {
		t.Fatalf("diag row %v, want the stale flag cleared by the publication", row)
	}
}

// --- the identity: a remount that only changes options is a different mount -----

// TestARemountThatOnlyChangesOptionsIsANewIncarnation is the second half. The mask
// bounds how long a wrong answer can be stated; this is what stops it being wrong
// in the first place. Both option lists count, because a remount reaches either
// one: `acl` lives in the superblock list and `ro` in the per-mount list.
func TestARemountThatOnlyChangesOptionsIsANewIncarnation(t *testing.T) {
	for name, remounted := range map[string]string{
		"superblock option: noacl -> acl": ext4AclRow,
		"per-mount option: rw -> ro":      ext4ReadOnlyRow,
	} {
		t.Run(name, func(t *testing.T) {
			p := newPlatform()
			p.setMounts(table(t, ext4NoaclRow))
			noACLSeams(p)
			p.Probe()
			was := incarnationOf(p, ext4MountPoint)
			if c, _ := p.ForLiteral(ext4MountPoint); c.ACLBackend != ACLNone {
				t.Fatalf("caps %+v, want the probed none before the remount", c)
			}

			p.setMounts(table(t, remounted))
			if got := incarnationOf(p, ext4MountPoint); got == was {
				t.Fatalf("incarnation %d unchanged: a filesystem remounted with different options is a filesystem to ask again, and nothing else in the row says so", got)
			}
			// The probed answer went with the incarnation, so until the pass runs the
			// mount reads as one nobody has looked at — which is the honest answer.
			if c, ok := p.ForLiteral(ext4MountPoint); !ok || c.ACLBackend != "" || c.ACLXattr != "" {
				t.Fatalf("caps %+v ok %v, want the cached probe dropped with the incarnation", c, ok)
			}
			if pending := pendingPoints(p.pendingProbes()); len(pending) != 1 || pending[0] != ext4MountPoint {
				t.Fatalf("pending %v, want the remounted filesystem queued for a fresh probe", pending)
			}

			// And the fresh probe is a real one: it asks the kernel again rather than
			// republishing what was carried across. The `ro` remount does not itself
			// change what ext4 answers — the seam is what changes here — and that is
			// the point: the rule cannot know which options matter, so it re-asks.
			p.SetXattrProbe(func(_, name string) (int, error) {
				if name == XattrPosixACL {
					return 88, nil
				}
				return 0, ErrNotSupported
			})
			p.kickProbe()
			awaitProbe(t, p)
			if c, _ := p.ForLiteral(ext4MountPoint); c.ACLBackend != ACLPosix {
				t.Fatalf("backend %q after the re-probe, want the posix the remounted filesystem now answers", c.ACLBackend)
			}
		})
	}
}

// TestARefreshWithIdenticalOptionsKeepsTheIncarnation is the cost the new field may
// not have. A table is re-read every five seconds and an unchanged row is the
// overwhelmingly common case; treating it as a new mount would re-probe every
// storage mount on the machine twelve times a minute, which is what the carry-
// across exists to prevent.
func TestARefreshWithIdenticalOptionsKeepsTheIncarnation(t *testing.T) {
	p := newPlatform()
	p.setMounts(table(t, ext4NoaclRow))
	noACLSeams(p)
	p.Probe()
	was := incarnationOf(p, ext4MountPoint)

	p.setMounts(table(t, ext4NoaclRow))
	if got := incarnationOf(p, ext4MountPoint); got != was {
		t.Fatalf("incarnation %d, was %d: an identical row is the same mount", got, was)
	}
	if c, _ := p.ForLiteral(ext4MountPoint); c.ACLBackend != ACLNone {
		t.Fatalf("caps %+v, want the probed answer carried across an unchanged refresh", c)
	}
	if pending := p.pendingProbes(); len(pending) != 0 {
		t.Fatalf("pending %v, want nothing at all: the row did not change and the answer is fresh", pending)
	}
}
