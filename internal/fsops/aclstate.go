package fsops

// The ACL badge: what a listing and the properties dialog report about one
// object's ACL (m3-contract §6).
//
// The badge reports a STATE and not a boolean, because on ZFS presence is the
// wrong question: every object on a dataset carries system.nfs4_acl, so "the
// attribute exists" would badge the entire NAS. What is worth telling the user
// is whether the ACL says something the MODE does not — a named user, a group,
// an inheritance flag — because that is exactly what editing the mode may
// destroy or silently reduce.
//
// Three properties bound it, and each is deliberate.
//
//   - It is asked only when the ROUTE asks (ListOptions.ACLProbe) and only where
//     the mount has an ACL backend at all. A listing of a plain ext4 share with
//     no ACL support costs nothing.
//   - It is bounded per page: 2000 entries and 64 KiB of attribute bytes.
//     Beyond either, the rest of the page is left unprobed — Entry.ACL stays ""
//     — and the listing says so in a note rather than pretending the badges are
//     complete. The byte bound is checked against the attribute's REPORTED SIZE
//     before it is read, not merely after (Astra M3 round 1, finding 18): the
//     old order let a page that was 60 KiB in read a 16 KiB attribute in full
//     and only then notice.
//   - In a LISTING it is a pathname probe (lgetxattr), deliberately. There is no
//     fgetxattrat, and opening every file in a directory to read an attribute
//     would ask for read permission the user may not have — which would turn a
//     badge into a refusal. A name re-pointed between getdents and the probe
//     therefore yields a wrong badge, and that is acceptable precisely because
//     the badge changes nothing the kernel does: it is display, and it is
//     recorded as a residual (contract residual 2).
//
// The properties dialog is the exception to that last point, and finding 4 is
// why. Its answer is not display: it is what the confirmation ladder grades, so
// it is an input to an authorization decision. There the object is already HELD
// as an O_PATH descriptor, and the attribute is read through /proc/self/fd/N of
// that descriptor — the same idiom chmod and chown use here — so the state
// describes the inode that is about to be changed rather than whatever answers
// to its name by then. Where /proc is unavailable the pathname probe is still
// made, but a reassuring answer from it is downgraded to fsx.ACLUnknown: a name
// cannot clear an inode of having an ACL.
//
// A read or parse failure is fsx.ACLUnknown and never fsx.ACLNone. Unknown shows
// the badge with the pessimistic text, which is the half that matters.

import (
	"io/fs"
	"os"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
)

// aclBudget is one listing page's allowance: how many entries may be probed and
// how many attribute bytes may be read before the rest of the page is left
// unbadged.
//
// It is a value of its own rather than a field of aclProbe because a page can
// need more than one BACKEND — a dataset mounted beneath a POSIX directory
// answers in a different attribute than its parent (finding 17) — while the
// bound the contract states is one bound per page, not one per backend.
type aclBudget struct {
	entries int
	bytes   int
	// capped records that a bound was reached, so the listing can say why some
	// entries carry no badge.
	capped bool
}

// aclProbe is one backend and the budget it spends. The zero value probes
// nothing.
type aclProbe struct {
	// backend is platform.ACLPosix or platform.ACLNFS4; xattr is the attribute
	// that backend answers in.
	backend string
	xattr   string

	bud *aclBudget
}

// aclBackendOf decides which attribute answers for the mount holding osPath.
//
// The lookup is the LITERAL one (finding 2). Platform.For normalises: it turns a
// backslash into a separator and Cleans the result, and on Linux a backslash is
// an ordinary character in a filename — so a file literally named
// `danger/..\safe/file` would be graded on the `safe` dataset while the chmod
// changed an inode on `danger`. Every ACL decision in the app now asks the
// literal table.
//
// A lookup that matches no row answers "" — unknown, never platform.ACLNone.
// The caller grades an unknown backend pessimistically, and saying "none" about
// a mount this could not find would be the one answer that silences the warning
// altogether.
func aclBackendOf(plat *platform.Platform, osPath string) (backend, xattr string) {
	if plat == nil || osPath == "" || !xattrProbeAvailable {
		return "", ""
	}
	caps, ok := plat.ForLiteral(osPath)
	if !ok {
		return "", ""
	}
	switch caps.ACLBackend {
	case platform.ACLPosix:
		return platform.ACLPosix, platform.XattrPosixACL
	case platform.ACLNFS4:
		name := caps.ACLXattr
		if name == "" {
			name = platform.XattrNFS4ACL
		}
		return platform.ACLNFS4, name
	}
	return "", ""
}

// newACLProbe decides whether this listing probes at all, and in which
// attribute. plat == nil, a mount with no ACL backend, a mount the literal
// lookup does not know, and a platform that cannot read extended attributes
// each answer "no" — and "no" means the entries keep an empty ACL state, which
// is "not probed" rather than "no ACL".
func newACLProbe(plat *platform.Platform, osDir string, want bool) *aclProbe {
	if !want {
		return nil
	}
	backend, xattr := aclBackendOf(plat, osDir)
	if backend == "" {
		return nil
	}
	return &aclProbe{backend: backend, xattr: xattr, bud: &aclBudget{}}
}

// aclTarget is the object one probe reads its attribute from.
//
// osPath is always set — it is the byte-exact OS spelling, and off the held
// path it is the only way in. held is the O_PATH descriptor when the CALLER is
// holding the object, which is what turns the answer from a fact about a name
// into a fact about an inode. link marks a symlink leaf, for which the held
// route is deliberately not taken: /proc/self/fd/N jumps to the dentry and a
// FOLLOWING getxattr would then read the target's attribute, which is the one
// thing the no-follow discipline forbids (the same trap chownViaProc documents).
type aclTarget struct {
	osPath string
	held   *os.File
	link   bool
}

// grade is where an answer that could not be taken from the held descriptor is
// made honest.
//
// A caller that HOLDS the object asked about that inode, and a pathname probe
// answered about whatever the name means now. The two reassuring states — "no
// ACL" and "only what the mode already says" — are the ones that switch a
// confirmation off, so those are downgraded to unknown; a state that already
// warns needs no help. Nothing is downgraded for a listing (which has no
// descriptor and whose residual is accepted) or for a symlink (whose mode
// cannot be changed at all, so there is no confirmation to protect).
func (t aclTarget) grade(state string, viaFD bool) string {
	if viaFD || t.held == nil || t.link {
		return state
	}
	switch state {
	case fsx.ACLNone, fsx.ACLNFS4Trivial:
		return fsx.ACLUnknown
	}
	return state
}

// probe classifies one object, or reports that the budget is spent. The caller
// leaves Entry.ACL alone when ok is false.
func (p *aclProbe) probe(t aclTarget) (state string, ok bool) {
	if p == nil || p.bud == nil || (t.osPath == "" && t.held == nil) {
		return "", false
	}
	if p.bud.entries >= fsx.ACLProbeMaxEntries || p.bud.bytes >= fsx.ACLProbeMaxBytes {
		p.bud.capped = true
		return "", false
	}
	p.bud.entries++

	size, viaFD, err := t.xattrSize(p.xattr)
	switch {
	case absentXattrErr(err):
		return t.grade(fsx.ACLNone, viaFD), true
	case err != nil:
		return fsx.ACLUnknown, true
	}
	if p.backend == platform.ACLPosix {
		// The POSIX question is exactly the "+" in ls -l: is the access ACL
		// there and non-empty. The bytes are never read, so a directory of ten
		// thousand entries costs one size query each — and the byte budget below
		// is never touched.
		if size <= 0 {
			return t.grade(fsx.ACLNone, viaFD), true
		}
		return fsx.ACLPosix, true
	}
	if size <= 0 {
		// An NFSv4 attribute that is present and empty parses as nothing, and
		// nothing is not "no ACL" — it is an attribute this cannot read.
		return fsx.ACLUnknown, true
	}
	if size > fsx.ACLProbeMaxBytes-p.bud.bytes {
		// Finding 18: the bound is asked BEFORE the read, against the size the
		// kernel just reported. Checking only afterwards meant a page with
		// 4 KiB of its allowance left could still pull a 16 KiB attribute into
		// memory and only then stop. The entry is left unbadged and the page
		// says why.
		p.bud.capped = true
		return "", false
	}
	buf, viaFD, err := t.xattrRead(p.xattr, size)
	p.bud.bytes += len(buf)
	switch {
	case absentXattrErr(err):
		// Removed between the two calls: the honest answer is that there is
		// none now.
		return t.grade(fsx.ACLNone, viaFD), true
	case err != nil:
		return fsx.ACLUnknown, true
	}
	return t.grade(perm.NFS4State(buf), viaFD), true
}

// probeListing fills Entry.ACL for one page of a listing and reports whether a
// bound was reached. The entries are addressed by the byte-exact child path of
// the directory's own mount-table spelling (literalChild), never by a tidied-up
// join: on Linux a backslash is an ordinary character in a filename.
//
// A child that is itself a MOUNT POINT is probed in its OWN backend (finding
// 17). A hero pool is one dataset per share and often per sub-folder, so a ZFS
// dataset mounted beneath a POSIX directory is perfectly ordinary — and probing
// it for system.posix_acl_access, which it does not have, badged every object on
// it "none" and took the NFSv4 warning away entirely. The bound stays one page's
// bound: every probe, whatever backend it asks, spends the same budget.
func probeListing(plat *platform.Platform, osDir string, entries []fsx.Entry, want bool) bool {
	if !want || plat == nil || osDir == "" || !xattrProbeAvailable {
		return false
	}
	bud := &aclBudget{}
	dir := newACLProbe(plat, osDir, want)
	if dir != nil {
		dir.bud = bud
	}
	for i := range entries {
		child := literalChild(osDir, entries[i].Name)
		p := dir
		if entries[i].MountPoint {
			backend, xattr := aclBackendOf(plat, child)
			if backend == "" {
				// A mount with no ACL backend of its own, or one the literal
				// table does not know. Its entry keeps "" — not probed — which
				// is the honest answer and not "none".
				continue
			}
			p = &aclProbe{backend: backend, xattr: xattr, bud: bud}
		}
		if p == nil {
			// The directory has no backend and this child is not a mount of its
			// own: there is nothing to ask.
			continue
		}
		state, ok := p.probe(aclTarget{osPath: child})
		if !ok {
			break
		}
		entries[i].SetACL(state)
	}
	return bud.capped
}

// probeOne is the same probe for a single object — the properties dialog's ACL
// row and the chmod precondition. It has a budget of one, which is the whole
// page it is.
//
// ref is the leaf the caller is HOLDING, and passing it is what makes the answer
// a fact about that inode rather than about its name (finding 4). A caller with
// no descriptor may pass nil and gets the pathname probe, which is what the
// listing's residual already accepts.
func probeOne(plat *platform.Platform, osPath string, ref *itemRef) (backend, xattr, state string) {
	p := newACLProbe(plat, osPath, true)
	if p == nil {
		// Unknown, not none: the caller decides what an unknown backend means,
		// and it must not be handed a confident answer this did not make.
		return "", "", ""
	}
	t := aclTarget{osPath: osPath, held: refFD(ref)}
	if ref != nil && ref.fi != nil {
		t.link = ref.fi.Mode()&fs.ModeSymlink != 0
	}
	state, ok := p.probe(t)
	if !ok {
		return p.backend, p.xattr, ""
	}
	return p.backend, p.xattr, state
}
