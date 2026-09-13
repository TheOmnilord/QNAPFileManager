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
//     complete.
//   - It is a PATHNAME probe (lgetxattr), deliberately. There is no fgetxattrat,
//     and opening every file in a directory to read an attribute would ask for
//     read permission the user may not have — which would turn a badge into a
//     refusal. A name re-pointed between getdents and the probe therefore yields
//     a wrong badge, and that is acceptable precisely because the badge changes
//     nothing the kernel does: it is display, and it is recorded as a residual
//     (contract residual 2).
//
// A read or parse failure is fsx.ACLUnknown and never fsx.ACLNone. Unknown shows
// the badge with the pessimistic text, which is the half that matters.

import (
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
)

// aclProbe is one page's budget. The zero value probes nothing.
type aclProbe struct {
	// backend is platform.ACLPosix or platform.ACLNFS4; xattr is the attribute
	// that backend answers in.
	backend string
	xattr   string

	entries int
	bytes   int
	// capped records that a bound was reached, so the listing can say why some
	// entries carry no badge.
	capped bool
}

// newACLProbe decides whether this listing probes at all, and in which
// attribute. plat == nil, a mount with no ACL backend, and a platform that
// cannot read extended attributes each answer "no" — and "no" means the entries
// keep an empty ACL state, which is "not probed" rather than "no ACL".
func newACLProbe(plat *platform.Platform, osDir string, want bool) *aclProbe {
	if !want || plat == nil || osDir == "" || !xattrProbeAvailable {
		return nil
	}
	caps := plat.For(osDir)
	switch caps.ACLBackend {
	case platform.ACLPosix:
		return &aclProbe{backend: platform.ACLPosix, xattr: platform.XattrPosixACL}
	case platform.ACLNFS4:
		name := caps.ACLXattr
		if name == "" {
			name = platform.XattrNFS4ACL
		}
		return &aclProbe{backend: platform.ACLNFS4, xattr: name}
	}
	return nil
}

// probe classifies one object by its OS path, or reports that the budget is
// spent. The caller leaves Entry.ACL alone when ok is false.
func (p *aclProbe) probe(osPath string) (state string, ok bool) {
	if p == nil || osPath == "" {
		return "", false
	}
	if p.entries >= fsx.ACLProbeMaxEntries || p.bytes >= fsx.ACLProbeMaxBytes {
		p.capped = true
		return "", false
	}
	p.entries++

	size, err := lgetxattrSize(osPath, p.xattr)
	switch {
	case absentXattrErr(err):
		return fsx.ACLNone, true
	case err != nil:
		return fsx.ACLUnknown, true
	}
	if p.backend == platform.ACLPosix {
		// The POSIX question is exactly the "+" in ls -l: is the access ACL
		// there and non-empty. The bytes are never read, so a directory of ten
		// thousand entries costs one size query each.
		if size <= 0 {
			return fsx.ACLNone, true
		}
		return fsx.ACLPosix, true
	}
	if size <= 0 {
		// An NFSv4 attribute that is present and empty parses as nothing, and
		// nothing is not "no ACL" — it is an attribute this cannot read.
		return fsx.ACLUnknown, true
	}
	buf, err := lgetxattrRead(osPath, p.xattr, size)
	p.bytes += len(buf)
	switch {
	case absentXattrErr(err):
		// Removed between the two calls: the honest answer is that there is
		// none now.
		return fsx.ACLNone, true
	case err != nil:
		return fsx.ACLUnknown, true
	}
	return perm.NFS4State(buf), true
}

// probeListing fills Entry.ACL for one page of a listing and reports whether a
// bound was reached. The entries are addressed by the byte-exact child path of
// the directory's own mount-table spelling (literalChild), never by a tidied-up
// join: on Linux a backslash is an ordinary character in a filename.
func probeListing(plat *platform.Platform, osDir string, entries []fsx.Entry, want bool) bool {
	p := newACLProbe(plat, osDir, want)
	if p == nil {
		return false
	}
	for i := range entries {
		state, ok := p.probe(literalChild(osDir, entries[i].Name))
		if !ok {
			break
		}
		entries[i].SetACL(state)
	}
	return p.capped
}

// probeOne is the same probe for a single object — the properties dialog's ACL
// row. It has a budget of one, which is the whole page it is.
func probeOne(plat *platform.Platform, osPath string) (backend, xattr, state string) {
	p := newACLProbe(plat, osPath, true)
	if p == nil {
		return platform.ACLNone, "", ""
	}
	state, ok := p.probe(osPath)
	if !ok {
		return p.backend, p.xattr, ""
	}
	return p.backend, p.xattr, state
}
