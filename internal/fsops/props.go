package fsops

// OpProps: everything the properties dialog shows about one path, from one
// canonical walk (m3-contract §8).
//
// It is a plain operation and not a job. One O_NOFOLLOW walk, one fstat on the
// held leaf, one fstatfs on that same descriptor, one xattr probe, and the mount
// facts out of the table the front end reads too — so the dialog and the
// confirmation ladder agree by construction rather than by two implementations
// happening to match (the trash-root argument, M2-A).
//
// The one thing it deliberately does NOT do is measure a directory. Size is a
// job, the dialog submits the existing one, polls it like any other and cancels
// it when it closes; a second size implementation living behind this call would
// be an uncancellable walk on a 15-second handler context.

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// Props describes one already-canonical path, and — when the caller supplies
// one — the already-resolved target of a symlink.
//
// targetPath is NOT resolved here, and that is the whole of the round-3 fix.
// This used to call StatFollow on the leaf, which resolves the link a second
// time, inside the worker, separated from the route's guard by a gap the client
// chooses: a link re-pointed in between was described from a path the guard had
// never seen. Now the route resolves it as the user, checks the guard on THAT
// spelling and sends it here, and this walks it O_NOFOLLOW per component like
// every other canonical path — a symlink among them is fsx.ErrChanged, never
// something to follow.
//
// An empty targetPath leaves Target nil, which is also what a DANGLING link
// produces: the route has no resolved spelling to send for one. The link itself
// is still fully described, because the dialog is exactly where somebody goes to
// find out that a link is broken.
func Props(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath, targetPath string) (wproto.PropsResp, error) {
	clean, err := fsx.Clean(apiPath)
	if err != nil {
		return wproto.PropsResp{}, err
	}
	if err := ctx.Err(); err != nil {
		return wproto.PropsResp{}, err
	}
	// Not resolve(): the caller sends the spelling its own guarded resolution
	// produced, and a second following resolution here would describe whatever
	// the tree says now (canonical.go).
	parent, ref, _, tg, err := canonicalLeaf(r, clean)
	if err != nil {
		return wproto.PropsResp{}, err
	}
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	if err := ctx.Err(); err != nil {
		return wproto.PropsResp{}, err
	}

	var (
		fi  fs.FileInfo
		id  mountIdentity
		res wproto.PropsResp
	)
	if ref == nil {
		// The jail base: no name below anything to open it by, so the stat comes
		// from the handle and there is no descriptor to fstatfs or to probe.
		if fi, err = statAt(tg.jail, tg.rel); err != nil {
			return wproto.PropsResp{}, err
		}
		id.dev, id.hasDev = devOf(fi)
	} else {
		fi = ref.fi
		id = itemIdentityOf(ref)
	}

	ids := IDMap()
	res.Entry = newEntry(clean, []byte(fsx.Base(clean)), fi, ids)
	if res.Entry.IsSymlink {
		if targetPath == "" {
			// Nobody told us where it lands, so the raw link text is all that can
			// be published about it — and the type and the resolved spelling are
			// worked out the way every listing works them out. That is a
			// following resolution, and it is the caller's job to avoid needing
			// it by sending Target.
			resolveLink(&res.Entry, r, tg.jail, tg.rel, clean, true, true)
		} else {
			// Only the raw readlink text; where it LANDS is the caller's already
			// guarded answer, not a second resolution of our own.
			resolveLink(&res.Entry, r, tg.jail, tg.rel, clean, false, false)
			t, terr := propsTarget(ctx, r, targetPath, ids)
			if terr != nil {
				// A symlink among the target's components is evidence the tree
				// moved after the route guarded it, and the dialog must not
				// describe an object nobody authorised. Anything else — the
				// target has since been removed, say — is simply no target, and
				// the link is still described.
				if errors.Is(terr, fsx.ErrChanged) {
					return wproto.PropsResp{}, terr
				}
			} else {
				res.Target = &t
				res.Entry.SetLinkResolved([]byte(t.Path))
				res.Entry.TargetType = t.Type
			}
		}
	}
	res.Identity = identityOfInfo(id, fi, refFD(ref))

	osPath, osErr := r.OS(tg.api)
	if osErr != nil {
		osPath = ""
	}
	res.FS = fsInfoFor(plat, osPath)
	// ref, not osPath alone: the ACL state this reports is what the confirmation
	// ladder grades, so it has to describe the inode the dialog is about to offer
	// a chmod of rather than whatever answers to its name (finding 4).
	res.ACL = aclInfoFor(plat, osPath, ref)
	if avail, total, ok := statfsHeld(ref); ok {
		res.FS.Avail, res.FS.Total = avail, total
	}
	// The per-entry ACL state goes on the entry as well as in ACLInfo, so a
	// dialog opened directly on a path badges it the same way the listing that
	// led there would have.
	if res.ACL.State != "" {
		res.Entry.SetACL(res.ACL.State)
	}
	return res, nil
}

// propsTarget describes a symlink's already-resolved target, through the same
// no-follow walk every other canonical path gets.
//
// The leaf is described as whatever it is, link included: if the route's
// resolution has gone stale and the target is itself a symlink now, that is what
// the dialog should say rather than something this chased one hop further.
func propsTarget(ctx context.Context, r fsx.Root, targetPath string, ids *idmap.Map) (fsx.Entry, error) {
	clean, err := fsx.Clean(targetPath)
	if err != nil {
		return fsx.Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return fsx.Entry{}, err
	}
	parent, ref, _, tg, err := canonicalLeaf(r, clean)
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	if err != nil {
		return fsx.Entry{}, err
	}
	var fi fs.FileInfo
	if ref == nil {
		// The jail base as a link target: no name below anything to open it by,
		// so the stat comes from the handle.
		if fi, err = statAt(tg.jail, tg.rel); err != nil {
			return fsx.Entry{}, err
		}
	} else {
		fi = ref.fi
	}
	e := newEntry(clean, []byte(fsx.Base(clean)), fi, ids)
	if e.IsSymlink {
		resolveLink(&e, r, tg.jail, tg.rel, clean, false, false)
	}
	return e, nil
}

// fsInfoFor describes the filesystem holding an OS path from the mount table.
// Avail and Total are NOT filled here: they come from fstatfs on the held
// descriptor, which is the only source that describes the filesystem the opened
// object is really on.
func fsInfoFor(plat *platform.Platform, osPath string) wproto.FSInfo {
	if plat == nil || osPath == "" {
		return wproto.FSInfo{}
	}
	caps := plat.For(osPath)
	info := wproto.FSInfo{
		FSType:  caps.FSType,
		Mount:   caps.Mount,
		Domain:  caps.Domain,
		Network: caps.Network,
	}
	if m, ok := plat.MountFor(osPath); ok {
		if info.Mount == "" {
			info.Mount = m.MountPoint
		}
		info.ReadOnly = mountIsReadOnly(m)
	}
	return info
}

// mountIsReadOnly reads the "ro" option off a mount. Both the per-mount options
// and the per-superblock options are consulted, because a read-only bind mount
// of a writable filesystem says it in the first and a filesystem mounted
// read-only says it in the second — and a dialog that showed "writable" for
// either would be wrong in the direction that matters.
func mountIsReadOnly(m platform.Mount) bool {
	for _, opts := range [][]string{m.Options, m.SuperOptions} {
		for _, o := range opts {
			if strings.EqualFold(o, "ro") {
				return true
			}
		}
	}
	return false
}

// aclInfoFor assembles the authoritative display copy of an object's ACL
// situation: the mount's backend and aclmode from the table, the dataset name
// the level-2 dialog has to be able to say, and this object's own probed state.
//
// Every lookup here is the LITERAL one (finding 2). Platform.For and MountFor
// normalise — a backslash becomes a separator and the result is Cleaned — and on
// Linux a backslash is an ordinary character in a filename, so a file literally
// named `danger/..\safe/file` was graded on the `safe` dataset while the chmod
// changed an inode on `danger`. ForLiteral and MountForLiteral answer from the
// same byte-exact match, so the aclmode and the dataset NAME in the level-2
// sentence describe one mount rather than two.
//
// An unmatched literal lookup leaves Backend empty, and empty means UNKNOWN. It
// is deliberately not promoted to platform.ACLNone: "none" is the one answer
// that silences the warning, and a mount this could not identify has not earned
// it. The caller grades an empty backend pessimistically.
//
// ZFSAclmode is reported exactly as the table holds it, empty included. An empty
// value means `zfs get` could not be called or gave no answer, and the front end
// treats that as "discard" — the pessimistic reading, which is the only honest
// one (identity plan §4.4 is explicit: never guess). Filling in a plausible
// default here would take that decision away from the side that has to make it.
func aclInfoFor(plat *platform.Platform, osPath string, ref *itemRef) wproto.ACLInfo {
	if plat == nil || osPath == "" {
		// There is no mount table to ask and no path to ask about — the dev
		// loop's degradation (§14), not a mount this failed to identify.
		return wproto.ACLInfo{Backend: platform.ACLNone}
	}
	caps, _ := plat.ForLiteral(osPath)
	info := wproto.ACLInfo{
		Backend: caps.ACLBackend,
		Xattr:   caps.ACLXattr,
		Aclmode: caps.ZFSAclmode,
	}
	if m, ok := plat.MountForLiteral(osPath); ok && strings.EqualFold(m.FSType, "zfs") {
		info.Dataset = m.Source
	}
	backend, xattr, state := probeOne(plat, osPath, ref)
	if state != "" {
		info.State = state
		if info.Xattr == "" {
			info.Xattr = xattr
		}
		if info.Backend == "" || info.Backend == platform.ACLNone {
			info.Backend = backend
		}
	}
	return info
}
