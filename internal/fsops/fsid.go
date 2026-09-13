package fsops

// The move pre-flight's worker half (M2-B contract §1.2).
//
// A move between two shares of one QuTS hero pool is an ordinary rename to look
// at and an EXDEV to the kernel: every share is its own dataset, so rename(2)
// refuses it and the move has to become copy-verify-delete. That changes what
// the user is agreeing to — minutes instead of an instant, cancellable, and a
// cancellation that leaves both copies — so the confirm dialog has to say so
// before the job starts.
//
// This is the measurement the prediction is made from, and it is deliberately
// only a PREDICTION: the engine still relies on the kernel's own EXDEV and
// never on this answer (INV-2). What the front-end gets is the identity of the
// filesystem behind an opened descriptor, taken exactly the way the walk takes
// it — the statx mount id where the kernel gives one, st_dev otherwise. The
// mount id is what matters on QTS, where the share layout is built out of bind
// mounts: two bind mounts of one device share a st_dev and have two mount ids,
// so a device comparison alone would predict "same filesystem" for a pair that
// renames perfectly well, and — worse — could predict it for a pair that does
// not.
//
// It runs in the worker, as the user, because the walk that reaches the path is
// the user's own: a path the user cannot traverse must answer EACCES here, not
// be resolved on their behalf by the root front-end (INV-2, the round-3
// finding ResolvePath exists for).

import (
	"context"
	"os"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// FSIdentity reports which filesystem holds apiPath.
//
// The entry itself is described and never followed — a symlink answers for the
// link, which is the object a move would rename — and the identity is taken
// from a HELD O_PATH descriptor rather than from a pathname: between an lstat
// and an answer a name can be re-pointed, and the whole value of this reply is
// that it describes one particular object.
//
// plat is accepted for symmetry with the rest of this package's entry points
// and is deliberately unused: the mount table cannot answer this question. It
// describes pathnames, and the caller is asking about a descriptor.
func FSIdentity(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string) (wproto.FSIdentityResp, error) {
	_ = plat
	clean, err := fsx.Clean(apiPath)
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	if err := ctx.Err(); err != nil {
		return wproto.FSIdentityResp{}, err
	}
	// NOT resolve(): the caller is the front-end, and what it sends is the
	// spelling its own guarded resolution produced (round 14 adversarial). A
	// second, FOLLOWING resolution here would walk whatever the tree says now —
	// so an ancestor swapped for a symlink in between would be followed, and
	// the identity this reply carries would describe the replacement perfectly.
	// The walk below follows nothing and refuses a symlink ancestor as evidence
	// that the tree changed; the leaf is described as itself, link or not,
	// which is what "the thing named is the thing measured" has always meant
	// here.
	parent, ref, _, tg, err := canonicalLeaf(r, clean)
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	if err := ctx.Err(); err != nil {
		return wproto.FSIdentityResp{}, err
	}

	var (
		id mountIdentity
		fi os.FileInfo
		fd *os.File
	)
	if ref == nil {
		// The jail base itself — "/" in production. There is no name below
		// anything to open it by (the lookup that would answer it lives in its
		// parent, outside the jail), so the identity comes from the stat of the
		// handle and the mount id is simply not available. st_dev is a complete
		// answer for a filesystem root, which is what this path always is.
		if fi, err = statAt(tg.jail, tg.rel); err != nil {
			return wproto.FSIdentityResp{}, err
		}
		id.dev, id.hasDev = devOf(fi)
	} else {
		fi = ref.fi
		id = itemIdentityOf(ref)
		fd = refFD(ref)
	}

	return identityOfInfo(id, fi, fd), nil
}

// identityOfInfo assembles the reply from a mount identity and the stat of the
// object it was taken from.
//
// Ino is what turns "which filesystem" into "which OBJECT", and it is the half
// an authorization is pinned to (M2-C review round 13): the front-end clears a
// directory, the worker opens it some time later, and the pathname in between
// is not a promise. It comes from inodeOf, so off Linux — where a FileInfo
// carries no inode number — it is simply absent, and SameInode's rule that a
// zero inode identifies nothing is what keeps that from being read as a match.
// The birth time comes from the DESCRIPTOR, which is why f is carried here at
// all: it is what an inode number recycled across a client-controlled gap
// cannot forge (round 14 adversarial, btime_linux.go). A caller with no
// descriptor — the jail base, which has no name to open — simply reports none,
// and the comparison degrades to device and inode.
func identityOfInfo(id mountIdentity, fi os.FileInfo, f *os.File) wproto.FSIdentityResp {
	resp := wproto.FSIdentityResp{
		Mount:    id.mnt,
		HasMount: id.hasMnt,
		Dev:      id.dev,
		Dir:      fi != nil && fi.IsDir(),
	}
	if k, ok := inodeOf(fi); ok {
		resp.Ino = k.ino
		if !resp.HasMount && id.dev == 0 {
			// devOf and inodeOf read the same Stat_t; where the first was not
			// available the second's device is still the right answer.
			resp.Dev = k.dev
		}
	}
	if oid := objectIDOf(f, fi); oid.hasBtime {
		resp.Btime, resp.HasBtime = oid.btime, true
	}
	return resp
}

// heldIdentityOf is identityOfInfo for a directory this process is HOLDING,
// which is the only form the upload's check may use: the question it answers is
// "is this descriptor the object that was authorized", and a descriptor is the
// one thing a rename cannot re-point underneath it.
func heldIdentityOf(d *dirRef) (wproto.FSIdentityResp, error) {
	fi, err := d.stat()
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	return identityOfInfo(identityFor(d), fi, d.f), nil
}
