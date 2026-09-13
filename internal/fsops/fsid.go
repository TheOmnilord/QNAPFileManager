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
	// followFinal is false: the thing named is the thing measured.
	tg, err := resolve(r, clean, false)
	if err != nil {
		return wproto.FSIdentityResp{}, err
	}
	if err := ctx.Err(); err != nil {
		return wproto.FSIdentityResp{}, err
	}

	var (
		id mountIdentity
		fi os.FileInfo
	)
	if tg.rel == "." || tg.rel == "" {
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
		ref, err := openItemRef(tg.jail, tg.rel)
		if err != nil {
			return wproto.FSIdentityResp{}, err
		}
		defer ref.close()
		fi = ref.fi
		id = itemIdentityOf(ref)
	}

	return wproto.FSIdentityResp{
		Mount:    id.mnt,
		HasMount: id.hasMnt,
		Dev:      id.dev,
		Dir:      fi.IsDir(),
	}, nil
}
