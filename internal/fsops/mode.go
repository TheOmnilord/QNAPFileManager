package fsops

// chmod, chown and properties: the M3 single-item operations (m3-contract §2,
// §3 and §8).
//
// Three rules shape every one of them, and all three are the copy engine's
// descriptor discipline applied to metadata rather than to bytes.
//
//  1. The path is NOT resolved here. What the route dispatches is already the
//     canonical spelling its own guarded resolution produced, and resolving it a
//     second time would follow whatever the tree says now — so an ancestor
//     swapped for a symlink between the authorization and the call would be
//     followed, and the guard, which passed judgement on a different tree, would
//     never be asked again. canonicalLeaf walks it O_NOFOLLOW per component and
//     a symlink among them is fsx.ErrChanged: evidence, not a way down.
//
//  2. The syscall addresses the DESCRIPTOR, never a name. chmod goes through
//     /proc/self/fd/N on the held O_PATH handle — the idiom this tree already
//     uses to publish an unnamed file (unnamed_linux.go) — and chown through
//     fchownat(fd, "", AT_EMPTY_PATH). Both act on that inode and on nothing
//     that merely answers to its name.
//
//  3. The stat before and the stat after come from that same descriptor. It is
//     the DIFF between them that the user is shown, so a wrong object there is
//     not a nuisance, it is a lie: "the setgid bit was not applied" about a file
//     that is not the one they asked about.
//
// What is deliberately not here: the protected-path table, the read-only
// toggle, the confirmation ladder and the aclmode warnings. All of that is the
// root front-end's guard, before the RPC (INV-1, PLAN.md decision 7). This file
// makes the syscall and reports what the kernel said (INV-2).

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// Chmod applies a mode CHANGE to one already-canonical path and reports what
// the kernel made of it.
//
// spec is a mask and a value, not an absolute mode, so the same call serves a
// full set (mask 07777), a single touched bit, and the three special bits
// (contract §1.1). The mode it is applied to is read from the held descriptor
// immediately before the call, so nothing has to be trusted about what the front
// end believed the mode was.
//
// A symlink leaf is refused with fsx.ErrUnsupported and never followed. Linux
// has no lchmod, and reaching through the link would change an object the guard
// never saw; ChmodReq.Follow is the ROUTE's instruction to resolve the link and
// re-guard the target as a path of its own, so by the time a request reaches
// here the spelling is already the target (§1.4).
func Chmod(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string, spec perm.ModeSpec) (wproto.ModeResp, error) {
	return modeOne(ctx, r, plat, apiPath, spec, -1, -1, false)
}

// Chown changes owner and/or group of one already-canonical path. -1 leaves
// that half alone, exactly as chown(2) reads it.
//
// It is always an lchown: the held descriptor was opened O_NOFOLLOW, so a
// symlink's OWN ownership is what changes and the target is never touched. That
// is why a symlink leaf is allowed here where chmod refuses one, and why
// ChownReq.Follow is refused as unsupported before this is called — one chown
// semantics, and no path on which a link is silently reached through.
//
// The kernel is what decides whether this is allowed, and its refusal is
// reported unchanged (INV-2). It is also what CLEARS setuid, and setgid on a
// group-executable file, when ownership changes — which no call can prevent and
// which the returned diff is there to report (§3.2).
func Chown(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string, uid, gid int) (wproto.ModeResp, error) {
	return modeOne(ctx, r, plat, apiPath, perm.ModeSpec{}, uid, gid, true)
}

// modeOne is the shared body of Chmod and Chown: one canonical walk, one held
// leaf, fstat, the syscall, fstat, and the diff between the two.
//
// A zero spec with real ids is a chown; a real spec with -1/-1 is a chmod. They
// share this because everything around the single syscall is identical, and
// because the diff has to be computed the same way for both — a chown's own
// diff is a mode difference (the setuid the kernel cleared), which a chown-only
// path would have had no reason to look for.
func modeOne(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string,
	spec perm.ModeSpec, uid, gid int, allowSymlink bool) (wproto.ModeResp, error) {

	_ = plat
	clean, err := fsx.Clean(apiPath)
	if err != nil {
		return wproto.ModeResp{}, err
	}
	if err := ctx.Err(); err != nil {
		return wproto.ModeResp{}, err
	}
	parent, ref, name, tg, err := canonicalLeaf(r, clean)
	if err != nil {
		return wproto.ModeResp{}, err
	}
	if parent != nil {
		defer parent.close()
	}
	if ref != nil {
		defer ref.close()
	}
	if ref == nil {
		// The jail base — "/" in production. There is no parent descriptor to
		// address it through, and nobody means to chmod the root of the
		// filesystem; the guard refuses it too.
		return wproto.ModeResp{}, fmt.Errorf("%q is the root of the tree and its permissions are not ours to change: %w",
			tg.api, fsx.ErrBadName)
	}
	if err := ctx.Err(); err != nil {
		return wproto.ModeResp{}, err
	}

	beforeInfo := ref.fi
	if beforeInfo.Mode()&fs.ModeSymlink != 0 && !allowSymlink {
		return wproto.ModeResp{}, fmt.Errorf(
			"%q is a symlink and Linux cannot change a symlink's mode; resolve it first and change the target as its own path: %w",
			clean, fsx.ErrUnsupported)
	}

	var afterInfo os.FileInfo
	if allowSymlink {
		afterInfo, err = chownHeld(parent, name, ref, uid, gid)
	} else {
		afterInfo, err = chmodHeld(parent, name, ref, spec.Apply(perm.Bits(beforeInfo.Mode())))
	}
	if err != nil {
		return wproto.ModeResp{}, err
	}

	ids := IDMap()
	base := []byte(fsx.Base(clean))
	before := newEntry(clean, base, beforeInfo, ids)
	after := newEntry(clean, base, afterInfo, ids)
	// A symlink's own target is worth carrying in both halves: the dialog that
	// chowned a link is about to redraw the row it came from. Only the raw
	// readlink is read — resolving where it lands is the properties dialog's
	// job, and costs a walk this call has no reason to make.
	if before.IsSymlink {
		resolveLink(&before, r, tg.jail, tg.rel, clean, false, false)
		resolveLink(&after, r, tg.jail, tg.rel, clean, false, false)
	}
	return wproto.ModeResp{
		Before: before,
		Entry:  after,
		Diffs:  perm.DiffOf(spec, uid, gid, before, after),
	}, nil
}
