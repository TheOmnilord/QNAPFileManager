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
//
// expect, when the caller supplies one, is the PRECONDITION the confirmation
// ladder was graded against, and it is proved on the held leaf before a single
// bit is changed (§8.1 as amended; Astra M3 round-1 finding 4). Nil means the
// caller asserted nothing.
func Chmod(ctx context.Context, r fsx.Root, plat *platform.Platform, apiPath string,
	spec perm.ModeSpec, expect *wproto.ACLExpect) (wproto.ModeResp, error) {
	return modeOne(ctx, r, plat, apiPath, spec, -1, -1, false, expect)
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
	// No ACL precondition: a chown neither reads nor rewrites an ACL, so there
	// is no ladder grade for one to protect.
	return modeOne(ctx, r, plat, apiPath, perm.ModeSpec{}, uid, gid, true, nil)
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
	spec perm.ModeSpec, uid, gid int, allowSymlink bool, expect *wproto.ACLExpect) (wproto.ModeResp, error) {

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

	if err := proveExpectation(r, plat, tg, ref, expect); err != nil {
		return wproto.ModeResp{}, err
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

// proveExpectation re-proves, on the HELD leaf, the two facts the confirmation
// ladder was graded against: which object this is, and what its ACL says
// (m3-contract §8.1 as amended; Astra M3 round-1 finding 4).
//
// It exists because the grading and the change are two round trips and the gap
// between them belongs to the client. Props describes an object, the front end
// decides from that description whether a typed phrase is needed, and the chmod
// arrives later — so somebody who can write in the parent directory can let a
// trivial file be graded, swap a non-trivial one over the name, and have the
// chmod discard an ACL nobody was ever warned about. The canonical walk already
// refuses a symlink among the components, but a plain rename of a sibling over
// the leaf's name is not a symlink and was never caught.
//
// Both halves are asked of the descriptor this call is holding, never of a name.
// The identity comparison is the one every pinned authorization in this app uses
// (device and inode, plus birth time when both sides have one), and the ACL is
// re-probed through /proc/self/fd/N of that same descriptor, which is what makes
// "the state has not moved" a statement about an inode.
//
// A nil expectation asserts nothing and is the ordinary case for a job, which
// grades no entry individually and can promise nothing about one.
func proveExpectation(r fsx.Root, plat *platform.Platform, tg jailPath, ref *itemRef, expect *wproto.ACLExpect) error {
	if expect == nil {
		return nil
	}
	if ref == nil {
		// Nothing is held, so nothing can be proved — and an unprovable
		// precondition is a refusal, not a pass.
		return fmt.Errorf("%q cannot be held long enough to prove what was confirmed: %w", tg.api, fsx.ErrChanged)
	}
	held := identityOfInfo(itemIdentityOf(ref), ref.fi, refFD(ref))
	if !unidentifiableObject(held, expect.Identity) && !held.SameInode(expect.Identity) {
		return fmt.Errorf(
			"%q is not the item the confirmation was given for; it was replaced after it was described: %w",
			tg.api, fsx.ErrChanged)
	}
	if expect.State == "" {
		// Nothing was observed when the object was described, so there is no ACL
		// claim to hold it to and the identity is the whole of the precondition
		// (Astra r2 #1/#6). Probing again here would only invent one.
		return nil
	}
	osPath, osErr := r.OS(tg.api)
	if osErr != nil {
		osPath = ""
	}
	_, _, state := probeOne(plat, osPath, ref)
	if !stateSatisfies(expect.State, state) {
		// Either direction is a refusal. A state that has become MORE serious is
		// the attack; one that has become less is still a tree that moved under a
		// decision the user made about something else, and the honest answer is
		// to ask again rather than to act on a grade nobody gave.
		return fmt.Errorf(
			"%q now has a %s ACL where the confirmation described %s; nothing was changed: %w",
			tg.api, aclWord(state), aclWord(expect.State), fsx.ErrChanged)
	}
	return nil
}

// stateSatisfies reports whether a re-probed ACL state honours the expectation.
//
// An EMPTY expectation is the absence of a claim and not a claim of absence
// (Astra r2 #1 in its second costume). The route sends what the worker OBSERVED
// when it described the object, so "" means "nothing was learned then" — and
// comparing that literally against a fresh reading made this side of the gap
// refuses a change nobody tampered with as soon as the two readings can differ
// for an innocent reason. They now can: the mount probe that decides whether
// there is a backend to read at all runs ASYNCHRONOUSLY after a refresh, so a
// mount that was unplaced during Props can be "posix" by the time the chmod
// arrives, and the object itself never moved. What "" leaves standing is the
// identity, which is the half that catches the swap this precondition exists
// for; the ACL half is proved when, and only when, there is an observation to
// prove it against.
func stateSatisfies(want, got string) bool {
	if want == "" {
		return true
	}
	return want == got
}

// unidentifiableObject reports that NEITHER side of an expectation carries an
// inode number, on a platform that has none to carry (Astra r2 #6).
//
// SameInode reads a zero inode as "identifies nothing", which is exactly right
// on Linux: an inode number that could not be read is not a proof, and a
// precondition that cannot be proved is a refusal. Off Linux there is no inode
// behind a FileInfo at all (inodeIdentity, copy_other.go), so BOTH the grade and
// the held leaf report the platform's own zero identity and every dev-loop chmod
// with a precondition failed "changed" — against §14, which asks the dev loop to
// answer best effort and states its degradation rather than faking one.
//
// So a zero on both sides, where the platform has no identities at all, is
// "nothing to compare" and the STATE alone is proved. On Linux nothing moves:
// inodeIdentity is true there, so a zero inode from a real filesystem stays the
// mismatch it has always been.
func unidentifiableObject(held, want wproto.FSIdentityResp) bool {
	return !inodeIdentity && held.Ino == 0 && want.Ino == 0
}

// aclWord spells an ACL state for the one sentence above, including the empty
// state, which is "not probed" and not a fact about the file.
func aclWord(state string) string {
	if state == "" {
		return "an unprobed"
	}
	return state
}
