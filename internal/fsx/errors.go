package fsx

import (
	"context"
	"errors"
	"io/fs"
	"syscall"
)

// The sentinels. Everything the daemon refuses on its own — as opposed to
// something the kernel refused — is one of these, wrapped with a message that
// names the path and the reason.
var (
	// ErrNotAbsolute: an API path that was empty or relative.
	ErrNotAbsolute = errors.New("path must be absolute")
	// ErrBadName: a name or path the daemon will not pass to a syscall.
	ErrBadName = errors.New("invalid name")
	// ErrOutsideRoot: an OS path that does not lie under the -jail root.
	ErrOutsideRoot = errors.New("path is outside the root")
	// ErrProtected: the guard's rule table refuses this path.
	ErrProtected = errors.New("path is protected")
	// ErrReadOnly: global read-only mode is on.
	ErrReadOnly = errors.New("read-only mode is enabled")
	// ErrRAMDisk: writing directly into the QTS /share RAM disk.
	ErrRAMDisk = errors.New("that directory is on the QTS RAM disk")
	// ErrCrossDevice: a rename across filesystems, which on QuTS hero means
	// across shares, since every share is its own dataset.
	ErrCrossDevice = errors.New("source and destination are on different filesystems")
	// ErrNoSpace: no room, or the user's quota is exhausted.
	ErrNoSpace = errors.New("not enough free space")
	// ErrConfirmRequired: the operation needs a confirmation token.
	ErrConfirmRequired = errors.New("confirmation required")
	// ErrUnsupported: not available on this platform or filesystem.
	ErrUnsupported = errors.New("operation is not supported here")
	// ErrWorkerGone: the per-user worker died or was reaped mid-call.
	ErrWorkerGone = errors.New("the worker process is gone")
	// ErrQueueFull: the job queue is at its limit.
	ErrQueueFull = errors.New("the queue is full")
	// ErrOwnerUnset: a create SUCCEEDED but the follow-up chown to the real user
	// did not (the admin-as-real-user mkdir path), so the new item exists but is
	// still owned by the daemon. It is positive proof the item was created and
	// the ownership step failed — the front-end reports "owner_unset" on this
	// code alone, never inferring it from an item merely existing (which a
	// pre-existing file plus an unrelated create failure would falsely satisfy).
	ErrOwnerUnset = errors.New("the item was created but its owner could not be set")
)

// Code maps an error to the API's error vocabulary, as fixed by
// docs/design/backend-packaging-plan.md §4.2:
//
//	bad_request unauthorized not_found exists not_empty permission protected
//	readonly ramdisk cross_device no_space too_large unsupported conflict
//	confirm_required cancelled queue_full internal
//
// Anything unrecognised is "internal" — deliberately, so a new failure mode
// shows up as a 500 in the logs rather than being quietly mislabelled as
// something the UI knows how to shrug off.
func Code(err error) string {
	switch {
	case err == nil:
		return ""

	// Our own sentinels first: several of them wrap a syscall error whose
	// generic mapping would be less informative than the reason we refused.
	case errors.Is(err, ErrProtected):
		return "protected"
	case errors.Is(err, ErrReadOnly):
		return "readonly"
	case errors.Is(err, ErrRAMDisk):
		return "ramdisk"
	case errors.Is(err, ErrConfirmRequired):
		return "confirm_required"
	case errors.Is(err, ErrQueueFull):
		return "queue_full"
	case errors.Is(err, ErrOwnerUnset):
		return "owner_unset"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrCrossDevice):
		return "cross_device"
	case errors.Is(err, ErrNoSpace):
		return "no_space"
	case errors.Is(err, ErrNotAbsolute), errors.Is(err, ErrBadName), errors.Is(err, ErrOutsideRoot):
		return "bad_request"
	// A dead worker is our bug or a crash, not something the caller did, but
	// it needs its own code: the pool reconstructs remote errors from the
	// code alone, and callers must still recognise the ErrWorkerGone sentinel.
	case errors.Is(err, ErrWorkerGone):
		return "worker_gone"

	case errors.Is(err, context.Canceled):
		return "cancelled"

	// Kernel truth (INV-2). fs.ErrPermission covers both EACCES and EPERM.
	case errors.Is(err, fs.ErrNotExist):
		return "not_found"
	// ENOTEMPTY must be tested before fs.ErrExist: on Windows syscall.Errno.Is
	// reports ENOTEMPTY (and ERROR_DIR_NOT_EMPTY) as ErrExist, so the reverse
	// order silently turns "the folder still has files in it" into "already
	// exists" — on the dev box only, which is where it would be missed.
	case errors.Is(err, syscall.ENOTEMPTY):
		return "not_empty"
	case errors.Is(err, fs.ErrExist):
		return "exists"
	case errors.Is(err, syscall.EXDEV):
		return "cross_device"
	case errors.Is(err, syscall.ENOSPC):
		return "no_space"
	// EDQUOT is a quota, not a full filesystem, but the user-facing advice is
	// the same; the message carries the distinction. Every errno named here is
	// defined by package syscall on Windows too (as an invented value), so no
	// _linux/_windows split is needed for this file.
	case errors.Is(err, syscall.EDQUOT):
		return "no_space"
	case errors.Is(err, syscall.EROFS):
		return "readonly"
	// A symlink loop and an over-long name are both malformed input.
	case errors.Is(err, syscall.ELOOP):
		return "bad_request"
	case errors.Is(err, syscall.ENAMETOOLONG):
		return "bad_request"
	case errors.Is(err, syscall.EBUSY):
		return "conflict"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	}
	return "internal"
}

// Errno digs the raw syscall.Errno out of an error so the worker can put the
// number on the wire and the front-end can be specific about it. It returns 0
// when there is none.
func Errno(err error) int {
	var e syscall.Errno
	if errors.As(err, &e) {
		return int(e)
	}
	return 0
}
