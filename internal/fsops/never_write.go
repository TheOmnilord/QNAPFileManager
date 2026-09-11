package fsops

// The worker's own never-write component rule (M2-A review round 1, finding
// F10).
//
// The front-end guard already refuses these names — neverWriteReason in
// internal/guard — but it only ever sees a job's ROOT paths. "Delete
// /share/Public" is one guarded path and a million unguarded ones: every entry
// the recursion then reaches was never shown to the guard at all. So the
// mutating walks repeat the rule per component, on the worker side, where the
// recursion actually happens.
//
// Two names are refused:
//
//   - ".zfs" is the ZFS snapshot directory. It is read-only in the kernel, its
//     contents are snapshots rather than files, and it can be enormous — a
//     delete that descended into it would ask the kernel a million times for
//     something it will never grant, and a size probe would count the whole
//     history of the share.
//   - "@Recycle" is QTS's own recycle bin. PLAN.md decision 10 is explicit that
//     it is never written to: its restore metadata is a firmware-private format,
//     and anything this app put there or took from there is something File
//     Station would then mis-handle. It stays an ordinary directory that can be
//     read and listed.
//
// That asymmetry is the reason there are two levels rather than one: a read-only
// walk (Size) skips ".zfs" because descending it is pointless and expensive, and
// counts "@Recycle" because reading it is harmless and its bytes are real.

import (
	"fmt"

	"qnapfilemanager/internal/fsx"
)

// Protect says which never-write components a walk refuses to enter (F10).
type Protect int

const (
	// ProtectNone refuses nothing. It is the zero value, for the internal walks
	// that are neither mutating nor user-visible.
	ProtectNone Protect = iota
	// ProtectSnapshots refuses ".zfs" only: the read-only walks, which may read
	// @Recycle but have no business counting a snapshot tree.
	ProtectSnapshots
	// ProtectWrite refuses ".zfs" and "@Recycle": every mutating walk.
	ProtectWrite
)

// refuses reports whether a component named name is refused at this level, and
// why. The reason is path-free, exactly as the guard's is, so it can be shown to
// a client without disclosing a resolved spelling.
func (p Protect) refuses(name string) (string, bool) {
	switch name {
	case ".zfs":
		if p == ProtectSnapshots || p == ProtectWrite {
			return "a read-only ZFS snapshot directory", true
		}
	case "@Recycle":
		if p == ProtectWrite {
			return "the QTS recycle bin, which this app never writes to", true
		}
	}
	return "", false
}

// NeverWriteName reports whether a single path component names something the
// worker must never create in, write to, or remove, and why (F10). It is
// ProtectWrite expressed as a function, and it mirrors the guard's
// neverWriteReason for the two names that are matched as components rather than
// as prefixes.
func NeverWriteName(name string) (reason string, hit bool) {
	return ProtectWrite.refuses(name)
}

// neverWriteErr builds the refusal a walk or a selected path reports. It wraps
// fsx.ErrProtected, so the one error vocabulary the whole app speaks turns it
// into the "protected" warning code without anything having to spell that out.
func neverWriteErr(apiPath, reason string) error {
	return fmt.Errorf("%q is %s and is never written to: %w", apiPath, reason, fsx.ErrProtected)
}

// neverWritePath reports whether any component of an already-cleaned API path is
// one the worker must never write through, and why. It is the check a *selected*
// path gets — the root of a delete or of a trash — where the recursion has not
// started yet and the whole spelling is in hand.
func neverWritePath(apiPath string) (reason string, hit bool) {
	start := 0
	for i := 0; i <= len(apiPath); i++ {
		if i < len(apiPath) && apiPath[i] != '/' {
			continue
		}
		if i > start {
			if reason, hit := NeverWriteName(apiPath[start:i]); hit {
				return reason, true
			}
		}
		start = i + 1
	}
	return "", false
}
