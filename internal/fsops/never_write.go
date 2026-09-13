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
	"strings"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
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
	return ProtectWrite.refusesPath(apiPath)
}

// refusesPath is refuses() applied to every component of an already-cleaned API
// path, for the check a SELECTED root gets.
//
// It exists because the walker only ever sees components it reaches by
// recursion: it refuses ".zfs" as a CHILD, and a job rooted AT
// /share/Public/.zfs/snapshot/… was never shown the component at all (M2-C
// review round 1 adversarial, finding 4). A read-only walk uses
// ProtectSnapshots here exactly as it does below, so ".zfs" is refused and
// "@Recycle" — which is ordinary readable content — is not.
func (p Protect) refusesPath(apiPath string) (reason string, hit bool) {
	start := 0
	for i := 0; i <= len(apiPath); i++ {
		if i < len(apiPath) && apiPath[i] != '/' {
			continue
		}
		if i > start {
			if reason, hit := p.refuses(apiPath[start:i]); hit {
				return reason, true
			}
		}
		start = i + 1
	}
	return "", false
}

// pseudoFSTypes are the kernel's own filesystems: they hold no user data, some
// of their files block forever when read, and the size of a "file" in them is a
// fiction. A traversal must never start on one.
//
// The walker already refuses to CROSS into them — MayCross wants Storage on
// both sides — but a job rooted directly at /proc was never crossing anything,
// so nothing looked (adversarial finding 4). This is that rule applied to the
// root itself.
//
// It is deliberately NOT "refuse everything that is not Storage", which is what
// the finding proposed. On the golden QTS table `/` is ext4 and Storage, but
// `/share` is a tmpfs — and `/share` is the folder the UI opens by default and
// the one every share hangs off. Refusing a search or an archive rooted there
// would refuse the ordinary case in order to catch the pathological one. The
// pathological one has a name, and this is the list of them.
var pseudoFSTypes = map[string]bool{
	"proc": true, "procfs": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "bpf": true, "pstore": true, "configfs": true,
	"fusectl": true, "mqueue": true, "hugetlbfs": true, "binfmt_misc": true,
	"selinuxfs": true, "nsfs": true, "efivarfs": true, "autofs": true,
	"rpc_pipefs": true, "sunrpc": true,
}

// refuseRoot decides whether a read-only traversal may start at an
// already-resolved path (adversarial finding 4).
//
// Two refusals, both of which the walker makes for every CHILD and neither of
// which it could make for the root:
//
//   - a never-read component (".zfs"), checked on both the requested spelling
//     and the resolved one, because resolve() follows the symlinks QTS builds
//     its shares out of and the component may only appear on the far side;
//   - a mount that is the kernel's own pseudo-filesystem, or a network mount.
//     The network half is refusedByTable's reason rather than decision 9's: a
//     hard NFS mount whose server has gone parks the caller inside a single
//     lstat, where no deadline in this process can reach it, and the walk would
//     never come back at all.
//
// plat == nil means "no mount knowledge", and the documented answer to that is
// that nothing is classified (List's rule); the component check still applies.
func refuseRoot(r fsx.Root, plat *platform.Platform, requested, resolved string, p Protect) error {
	for _, spelling := range []string{requested, resolved} {
		if reason, hit := p.refusesPath(spelling); hit {
			return neverWriteErr(requested, reason)
		}
	}
	return refuseRootMount(r, plat, requested, resolved)
}

// refuseRootPath is refuseRoot's half that can be decided BEFORE the path is
// resolved, and it exists because resolving is itself the dangerous act (M2-C
// review round 2 adversarial, finding 2).
//
// A root inside a hard NFS mount whose server has gone parks the caller inside
// the first lstat of resolve(), in uninterruptible sleep, where no deadline in
// this process can reach it — and the request slot it holds is never given
// back, so a handful of retries takes the worker. The mount table answers
// "which filesystem is that name on" with no syscall at all, which is exactly
// what refusedByTable does for every CHILD the walk meets; this is the same
// question asked about the root, before anything touches it.
//
// It is a spelling-based answer and therefore only the FIRST half: a symlink
// into a dead mount is not visible here, and resolve() is what would find it.
// That residual is the route's too (resolveForGuard runs before this) and is
// recorded rather than papered over.
func refuseRootPath(r fsx.Root, plat *platform.Platform, requested string, p Protect) error {
	if reason, hit := p.refusesPath(requested); hit {
		return neverWriteErr(requested, reason)
	}
	return refuseRootMount(r, plat, requested, requested)
}

// refuseRootMount is the mount-table half, asked about one spelling.
//
// The lookup is ForLiteral and not For, and the difference is a refusal that
// does not work (M2-C review round 3 adversarial, finding 1). For normalises:
// it turns a backslash into a separator and then Cleans the result. On Linux a
// backslash is an ORDINARY CHARACTER in a filename, so a real NFS mount at
// `/share/remote\backup` never matches its own row — and a path inside it
// therefore sails past the one check that was supposed to stop the daemon from
// touching it. ForLiteral compares the bytes the kernel wrote, on element
// boundaries, longest prefix first, which is the same exactness the walk's own
// pre-lstat mount check needs (MountByLiteralPath, refusedByTable).
//
// "No row matched" is NOT a refusal. The table does not describe every path —
// most paths are not under any mount point it lists as special — and the
// descriptor-based checks the walk makes afterwards are what cover a mount that
// appeared since the table was read. plat == nil is the same answer for the
// same reason: no mount knowledge classifies nothing (List's rule).
func refuseRootMount(r fsx.Root, plat *platform.Platform, requested, spelling string) error {
	if plat == nil {
		return nil
	}
	osPath, err := r.OS(spelling)
	if err != nil || osPath == "" {
		return nil
	}
	caps, ok := plat.ForLiteral(osPath)
	if !ok {
		return nil
	}
	switch {
	case pseudoFSTypes[strings.ToLower(caps.FSType)]:
		return fmt.Errorf("%q is on %s, which is the kernel's own filesystem and holds no files to work with: %w",
			requested, caps.FSType, fsx.ErrProtected)
	case caps.Network:
		return fmt.Errorf("%q is on a %s mount, which this app does not traverse: %w",
			requested, caps.FSType, fsx.ErrProtected)
	}
	return nil
}
