package platform

import (
	"regexp"
	"strings"
)

// ACL backend names used by FSCaps.ACLBackend.
const (
	ACLNone  = "none"
	ACLPosix = "posix"
	ACLNFS4  = "nfs4"
)

// Extended attribute names probed to decide the ACL backend of a mount.
const (
	XattrPosixACL = "system.posix_acl_access"
	XattrNFS4ACL  = "system.nfs4_acl"
	XattrRichACL  = "system.richacl"
)

// FSCaps describes what a mount can do, as required by the identity plan §4.2.
// Everything an operation needs to know about a path's filesystem is here; no
// operation may branch on Platform.Family.
type FSCaps struct {
	FSType  string // mountinfo fstype: "ext4", "zfs", "tmpfs", "nfs4", "fuse.sshfs", ...
	Storage bool   // real user-data filesystem that we are willing to walk and write

	// Domain groups mounts that a recursive walk may cross between:
	// "zfs:<pool>" for ZFS datasets (so every dataset of one pool is one
	// domain) and "dev:<major>:<minor>" otherwise.
	Domain string

	Mount string // mount point this FSCaps was derived from

	ACLBackend string // "posix" | "nfs4" | "none" | "" when not probed yet
	ACLXattr   string // the xattr name that answered, or ""
	ZFSAclmode string // "discard"|"groupmask"|"passthrough"|"restricted"|"" (unknown)

	Network bool // nfs, cifs, sshfs, most fuse mounts: never crossed by default
	Tmpfs   bool // memory-backed: never a storage target

	// RAM is a general-purpose RAM filesystem — tmpfs or ramfs, NOT devtmpfs —
	// the kind QTS builds /share and /tmp out of, which can hold mount points
	// for real storage. Root is the mount at "/", decided from the mount row
	// itself. Together they say what a read walk may treat as a "system" parent
	// (MayCrossRead, PLAN.md decision 9 as amended).
	RAM  bool
	Root bool
}

// storageFSTypes are the filesystems that hold user data on QTS and QuTS hero.
var storageFSTypes = map[string]bool{
	"ext2":  true,
	"ext3":  true,
	"ext4":  true,
	"xfs":   true,
	"btrfs": true,
	"zfs":   true,
	"f2fs":  true,
}

// networkFSTypes are remote filesystems. Every fuse.* type is treated as
// network too (they are usually remote and always opaque), except fuse.zfs.
var networkFSTypes = map[string]bool{
	"nfs":   true,
	"nfs4":  true,
	"cifs":  true,
	"smb3":  true,
	"smbfs": true,
	"sshfs": true,
}

var memoryFSTypes = map[string]bool{
	"tmpfs":    true,
	"devtmpfs": true,
	"ramfs":    true,
}

// IsStorageFS reports whether fstype holds user data we are willing to walk.
func IsStorageFS(fstype string) bool { return storageFSTypes[strings.ToLower(fstype)] }

// IsNetworkFS reports whether fstype is a remote filesystem. All fuse.* types
// count as network except fuse.zfs.
func IsNetworkFS(fstype string) bool {
	t := strings.ToLower(fstype)
	if networkFSTypes[t] {
		return true
	}
	if t == "fuse.zfs" {
		return false
	}
	return t == "fuse" || strings.HasPrefix(t, "fuse.")
}

// IsMemoryFS reports whether fstype is memory backed (tmpfs and friends).
func IsMemoryFS(fstype string) bool { return memoryFSTypes[strings.ToLower(fstype)] }

// ZFSPool returns the pool name of a ZFS dataset source ("zpool1/vol/Public"
// -> "zpool1").
func ZFSPool(source string) string {
	if i := strings.IndexByte(source, '/'); i >= 0 {
		return source[:i]
	}
	return source
}

// CapsFor derives the static capabilities of a mount. It performs no I/O; the
// probed fields (ACLBackend, ACLXattr, ZFSAclmode) are filled in later by
// Platform.Probe on Linux.
func CapsFor(m Mount) FSCaps {
	t := strings.ToLower(m.FSType)
	c := FSCaps{
		FSType:  m.FSType,
		Storage: IsStorageFS(t),
		Mount:   m.MountPoint,
		Network: IsNetworkFS(t),
		Tmpfs:   IsMemoryFS(t),
		RAM:     t == "tmpfs" || t == "ramfs",
		Root:    m.MountPoint == "/",
	}
	if t == "zfs" {
		c.Domain = "zfs:" + ZFSPool(m.Source)
	} else {
		c.Domain = "dev:" + m.Dev()
	}
	return c
}

// volumeNameRe is a UI grouping heuristic only. Volume roots are derived from
// the mount table (VolumeRoots), never from this pattern.
var volumeNameRe = regexp.MustCompile(`^(CACHEDEV\d+|ZFS\d+|HD[A-Z]|MD\d+)_DATA$`)

// VolumeLabel returns a short human label for a volume-root directory name,
// for grouping in the UI. It returns "" when the name does not look like a
// QNAP volume root. Nothing in the app may branch on this value.
//
//	CACHEDEV1_DATA -> "Volume 1"
//	ZFS530_DATA    -> "Pool volume 530"
//	HDA_DATA       -> "Legacy volume A"
//	MD3_DATA       -> "RAID volume 3"
func VolumeLabel(name string) string {
	mm := volumeNameRe.FindStringSubmatch(name)
	if mm == nil {
		return ""
	}
	tok := mm[1]
	switch {
	case strings.HasPrefix(tok, "CACHEDEV"):
		return "Volume " + strings.TrimPrefix(tok, "CACHEDEV")
	case strings.HasPrefix(tok, "ZFS"):
		return "Pool volume " + strings.TrimPrefix(tok, "ZFS")
	case strings.HasPrefix(tok, "MD"):
		return "RAID volume " + strings.TrimPrefix(tok, "MD")
	default: // HD[A-Z]
		return "Legacy volume " + strings.TrimPrefix(tok, "HD")
	}
}
