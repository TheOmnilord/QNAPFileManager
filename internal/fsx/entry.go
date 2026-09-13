// Package fsx holds the read-only path, type and error vocabulary shared by
// the root front-end and the per-user worker. Nothing in this package mutates
// the filesystem: mutation lives in internal/fsops, which only the worker
// imports (INV-1).
package fsx

import (
	"encoding/base64"
	"io/fs"
	"strconv"
	"time"
	"unicode/utf8"
)

// Entry describes one directory entry. The shape is fixed by
// docs/design/backend-packaging-plan.md §2.1 and is what the HTTP API returns
// verbatim.
//
// Linux filenames are arbitrary byte strings, but encoding/json replaces
// invalid UTF-8 with U+FFFD, so such a name cannot round-trip through Name.
// NameB64/PathB64 carry the raw bytes in that case and every endpoint that
// accepts a path also accepts pathB64.
type Entry struct {
	Name    string `json:"name"`
	NameB64 string `json:"nameB64,omitempty"`
	Path    string `json:"path"`
	PathB64 string `json:"pathB64,omitempty"`

	// Type is "dir", "file", "symlink", "fifo", "socket", "device" or "other".
	Type string `json:"type"`
	// Size is st_size; for a symlink that is the length of the link text, not
	// the size of its target.
	Size int64 `json:"size"`
	// Mode is octal and includes setuid/setgid/sticky, e.g. "0755".
	Mode string `json:"mode"`
	// ModeStr is the ls -l rendering, e.g. "drwxr-sr-x".
	ModeStr string `json:"modeStr"`

	UID int `json:"uid"`
	GID int `json:"gid"`
	// User and Group are empty when the id does not resolve; the UI then shows
	// the number.
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`

	MTime time.Time `json:"mtime"`
	Nlink uint64    `json:"nlink"`

	IsSymlink bool `json:"isSymlink,omitempty"`
	// LinkTarget is the raw readlink(2) text.
	LinkTarget string `json:"linkTarget,omitempty"`
	// LinkTargetB64 carries the same bytes base64url-encoded, and is set only
	// when they are not valid UTF-8 — exactly like NameB64. A symlink target is
	// an arbitrary byte string on Linux, so a target that JSON would rewrite
	// into U+FFFD has to travel beside the display string. The UI must send
	// this value (as pathB64) rather than linkTarget whenever it is present.
	LinkTargetB64 string `json:"linkTargetB64,omitempty"`
	// LinkResolved is the fully evaluated target, empty when dangling or looping.
	LinkResolved string `json:"linkResolved,omitempty"`
	// LinkResolvedB64 is LinkResolved's raw-bytes counterpart, set on the same
	// rule. "Go to symlink target" must navigate with this when it is present:
	// the string form of a non-UTF-8 path names a different file, or none.
	LinkResolvedB64 string `json:"linkResolvedB64,omitempty"`
	// TargetType is the Type of the resolved target, empty when dangling.
	TargetType string `json:"targetType,omitempty"`

	Hidden bool `json:"hidden,omitempty"`
	// HasACL is the boolean kept for compatibility: true for ACLPosix, ACLNFS4
	// and ACLUnknown, false for everything else including "not probed".
	HasACL bool `json:"hasAcl,omitempty"`
	// ACL is the ACL STATE of the entry (M3 contract §6.1): "" when it was not
	// probed at all, else ACLNone, ACLPosix, ACLNFS4, ACLNFS4Trivial or
	// ACLUnknown.
	//
	// A state and not a boolean, because on ZFS presence is the wrong question:
	// every object on a dataset carries system.nfs4_acl, so "the attribute
	// exists" would badge the whole NAS. What the badge reports is whether the
	// ACL says anything the mode does not.
	ACL        string `json:"acl,omitempty"`
	MountPoint bool   `json:"mountPoint,omitempty"`

	// Class is the guard classification: "normal", "warn" or "protected".
	Class string `json:"class,omitempty"`
	// ShareLink and VolumeRoot tag the two kinds of entry found at /share.
	ShareLink  bool `json:"shareLink,omitempty"`
	VolumeRoot bool `json:"volumeRoot,omitempty"`
}

// The Entry.ACL vocabulary (M3 contract §6.1). The empty string is a sixth
// value with a meaning of its own — "not probed" — and is deliberately not a
// constant here: it is the zero value, and naming it would invite a caller to
// treat "we did not look" as a fact about the file.
const (
	// ACLNone: the filesystem has an ACL backend and this object carries no
	// ACL beyond the mode.
	ACLNone = "none"
	// ACLPosix: system.posix_acl_access is present and non-empty — exactly the
	// "+" in ls -l.
	ACLPosix = "posix"
	// ACLNFS4: an NFSv4 ACL that names somebody other than
	// OWNER@/GROUP@/EVERYONE@, or carries an inheritance flag.
	ACLNFS4 = "nfs4"
	// ACLNFS4Trivial: an NFSv4 ACL that is only what the mode already describes.
	// ZFS gives every object one of these, so this is the ordinary state on a
	// hero dataset and is NOT badged.
	ACLNFS4Trivial = "nfs4-trivial"
	// ACLUnknown: the attribute could not be read or could not be parsed. It is
	// never reported as ACLNone — a failure fails towards the pessimistic side,
	// which is the half that matters.
	ACLUnknown = "unknown"
)

// ACLPresent reports whether an ACL state means "there is an ACL here worth
// telling the user about". It is what fills Entry.HasACL.
func ACLPresent(state string) bool {
	switch state {
	case ACLPosix, ACLNFS4, ACLUnknown:
		return true
	}
	return false
}

// SetACL records a probed ACL state and keeps HasACL consistent with it.
func (e *Entry) SetACL(state string) {
	e.ACL = state
	e.HasACL = ACLPresent(state)
}

// SetName fills Name and, only when the raw bytes are not valid UTF-8,
// NameB64. Callers pass the bytes exactly as the kernel returned them.
func (e *Entry) SetName(raw []byte) {
	e.Name = string(raw)
	if utf8.Valid(raw) {
		e.NameB64 = ""
		return
	}
	e.NameB64 = base64.RawURLEncoding.EncodeToString(raw)
}

// SetPath is SetName's counterpart for the Path/PathB64 pair.
func (e *Entry) SetPath(raw []byte) {
	e.Path = string(raw)
	if utf8.Valid(raw) {
		e.PathB64 = ""
		return
	}
	e.PathB64 = base64.RawURLEncoding.EncodeToString(raw)
}

// SetLinkTarget fills LinkTarget and, only for bytes that are not valid UTF-8,
// LinkTargetB64. readlink(2) returns whatever bytes were stored, so the same
// rule that protects a filename has to protect a link target.
func (e *Entry) SetLinkTarget(raw []byte) {
	e.LinkTarget = string(raw)
	if utf8.Valid(raw) {
		e.LinkTargetB64 = ""
		return
	}
	e.LinkTargetB64 = base64.RawURLEncoding.EncodeToString(raw)
}

// SetLinkResolved is SetLinkTarget's counterpart for the fully evaluated
// target, which is the value the UI navigates to.
func (e *Entry) SetLinkResolved(raw []byte) {
	e.LinkResolved = string(raw)
	if utf8.Valid(raw) {
		e.LinkResolvedB64 = ""
		return
	}
	e.LinkResolvedB64 = base64.RawURLEncoding.EncodeToString(raw)
}

// SortKey values accepted by ListOptions.Sort. They are untyped string
// constants so the field can stay a plain string in JSON.
const (
	SortName  = "name"
	SortSize  = "size"
	SortMTime = "mtime"
	SortType  = "type"
)

// DefaultListLimit and MaxListLimit bound a single listing. A directory with
// more entries than the cap comes back with Listing.Truncated set rather than
// as a multi-megabyte response.
const (
	DefaultListLimit = 5000
	MaxListLimit     = 50000
)

// ValidSortKey reports whether s names a sort order List understands. The
// empty string means "the default", so it is valid.
func ValidSortKey(s string) bool {
	switch s {
	case "", SortName, SortSize, SortMTime, SortType:
		return true
	}
	return false
}

// ListOptions are the knobs on a single directory listing.
type ListOptions struct {
	// ShowHidden includes dotfiles.
	ShowHidden bool `json:"showHidden,omitempty"`
	// ShowVolumeRoots reveals the raw volume mounts at /share (§2.2).
	ShowVolumeRoots bool `json:"showVolumeRoots,omitempty"`
	// ResolveLinks stats each symlink to learn its target type. Costly on
	// /share; defaults to true at the API layer.
	ResolveLinks bool   `json:"resolveLinks,omitempty"`
	Sort         string `json:"sort,omitempty"`
	Desc         bool   `json:"desc,omitempty"`
	// DirsFirst groups directories above everything else, whatever the sort
	// key and whatever Desc says — reversing that grouping is not what anyone
	// means by "sort descending".
	DirsFirst bool `json:"dirsFirst,omitempty"`
	Offset    int  `json:"offset,omitempty"`
	// Limit defaults to DefaultListLimit and is capped at MaxListLimit.
	Limit int `json:"limit,omitempty"`
	// ACLProbe asks the listing to fill Entry.ACL (M3 contract §6.2). It costs
	// one lgetxattr per entry, so it is off unless the route asks, it is only
	// honoured where the mount has an ACL backend at all, and it is bounded per
	// page by ACLProbeMaxEntries and ACLProbeMaxBytes — beyond either, the rest
	// of the page is left unprobed and the listing says so.
	ACLProbe bool `json:"aclProbe,omitempty"`
}

// The ACL probe's per-page bounds (M3 contract §6.2 and §13). They are per PAGE
// rather than per directory because the probe runs over the entries actually
// being returned: paging through a huge folder therefore badges each page it
// shows instead of badging nothing at all.
const (
	ACLProbeMaxEntries = 2000
	ACLProbeMaxBytes   = 64 << 10
)

// ACLProbeCappedNote is the listing note the probe adds when it stopped at one
// of its bounds. It is a sentence and not a code because it is shown verbatim.
const ACLProbeCappedNote = "ACL badges are not shown for very large folders."

// Listing is one page of a directory.
type Listing struct {
	Path      string  `json:"path"`
	Parent    string  `json:"parent"`
	Entries   []Entry `json:"entries"`
	Total     int     `json:"total"`
	Truncated bool    `json:"truncated,omitempty"`
	// Notes are human-readable remarks about the directory itself, e.g.
	// "on the QTS RAM disk" or "mount point".
	Notes []string `json:"notes,omitempty"`
	// Class is the guard classification of the directory itself.
	Class string `json:"class,omitempty"`
}

// TypeString maps a mode to the Entry.Type vocabulary.
func TypeString(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	case m.IsRegular():
		return "file"
	}
	return "other"
}

// ModeOctal renders the permission bits plus setuid/setgid/sticky the way
// chmod states them, e.g. "0755" or "1777".
func ModeOctal(m fs.FileMode) string {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	s := strconv.FormatUint(uint64(v), 8)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// ModeString renders a mode the way ls -l does, e.g. "drwxr-sr-x". This is
// deliberately not fs.FileMode.String: Go prints setuid/setgid/sticky as
// extra leading letters ("ug t"), which no NAS operator reads fluently.
func ModeString(m fs.FileMode) string {
	buf := make([]byte, 0, 10)
	switch {
	case m&fs.ModeSymlink != 0:
		buf = append(buf, 'l')
	case m.IsDir():
		buf = append(buf, 'd')
	case m&fs.ModeCharDevice != 0:
		buf = append(buf, 'c')
	case m&fs.ModeDevice != 0:
		buf = append(buf, 'b')
	case m&fs.ModeNamedPipe != 0:
		buf = append(buf, 'p')
	case m&fs.ModeSocket != 0:
		buf = append(buf, 's')
	default:
		buf = append(buf, '-')
	}
	perm := m.Perm()
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			buf = append(buf, rwx[i])
		} else {
			buf = append(buf, '-')
		}
	}
	// The execute column of each triple doubles as the setuid/setgid/sticky
	// flag; upper case when the underlying execute bit is clear.
	set := func(i int, lower, upper byte) {
		if buf[i] == 'x' {
			buf[i] = lower
		} else {
			buf[i] = upper
		}
	}
	if m&fs.ModeSetuid != 0 {
		set(3, 's', 'S')
	}
	if m&fs.ModeSetgid != 0 {
		set(6, 's', 'S')
	}
	if m&fs.ModeSticky != 0 {
		set(9, 't', 'T')
	}
	return string(buf)
}
