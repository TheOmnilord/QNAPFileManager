//go:build !linux

package breakglass

import "os"

// The ownership and mode rules of the key pair are Linux-only (contract §15).
// Off Linux there is no uid 0 to compare against, and the permission bits a
// Stat reports are a translation of Windows ACLs rather than POSIX modes — a
// file there reads as 0666 whatever its real ACL says, so applying the rule
// would refuse every path on the dev box while proving nothing about the ACL
// that actually governs it. Saying the check is not made is better than making
// one that cannot mean what it says (INV-2: the kernel decides, the app only
// predicts, and here there is no kernel to ask). No real credential lives on a
// dev box; the NAS is Linux.
func fileStrict(os.FileInfo, string, bool) error { return nil }

func treeStrict(string) error { return nil }

// openNoFollow is a plain open off Linux: O_NOFOLLOW has no portable
// equivalent, and the checks it protects are not made here anyway.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
