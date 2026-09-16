//go:build !linux

package config

// keyDirStrict is Linux-only (contract §15). Off Linux there is no uid 0 to
// compare against, and the permission bits os.Stat reports are a translation of
// Windows ACLs rather than POSIX modes — a directory there reads as 0777
// whatever its real ACL says, so applying the rule would refuse every explicit
// key path on the dev box while proving nothing about the ACL that actually
// governs it. Saying the check is not made is better than making one that
// cannot mean what it says (INV-2: the kernel decides, the app only predicts,
// and here there is no kernel to ask).
func keyDirStrict(string) error { return nil }
