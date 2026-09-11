//go:build !linux

package trashroot

// stickyEnforced is false off Linux. Windows has no sticky bit: os.Chmod
// ignores os.ModeSticky and os.Lstat never reports it, so asserting it would
// fail on the dev box for a property the kernel there does not have. The
// directory is still created, and the assertion is the CI job's on Linux
// (INV-2: never simulate the kernel).
const stickyEnforced = false
