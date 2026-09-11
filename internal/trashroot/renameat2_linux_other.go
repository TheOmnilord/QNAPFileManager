//go:build linux && !amd64 && !arm64

package trashroot

// sysRenameat2 is zero on architectures whose number is not compiled in here.
// renameat2 treats zero as "unavailable" and returns ENOSYS, so the publication
// takes the fstatat pre-check fallback — the same path an old kernel takes. The
// v1 targets are x86_64 and arm_64 (PLAN.md), which have their own files.
var sysRenameat2 uintptr = 0
