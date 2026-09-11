//go:build linux && !amd64 && !arm64

package fsops

// sysStatx is zero on architectures whose number is not compiled in here.
// mountIDOf treats zero as "unavailable" and falls back to /proc/self/fdinfo,
// which every kernel since 3.8 answers. The v1 targets are x86_64 and arm_64
// (PLAN.md), which have their own files.
var sysStatx uintptr = 0
