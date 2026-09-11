package fsops

// sysStatx is the statx(2) syscall number on linux/amd64. The syscall package
// exports no SYS_STATX on any architecture, so it is named per architecture here
// exactly as sysRenameat2 is. A var, not a const, so the "unavailable" check in
// mountIDOf is not folded away on the architectures that do define it.
var sysStatx uintptr = 332
