package fsops

// sysRenameat2 is the renameat2(2) syscall number on linux/amd64. The syscall
// package does not export SYS_RENAMEAT2, so it is named per architecture here.
// A var, not a const, so the "unavailable" check in renameat2 is not folded to
// a constant on the architectures that do define it.
var sysRenameat2 uintptr = 316
