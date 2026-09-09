package worker

import "syscall"

// setUmask fixes the mode mask this worker creates files with. syscall.Umask
// is process-wide and not thread-local, which is exactly right here: the
// worker is a single-user process and this is the one moment it is configured.
func setUmask(m uint32) { syscall.Umask(int(m & 0o777)) }
