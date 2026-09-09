//go:build !linux

package worker

// setUmask has nothing to do off Linux: Windows has no umask, and the dev loop
// creates files with whatever the OS gives it.
func setUmask(m uint32) { _ = m }
