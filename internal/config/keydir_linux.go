package config

import (
	"fmt"
	"os"
	"syscall"
)

// keyDirStrict applies sshd's rule to the directory an explicitly configured
// break-glass key lives in: owned by uid 0, and writable by nobody but its
// owner (Astra r1 #9).
//
// A directory that does not exist yet is not a finding — the daemon creates it
// at 0700 when it generates the pair, and refusing here would make "the
// certificate has not been generated yet" a reason not to bind at all.
func keyDirStrict(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("the break-glass key directory %s could not be read: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("the break-glass key directory %s is not a directory", dir)
	}
	if mode := fi.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("the break-glass key directory %s is mode %04o: group- or world-writable, so the key the emergency door serves can be replaced by someone other than root", dir, mode)
	}
	// Ownership is asked of the kernel, not predicted (INV-2): Stat's Sys is the
	// stat(2) the kernel returned.
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 {
		return fmt.Errorf("the break-glass key directory %s is owned by uid %d, not root", dir, st.Uid)
	}
	return nil
}
