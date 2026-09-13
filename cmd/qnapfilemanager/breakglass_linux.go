package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// requireRoot refuses to touch the credential store as anyone but root. The
// file is mode 0600 and root-owned, so a non-root run would fail anyway — but
// it would fail halfway, and "permission denied" on a rename is a worse message
// than saying up front what the rule is.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root (effective uid is %d); the break-glass credential lives in a root-owned, mode 0600 file", os.Geteuid())
	}
	return nil
}

// rootCheckNote is empty on Linux: the check above is real here.
func rootCheckNote() string { return "" }

// checkCredentialMode refuses a config file that is not owned by uid 0 or is
// group- or world-readable (contract §4.1). A credential store with the wrong
// mode is a bug worth stopping for, not warning about: whoever can read it can
// take the hash offline and grind it at their leisure.
func checkCredentialMode(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: its ownership could not be read", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root; refusing to write a credential into it", path, st.Uid)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s is mode %04o; it must not be readable by group or other (chmod 600 it first)", path, mode)
	}
	return nil
}

// disableEcho turns the controlling terminal's echo off through stty, because
// golang.org/x/term would be a second dependency and bcrypt is the only one
// this project allows (PLAN decision 1). It returns a restore function and
// whether the echo was actually turned off; a caller that gets false warns
// rather than pretending the password is hidden.
func disableEcho() (restore func(), ok bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return func() {}, false
	}
	run := func(arg string) error {
		cmd := exec.Command("stty", arg)
		cmd.Stdin = tty
		cmd.Stdout, cmd.Stderr = nil, nil
		return cmd.Run()
	}
	if err := run("-echo"); err != nil {
		tty.Close()
		return func() {}, false
	}
	return func() {
		if err := run("echo"); err != nil {
			// The shell's own `stty echo` is the operator's recourse; saying so
			// is better than leaving a terminal silently deaf.
			fmt.Fprintln(os.Stderr, "warning: the terminal echo could not be restored; run `stty echo`")
		}
		tty.Close()
	}, true
}
