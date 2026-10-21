//go:build !linux

package main

import "os"

// Off Linux there is no geteuid and no Unix ownership, so the root check and
// the mode check cannot be performed. They are not faked: the CLI says what it
// did not check rather than pretending to have checked it (contract §15). This
// path exists for the Windows dev loop; the NAS is Linux.

func requireRoot() error { return nil }

func rootCheckNote() string {
	return "this platform has no effective uid, so the root check was not performed; on the NAS this command must be run as root"
}

func checkCredentialMode(string, os.FileInfo) error { return nil }

// disableEcho cannot turn the echo off without a terminal dependency, so it
// reports false and the caller warns that the password will be visible. -stdin
// is the supported path here.
func disableEcho() (restore func(), ok bool) { return func() {}, false }
