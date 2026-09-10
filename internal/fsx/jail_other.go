//go:build !linux

package fsx

import "os"

// Jail off Linux is *os.Root itself.
//
// There is no O_PATH here to separate "give me a handle" from "let me read
// this", and no openat to walk with, so the confinement handle and the walker
// are the same object — which is what os.Root is. The consequence is the one
// the Linux side exists to remove: os.Root opens the base, and every directory
// on the way to a file, with a plain O_RDONLY, so it asks for read permission
// where the kernel asks only for search. That is stricter than the kernel
// rather than looser, and this platform is the Windows dev box, whose ACLs have
// no "search but not read" shape to get wrong.
//
// It is an alias rather than a wrapper so that the platform half of fsops
// (open_other.go) keeps calling os.Root's own methods on it, while the shared
// half — which only ever passes the handle along — reads the same on both
// platforms.
type Jail = *os.Root

// openJail opens the confinement handle.
func openJail(dir string) (Jail, error) { return os.OpenRoot(dir) }
