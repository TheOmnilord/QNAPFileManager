//go:build !linux

package fsops

// The dev loop's half of "when was this object created": there is none.
//
// statx is Linux's, and off Linux this package has no inode identity to
// strengthen in the first place (inodeIdentity is false there). The comparison
// degrades to what it already was, which is the same INV-2 degradation every
// identity check here accepts — the NAS and the CI Linux jobs make the real
// one. See btime_linux.go for what it buys.
func birthTimeOf(fd int) (int64, bool) {
	_ = fd
	return 0, false
}
