package platform

// literalMountKey is the table key for a path that must be matched byte for
// byte (MountByLiteralPath).
//
// On Linux a mount point is bytes: every byte but '/' and NUL is legal in a
// filename, a backslash included, and the kernel prints the mount point in
// mountinfo with only \040-style octal escapes for space, tab, newline and
// backslash — which the parser has already decoded. So the key is the path
// itself, with one demand made of it: it has to be absolute, because every row
// in the table is.
//
// Nothing is cleaned. A caller that has "/a/b/../c" has a path whose meaning
// depends on what "b" currently is, and this lookup is made precisely when
// nothing may be resolved; a spelling that is not already canonical simply does
// not match a row, which is the safe answer here (the walk falls through to its
// descriptor-based checks).
func literalMountKey(osPath string) string {
	if osPath == "" || osPath[0] != '/' {
		return ""
	}
	return osPath
}
