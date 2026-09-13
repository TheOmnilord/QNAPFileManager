//go:build !linux

package platform

// literalMountKey off Linux is the ordinary normalisation, backslashes and all.
//
// There is no kernel mount table here to be literal about: the tables this
// package holds off Linux are the synthetic ones the dev box builds (PLAN.md
// decision 15), and the paths handed to them are Windows spellings — "\Users\x"
// for what the table calls "/Users/x". Matching those byte for byte would match
// nothing at all, so the dev box keeps the lenient lookup and the Linux file
// keeps the exact one. INV-2: the kernel decides, and this is not that kernel.
func literalMountKey(osPath string) string {
	return normalizePath(osPath)
}
