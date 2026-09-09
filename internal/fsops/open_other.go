//go:build !linux

package fsops

import "os"

// openReadFlags off Linux is a plain read-only open: there is no O_NOFOLLOW to
// ask for. The final component is therefore followed on the dev box, which is
// a difference from the NAS and is why nothing but the dev loop runs here.
func openReadFlags() int { return os.O_RDONLY }
