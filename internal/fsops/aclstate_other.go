//go:build !linux

package fsops

// There are no extended attributes to read off Linux, so the badge never
// appears and the dialogs hide the ACL row (m3-contract §14). Nothing is
// simulated: an invented "none" for a filesystem that has ACLs would be worse
// than no badge at all, and the platform's own probe already reports
// ACLBackend "none" here, so newACLProbe never gets this far.

import "qnapfilemanager/internal/fsx"

// xattrProbeAvailable is false: this platform reads no extended attributes.
const xattrProbeAvailable = false

func lgetxattrSize(path, name string) (int, error) { return 0, fsx.ErrUnsupported }

func lgetxattrRead(path, name string, size int) ([]byte, error) { return nil, fsx.ErrUnsupported }

// absentXattrErr is never consulted here, because nothing probes; it answers
// false so that any future caller reads an unsupported probe as "unknown"
// rather than as "there is no ACL".
func absentXattrErr(err error) bool { return false }
