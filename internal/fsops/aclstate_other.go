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

// xattrSize and xattrRead answer "unsupported" from either route. viaFD is
// false because there is no descriptor route here to have taken — which is the
// honest input to aclTarget.grade, even though nothing off Linux ever builds a
// probe to ask it.
func (t aclTarget) xattrSize(name string) (int, bool, error) { return 0, false, fsx.ErrUnsupported }

func (t aclTarget) xattrRead(name string, size int) ([]byte, bool, error) {
	return nil, false, fsx.ErrUnsupported
}

// absentXattrErr is never consulted here, because nothing probes; it answers
// false so that any future caller reads an unsupported probe as "unknown"
// rather than as "there is no ACL".
func absentXattrErr(err error) bool { return false }
