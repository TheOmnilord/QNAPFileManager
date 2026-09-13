//go:build !linux

package fsops

// The no-follow walk off Linux: os.Root's, which is not the same thing and is
// said so rather than papered over (INV-2).
//
// There is no O_PATH here and no openat to walk with, so what confines the
// lookup is os.Root resolving each name against the root descriptor and
// refusing anything that would leave the tree. What it does NOT do is refuse a
// symlink that stays inside — so the round-14 refusal (a symlink where a
// canonical path cannot have one is evidence the tree changed) is a Linux
// answer, and the CI Linux jobs and the NAS are where it is made.
//
// Nothing in production takes this path: the operations that use it — upload,
// archive, the move pre-flight — all need descriptor passing or a real worker,
// and the dev loop has neither.

import (
	"os"

	"qnapfilemanager/internal/fsx"
)

func openCanonicalDir(j fsx.Jail, rel, apiPath string) (*dirRef, error) {
	_ = apiPath
	return openPathRef(j, rel)
}

// dirRefFrom wraps a descriptor as the handle the walk takes. Off Linux a
// dirRef resolves its entries by name through the jail, so the jail is part of
// it — and a handle built without one would panic at the first lookup.
func dirRefFrom(j fsx.Jail, f *os.File, rel string) *dirRef {
	return &dirRef{j: j, f: f, rel: rel}
}
