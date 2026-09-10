//go:build !linux

package fsops

import (
	"os"

	"qnapfilemanager/internal/fsx"
)

// The mutations off Linux go through os.Root's own methods, exactly as the read
// side does in open_other.go. There is no O_PATH handle and no *at syscall to
// reach for, so the confinement handle and the operation are one object — which
// is what os.Root is: every name is resolved relative to the root descriptor
// and a symlink that would leave the tree is refused. This is the Windows dev
// box and the in-process worker the tests and the dev loop use (ModeInProcess);
// impersonation and the O_PATH permission semantics are the two things it does
// not reproduce, and both are the kernel's job, which is why they are only ever
// exercised on Linux (INV-2).

// mkdirAt creates name inside the directory named by parentRel, creating the
// missing intermediate directories of parentRel first when parents is set. The
// final component keeps O_EXCL semantics: os.Root.Mkdir reports an existing
// name as fs.ErrExist rather than succeeding.
func mkdirAt(j fsx.Jail, parentRel, name string, mode os.FileMode, parents bool) error {
	child := relJoin(parentRel, name)
	if parents && parentRel != "." && parentRel != "" {
		if err := j.MkdirAll(parentRel, mode); err != nil {
			return err
		}
	}
	return j.Mkdir(child, mode)
}

// renameAt renames fromName under fromParentRel to toName under toParentRel.
// Both parents belong to the same Root, so both jail handles are the same
// os.Root and either serves; os.Root.Rename resolves both names against it.
func renameAt(fromJail fsx.Jail, fromParentRel, fromName string, _ fsx.Jail, toParentRel, toName string) error {
	return fromJail.Rename(relJoin(fromParentRel, fromName), relJoin(toParentRel, toName))
}

// unlinkAt removes name from the directory named by parentRel. os.Root.Remove
// deletes a file or an empty directory and refuses a non-empty one with
// ENOTEMPTY, removing a symlink as the link rather than following it — so the
// isDir hint the Linux path needs to choose AT_REMOVEDIR is not needed here.
func unlinkAt(j fsx.Jail, parentRel, name string, _ bool) error {
	return j.Remove(relJoin(parentRel, name))
}
