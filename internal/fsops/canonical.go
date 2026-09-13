package fsops

// Opening a path the front-end has ALREADY resolved, without resolving it again
// (M2-C review round 14 adversarial, findings 1 and 2).
//
// Every M2-C operation is authorized in two halves. The route resolves the
// user's path through the guard's oracle — which follows symlinks, because that
// is what /share/Public is — checks the protected-path table against the
// canonical spelling, and sends THAT to the worker. The worker then used to
// resolve it a second time, following symlinks all over again, and the two
// resolutions are separated by a gap the client chooses: the upload's body
// headers, the archive's stream, the wait between a move's pre-flight and its
// job.
//
// An ancestor swapped for a symlink inside that gap was followed by the second
// resolution. The path still "resolved", the identity recorded afterwards
// proved the wrong object perfectly, and the guard — which had passed judgement
// on a different tree — was never asked again. So the second resolution is not
// a resolution any more: it is a walk that follows nothing.
//
// A canonical path contains no symlinks by construction. One found here is
// therefore not a path to follow, it is evidence that the tree changed after it
// was authorized, and the answer is fsx.ErrChanged — never the replacement's
// contents.
//
// The LEAF is a different question and each caller answers it: a directory
// caller (an upload's destination, a search root) refuses a symlink leaf
// because it wants the directory that was cleared, while an archive root or an
// FSIdentity describes whatever is at the name, symlink included, without ever
// following it.
//
// resolve() is untouched and still follows. It is the oracle the guard's own
// answer is built from, and that is its job.

import (
	"fmt"
	"os"

	"qnapfilemanager/internal/fsx"
)

// canonicalTarget names an already-canonical API path inside the jail, without
// resolving anything at all: the components are taken as written and the walk
// that opens them is what refuses a symlink among them.
func canonicalTarget(r fsx.Root, apiPath string) (jailPath, error) {
	j, err := r.Open()
	if err != nil {
		return jailPath{}, err
	}
	rel, err := r.Rel(apiPath)
	if err != nil {
		return jailPath{}, err
	}
	return jailPath{jail: j, rel: rel, api: apiPath}, nil
}

// canonicalDir opens an already-canonical API path as a DIRECTORY, following
// nothing, and hands back a dirfd-only handle for it.
//
// It is openPathRef's no-follow twin, and the difference is the point: this one
// refuses a symlink anywhere on the path INCLUDING the leaf, because every
// caller of it wants the directory that was authorized rather than whatever a
// link of that name points at now.
func canonicalDir(r fsx.Root, apiPath string) (*dirRef, jailPath, error) {
	tg, err := canonicalTarget(r, apiPath)
	if err != nil {
		return nil, jailPath{}, err
	}
	d, err := openCanonicalDir(tg.jail, tg.rel, apiPath)
	if err != nil {
		return nil, jailPath{}, err
	}
	return d, tg, nil
}

// canonicalLeaf opens the leaf of an already-canonical API path with no-follow
// and hands back both the leaf (held) and its parent directory.
//
// A symlink LEAF is perfectly legitimate here — it is described as the link it
// is, which is what an archive of a symlink and an FSIdentity of one both want
// — while a symlink ANCESTOR is the refusal above. The jail base has no parent
// and is returned with a nil one.
func canonicalLeaf(r fsx.Root, apiPath string) (parent *dirRef, ref *itemRef, name string, tg jailPath, err error) {
	tg, err = canonicalTarget(r, apiPath)
	if err != nil {
		return nil, nil, "", jailPath{}, err
	}
	if tg.rel == "." || tg.rel == "" {
		return nil, nil, "", tg, nil
	}
	parentRel, leaf := splitFinal(tg.rel)
	parent, err = openCanonicalDir(tg.jail, parentRel, apiPath)
	if err != nil {
		return nil, nil, "", jailPath{}, err
	}
	ref, err = itemRefIn(parent, leaf)
	if err != nil {
		parent.close()
		return nil, nil, "", jailPath{}, err
	}
	return parent, ref, leaf, tg, nil
}

// errCanonicalChanged is the refusal every symlink found on an already-resolved
// path produces. The message says what was expected of the caller, because the
// most likely way to meet it in development is a front-end that forgot to send
// the resolved spelling.
func errCanonicalChanged(apiPath, component string) error {
	return fmt.Errorf(
		"%q passes through %q, which is now a symlink; this operation is given paths that were already resolved, so the folder it was authorized against has been replaced: %w",
		apiPath, component, fsx.ErrChanged)
}

// errNotADirectory is the other refusal the walk makes: a component that is
// there and is not a directory. It is the kernel's ENOTDIR expressed in this
// app's vocabulary, so a caller reports "bad request" rather than "internal".
func errNotADirectory(apiPath, component string) error {
	return fmt.Errorf("%q passes through %q, which is not a directory: %w", apiPath, component, fsx.ErrBadName)
}

// objectID is what makes two lookups the same OBJECT rather than two objects of
// one name: the device and inode, and — where the filesystem records it — the
// moment the object was created.
//
// The birth time is the half that survives a gap. An inode number is freed with
// its object and may be handed back to the next thing created at that name, so
// a client that controls how long the gap is can loop until the number repeats
// (round 14 adversarial). Nothing can change a birth time once it is set.
type objectID struct {
	key      inodeKey
	have     bool
	btime    int64
	hasBtime bool
}

// objectIDOf reads an identity from a HELD descriptor and the stat that was
// taken of it. f may be nil, in which case only what a FileInfo carries is
// available — which is why every check that matters is made on a descriptor.
func objectIDOf(f *os.File, fi os.FileInfo) objectID {
	var id objectID
	id.key, id.have = inodeOf(fi)
	if f == nil {
		return id
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return id
	}
	_ = rc.Control(func(fd uintptr) {
		id.btime, id.hasBtime = birthTimeOf(int(fd))
	})
	return id
}

// same reports whether two recorded identities describe one object.
//
// An identity that could not be READ is a refusal wherever the platform has
// identities at all (sameRecordedInode's rule): no proof, no action. Off Linux
// there are none and the comparison is not made, which is the INV-2
// degradation every identity check in this package accepts.
func (a objectID) same(b objectID) bool {
	if !inodeIdentity {
		return true
	}
	if !a.have || !b.have || a.key != b.key {
		return false
	}
	if a.hasBtime && b.hasBtime {
		return a.btime == b.btime
	}
	return true
}
