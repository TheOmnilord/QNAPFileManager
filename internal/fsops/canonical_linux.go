package fsops

// The no-follow walk itself. See canonical.go for why it exists.

import (
	"io/fs"
	"os"
	"syscall"

	"qnapfilemanager/internal/fsx"
)

// openCanonicalDir opens the directory named by an already-canonical
// jail-relative path, one component at a time, following nothing.
//
// It is walkOPath with two differences, and both are the point:
//
//   - every component is opened O_PATH|O_NOFOLLOW and then FSTAT'ed, rather
//     than opened with O_DIRECTORY and left to the kernel. O_PATH|O_NOFOLLOW on
//     a symlink hands back a descriptor for the LINK — which O_DIRECTORY would
//     turn into a bare ENOTDIR, indistinguishable from "that component is a
//     file". The distinction is exactly what has to be reported here: a file in
//     the way is a bad request, and a symlink in the way is evidence that the
//     tree changed after it was authorized;
//   - the descriptor that comes back is the one that was checked. Nothing is
//     looked up twice.
//
// The result is a dirfd-only O_PATH handle, like openPathRef's: creating an
// entry needs search permission on the directory and not read (INV-2), so a
// mode-0333 drop directory is one the kernel allows and this must not refuse.
func openCanonicalDir(j fsx.Jail, rel, apiPath string) (*dirRef, error) {
	dir, err := j.OpenBase()
	if err != nil {
		return nil, err
	}
	for i, part := range splitRel(rel) {
		switch part {
		case "", ".":
			continue
		case "..":
			// resolve() applies "..", with the kernel's own permission check;
			// a canonical path has none left in it and a second interpretation
			// here could only disagree with the first (walkOPath's rule).
			dir.Close()
			return nil, &fs.PathError{Op: "openat", Path: rel, Err: syscall.EINVAL}
		}
		fd, oerr := openatIn(dir, part, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC)
		dir.Close()
		if oerr != nil {
			return nil, &fs.PathError{Op: "openat", Path: relOf(splitRel(rel)[:i+1]), Err: oerr}
		}
		dir = os.NewFile(uintptr(fd), relOf(splitRel(rel)[:i+1]))
		fi, serr := dir.Stat()
		if serr != nil {
			dir.Close()
			return nil, serr
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			dir.Close()
			return nil, errCanonicalChanged(apiPath, part)
		}
		if !fi.IsDir() {
			dir.Close()
			return nil, errNotADirectory(apiPath, part)
		}
	}
	return &dirRef{f: dir, rel: rel}, nil
}

// dirRefFrom wraps a descriptor this package already holds as the handle the
// walk takes. On Linux a dirRef IS the descriptor, so the jail is not part of
// it; off Linux it is a jail-relative name and the jail is (canonical_other.go).
func dirRefFrom(j fsx.Jail, f *os.File, rel string) *dirRef {
	_ = j
	return &dirRef{f: f, rel: rel}
}
