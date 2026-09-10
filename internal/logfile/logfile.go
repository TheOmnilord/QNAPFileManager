// Copied from GitBackup internal/logfile/logfile.go

// Package logfile provides the log destination a background service needs:
// a file that cannot grow without bound. A Windows service (and any daemon)
// has no console to print to, so without this the run log of a program that
// is meant to run for years would either be lost or eat a disk.
package logfile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMaxBytes keeps a log small enough to open in Notepad while still
// holding a long history of runs — entries are one line each.
const DefaultMaxBytes = 8 << 20

// Writer appends to a file, rotating it once when it grows past a limit. One
// previous generation is kept as "<name>.1": enough to investigate a failure
// that happened overnight, bounded at twice the limit on disk.
type Writer struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
	// closed distinguishes "shut down deliberately" from "not open right
	// now": only the first must refuse later writes.
	closed bool
}

// Open prepares path for appending, creating its directory if needed.
func Open(path string, max int64) (*Writer, error) {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &Writer{path: path, max: max}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	size := int64(0)
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	w.f, w.size = f, size
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.f == nil {
		// A previous rotation could not reopen the file — a moment of
		// antivirus interference, a full disk. Without this the writer
		// stayed dead for the life of the process and the service's log
		// simply ended, months before anyone looked for it. Every write is
		// another chance to come back.
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	// Rotate before the write rather than after, so a single large entry
	// still lands whole in the new file.
	if w.size > 0 && w.size+int64(len(p)) > w.max {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// Sync flushes the file's buffered data to stable storage by calling the
// underlying *os.File.Sync. A durable audit line (an intent line, a safety
// milestone) is only truly persisted once this returns, so the caller can wait
// on it before proceeding. It returns os.ErrClosed on a deliberately closed
// writer and nil when the file is momentarily not open (a rotation could not
// reopen it): there is nothing buffered in that case, and the next Write reopens.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if w.f == nil {
		return nil
	}
	return w.f.Sync()
}

// rotate is called with the lock held. Windows will not rename a file that is
// still open, so the handle is closed first; if anything fails the writer is
// reopened on the original path rather than left without a destination.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		// The handle is in an unknown state, so skip the rename — but reopen
		// the path. Leaving f nil would return os.ErrClosed for every later
		// write, silently ending the service's log until a restart.
		w.f = nil
		if oerr := w.open(); oerr != nil {
			return errors.Join(err, oerr)
		}
		return err
	}
	w.f = nil
	// Move the previous generation aside rather than deleting it, and only
	// drop it once the new one is safely in place. Removing it up front
	// destroyed yesterday's log even when the rename then failed — a viewer
	// holding the current file open is enough on Windows — so an
	// investigation lost the very history this file is kept for. Windows
	// will not rename onto an existing name, hence the shuffle rather than
	// one rename.
	previous := w.path + ".1"
	superseded := w.path + ".2"
	// A previous attempt may have died between the two renames below, or
	// failed to put back what it moved aside, leaving the only copy of the
	// previous generation at .2 with no .1 beside it. Nothing else ever
	// reads .2, so deleting it here — the first thing this function used to
	// do — would throw away the very history the shuffle exists to keep.
	// Put it back instead, then carry on.
	// Whether the put-back worked decides whether the next line is a routine
	// deletion or the loss of the only copy. Discarding its error and then
	// removing unconditionally destroyed a stranded generation whenever the
	// rename failed and the remove did not — an antivirus scanner releasing
	// its handle between two adjacent syscalls is enough — which is the exact
	// outcome the paragraph above exists to prevent.
	//
	// And a stat that failed is not a .2 that is absent. With no .1 beside
	// it, whatever is at .2 is the only previous generation there is; not
	// knowing whether it exists is a reason to leave it, not to remove it.
	stranded := false
	if _, err := os.Stat(previous); os.IsNotExist(err) {
		switch _, err := os.Stat(superseded); {
		case err == nil:
			if err := renameFile(superseded, previous); err != nil {
				stranded = true
			}
		case !os.IsNotExist(err):
			stranded = true
		}
	}
	if !stranded {
		_ = os.Remove(superseded)
	}
	if err := renameFile(previous, superseded); err != nil && !os.IsNotExist(err) {
		// The old generation cannot be moved: keep it, keep logging, and
		// try again at the next rotation.
		return w.open()
	}
	if err := renameFile(w.path, previous); err != nil {
		// Rotation failed. Put the previous generation back, so nothing was
		// given up for a rotation that did not happen.
		_ = renameFile(superseded, previous)
		return w.open()
	}
	_ = os.Remove(superseded)
	return w.open()
}

// renameFile is os.Rename, indirected so a test can fail it: the whole
// point of the shuffle above is what happens when it does.
var renameFile = os.Rename

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Recorded separately from f being nil, which now only means "not open
	// at the moment" — a closed writer must stay closed rather than reopen
	// itself on the next stray write.
	w.closed = true
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
