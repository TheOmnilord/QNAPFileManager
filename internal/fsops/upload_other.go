//go:build !linux

package fsops

// The upload's platform half off Linux: the dev loop's.
//
// There is no O_TMPFILE here (unnamed_other.go), so every upload takes the
// named `.qfm-upload-<hex>.part` fallback, and there is no portable dup(2) for
// an *os.File either. The second descriptor is therefore obtained by opening
// the `.part` again through the held directory — one extra lookup of a hidden,
// unguessable name, immediately after this process created it with O_EXCL.
//
// That is a real difference and it is stated rather than papered over (INV-2):
// on the NAS the front-end is handed a dup of the very descriptor the worker
// holds, and here it is handed a second open of a name. Nothing in production
// takes this path — descriptor passing needs a Unix socket, which is Linux
// here, and the in-process pool refuses uploads outright — so what this buys is
// that the engine and its tests can be exercised on the dev box at all.

import (
	"fmt"
	"os"

	"qnapfilemanager/internal/fsx"
)

func dupForWire(h *UploadHandle) (*os.File, error) {
	if h == nil || h.f == nil {
		return nil, fmt.Errorf("this upload has no descriptor to hand over: %w", fsx.ErrUnsupported)
	}
	if !h.named || h.tmpName == "" {
		// Unreachable: off Linux openUnnamed always reports errNoUnnamed, so
		// create() always takes the named path. Said out loud so that a future
		// unnamed implementation here fails loudly instead of silently handing
		// back the worker's own descriptor.
		return nil, fmt.Errorf("an unnamed upload cannot be handed over on this platform: %w", fsx.ErrUnsupported)
	}
	return h.dir.openFile(h.tmpName, os.O_WRONLY, 0)
}
